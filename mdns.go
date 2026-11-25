package main

// Minimal built-in mDNS publisher/responder, used when the zeroconf
// library cannot work (Android/Termux: Go cannot enumerate network
// interfaces there at all). It needs only our LAN IP address: the
// multicast group is joined with IP_ADD_MEMBERSHIP addressed by that
// IP, and announcements are sent with IP_MULTICAST_IF set to it.

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"time"
)

type mdnsSvc struct {
	service  string // "_raop._tcp.local"
	instance string // "xxxx@GoAirPlay._raop._tcp.local"
	txt      []string
}

type miniMDNS struct {
	conn *net.UDPConn
	ip   net.IP
	host string // "GoAirPlay.local"
	port int
	svcs []mdnsSvc
	done chan struct{}
}

const mdnsGroupIP = "224.0.0.251"

func startMiniMDNS(ipStr string, port int, hostName string, svcs []mdnsSvc) (*miniMDNS, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return nil, &net.ParseError{Type: "IP address", Text: ipStr}
	}
	conn, err := mdnsSocket(ip)
	if err != nil {
		return nil, err
	}
	m := &miniMDNS{conn: conn, ip: ip, host: hostName + ".local", port: port, svcs: svcs, done: make(chan struct{})}
	go m.announceLoop()
	go m.queryLoop()
	log.Printf("[mdns-mini] publishing on %s via %s", hostName, ipStr)
	return m, nil
}

func (m *miniMDNS) Shutdown() {
	close(m.done)
	m.conn.Close()
}

// ---- DNS wire helpers ----

func writeName(buf []byte, name string) []byte {
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

func writeRR(buf []byte, name string, rtype uint16, ttl uint32, rdata []byte) []byte {
	buf = writeName(buf, name)
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:], rtype)
	binary.BigEndian.PutUint16(fixed[2:], 1) // class IN (cache-flush bit set below for unique records)
	if rtype == 33 || rtype == 16 || rtype == 1 {
		binary.BigEndian.PutUint16(fixed[2:], 0x8001) // cache-flush + IN
	}
	binary.BigEndian.PutUint32(fixed[4:], ttl)
	binary.BigEndian.PutUint16(fixed[8:], uint16(len(rdata)))
	buf = append(buf, fixed[:]...)
	return append(buf, rdata...)
}

func (m *miniMDNS) allRecords() (rrs []struct {
	name  string
	rtype uint16
	rdata []byte
}) {
	add := func(name string, rtype uint16, rdata []byte) {
		rrs = append(rrs, struct {
			name  string
			rtype uint16
			rdata []byte
		}{name, rtype, rdata})
	}
	for _, s := range m.svcs {
		add(s.service, 12, writeName(nil, s.instance)) // PTR
		var srv []byte
		var p [6]byte
		binary.BigEndian.PutUint16(p[4:], uint16(m.port))
		srv = append(srv, p[:]...)
		srv = writeName(srv, m.host)
		add(s.instance, 33, srv) // SRV
		var txt []byte
		for _, t := range s.txt {
			txt = append(txt, byte(len(t)))
			txt = append(txt, t...)
		}
		if len(txt) == 0 {
			txt = []byte{0}
		}
		add(s.instance, 16, txt) // TXT
	}
	add(m.host, 1, []byte(m.ip)) // A
	add("_services._dns-sd._udp.local", 12, writeName(nil, m.svcs[0].service))
	for _, s := range m.svcs[1:] {
		add("_services._dns-sd._udp.local", 12, writeName(nil, s.service))
	}
	return rrs
}

func (m *miniMDNS) buildPacket(an, ar []struct {
	name  string
	rtype uint16
	rdata []byte
}) []byte {
	var buf []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[2:], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(hdr[6:], uint16(len(an)))
	binary.BigEndian.PutUint16(hdr[10:], uint16(len(ar)))
	buf = append(buf, hdr...)
	for _, rr := range an {
		buf = writeRR(buf, rr.name, rr.rtype, 120, rr.rdata)
	}
	for _, rr := range ar {
		buf = writeRR(buf, rr.name, rr.rtype, 120, rr.rdata)
	}
	return buf
}

func (m *miniMDNS) announceLoop() {
	dst := &net.UDPAddr{IP: net.ParseIP(mdnsGroupIP), Port: 5353}
	send := func() {
		all := m.allRecords()
		m.conn.WriteToUDP(m.buildPacket(all, nil), dst)
	}
	send()
	for i := 0; i < 2; i++ {
		select {
		case <-m.done:
			return
		case <-time.After(time.Second):
			send()
		}
	}
	for {
		select {
		case <-m.done:
			return
		case <-time.After(60 * time.Second):
			send()
		}
	}
}

// readQName parses a possibly-compressed DNS name at off.
func readQName(pkt []byte, off int) (string, int, bool) {
	var labels []string
	jumped := false
	end := off
	jumps := 0
	for {
		if off >= len(pkt) {
			return "", 0, false
		}
		l := int(pkt[off])
		if l == 0 {
			off++
			if !jumped {
				end = off
			}
			break
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				return "", 0, false
			}
			ptr := int(l&0x3F)<<8 | int(pkt[off+1])
			if !jumped {
				end = off + 2
			}
			off = ptr
			jumped = true
			jumps++
			if jumps > 10 {
				return "", 0, false
			}
			continue
		}
		off++
		if off+l > len(pkt) {
			return "", 0, false
		}
		labels = append(labels, string(pkt[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), end, true
}

func (m *miniMDNS) queryLoop() {
	buf := make([]byte, 9000)
	for {
		n, src, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if n < 12 {
			continue
		}
		flags := binary.BigEndian.Uint16(pkt[2:])
		if flags&0x8000 != 0 {
			continue // a response, not a query
		}
		qd := int(binary.BigEndian.Uint16(pkt[4:]))
		off := 12
		type q struct {
			name  string
			rtype uint16
		}
		var queries []q
		ok := true
		for i := 0; i < qd; i++ {
			name, next, good := readQName(pkt, off)
			if !good || next+4 > n {
				ok = false
				break
			}
			queries = append(queries, q{name, binary.BigEndian.Uint16(pkt[next:])})
			off = next + 4
		}
		if !ok {
			continue
		}
		all := m.allRecords()
		for _, query := range queries {
			var an, ar []struct {
				name  string
				rtype uint16
				rdata []byte
			}
			matched := false
			for _, rr := range all {
				if strings.EqualFold(rr.name, query.name) && (query.rtype == 255 || rr.rtype == query.rtype) {
					an = append(an, rr)
					matched = true
				} else {
					ar = append(ar, rr)
				}
			}
			if !matched {
				continue
			}
			resp := m.buildPacket(an, ar)
			m.conn.WriteToUDP(resp, src)
			// also multicast the answer so other queriers benefit
			m.conn.WriteToUDP(resp, &net.UDPAddr{IP: net.ParseIP(mdnsGroupIP), Port: 5353})
		}
	}
}
