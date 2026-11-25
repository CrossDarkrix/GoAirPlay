package main

// Diagnostic -browse mode. On platforms where Go can enumerate
// interfaces, the zeroconf resolver does the work. Everywhere else
// (Android/Termux) a hand-rolled browse runs over the mini mDNS
// socket: it multicasts PTR queries and prints every record that
// comes back for a few seconds.

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

func runBrowse() {
	_, _, lanIP := pickLANInterface()
	if lanIP == "" {
		lanIP = fallbackDialIP()
	}
	if lanIP != "" {
		if err := miniBrowse(lanIP); err == nil {
			return
		} else {
			log.Printf("[browse] mini browse failed: %v - trying zeroconf", err)
		}
	}
	zeroconfBrowse()
}

func zeroconfBrowse() {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalf("browse: resolver failed: %v", err)
	}
	entries := make(chan *zeroconf.ServiceEntry, 8)
	go func() {
		for e := range entries {
			log.Printf("[browse] %s -> %s:%d addrs=%v", e.Instance, e.HostName, e.Port, append(e.AddrIPv4, e.AddrIPv6...))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	for _, svc := range []string{"_raop._tcp", "_airplay._tcp"} {
		if err := resolver.Browse(ctx, svc, "local.", entries); err != nil {
			log.Printf("[browse] %s failed: %v", svc, err)
		}
	}
	<-ctx.Done()
	log.Printf("[browse] done")
}

func miniBrowse(ipStr string) error {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("bad ip %q", ipStr)
	}
	conn, err := mdnsSocket(ip)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("[browse] listening for mDNS on %s for 8 seconds...", ipStr)

	dst := &net.UDPAddr{IP: net.ParseIP(mdnsGroupIP), Port: 5353}
	query := func(service string) {
		var pkt []byte
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint16(hdr[4:], 1) // QDCOUNT
		pkt = append(pkt, hdr...)
		pkt = writeName(pkt, service)
		var q [4]byte
		binary.BigEndian.PutUint16(q[0:], 12) // PTR
		binary.BigEndian.PutUint16(q[2:], 1)  // IN
		pkt = append(pkt, q[:]...)
		conn.WriteToUDP(pkt, dst)
	}
	query("_raop._tcp.local")
	query("_airplay._tcp.local")

	seen := map[string]bool{}
	printRR := func(line string) {
		if !seen[line] {
			seen[line] = true
			log.Printf("[browse] %s", line)
		}
	}
	buf := make([]byte, 9000)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		parseBrowsePacket(buf[:n], printRR)
	}
	log.Printf("[browse] done (%d records)", len(seen))
	return nil
}

func parseBrowsePacket(pkt []byte, printRR func(string)) {
	if len(pkt) < 12 {
		return
	}
	an := int(binary.BigEndian.Uint16(pkt[6:]))
	ns := int(binary.BigEndian.Uint16(pkt[8:]))
	ar := int(binary.BigEndian.Uint16(pkt[10:]))
	off := 12
	// skip questions
	qd := int(binary.BigEndian.Uint16(pkt[4:]))
	for i := 0; i < qd; i++ {
		_, next, ok := readQName(pkt, off)
		if !ok {
			return
		}
		off = next + 4
	}
	for i := 0; i < an+ns+ar; i++ {
		name, next, ok := readQName(pkt, off)
		if !ok || next+10 > len(pkt) {
			return
		}
		rtype := binary.BigEndian.Uint16(pkt[next:])
		rdlen := int(binary.BigEndian.Uint16(pkt[next+8:]))
		rdataOff := next + 10
		if rdataOff+rdlen > len(pkt) {
			return
		}
		rdata := pkt[rdataOff : rdataOff+rdlen]
		switch rtype {
		case 12: // PTR
			if target, _, ok := readQName(pkt, rdataOff); ok {
				printRR(fmt.Sprintf("PTR  %s -> %s", name, target))
			}
		case 33: // SRV
			if len(rdata) >= 7 {
				port := binary.BigEndian.Uint16(rdata[4:])
				if target, _, ok := readQName(pkt, rdataOff+6); ok {
					printRR(fmt.Sprintf("SRV  %s -> %s:%d", name, target, port))
				}
			}
		case 1: // A
			if len(rdata) == 4 {
				printRR(fmt.Sprintf("A    %s -> %s", name, net.IP(rdata)))
			}
		case 16: // TXT
			var parts []string
			for j := 0; j < len(rdata); {
				l := int(rdata[j])
				j++
				if j+l > len(rdata) {
					break
				}
				parts = append(parts, string(rdata[j:j+l]))
				j += l
			}
			printRR(fmt.Sprintf("TXT  %s [%s]", name, strings.Join(parts, " ")))
		}
		off = rdataOff + rdlen
	}
}
