//go:build linux || android

package main

// mDNS socket for Linux/Android: bind :5353 with SO_REUSEADDR, join
// the multicast group by local IP address (IP_ADD_MEMBERSHIP with
// imr_interface = our IP needs no interface enumeration), and pin
// outgoing multicast to that address (IP_MULTICAST_IF).

import (
	"context"
	"net"
	"syscall"
)

const (
	ipTTL           = 2  // IP_TTL
	ipAddMembership = 35 // IP_ADD_MEMBERSHIP
	ipMulticastIF   = 32 // IP_MULTICAST_IF
	ipMulticastTTL  = 33 // IP_MULTICAST_TTL
)

func mdnsSocket(ip net.IP) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", ":5353")
	if err != nil {
		return nil, err
	}
	conn := pc.(*net.UDPConn)
	f, err := conn.File()
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer f.Close()
	fd := int(f.Fd())
	mreq := make([]byte, 8)
	copy(mreq[0:4], net.ParseIP(mdnsGroupIP).To4())
	copy(mreq[4:8], ip)
	if err := syscall.SetsockoptString(fd, 0, ipAddMembership, string(mreq)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := syscall.SetsockoptString(fd, 0, ipMulticastIF, string(ip)); err != nil {
		conn.Close()
		return nil, err
	}
	// RFC 6762: mDNS packets must be sent with IP TTL 255; receivers
	// (iOS in particular) silently drop packets with any other TTL.
	// A plain Go UDP socket defaults to multicast TTL 1.
	syscall.SetsockoptInt(fd, 0, ipMulticastTTL, 255)
	syscall.SetsockoptInt(fd, 0, ipTTL, 255)
	return conn, nil
}
