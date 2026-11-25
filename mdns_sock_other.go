//go:build !linux && !android

package main

import (
	"errors"
	"net"
)

// The built-in mDNS publisher is only implemented for Linux/Android
// (on Windows the zeroconf library works and is used instead).
func mdnsSocket(ip net.IP) (*net.UDPConn, error) {
	return nil, errors.New("mini mDNS not supported on this platform")
}
