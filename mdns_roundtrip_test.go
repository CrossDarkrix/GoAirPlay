package main

import (
	"fmt"
	"net"
	"testing"
)

func TestMiniAnnouncementRoundTrip(t *testing.T) {
	m := &miniMDNS{
		ip:   net.ParseIP("192.168.0.42").To4(),
		host: "Termux.local",
		port: 7000,
		svcs: []mdnsSvc{
			{service: "_raop._tcp.local", instance: "a23664853bf3@Termux._raop._tcp.local", txt: []string{"txtvers=1", "ch=2", "sr=44100"}},
			{service: "_airplay._tcp.local", instance: "Termux._airplay._tcp.local", txt: []string{"deviceid=a2:36:64:85:3b:f3", "features=0x5A7FFFF7,0x1E"}},
		},
	}
	all := m.allRecords()
	pkt := m.buildPacket(all, nil)
	fmt.Printf("packet: %d bytes\n", len(pkt))
	var lines []string
	parseBrowsePacket(pkt, func(s string) { lines = append(lines, s) })
	for _, l := range lines {
		fmt.Println(" ", l)
	}
	if len(lines) != len(all) {
		t.Fatalf("parsed %d records, built %d", len(lines), len(all))
	}
}
