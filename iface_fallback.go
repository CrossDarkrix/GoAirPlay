package main

// Fallback network-interface discovery via /sys/class/net, for
// environments where Go's own enumeration returns nothing usable
// (Android/Termux restricts the netlink queries Go relies on).
// On Windows the sysfs tree does not exist and this returns nil.

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// sysfsInterfaces builds net.Interface values from /sys/class/net.
// Wi-Fi interfaces sort first, then Ethernet, then the rest.
func sysfsInterfaces() []net.Interface {
	base := "/sys/class/net"
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.Name() != "lo" {
			names = append(names, e.Name())
		}
	}
	rank := func(n string) int {
		switch {
		case strings.HasPrefix(n, "wlan"):
			return 0
		case strings.HasPrefix(n, "eth"):
			return 1
		default:
			return 2
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if rank(names[i]) != rank(names[j]) {
			return rank(names[i]) < rank(names[j])
		}
		return names[i] < names[j]
	})
	var out []net.Interface
	for _, name := range names {
		readInt := func(file string) int {
			b, err := os.ReadFile(filepath.Join(base, name, file))
			if err != nil {
				return 0
			}
			v, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			return v
		}
		if b, err := os.ReadFile(filepath.Join(base, name, "operstate")); err == nil {
			if strings.TrimSpace(string(b)) == "down" {
				continue
			}
		}
		ifc := net.Interface{
			Name:  name,
			Index: readInt("ifindex"),
			MTU:   readInt("mtu"),
			Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
		}
		if b, err := os.ReadFile(filepath.Join(base, name, "address")); err == nil {
			if hw, err := net.ParseMAC(strings.TrimSpace(string(b))); err == nil {
				ifc.HardwareAddr = hw
			}
		}
		out = append(out, ifc)
	}
	return out
}
