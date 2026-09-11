package vocat

import "net/netip"

// netipAddr parses a host as an IP address. It exists so normalizeBase can
// reject a non-loopback target without pulling net/netip into that file's
// readable flow.
func netipAddr(host string) (netip.Addr, error) {
	return netip.ParseAddr(host)
}
