package nradix

import (
	"net"
	"net/netip"
)

// Pre-computed masks for IPv4 and IPv6
var ipv4MaskCache [33]uint32
var ipv6MaskCache [129][16]byte

func init() {
	// Initialize IPv4 mask table
	for i := 0; i <= 32; i++ {
		ipv4MaskCache[i] = uint32(0xffffffff) << (32 - i)
	}

	// Initialize IPv6 mask cache
	for ones := 0; ones <= 128; ones++ {
		bytes := ones / 8
		bits := ones % 8
		for i := 0; i < bytes; i++ {
			ipv6MaskCache[ones][i] = 0xff
		}
		if bits > 0 {
			ipv6MaskCache[ones][bytes] = ^byte(0xff >> bits)
		}
	}
}

func getIPv6Mask(ones int) []byte {
	return ipv6MaskCache[ones][:]
}

// getNetIPPrefix returns the netip.Prefix corresponding to the given IPv4 or IPv6 address and mask.
// This optimized version avoids allocations by using netip.AddrFrom4 or netip.AddrFrom16 directly.
func getNetIPPrefix(key net.IP, mask net.IPMask) netip.Prefix {
	keyLen := len(key)
	if keyLen != 4 && keyLen != 16 {
		// Invalid length, return an empty prefix (could alternatively panic or return an error).
		return netip.Prefix{}
	}

	// Convert the mask to its prefix length (leading ones).
	ones, _ := mask.Size()

	// Build the netip.Addr without heap allocations.
	switch keyLen {
	case 4:
		var a4 [4]byte
		copy(a4[:], key)
		return netip.PrefixFrom(netip.AddrFrom4(a4), ones)
	case 16:
		var a16 [16]byte
		copy(a16[:], key)
		return netip.PrefixFrom(netip.AddrFrom16(a16), ones)
	default:
		// Fallback safe-guard.
		return netip.Prefix{}
	}
}
