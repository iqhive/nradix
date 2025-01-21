package nradix

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
