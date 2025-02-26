package nradix

import (
	"net"
	"net/netip"
	"testing"
)

func BenchmarkSetCIDRString(b *testing.B) {
	tree := NewTree(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.SetCIDRString("192.168.1.0/24", i, true)
	}
}

func BenchmarkSetCIDRNetIP(b *testing.B) {
	tree := NewTree(0)
	ip := net.ParseIP("192.168.1.0")
	mask := net.CIDRMask(24, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.SetCIDRNetIP(ip, mask, i, true)
	}
}

func BenchmarkSetCIDRNetIPAddr(b *testing.B) {
	tree := NewTree(0)
	addr := netip.MustParseAddr("192.168.1.0")
	prefix := netip.MustParsePrefix("192.168.1.0/24")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.SetCIDRNetIPAddr(addr, prefix, i, true)
	}
}

func BenchmarkFindCIDRString(b *testing.B) {
	tree := NewTree(0)
	tree.SetCIDRString("192.168.1.0/24", 1, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.FindCIDRString("192.168.1.1")
	}
}

func BenchmarkFindCIDRNetIP(b *testing.B) {
	tree := NewTree(0)
	tree.SetCIDRString("192.168.1.0/24", 1, true)
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.FindCIDRNetIP(ip)
	}
}

func BenchmarkFindCIDRNetIPAddr(b *testing.B) {
	tree := NewTree(0)
	tree.SetCIDRString("192.168.1.0/24", 1, true)
	addr := netip.MustParseAddr("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.FindCIDRNetIPAddr(addr)
	}
}

func BenchmarkInsert4(b *testing.B) {
	tree := NewTree(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.insert4(0xC0A80100, 0xFFFFFF00, i, true)
	}
}

func BenchmarkFind32(b *testing.B) {
	tree := NewTree(0)
	tree.insert4(0xC0A80100, 0xFFFFFF00, 1, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.find32(0xC0A80101, 0xFFFFFFFF)
	}
}
