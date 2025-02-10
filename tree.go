// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.
// (adapted from github.com/asergeyev/nradix)

package nradix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Tree implements a radix tree for working with IP/mask.
// Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree struct {
	root   *Node
	rootV4 *Node // TODO:create a short-cut for IPv4 lookups, deep in the tree

	free *Node

	alloc []Node
	mutex sync.RWMutex
}

const (
	startbit  = uint32(0x80000000)
	startbyte = byte(0x80)
)

var (
	ErrNodeBusy = errors.New("Node Busy")
	ErrNotFound = errors.New("No Such Node")
	ErrBadIP    = errors.New("Bad IP address or mask")
)

// NewTree initializes a Tree and preallocates a specified number of nodes ready to store data.
// It creates a new Tree structure, sets up the root node, and optionally preallocates nodes
// based on the number of bits specified. This is useful for optimizing the tree for a certain
// number of entries.
func NewTree(preallocate int) *Tree {
	tree := new(Tree)
	tree.root = tree.newnode(net.IPv6zero, net.CIDRMask(0, 128))

	// Set up the IPv4 root node to optimise IPv4 lookups
	tree.setupIPv4Root()

	if preallocate == 0 {
		return tree
	}

	// Simplification, static preallocate max 8 bits
	if preallocate > 8 || preallocate < 0 {
		preallocate = 8
	}

	var key, mask uint32

	for inc := startbit; preallocate > 0; inc, preallocate = inc>>1, preallocate-1 {
		key = 0
		mask >>= 1
		mask |= startbit

		for {
			tree.insert4(key, mask, nil, false)
			key += inc
			if key == 0 { // magic bits collide
				break
			}
		}
	}

	return tree
}

// setupIPv4Root creates a shortcut node for IPv4 lookups at the ::ffff:0:0/96 position
func (tree *Tree) setupIPv4Root() {
	// Create the IPv4-mapped IPv6 prefix (::ffff:0:0/96)
	ipv6 := make([]byte, 16)
	ipv6[10] = 0xff
	ipv6[11] = 0xff

	// Create mask for first 96 bits
	mask := make([]byte, 16)
	for i := 0; i < 12; i++ {
		mask[i] = 0xff
	}

	// Navigate to or create the IPv4 root node
	var i int
	bit := startbyte
	node := tree.root
	for i < 12 { // First 96 bits (12 bytes)
		next := node.right
		if (ipv6[i] & bit) == 0 {
			next = node.left
		}

		if next == nil {
			next = tree.newnode(ipv6, net.CIDRMask(0, 32))
			next.parent = node
			if (ipv6[i] & bit) != 0 {
				node.right = next
			} else {
				node.left = next
			}
		}

		node = next

		if bit >>= 1; bit == 0 {
			i++
			bit = startbyte
		}
	}

	// Store this node as the IPv4 root
	tree.rootV4 = node
}

// SetCIDRString sets a value associated with an IP/mask in the tree, overwriting any existing value.
// It locks the tree for writing, converts the CIDR string to bytes, and calls SetCIDRb.
func (tree *Tree) SetCIDRString(cidr string, val interface{}, overwrite bool) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	return tree.SetCIDRb([]byte(cidr), val, overwrite)
}

// SetCIDRNetIP sets a value associated with a net.IP and net.IPMask in the tree, overwriting any existing value.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and inserts it into the tree with overwrite enabled.
func (tree *Tree) SetCIDRNetIP(ip net.IP, mask net.IPMask, val interface{}, overwrite bool) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	// Optimize IPv4 check using To4() which handles all IPv4 cases including mapped addresses
	if ip4 := ip.To4(); ip4 != nil {
		ipFlat := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		return tree.insert4(ipFlat, binary.BigEndian.Uint32(mask), val, true)
	}
	return tree.insert6(ip, mask, val, overwrite)
}

// SetCIDRNetIPAddr sets a value associated with a netip.Addr IP and netip.Prefix mask in the tree, overwriting any existing value.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and inserts it into the tree with overwrite enabled.
func (tree *Tree) SetCIDRNetIPAddr(ip netip.Addr, mask netip.Prefix, val interface{}, overwrite bool) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	if ip.Is4() {
		ipv4 := ip.As4()
		ipFlat := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		// Use pre-computed mask table instead of shift operation
		maskBits := ipv4MaskCache[mask.Bits()]
		return tree.insert4(ipFlat, maskBits, val, overwrite)
	}

	// For IPv6, use pre-computed mask table
	ipv6 := ip.As16()
	maskv6 := getIPv6Mask(mask.Bits())
	return tree.insert6(ipv6[:], maskv6[:], val, overwrite)
}

// SetCIDRNetIPPrefix sets a value associated with a netip.Addr IP and netip.Prefix mask in the tree, overwriting any existing value.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and inserts it into the tree with overwrite enabled.
func (tree *Tree) SetCIDRNetIPPrefix(prefix netip.Prefix, val interface{}, overwrite bool) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	if !prefix.IsValid() {
		return ErrBadIP
	}

	if prefix.Addr().Is4() {
		ipv4 := prefix.Addr().As4()
		ipFlat := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		// Use pre-computed mask table instead of shift operation
		maskBits := ipv4MaskCache[prefix.Bits()]
		return tree.insert4(ipFlat, maskBits, val, overwrite)
	}

	// For IPv6, use pre-computed mask table
	ipv6 := prefix.Addr().As16()
	maskv6 := getIPv6Mask(prefix.Bits())
	return tree.insert6(ipv6[:], maskv6[:], val, overwrite)
}

// SetCIDRb adds a value associated with an IP/mask to the tree using byte slices.
// It determines if the CIDR is IPv4 or IPv6, parses it, and inserts it into the tree.
func (tree *Tree) SetCIDRb(cidr []byte, val interface{}, overwrite bool) error {
	if bytes.IndexByte(cidr, '.') > 0 {
		ip, mask, err := parsecidr4(cidr)
		if err != nil {
			return err
		}
		return tree.insert4(ip, mask, val, overwrite)
	}
	ip, mask, err := parsecidr6(cidr)
	if err != nil {
		return err
	}
	return tree.insert6(ip, mask, val, overwrite)
}

// DeleteWholeRangeCIDR removes all values associated with IPs in the entire subnet specified by the CIDR.
// It locks the tree for writing, converts the CIDR string to bytes, and calls DeleteWholeRangeCIDRb.
func (tree *Tree) DeleteWholeRangeCIDR(cidr string) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	return tree.DeleteWholeRangeCIDRb([]byte(cidr))
}

// DeleteWholeRangeCIDRb removes all values associated with IPs in the entire subnet specified by the CIDR using byte slices.
// It determines if the CIDR is IPv4 or IPv6, parses it, and deletes the entire range from the tree.
func (tree *Tree) DeleteWholeRangeCIDRb(cidr []byte) error {
	if bytes.IndexByte(cidr, '.') > 0 {
		ip, mask, err := parsecidr4(cidr)
		if err != nil {
			return err
		}
		return tree.deleteIPv4(ip, mask, true)
	}
	ip, mask, err := parsecidr6(cidr)
	if err != nil {
		return err
	}
	return tree.deleteIPv6(ip, mask, true)
}

// DeleteCIDRString removes a value associated with an IP/mask from the tree.
// It locks the tree for writing, converts the CIDR string to bytes, and calls DeleteCIDRb.
func (tree *Tree) DeleteCIDRString(cidr string) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	return tree.DeleteCIDRb([]byte(cidr))
}

// DeleteCIDRNetIP removes a value associated with a net.IP and net.IPMask from the tree.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and deletes the specific entry from the tree.
// For IPv4 addresses, it converts the IP and mask to uint32 format before deletion.
func (tree *Tree) DeleteCIDRNetIP(ip net.IP, mask net.IPMask) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	if len(ip) == 4 {
		return tree.deleteIPv4(uint32(ip[0])<<24|uint32(ip[1])<<16|uint32(ip[2])<<8|uint32(ip[3]), uint32(mask[0])<<24|uint32(mask[1])<<16|uint32(mask[2])<<8|uint32(mask[3]), false)
	}
	return tree.deleteIPv6(ip, mask, false)
}

// DeleteCIDRNetIPAddr removes a value associated with a netip.Addr and netip.Prefix from the tree.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and deletes the specific entry from the tree.
// For IPv4 addresses, it uses pre-computed masks from a cache for better performance.
func (tree *Tree) DeleteCIDRNetIPAddr(ip netip.Addr, mask netip.Prefix) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	if ip.Is4() {
		ipv4 := ip.As4()
		ipFlat := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		// Pre-compute common masks to avoid shifts
		maskBits := ipv4MaskCache[mask.Bits()]
		return tree.deleteIPv4(ipFlat, maskBits, false)
	}

	// For IPv6, convert to net.IP and net.IPMask
	ipv6 := ip.As16()
	maskv6 := getIPv6Mask(mask.Bits())
	return tree.deleteIPv6(ipv6[:], maskv6[:], false)
}

// DeleteCIDRb removes a value associated with an IP/mask from the tree using byte slices.
// It determines if the CIDR is IPv4 or IPv6, parses it, and deletes the specific entry from the tree.
func (tree *Tree) DeleteCIDRb(cidr []byte) error {
	if bytes.IndexByte(cidr, '.') > 0 {
		ip, mask, err := parsecidr4(cidr)
		if err != nil {
			return err
		}
		return tree.deleteIPv4(ip, mask, false)
	}
	ip, mask, err := parsecidr6(cidr)
	if err != nil {
		return err
	}
	return tree.deleteIPv6(ip, mask, false)
}

// FindCIDRString traverses the tree to the proper node and returns previously saved information in the longest covered IP.
// It locks the tree for reading, converts the CIDR string to bytes, and calls FindCIDRb.
func (tree *Tree) FindCIDRString(cidr string) (interface{}, error) {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()
	return tree.FindCIDRb([]byte(cidr))
}

// FindCIDRb traverses the tree to the proper node and returns previously saved information in the longest covered IP using byte slices.
// It determines if the CIDR is IPv4 or IPv6, parses it, and finds the corresponding entry in the tree.
func (tree *Tree) FindCIDRb(cidr []byte) (interface{}, error) {
	if bytes.IndexByte(cidr, '.') > 0 {
		ip, mask, err := parsecidr4(cidr)
		if err != nil {
			return nil, err
		}
		return tree.find32(ip, mask), nil
	}
	ip, mask, err := parsecidr6(cidr)
	if err != nil || ip == nil {
		return nil, err
	}
	return tree.find6(ip, mask), nil
}

// FindCIDRIPNet finds the value associated with a given net.IPNet.
// It locks the tree for reading and determines if the IP is IPv4 or IPv6, then finds the corresponding entry in the tree.
func (tree *Tree) FindCIDRIPNet(ipm net.IPNet) (interface{}, error) {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()
	ip := ipm.IP
	mask := ipm.Mask

	if ip.To4() != nil {
		var ipFlat uint32
		ipFlat = uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		return tree.find32(ipFlat, 0xffffffff), nil
	}

	return tree.find6(ipm.IP, mask), nil
}

// FindCIDRNetIP finds the value associated with a given net.IP.
// It locks the tree for reading and determines if the IP is IPv4 or IPv6, then finds the corresponding entry in the tree.
func (tree *Tree) FindCIDRNetIP(ip net.IP) (interface{}, error) {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()

	if ip.To4() != nil {
		var ipFlat uint32
		ipFlat = uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		return tree.find32(ipFlat, 0xffffffff), nil
	}

	ipm := net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	return tree.find6(ipm.IP, ipm.Mask), nil
}

func (tree *Tree) FindCIDRNetIPAddr(nip netip.Addr) (interface{}, error) {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()

	if nip.Is4() {
		ipFlat := nip.As4()
		return tree.find32(uint32(ipFlat[0])<<24|uint32(ipFlat[1])<<16|uint32(ipFlat[2])<<8|uint32(ipFlat[3]), 0xffffffff), nil
	}

	ipm := net.IPNet{IP: nip.AsSlice(), Mask: net.CIDRMask(128, 128)}
	return tree.find6(ipm.IP, ipm.Mask), nil
}

func (tree *Tree) FindCIDRNetIPAddrWithNode(nip netip.Addr) (node *Node, value interface{}, err error) {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()
	if nip.Is4() {
		ipFlat := nip.As4()
		node, value = tree.find32WithNode(uint32(ipFlat[0])<<24|uint32(ipFlat[1])<<16|uint32(ipFlat[2])<<8|uint32(ipFlat[3]), 0xffffffff)
		return node, value, nil
	}

	ipm := net.IPNet{IP: nip.AsSlice(), Mask: net.CIDRMask(128, 128)}
	node, value = tree.find6WithNode(ipm.IP, ipm.Mask)
	return node, value, nil
}

func (tree *Tree) FindCIDRNetIPAddrV2(nip netip.Addr) (node *Node, value interface{}, err error) {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()

	if nip.Is4() {
		ipFlat := nip.As4()
		node, value = tree.find32WithNode(uint32(ipFlat[0])<<24|uint32(ipFlat[1])<<16|uint32(ipFlat[2])<<8|uint32(ipFlat[3]), 0xffffffff)
		return node, value, nil
	}

	ipm := net.IPNet{IP: nip.AsSlice(), Mask: net.CIDRMask(128, 128)}

	node, value = tree.find6WithNode(ipm.IP, ipm.Mask)
	return node, value, nil
}

// insert4 inserts a value into the tree for a given IPv4 key and mask.
// It traverses the tree based on the key and mask, creating new nodes as necessary, and sets the value at the appropriate node.
func (tree *Tree) insert4(key, mask uint32, value interface{}, overwrite bool) error {
	// Convert IPv4 to IPv4-mapped IPv6 address
	ipv6 := make([]byte, 16)
	// Explicitly set first 10 bytes to 0x00
	for i := 0; i < 10; i++ {
		ipv6[i] = 0x00
	}
	// Set the IPv4-mapped IPv6 prefix (::ffff:)
	ipv6[10] = 0xff
	ipv6[11] = 0xff
	// Add the IPv4 address
	ipv6[12] = byte(key >> 24)
	ipv6[13] = byte(key >> 16)
	ipv6[14] = byte(key >> 8)
	ipv6[15] = byte(key)

	// Create IPv6 mask from IPv4 mask
	maskv6 := make([]byte, 16)
	for i := 0; i < 12; i++ {
		maskv6[i] = 0xff
	}
	// First 12 bytes should be 0x00 for IPv4-mapped IPv6
	// Only the IPv4 portion should be masked
	// Last 4 bytes contain the IPv4 mask
	maskv6[12] = byte(mask >> 24)
	maskv6[13] = byte(mask >> 16)
	maskv6[14] = byte(mask >> 8)
	maskv6[15] = byte(mask)

	return tree.insert6(ipv6, maskv6, value, overwrite)
}

// insert6 inserts a value into the tree for a given IPv6 key and mask.
// It traverses the tree based on the key and mask, creating new nodes as necessary, and sets the value at the appropriate node.
func (tree *Tree) insert6(key net.IP, mask net.IPMask, value interface{}, overwrite bool) error {
	if len(key) != len(mask) {
		return ErrBadIP
	}
	var i int
	bit := startbyte
	node := tree.root
	next := tree.root
	for bit&mask[i] != 0 {
		if key[i]&bit != 0 {
			next = node.right
		} else {
			next = node.left
		}
		if next == nil {
			break
		}

		node = next

		if bit >>= 1; bit == 0 {
			if i++; i == len(key) {
				break
			}
			bit = startbyte
		}

	}
	if next != nil {
		if node.value != nil && !overwrite {
			return ErrNodeBusy
		}
		node.value = value
		node.prefix = getNetIPPrefix(key, mask)
		return nil
	}

	for bit&mask[i] != 0 {
		next = tree.newnode(key, mask)
		next.parent = node
		if key[i]&bit != 0 {
			node.right = next
		} else {
			node.left = next
		}
		node = next
		if bit >>= 1; bit == 0 {
			if i++; i == len(key) {
				break
			}
			bit = startbyte
		}
	}
	node.value = value
	node.prefix = getNetIPPrefix(key, mask)

	return nil
}

// deleteIPv4 removes a value from the tree for a given IPv4 key and mask.
// It traverses the tree based on the key and mask, and removes the node if it is a leaf or clears the value if not.
func (tree *Tree) deleteIPv4(key, mask uint32, wholeRange bool) error {
	// Convert IPv4 to IPv4-mapped IPv6 address
	ipv6 := make([]byte, 16)
	ipv6[10] = 0xff
	ipv6[11] = 0xff
	ipv6[12] = byte(key >> 24)
	ipv6[13] = byte(key >> 16)
	ipv6[14] = byte(key >> 8)
	ipv6[15] = byte(key)

	// Create IPv6 mask from IPv4 mask
	maskv6 := make([]byte, 16)
	for i := 0; i < 12; i++ {
		maskv6[i] = 0xff
	}
	maskv6[12] = byte(mask >> 24)
	maskv6[13] = byte(mask >> 16)
	maskv6[14] = byte(mask >> 8)
	maskv6[15] = byte(mask)

	return tree.deleteIPv6(ipv6, maskv6, wholeRange)
}

// deleteIPv6 removes a value from the tree for a given IPv6 key and mask.
// It traverses the tree based on the key and mask, and removes the node if it is a leaf or clears the value if not.
func (tree *Tree) deleteIPv6(key net.IP, mask net.IPMask, wholeRange bool) error {
	if len(key) != len(mask) {
		return ErrBadIP
	}

	var i int
	bit := startbyte
	node := tree.root
	for node != nil && bit&mask[i] != 0 {
		if key[i]&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if bit >>= 1; bit == 0 {
			if i++; i == len(key) {
				break
			}
			bit = startbyte
		}
	}
	if node == nil {
		return ErrNotFound
	}

	if !wholeRange && (node.right != nil || node.left != nil) {
		// keep it just trim value
		if node.value != nil {
			node.value = nil
			return nil
		}
		return ErrNotFound
	}

	// need to trim leaf
	for {
		if node.parent.right == node {
			node.parent.right = nil
		} else {
			node.parent.left = nil
		}
		// reserve this node for future use
		node.right = tree.free
		tree.free = node

		// move to parent, check if it's free of value and children
		node = node.parent
		if node.right != nil || node.left != nil || node.value != nil {
			break
		}
		// do not delete root node
		if node.parent == nil {
			break
		}
	}

	return nil
}

// find32 finds the value associated with a given IPv4 key and mask.
// It traverses the tree based on the key and mask, returning the value of the longest matching prefix.
func (tree *Tree) find32(ipv4 uint32, mask uint32) (value interface{}) {
	_, value = tree.find32WithNode(ipv4, mask)
	return
}

// find32 finds the value associated with a given IPv4 key and mask.
// It traverses the tree based on the key and mask, returning the value of the longest matching prefix.
func (tree *Tree) find32WithNode(ipv4 uint32, mask uint32) (nodeRet *Node, value interface{}) {
	// Start from IPv4 root if available
	if tree.rootV4 != nil {
		node := tree.rootV4
		bit := startbit
		value = node.value // Store initial value if exists
		nodeRet = node

		for node != nil && bit != 0 {
			if mask&bit == 0 { // Move mask check to start of loop
				break
			}

			if ipv4&bit != 0 {
				node = node.right
			} else {
				node = node.left
			}

			if node != nil && node.value != nil {
				value = node.value
				nodeRet = node
			}

			bit >>= 1
		}
		return nodeRet, value
	}

	// Fall back to existing IPv6-mapped path if rootV4 is not set
	ipv6 := make([]byte, 16)
	ipv6[10] = 0xff
	ipv6[11] = 0xff
	ipv6[12] = byte(ipv4 >> 24)
	ipv6[13] = byte(ipv4 >> 16)
	ipv6[14] = byte(ipv4 >> 8)
	ipv6[15] = byte(ipv4)

	// Create IPv6 mask
	maskv6 := make([]byte, 16)
	for i := 0; i < 12; i++ {
		maskv6[i] = 0xff
	}
	maskv6[12] = byte(mask >> 24)
	maskv6[13] = byte(mask >> 16)
	maskv6[14] = byte(mask >> 8)
	maskv6[15] = byte(mask)

	return tree.find6WithNode(ipv6, maskv6)
}

// find6 finds the value associated with a given IPv6 key and mask.
// It traverses the tree based on the key and mask, returning the value of the longest matching prefix.
func (tree *Tree) find6(key net.IP, mask net.IPMask) (value interface{}) {
	_, value = tree.find6WithNode(key, mask)
	return
}

// find6WithNode finds the value associated with a given IPv6 key and mask.
// It traverses the tree based on the key and mask, returning the value of the longest matching prefix.
func (tree *Tree) find6WithNode(key net.IP, mask net.IPMask) (nodeRet *Node, value interface{}) {
	node := tree.root
	nodeRet = node
	if len(key) != len(mask) {
		return nodeRet, ErrBadIP
	}
	var i int
	bit := startbyte
	for node != nil {
		if node.value != nil {
			value = node.value
			nodeRet = node
		}
		if key[i]&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if mask[i]&bit == 0 {
			break
		}
		if bit >>= 1; bit == 0 {
			i, bit = i+1, startbyte
			if i >= len(key) {
				// reached depth of the tree, there should be matching node...
				if node != nil {
					value = node.value
					nodeRet = node
				}
				break
			}
		}
	}
	return nodeRet, value
}

// newnode creates a new node for the tree, reusing a node from the free list if available.
// It initializes the node's fields and returns a pointer to the new node.
func (tree *Tree) newnode(key net.IP, mask net.IPMask) (p *Node) {
	if tree.free != nil {
		p = tree.free
		tree.free = tree.free.right

		// release all prior links
		p.right = nil
		p.parent = nil
		p.left = nil
		p.value = nil
		p.prefix = getNetIPPrefix(key, mask)
		return p
	}

	ln := len(tree.alloc)
	if ln == cap(tree.alloc) {
		// filled one row, make bigger one
		tree.alloc = make([]Node, ln+200)[:1] // 200, 600, 1400, 3000, 6200, 12600 ...
		ln = 0
	} else {
		tree.alloc = tree.alloc[:ln+1]
	}
	return &(tree.alloc[ln])
}

// loadip4 converts an IPv4 address from a byte slice to a uint32 representation.
// It parses the address, ensuring it is valid, and returns the 32-bit representation.
func loadip4(ipstr []byte) (uint32, error) {
	var (
		ip  uint32
		oct uint32
		b   byte
		num byte
	)

	for _, b = range ipstr {
		switch {
		case b == '.':
			num++
			if 0xffffffff-ip < oct {
				return 0, ErrBadIP
			}
			ip = ip<<8 + oct
			oct = 0
		case b >= '0' && b <= '9':
			oct = oct*10 + uint32(b-'0')
			if oct > 255 {
				return 0, ErrBadIP
			}
		default:
			return 0, ErrBadIP
		}
	}
	if num != 3 {
		return 0, ErrBadIP
	}
	if 0xffffffff-ip < oct {
		return 0, ErrBadIP
	}
	return ip<<8 + oct, nil
}

// parsecidr4 parses a CIDR notation IPv4 address and returns the IP and mask as uint32 values.
// It extracts the IP and mask from the CIDR string, ensuring they are valid, and returns them.
func parsecidr4(cidr []byte) (uint32, uint32, error) {
	var mask uint32
	p := bytes.IndexByte(cidr, '/')
	if p > 0 {
		for _, c := range cidr[p+1:] {
			if c < '0' || c > '9' {
				return 0, 0, ErrBadIP
			}
			mask = mask*10 + uint32(c-'0')
		}
		mask = 0xffffffff << (32 - mask)
		cidr = cidr[:p]
	} else {
		mask = 0xffffffff
	}
	ip, err := loadip4(cidr)
	if err != nil {
		return 0, 0, err
	}
	return ip, mask, nil
}

// parsecidr6 parses a CIDR notation IPv6 address and returns the IP and mask as net.IP and net.IPMask.
// It extracts the IP and mask from the CIDR string, ensuring they are valid, and returns them.
func parsecidr6(cidr []byte) (net.IP, net.IPMask, error) {
	p := bytes.IndexByte(cidr, '/')
	if p > 0 {
		_, ipm, err := net.ParseCIDR(string(cidr))
		if err != nil {
			return nil, nil, err
		}
		return ipm.IP, ipm.Mask, nil
	}
	ip := net.ParseIP(string(cidr))
	if ip == nil {
		return nil, nil, ErrBadIP
	}
	return ip, net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, nil
}

// WalkFunc is the type of the function called for each node visited by Walk.
// The path argument contains the prefix leading to this node.
// If the function returns an error, walking stops and the error is returned.
type WalkFunc func(prefix netip.Prefix, value interface{}) error

// Walk traverses the tree in-order, calling walkFn for each node that contains a value.
// The walk function receives the CIDR prefix as a string and the value stored at that node.
func (tree *Tree) WalkV4(walkFn WalkFunc) error {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()

	// Wrapper function to call walkFn only for IPv4 or IPv4-mapped IPv6 prefixes
	walkFnWrapper := func(prefix netip.Prefix, value interface{}) error {
		if prefix.Addr().Is4In6() {
			ip4prefix := netip.PrefixFrom(netip.AddrFrom4(prefix.Addr().As4()), prefix.Bits()-96)
			// ip4prefix := netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			return walkFn(ip4prefix, value)
		} else if prefix.Addr().Is4() {
			return walkFn(prefix, value)
		}
		return nil
	}

	initialPrefix := netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0)
	return tree.walk(tree.root, initialPrefix, 0, walkFnWrapper)
}

func (tree *Tree) WalkV6(walkFn WalkFunc) error {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()

	// Wrapper function to call walkFn only for IPv6 prefixes
	walkFnWrapper := func(prefix netip.Prefix, value interface{}) error {
		if prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			return walkFn(prefix, value)
		}
		return nil
	}

	// Initialize with a valid IPv6 prefix, e.g., an empty IPv6 address with a prefix length of 0
	initialPrefix := netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0)
	return tree.walk(tree.root, initialPrefix, 0, walkFnWrapper)
}

func (tree *Tree) walk(n *Node, prefix netip.Prefix, depth int, walkFn WalkFunc) error {
	if n == nil {
		return errors.New("node is nil")
	}

	// Don't go deeper than 128 bits (the full IPv6 length).
	// For IPv4-mapped addresses, bits [0..95] are ::ffff: and bits [96..127] are the real IPv4.
	// Once depth == 128, we have exhausted all bits.
	const maxDepth = 128
	if depth >= maxDepth {
		// If there's a value here, report it; otherwise just return.
		if n.value != nil {
			if err := walkFn(prefix, n.value); err != nil {
				return fmt.Errorf("error processing node value at max depth: %w", err)
			}
		}
		return nil
	}

	// Process current node if it has a value
	if n.value != nil {
		if err := walkFn(prefix, n.value); err != nil {
			return fmt.Errorf("error processing node value: %w", err)
		}
	}

	// Walk left subtree
	if n.left != nil {
		leftAddr, ok := setBitAtDepth(prefix.Addr(), depth, false)
		if !ok {
			return fmt.Errorf("failed to set bit at depth %d", depth)
		}
		leftPrefix := netip.PrefixFrom(leftAddr, depth+1)
		if err := tree.walk(n.left, leftPrefix, depth+1, walkFn); err != nil {
			return fmt.Errorf("error walking left subtree: %w", err)
		}
	}

	// Walk right subtree
	if n.right != nil {
		rightAddr, ok := setBitAtDepth(prefix.Addr(), depth, true)
		if !ok {
			return fmt.Errorf("failed to set bit at depth %d", depth)
		}
		rightPrefix := netip.PrefixFrom(rightAddr, depth+1)
		if err := tree.walk(n.right, rightPrefix, depth+1, walkFn); err != nil {
			return fmt.Errorf("error walking right subtree: %w", err)
		}
	}

	return nil
}

// Helper function to set a specific bit in the address at a given depth
func setBitAtDepth(addr netip.Addr, depth int, isRight bool) (netip.Addr, bool) {
	// Convert the address to a mutable byte slice
	addrBytes := addr.AsSlice()
	byteIndex := depth / 8
	bitIndex := depth % 8

	if byteIndex < len(addrBytes) {
		if isRight {
			addrBytes[byteIndex] |= (1 << (7 - bitIndex))
		} else {
			addrBytes[byteIndex] &^= (1 << (7 - bitIndex))
		}
	}

	// Reconstruct the address from the modified byte slice
	return netip.AddrFromSlice(addrBytes)
}

// formatPrefixToCIDR converts a netip.Prefix to a CIDR string
func formatPrefixToCIDR(prefix netip.Prefix) string {
	return prefix.String()
}
