// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

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

type node struct {
	left, right, parent *node
	value               interface{}
}

// Tree implements a radix tree for working with IP/mask.
// Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree struct {
	root *node
	free *node

	alloc []node
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
	tree.root = tree.newnode()
	if preallocate == 0 {
		return tree
	}

	// Simplification, static preallocate max 6 bits
	if preallocate > 6 || preallocate < 0 {
		preallocate = 6
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

// AddCIDRString adds a value associated with an IP/mask to the tree.
// It locks the tree for writing, converts the CIDR string to bytes, and calls AddCIDRb.
func (tree *Tree) AddCIDRString(cidr string, val interface{}) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	return tree.AddCIDRb([]byte(cidr), val)
}

// AddCIDRNetIP adds a value associated with a net.IP and net.IPMask to the tree.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and inserts it into the tree.
// For IPv4 addresses, it converts the IP and mask to uint32 values before insertion.
func (tree *Tree) AddCIDRNetIP(ip net.IP, mask net.IPMask, val interface{}) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	// Optimize IPv4 check using To4() which handles all IPv4 cases including mapped addresses
	if ip4 := ip.To4(); ip4 != nil {
		ipFlat := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		return tree.insert4(ipFlat, binary.BigEndian.Uint32(mask), val, false)
	}
	return tree.insert6(ip, mask, val, false)
}

// AddCIDRNetIPAddr adds a value associated with a netip.Addr and netip.Prefix to the tree.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and inserts it into the tree.
// For IPv4 addresses, it uses pre-computed masks from a cache for better performance.
func (tree *Tree) AddCIDRNetIPAddr(ip netip.Addr, mask netip.Prefix, val interface{}) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	if ip.Is4() {
		ipv4 := ip.As4()
		ipFlat := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		// Pre-compute common masks to avoid shifts
		maskBits := ipv4MaskCache[mask.Bits()]
		return tree.insert4(ipFlat, maskBits, val, false)
	}

	// For IPv6, use a pre-computed mask table or simplified mask creation
	ipv6 := ip.As16()
	maskv6 := getIPv6Mask(mask.Bits()) // Implementation below
	return tree.insert6(ipv6[:], maskv6[:], val, false)
}

// AddCIDRb adds a value associated with an IP/mask to the tree using byte slices.
// It determines if the CIDR is IPv4 or IPv6, parses it, and inserts it into the tree.
func (tree *Tree) AddCIDRb(cidr []byte, val interface{}) error {
	if bytes.IndexByte(cidr, '.') > 0 {
		ip, mask, err := parsecidr4(cidr)
		if err != nil {
			return err
		}
		return tree.insert4(ip, mask, val, false)
	}
	ip, mask, err := parsecidr6(cidr)
	if err != nil {
		return err
	}
	return tree.insert6(ip, mask, val, false)
}

// SetCIDRString sets a value associated with an IP/mask in the tree, overwriting any existing value.
// It locks the tree for writing, converts the CIDR string to bytes, and calls SetCIDRb.
func (tree *Tree) SetCIDRString(cidr string, val interface{}) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()
	return tree.SetCIDRb([]byte(cidr), val)
}

// SetCIDRNetIP sets a value associated with a net.IP and net.IPMask in the tree, overwriting any existing value.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and inserts it into the tree with overwrite enabled.
func (tree *Tree) SetCIDRNetIP(ip net.IP, mask net.IPMask, val interface{}) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	// Optimize IPv4 check using To4() which handles all IPv4 cases including mapped addresses
	if ip4 := ip.To4(); ip4 != nil {
		ipFlat := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		return tree.insert4(ipFlat, binary.BigEndian.Uint32(mask), val, true)
	}
	return tree.insert6(ip, mask, val, true)
}

// SetCIDRNetIPAddr sets a value associated with a netip.Addr IP and netip.Prefix mask in the tree, overwriting any existing value.
// It locks the tree for writing, determines if the IP is IPv4 or IPv6, and inserts it into the tree with overwrite enabled.
func (tree *Tree) SetCIDRNetIPAddr(ip netip.Addr, mask netip.Prefix, val interface{}) error {
	tree.mutex.Lock()
	defer tree.mutex.Unlock()

	if ip.Is4() {
		ipv4 := ip.As4()
		ipFlat := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
		// Use pre-computed mask table instead of shift operation
		maskBits := ipv4MaskCache[mask.Bits()]
		return tree.insert4(ipFlat, maskBits, val, true)
	}

	// For IPv6, use pre-computed mask table
	ipv6 := ip.As16()
	maskv6 := getIPv6Mask(mask.Bits())
	return tree.insert6(ipv6[:], maskv6[:], val, true)
}

// SetCIDRb sets a value associated with an IP/mask in the tree using byte slices, overwriting any existing value.
// It determines if the CIDR is IPv4 or IPv6, parses it, and inserts it into the tree with overwrite enabled.
func (tree *Tree) SetCIDRb(cidr []byte, val interface{}) error {
	if bytes.IndexByte(cidr, '.') > 0 {
		ip, mask, err := parsecidr4(cidr)
		if err != nil {
			return err
		}
		return tree.insert4(ip, mask, val, true)
	}
	ip, mask, err := parsecidr6(cidr)
	if err != nil {
		return err
	}
	return tree.insert6(ip, mask, val, true)
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
		ipFlat = uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
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
		ipFlat = uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
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

	ipm := net.IPNet{IP: nip.AsSlice(), Mask: net.CIDRMask(64, 64)}
	return tree.find6(ipm.IP, ipm.Mask), nil
}

// insert4 inserts a value into the tree for a given IPv4 key and mask.
// It traverses the tree based on the key and mask, creating new nodes as necessary, and sets the value at the appropriate node.
func (tree *Tree) insert4(key, mask uint32, value interface{}, overwrite bool) error {
	bit := startbit
	node := tree.root
	next := tree.root
	for bit&mask != 0 {
		if key&bit != 0 {
			next = node.right
		} else {
			next = node.left
		}
		if next == nil {
			break
		}
		bit = bit >> 1
		node = next
	}
	if next != nil {
		if node.value != nil && !overwrite {
			return ErrNodeBusy
		}
		node.value = value
		return nil
	}
	for bit&mask != 0 {
		next = tree.newnode()
		next.parent = node
		if key&bit != 0 {
			node.right = next
		} else {
			node.left = next
		}
		bit >>= 1
		node = next
	}
	node.value = value

	return nil
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
		return nil
	}

	for bit&mask[i] != 0 {
		next = tree.newnode()
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

	return nil
}

// deleteIPv4 removes a value from the tree for a given IPv4 key and mask.
// It traverses the tree based on the key and mask, and removes the node if it is a leaf or clears the value if not.
func (tree *Tree) deleteIPv4(key, mask uint32, wholeRange bool) error {
	bit := startbit
	node := tree.root
	for node != nil && bit&mask != 0 {
		if key&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}
		bit >>= 1
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
	bit := startbit
	node := tree.root
	for node != nil {
		if node.value != nil {
			value = node.value
		}
		if ipv4&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if mask&bit == 0 {
			break
		}
		bit >>= 1

	}
	return value
}

// find6 finds the value associated with a given IPv6 key and mask.
// It traverses the tree based on the key and mask, returning the value of the longest matching prefix.
func (tree *Tree) find6(key net.IP, mask net.IPMask) (value interface{}) {
	if len(key) != len(mask) {
		return ErrBadIP
	}
	var i int
	bit := startbyte
	node := tree.root
	for node != nil {
		if node.value != nil {
			value = node.value
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
				}
				break
			}
		}
	}
	return value
}

// newnode creates a new node for the tree, reusing a node from the free list if available.
// It initializes the node's fields and returns a pointer to the new node.
func (tree *Tree) newnode() (p *node) {
	if tree.free != nil {
		p = tree.free
		tree.free = tree.free.right

		// release all prior links
		p.right = nil
		p.parent = nil
		p.left = nil
		p.value = nil
		return p
	}

	ln := len(tree.alloc)
	if ln == cap(tree.alloc) {
		// filled one row, make bigger one
		tree.alloc = make([]node, ln+200)[:1] // 200, 600, 1400, 3000, 6200, 12600 ...
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
type WalkFunc func(prefix string, value interface{}) error

// Walk traverses the tree in-order, calling walkFn for each node that contains a value.
// The walk function receives the CIDR prefix as a string and the value stored at that node.
func (tree *Tree) Walk(walkFn WalkFunc) error {
	tree.mutex.RLock()
	defer tree.mutex.RUnlock()
	return tree.walk(tree.root, []byte{}, 0, walkFn)
}

func (tree *Tree) walk(n *node, path []byte, depth int, walkFn WalkFunc) error {
	if n == nil {
		return nil
	}

	// Walk left subtree
	if n.left != nil {
		newPath := append(path, '0')
		if err := tree.walk(n.left, newPath, depth+1, walkFn); err != nil {
			return err
		}
	}

	// Process current node if it has a value
	if n.value != nil {
		prefix := fmt.Sprintf("%s/%d", formatPath(path), depth)
		if err := walkFn(prefix, n.value); err != nil {
			return err
		}
	}

	// Walk right subtree
	if n.right != nil {
		newPath := append(path, '1')
		if err := tree.walk(n.right, newPath, depth+1, walkFn); err != nil {
			return err
		}
	}

	return nil
}

// formatPath converts a binary path to a CIDR prefix
func formatPath(path []byte) string {
	if len(path) == 0 {
		return "*"
	}

	// Convert binary path to IP address string
	var ip net.IP
	if len(path) <= 32 { // IPv4
		ipInt := uint32(0)
		for _, b := range path {
			ipInt = (ipInt << 1) | uint32(b-'0')
		}
		ip = make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, ipInt)
	} else { // IPv6
		ip = make(net.IP, 16)
		for i := 0; i < len(path); i += 8 {
			end := i + 8
			if end > len(path) {
				end = len(path)
			}
			b := byte(0)
			for j := i; j < end; j++ {
				b = (b << 1) | (path[j] - '0')
			}
			ip[i/8] = b
		}
	}
	return ip.String()
}
