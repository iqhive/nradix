package nradix

import (
	"net/netip"
)

type Node struct {
	left, right, parent *Node
	value               interface{}
	prefix              netip.Prefix
}

// GetTreeParent returns the parent node of the current node.
// This is the node that is used to traverse the tree.
func (n *Node) GetTreeParent() *Node {
	return n.parent
}

// GetParent returns the parent node of the current node.
// This is the first node that has a value above the current node.
func (n *Node) GetParent() *Node {
	for n.parent != nil {
		if n.parent.prefix.IsValid() {
			return n.parent
		}
		n = n.parent
	}
	return nil
}

func (n *Node) GetAllParents() []*Node {
	parents := []*Node{}
	for n.parent != nil {
		if n.parent.prefix.IsValid() {
			parents = append(parents, n.parent)
		}
		n = n.parent
	}
	return parents
}

func (n *Node) GetLeft() *Node {
	return n.left
}

func (n *Node) GetRight() *Node {
	return n.right
}

func (n *Node) GetValue() interface{} {
	return n.value
}

func (n *Node) SetValue(value interface{}) {
	n.value = value
}

func (n *Node) GetPrefix() netip.Prefix {
	if n.prefix.Addr().Is4In6() {
		return netip.PrefixFrom(n.prefix.Addr().Unmap(), n.prefix.Bits()-96)
	}
	return n.prefix
}
