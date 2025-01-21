package nradix

import "testing"

// TestTree tests the basic functionality of the tree, including adding, finding, and deleting CIDRs.
func TestTree(t *testing.T) {
	tr := NewTree(0)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}

	// Add a CIDR to the tree
	err := tr.AddCIDRString("1.2.3.0/25", 1)
	if err != nil {
		t.Error(err)
	}

	// Test matching defined CIDR
	info, err := tr.FindCIDRString("1.2.3.1/25")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 1 {
		t.Errorf("Wrong value, expected 1, got %v", info)
	}

	// Test inside defined CIDR
	info, err = tr.FindCIDRString("1.2.3.60/32")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 1 {
		t.Errorf("Wrong value, expected 1, got %v", info)
	}
	info, err = tr.FindCIDRString("1.2.3.60")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 1 {
		t.Errorf("Wrong value, expected 1, got %v", info)
	}

	// Test outside defined CIDR
	info, err = tr.FindCIDRString("1.2.3.160/32")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}
	info, err = tr.FindCIDRString("1.2.3.160")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}

	info, err = tr.FindCIDRString("1.2.3.128/25")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}

	// Test covering not defined
	info, err = tr.FindCIDRString("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}

	// Add a covering CIDR to the tree
	err = tr.AddCIDRString("1.2.3.0/24", 2)
	if err != nil {
		t.Error(err)
	}
	info, err = tr.FindCIDRString("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 2 {
		t.Errorf("Wrong value, expected 2, got %v", info)
	}

	info, err = tr.FindCIDRString("1.2.3.160/32")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 2 {
		t.Errorf("Wrong value, expected 2, got %v", info)
	}

	// Test hitting both covering and internal, should choose most specific
	info, err = tr.FindCIDRString("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 1 {
		t.Errorf("Wrong value, expected 1, got %v", info)
	}

	// Delete internal CIDR
	err = tr.DeleteCIDRString("1.2.3.0/25")
	if err != nil {
		t.Error(err)
	}

	// Test hitting covering with old IP
	info, err = tr.FindCIDRString("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 2 {
		t.Errorf("Wrong value, expected 2, got %v", info)
	}

	// Add internal CIDR back in
	err = tr.AddCIDRString("1.2.3.0/25", 1)
	if err != nil {
		t.Error(err)
	}

	// Delete covering CIDR
	err = tr.DeleteCIDRString("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}

	// Test hitting with old IP
	info, err = tr.FindCIDRString("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 1 {
		t.Errorf("Wrong value, expected 1, got %v", info)
	}

	// Test finding covering again
	info, err = tr.FindCIDRString("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}

	// Add covering CIDR back in
	err = tr.AddCIDRString("1.2.3.0/24", 2)
	if err != nil {
		t.Error(err)
	}
	info, err = tr.FindCIDRString("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 2 {
		t.Errorf("Wrong value, expected 2, got %v", info)
	}

	// Delete the whole range
	err = tr.DeleteWholeRangeCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	// Should be no value for covering
	info, err = tr.FindCIDRString("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}
	// Should be no value for internal
	info, err = tr.FindCIDRString("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}
}

// TestSet tests the SetCIDR functionality of the tr.
func TestSet(t *testing.T) {
	tr := NewTree(0)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}

	// Add a CIDR to the tree
	tr.AddCIDRString("1.1.1.0/24", 1)
	info, err := tr.FindCIDRString("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 1 {
		t.Errorf("Wrong value, expected 1, got %v", info)
	}

	// Add a more specific CIDR to the tree
	tr.AddCIDRString("1.1.1.0/25", 2)
	info, err = tr.FindCIDRString("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 2 {
		t.Errorf("Wrong value, expected 2, got %v", info)
	}
	info, err = tr.FindCIDRString("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 1 {
		t.Errorf("Wrong value, expected 1, got %v", info)
	}

	// Add covering CIDR should fail
	err = tr.AddCIDRString("1.1.1.0/24", 60)
	if err != ErrNodeBusy {
		t.Errorf("Should have gotten ErrNodeBusy, instead got err: %v", err)
	}

	// Set covering CIDR
	err = tr.SetCIDRString("1.1.1.0/24", 3)
	if err != nil {
		t.Error(err)
	}
	info, err = tr.FindCIDRString("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 2 {
		t.Errorf("Wrong value, expected 2, got %v", info)
	}
	info, err = tr.FindCIDRString("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 3 {
		t.Errorf("Wrong value, expected 3, got %v", info)
	}

	// Set internal CIDR
	err = tr.SetCIDRString("1.1.1.0/25", 4)
	if err != nil {
		t.Error(err)
	}
	info, err = tr.FindCIDRString("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 4 {
		t.Errorf("Wrong value, expected 4, got %v", info)
	}
	info, err = tr.FindCIDRString("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 3 {
		t.Errorf("Wrong value, expected 3, got %v", info)
	}
}

// TestRegression tests a specific regression case where deleting and adding CIDRs caused issues.
func TestRegression(t *testing.T) {
	tr := NewTree(0)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}

	// Add a CIDR to the tree
	tr.AddCIDRString("1.1.1.0/24", 1)

	// Delete the CIDR and add a more specific CIDR
	tr.DeleteCIDRString("1.1.1.0/24")
	tr.AddCIDRString("1.1.1.0/25", 2)

	// Test inside old range, outside new range
	info, err := tr.FindCIDRString("1.1.1.128")
	if err != nil {
		t.Error(err)
	} else if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}
}

// TestTree6 tests the functionality of the tree with IPv6 addresses.
func TestTree6(t *testing.T) {
	tr := NewTree(0)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}

	// Add an IPv6 CIDR to the tree
	err := tr.AddCIDRString("dead::0/16", 3)
	if err != nil {
		t.Error(err)
	}

	// Test matching defined IPv6 CIDR
	info, err := tr.FindCIDRString("dead::beef")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 3 {
		t.Errorf("Wrong value, expected 3, got %v", info)
	}

	// Test outside defined IPv6 CIDR
	info, err = tr.FindCIDRString("deed::beef/32")
	if err != nil {
		t.Error(err)
	}
	if info != nil {
		t.Errorf("Wrong value, expected nil, got %v", info)
	}

	// Add a more specific IPv6 CIDR to the tree
	err = tr.AddCIDRString("dead:beef::0/48", 4)
	if err != nil {
		t.Error(err)
	}

	// Test matching defined IPv6 subnet
	info, err = tr.FindCIDRString("dead:beef::0a5c:0/64")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 4 {
		t.Errorf("Wrong value, expected 4, got %v", info)
	}

	// Test matching outside defined IPv6 subnet
	info, err = tr.FindCIDRString("dead:0::beef:0a5c:0/64")
	if err != nil {
		t.Error(err)
	}
	if info.(int) != 3 {
		t.Errorf("Wrong value, expected 3, got %v", info)
	}
}

// TestRegression6 tests a specific regression case with IPv6 addresses where /128 addresses caused panic.
func TestRegression6(t *testing.T) {
	tr := NewTree(0)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}

	// Add IPv6 CIDRs to the tree
	tr.AddCIDRString("2620:10f::/32", 54321)
	tr.AddCIDRString("2620:10f:d000:100::5/128", 12345)

	// Test finding the /128 IPv6 address
	info, err := tr.FindCIDRString("2620:10f:d000:100::5/128")
	if err != nil {
		t.Errorf("Could not get /128 address from the tree, error: %s", err)
	} else if info.(int) != 12345 {
		t.Errorf("Wrong value from /128 test, got %d, expected 12345", info)
	}
}
