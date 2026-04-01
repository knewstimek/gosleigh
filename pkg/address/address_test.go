package address

import "testing"

func TestSpaceValidate(t *testing.T) {
	valid := Space{Name: "ram", Kind: SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Delay: 0}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}

	invalid := Space{Name: "", Kind: SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Delay: 0}
	if err := invalid.Validate(); err == nil {
		t.Fatal("Validate() returned nil for invalid space")
	}
}

func TestSpaceValidateRejectsNegativeDelay(t *testing.T) {
	invalid := Space{Name: "ram", Kind: SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Delay: -1}
	if err := invalid.Validate(); err == nil {
		t.Fatal("Validate() returned nil for negative delay")
	}
}

func TestAddressOrderingAndString(t *testing.T) {
	ram := &Space{Name: "ram", Kind: SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Delay: 0}
	reg := &Space{Name: "register", Kind: SpaceKindProcessor, Index: 2, AddrSize: 4, WordSize: 1, Delay: 0}

	a := Address{Space: ram, Offset: 0x10}
	b := Address{Space: ram, Offset: 0x20}
	c := Address{Space: reg, Offset: 0x01}

	if !a.Less(b) {
		t.Fatal("expected lower offset in same space to compare smaller")
	}
	if !a.Less(c) {
		t.Fatal("expected lower space index to compare smaller")
	}
	if got := a.String(); got != "ram:0x10" {
		t.Fatalf("unexpected String() value: %s", got)
	}
}

func TestInvalidAddress(t *testing.T) {
	var invalid Address
	if !invalid.IsInvalid() {
		t.Fatal("zero Address should be invalid")
	}
	if got := invalid.String(); got != "<invalid>" {
		t.Fatalf("unexpected invalid String() value: %s", got)
	}
}
