package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

func TestOpCodeString(t *testing.T) {
	if got := CPUI_INT_ADD.String(); got != "INT_ADD" {
		t.Fatalf("unexpected opcode string: %s", got)
	}
	if got := OpCode(999).String(); got != "OpCode(999)" {
		t.Fatalf("unexpected fallback string: %s", got)
	}
}

func TestVarnodeDataValidateAndOrdering(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	a := VarnodeData{Space: ram, Offset: 0x10, Size: 8}
	b := VarnodeData{Space: ram, Offset: 0x10, Size: 4}

	if err := a.Validate(); err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}
	if !a.Less(b) {
		t.Fatal("expected larger size at same location to sort first")
	}

	addr := a.Address()
	if addr.Space != ram || addr.Offset != 0x10 {
		t.Fatalf("unexpected address projection: %+v", addr)
	}
}

func TestVarnodeDataRejectsZeroSize(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	v := VarnodeData{Space: ram, Offset: 0, Size: 0}
	if err := v.Validate(); err == nil {
		t.Fatal("Validate() returned nil for zero-sized varnode")
	}
}

func TestRawOpValidateAndString(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	reg := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 4, WordSize: 1}

	out := VarnodeData{Space: reg, Offset: 0x20, Size: 4}
	in0 := VarnodeData{Space: reg, Offset: 0x10, Size: 4}
	in1 := VarnodeData{Space: ram, Offset: 0x1000, Size: 4}

	op := RawOp{
		SeqNum: SeqNum{
			Address: address.Address{Space: ram, Offset: 0x401000},
			Time:    1,
			Order:   0,
		},
		OpCode: CPUI_INT_ADD,
		Output: &out,
		Inputs: []VarnodeData{in0, in1},
	}

	if err := op.Validate(); err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}

	got := op.String()
	want := "ram:0x401000 INT_ADD register:0x20[4] = register:0x10[4] ram:0x1000[4]"
	if got != want {
		t.Fatalf("unexpected String() value:\n got: %s\nwant: %s", got, want)
	}
}

func TestRawOpRejectsMissingOpcode(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	op := RawOp{
		SeqNum: SeqNum{
			Address: address.Address{Space: ram, Offset: 0x10},
		},
	}
	if err := op.Validate(); err == nil {
		t.Fatal("Validate() returned nil for missing opcode")
	}
}
