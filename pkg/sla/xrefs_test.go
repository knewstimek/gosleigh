package sla

import (
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

func TestBuildXrefsCollectsVarnodeRegisterNames(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "RAX",
				ID:            0,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemVarnodeSymHead,
				BodyElement:   elemVarnodeSym,
				Body: SymbolBodyBoundary{
					Varnode: &VarnodeSymbolBoundary{SpaceIndex: 3, Offset: 0x00, Size: 8},
				},
			},
			{
				Name:          "EAX",
				ID:            1,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemVarnodeSymHead,
				BodyElement:   elemVarnodeSym,
				Body: SymbolBodyBoundary{
					Varnode: &VarnodeSymbolBoundary{SpaceIndex: 3, Offset: 0x00, Size: 4},
				},
			},
		},
	}

	xrefs, err := BuildXrefs(symbols)
	if err != nil {
		t.Fatalf("BuildXrefs failed: %v", err)
	}
	if len(xrefs.VarnodeXref) != 2 {
		t.Fatalf("expected 2 varnode xref entries, got %d", len(xrefs.VarnodeXref))
	}

	// Entries should be sorted by (space, offset, size).
	if xrefs.VarnodeXref[0].Name != "EAX" || xrefs.VarnodeXref[0].Size != 4 {
		t.Fatalf("first entry should be EAX (size 4), got %s (size %d)", xrefs.VarnodeXref[0].Name, xrefs.VarnodeXref[0].Size)
	}
	if xrefs.VarnodeXref[1].Name != "RAX" || xrefs.VarnodeXref[1].Size != 8 {
		t.Fatalf("second entry should be RAX (size 8), got %s (size %d)", xrefs.VarnodeXref[1].Name, xrefs.VarnodeXref[1].Size)
	}
}

func TestBuildXrefsCollectsUserOpNames(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "syscall",
				ID:            0,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemUserOpHead,
				BodyElement:   elemUserOp,
				Body: SymbolBodyBoundary{
					UserOp: &UserOpBoundary{Index: 3},
				},
			},
			{
				Name:          "breakpoint",
				ID:            1,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemUserOpHead,
				BodyElement:   elemUserOp,
				Body: SymbolBodyBoundary{
					UserOp: &UserOpBoundary{Index: 7},
				},
			},
		},
	}

	xrefs, err := BuildXrefs(symbols)
	if err != nil {
		t.Fatalf("BuildXrefs failed: %v", err)
	}
	if len(xrefs.UserOpNames) != 8 {
		t.Fatalf("expected 8 user-op name slots, got %d", len(xrefs.UserOpNames))
	}
	if xrefs.UserOpNames[3] != "syscall" {
		t.Fatalf("expected user-op 3 = syscall, got %q", xrefs.UserOpNames[3])
	}
	if xrefs.UserOpNames[7] != "breakpoint" {
		t.Fatalf("expected user-op 7 = breakpoint, got %q", xrefs.UserOpNames[7])
	}
	if xrefs.UserOpNames[0] != "" {
		t.Fatalf("expected user-op 0 = empty, got %q", xrefs.UserOpNames[0])
	}
	if xrefs.GetUserOpName(3) != "syscall" {
		t.Fatalf("GetUserOpName(3) expected syscall, got %q", xrefs.GetUserOpName(3))
	}
	if xrefs.GetUserOpName(99) != "" {
		t.Fatalf("GetUserOpName(99) expected empty, got %q", xrefs.GetUserOpName(99))
	}
}

func TestBuildXrefsCollectsContextFields(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "phase",
				ID:            0,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemContextSymHead,
				BodyElement:   elemContextSym,
				Body: SymbolBodyBoundary{
					Context: &ContextSymbolBoundary{
						VarnodeSymbolID:    10,
						HasVarnodeSymbolID: true,
						Low:                0,
						High:               3,
						Flow:               true,
						Pattern:            &PatternSymbolBoundary{},
					},
				},
			},
			{
				Name:          "addrsize",
				ID:            1,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemContextSymHead,
				BodyElement:   elemContextSym,
				Body: SymbolBodyBoundary{
					Context: &ContextSymbolBoundary{
						Low:  4,
						High: 5,
						Flow: false,
					},
				},
			},
		},
	}

	xrefs, err := BuildXrefs(symbols)
	if err != nil {
		t.Fatalf("BuildXrefs failed: %v", err)
	}
	if len(xrefs.ContextFields) != 2 {
		t.Fatalf("expected 2 context fields, got %d", len(xrefs.ContextFields))
	}
	if xrefs.ContextFields[0].Name != "phase" || xrefs.ContextFields[0].StartBit != 0 || xrefs.ContextFields[0].EndBit != 3 || !xrefs.ContextFields[0].Flow {
		t.Fatalf("unexpected context field 0: %+v", xrefs.ContextFields[0])
	}
	if xrefs.ContextFields[1].Name != "addrsize" || xrefs.ContextFields[1].StartBit != 4 || xrefs.ContextFields[1].EndBit != 5 || xrefs.ContextFields[1].Flow {
		t.Fatalf("unexpected context field 1: %+v", xrefs.ContextFields[1])
	}
}

func TestBuildXrefsSkipsNonGlobalScope(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "localreg",
				ID:            0,
				ScopeID:       5, // not global scope
				HeaderElement: elemVarnodeSymHead,
				BodyElement:   elemVarnodeSym,
				Body: SymbolBodyBoundary{
					Varnode: &VarnodeSymbolBoundary{SpaceIndex: 3, Offset: 0x10, Size: 4},
				},
			},
		},
	}

	xrefs, err := BuildXrefs(symbols)
	if err != nil {
		t.Fatalf("BuildXrefs failed: %v", err)
	}
	if len(xrefs.VarnodeXref) != 0 {
		t.Fatalf("expected 0 varnode xref entries for non-global scope, got %d", len(xrefs.VarnodeXref))
	}
}

func TestBuildXrefsDetectsDuplicateVarnodes(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "R0",
				ID:            0,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemVarnodeSymHead,
				BodyElement:   elemVarnodeSym,
				Body: SymbolBodyBoundary{
					Varnode: &VarnodeSymbolBoundary{SpaceIndex: 3, Offset: 0x00, Size: 4},
				},
			},
			{
				Name:          "R0_dup",
				ID:            1,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemVarnodeSymHead,
				BodyElement:   elemVarnodeSym,
				Body: SymbolBodyBoundary{
					Varnode: &VarnodeSymbolBoundary{SpaceIndex: 3, Offset: 0x00, Size: 4},
				},
			},
		},
	}

	_, err := BuildXrefs(symbols)
	if err == nil {
		t.Fatal("expected error for duplicate register pairs")
	}
}

func TestGetRegisterNameFindsContainingRegister(t *testing.T) {
	xrefs := &XRefs{
		VarnodeXref: []VarnodeXrefEntry{
			{SpaceIndex: 3, Offset: 0x00, Size: 4, Name: "EAX"},
			{SpaceIndex: 3, Offset: 0x00, Size: 8, Name: "RAX"},
			{SpaceIndex: 3, Offset: 0x08, Size: 8, Name: "RCX"},
		},
	}

	// Exact match
	if name := xrefs.GetExactRegisterName(3, 0x00, 8); name != "RAX" {
		t.Fatalf("expected RAX, got %q", name)
	}

	// No match in different space
	if name := xrefs.GetRegisterName(5, 0x00, 4); name != "" {
		t.Fatalf("expected empty for wrong space, got %q", name)
	}
}

func TestBuildXrefsNilSymbols(t *testing.T) {
	xrefs, err := BuildXrefs(nil)
	if err != nil {
		t.Fatalf("BuildXrefs(nil) failed: %v", err)
	}
	if len(xrefs.VarnodeXref) != 0 || len(xrefs.UserOpNames) != 0 || len(xrefs.ContextFields) != 0 {
		t.Fatal("expected empty xrefs for nil symbols")
	}
}

func TestBoundariesBuildXrefs(t *testing.T) {
	b := &Boundaries{
		SymbolTable: &SymbolTableBoundary{
			Symbols: []SymbolBoundary{
				{
					Name:          "SP",
					ID:            0,
					ScopeID:       globalSymbolScopeID,
					HeaderElement: elemVarnodeSymHead,
					BodyElement:   elemVarnodeSym,
					Body: SymbolBodyBoundary{
						Varnode: &VarnodeSymbolBoundary{SpaceIndex: 3, Offset: 0x20, Size: 8},
					},
				},
			},
		},
	}
	xrefs, err := b.BuildXrefs()
	if err != nil {
		t.Fatalf("Boundaries.BuildXrefs failed: %v", err)
	}
	if len(xrefs.VarnodeXref) != 1 || xrefs.VarnodeXref[0].Name != "SP" {
		t.Fatal("Boundaries.BuildXrefs did not collect SP register")
	}
}

// TestXRefsUserOpNamesLookupWiring verifies that GetUserOpName correctly routes
// through the UserOpNames slice built by BuildXrefs, including out-of-range safety.
// This tests the "wiring" between BuildXrefs output and the runtime lookup path.
func TestXRefsUserOpNamesLookupWiring(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "callother_op",
				ID:            0,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemUserOpHead,
				BodyElement:   elemUserOp,
				Body:          SymbolBodyBoundary{UserOp: &UserOpBoundary{Index: 2}},
			},
			{
				Name:          "another_op",
				ID:            1,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemUserOpHead,
				BodyElement:   elemUserOp,
				Body:          SymbolBodyBoundary{UserOp: &UserOpBoundary{Index: 5}},
			},
		},
	}

	xrefs, err := BuildXrefs(symbols)
	if err != nil {
		t.Fatalf("BuildXrefs failed: %v", err)
	}

	// Wiring check: GetUserOpName must route through UserOpNames correctly.
	if got := xrefs.GetUserOpName(2); got != "callother_op" {
		t.Fatalf("GetUserOpName(2) = %q, want callother_op", got)
	}
	if got := xrefs.GetUserOpName(5); got != "another_op" {
		t.Fatalf("GetUserOpName(5) = %q, want another_op", got)
	}
	// Slots not set by any symbol must be empty strings (zero-value fill).
	if got := xrefs.GetUserOpName(0); got != "" {
		t.Fatalf("GetUserOpName(0) = %q, want empty (no symbol at index 0)", got)
	}
	if got := xrefs.GetUserOpName(1); got != "" {
		t.Fatalf("GetUserOpName(1) = %q, want empty (no symbol at index 1)", got)
	}
	// Out-of-range must not panic and must return empty.
	if got := xrefs.GetUserOpName(-1); got != "" {
		t.Fatalf("GetUserOpName(-1) = %q, want empty for negative index", got)
	}
	if got := xrefs.GetUserOpName(1000); got != "" {
		t.Fatalf("GetUserOpName(1000) = %q, want empty for out-of-range index", got)
	}
	// Nil receiver must not panic.
	var nilXrefs *XRefs
	if got := nilXrefs.GetUserOpName(2); got != "" {
		t.Fatalf("nil.GetUserOpName(2) = %q, want empty", got)
	}
}

// TestCallotherXRefsUserOpWiring is a regression test that verifies the
// CALLOTHER user-op wiring end-to-end: BuildXrefs populates UserOpNames, and
// GetUserOpName resolves the name from a CALLOTHER op's first input offset.
//
// In Ghidra's sleigh.cc, a CALLOTHER raw op stores the user-op index in
// Inputs[0].Offset (constant space varnode). This test creates a synthetic
// engine state -- symbol table with two UserOpSymbols, a CALLOTHER RawOp with
// the matching constant input -- and verifies that the XRefs lookup resolves
// both names correctly without any real .sla data.
func TestCallotherXRefsUserOpWiring(t *testing.T) {
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 0, AddrSize: 8}
	ramSpace := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ramAddr := address.Address{Space: ramSpace, Offset: 0x4000}

	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "os_call",
				ID:            10,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemUserOpHead,
				BodyElement:   elemUserOp,
				Body:          SymbolBodyBoundary{UserOp: &UserOpBoundary{Index: 0}},
			},
			{
				Name:          "debugbreak",
				ID:            11,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemUserOpHead,
				BodyElement:   elemUserOp,
				Body:          SymbolBodyBoundary{UserOp: &UserOpBoundary{Index: 1}},
			},
		},
	}

	xrefs, err := BuildXrefs(symbols)
	if err != nil {
		t.Fatalf("BuildXrefs() failed: %v", err)
	}
	if len(xrefs.UserOpNames) < 2 {
		t.Fatalf("UserOpNames length = %d, want >= 2", len(xrefs.UserOpNames))
	}

	// Synthetic CALLOTHER ops: first input is a constant varnode whose Offset
	// encodes the user-op index, mirroring the encoding in sleigh.cc emit().
	makeCallother := func(userOpIndex uint64) pcode.RawOp {
		return pcode.RawOp{
			SeqNum: pcode.SeqNum{Address: ramAddr},
			OpCode: pcode.CPUI_CALLOTHER,
			Inputs: []pcode.VarnodeData{
				{Space: constSpace, Offset: userOpIndex, Size: 4},
			},
		}
	}

	op0 := makeCallother(0)
	op1 := makeCallother(1)

	// Wiring check: XRefs.GetUserOpName must resolve both names from the
	// user-op index carried in the CALLOTHER op's first input offset.
	idx0 := int(op0.Inputs[0].Offset)
	if got := xrefs.GetUserOpName(idx0); got != "os_call" {
		t.Fatalf("CALLOTHER index 0: GetUserOpName = %q, want os_call", got)
	}
	idx1 := int(op1.Inputs[0].Offset)
	if got := xrefs.GetUserOpName(idx1); got != "debugbreak" {
		t.Fatalf("CALLOTHER index 1: GetUserOpName = %q, want debugbreak", got)
	}
}

// TestXRefsContextFieldsAccessWiring verifies that BuildXrefs populates
// ContextFields correctly and that direct slice access returns the expected
// bit-range and flow data for each registered context symbol.
// This tests the "wiring" from ContextSymbolBoundary into XRefs.ContextFields.
func TestXRefsContextFieldsAccessWiring(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:          "TF",
				ID:            0,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemContextSymHead,
				BodyElement:   elemContextSym,
				Body: SymbolBodyBoundary{
					Context: &ContextSymbolBoundary{Low: 8, High: 8, Flow: false},
				},
			},
			{
				Name:          "DF",
				ID:            1,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemContextSymHead,
				BodyElement:   elemContextSym,
				Body: SymbolBodyBoundary{
					Context: &ContextSymbolBoundary{Low: 10, High: 10, Flow: true},
				},
			},
			{
				// Non-context symbol must not appear in ContextFields.
				Name:          "EAX",
				ID:            2,
				ScopeID:       globalSymbolScopeID,
				HeaderElement: elemVarnodeSymHead,
				BodyElement:   elemVarnodeSym,
				Body: SymbolBodyBoundary{
					Varnode: &VarnodeSymbolBoundary{SpaceIndex: 3, Offset: 0x00, Size: 4},
				},
			},
		},
	}

	xrefs, err := BuildXrefs(symbols)
	if err != nil {
		t.Fatalf("BuildXrefs failed: %v", err)
	}

	// Wiring check: only context symbols must appear in ContextFields.
	if len(xrefs.ContextFields) != 2 {
		t.Fatalf("ContextFields length = %d, want 2", len(xrefs.ContextFields))
	}

	// Access ContextFields directly to verify wiring from Low/High/Flow boundary fields.
	tfField := xrefs.ContextFields[0]
	if tfField.Name != "TF" || tfField.StartBit != 8 || tfField.EndBit != 8 || tfField.Flow {
		t.Fatalf("ContextFields[0] = %+v, want {Name:TF StartBit:8 EndBit:8 Flow:false}", tfField)
	}
	dfField := xrefs.ContextFields[1]
	if dfField.Name != "DF" || dfField.StartBit != 10 || dfField.EndBit != 10 || !dfField.Flow {
		t.Fatalf("ContextFields[1] = %+v, want {Name:DF StartBit:10 EndBit:10 Flow:true}", dfField)
	}

	// Verify no VarnodeXref entry for context symbols.
	for _, vn := range xrefs.VarnodeXref {
		if vn.Name == "TF" || vn.Name == "DF" {
			t.Fatalf("context symbol %q incorrectly appears in VarnodeXref", vn.Name)
		}
	}
}
