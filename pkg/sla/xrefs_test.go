package sla

import "testing"

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
