package sla

import (
	"errors"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

func assertDynamicSpaceSelector(t *testing.T, got pcode.VarnodeData, constSpace *address.Space, targetSpace *address.Space) {
	t.Helper()
	if got.Space != constSpace {
		t.Fatalf("space selector constant-space mismatch: got=%v want=%v", got.Space, constSpace)
	}
	if got.Offset != dynamicSpaceSelectorPayload(targetSpace) {
		t.Fatalf("space selector payload mismatch: got=0x%x want=0x%x", got.Offset, dynamicSpaceSelectorPayload(targetSpace))
	}
	if got.Size != dynamicSpaceSelectorSize() {
		t.Fatalf("space selector size mismatch: got=%d want=%d", got.Size, dynamicSpaceSelectorSize())
	}
}

func TestLowerConstructTpl(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x401000},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		UniqueSpace:   unique,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constant},
		Handles: []HandleReference{
			{
				Space:      ram,
				Size:       4,
				Offset:     0x30,
				TempSpace:  unique,
				TempOffset: 0x200,
			},
			{
				Space:  constant,
				Size:   4,
				Offset: 0x30,
			},
		},
		NextOffset:  0x401004,
		HasNext:     true,
		Next2Offset: 0x401008,
		HasNext2:    true,
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{
			{
				OpcodeID: int64(pcode.CPUI_INT_ADD),
				Opcode:   pcode.CPUI_INT_ADD.String(),
				Output: &VarnodeTplBoundary{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x20},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				},
				Inputs: []VarnodeTplBoundary{
					{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x10},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					},
					{
						Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
						Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 8},
						Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
					},
				},
			},
			{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
				Output: &VarnodeTplBoundary{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
					Offset: ConstBoundary{Kind: ConstKindNext, Value: 0},
					Size:   ConstBoundary{Kind: ConstKindCurSpaceSize},
				},
				Inputs: []VarnodeTplBoundary{{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 3},
					Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 1, Selector: handleFieldOffsetPlus, Plus: 0x00020000},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				}},
			},
		},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("unexpected lowered op count: got %d", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("unexpected first opcode: got %v", ops[0].OpCode)
	}
	if ops[0].SeqNum.Address != ctx.Instruction || ops[1].SeqNum.Address != ctx.Instruction {
		t.Fatalf("unexpected seqnum addresses: op0=%v op1=%v want %v", ops[0].SeqNum.Address, ops[1].SeqNum.Address, ctx.Instruction)
	}
	if ops[0].Output == nil || ops[0].Output.Space != unique || ops[0].Output.Offset != 0x20 {
		t.Fatalf("unexpected first output: %+v", ops[0].Output)
	}
	if len(ops[0].Inputs) != 2 {
		t.Fatalf("unexpected first input count: got %d", len(ops[0].Inputs))
	}
	if ops[0].Inputs[1].Space != ram || ops[0].Inputs[1].Offset != 0x38 || ops[0].Inputs[1].Size != 4 {
		t.Fatalf("unexpected handle-lowered input: %+v", ops[0].Inputs[1])
	}
	if ops[1].Output == nil || ops[1].Output.Offset != 0x401004 || ops[1].Output.Size != 8 {
		t.Fatalf("unexpected second output: %+v", ops[1].Output)
	}
	if len(ops[1].Inputs) != 1 || ops[1].Inputs[0].Space != constant || ops[1].Inputs[0].Offset != 0 {
		t.Fatalf("unexpected constant-handle lowering: %+v", ops[1].Inputs)
	}
}

func TestLowerConstructTplUsesRootInstructionForSeqNumAddress(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	active := address.Address{Space: ram, Offset: 0x402000}
	root := address.Address{Space: ram, Offset: 0x401000}
	ctx := LoweringContext{
		Instruction:     active,
		RootInstruction: root,
		CurrentSpace:    ram,
		ConstantSpace:   constant,
		SpacesByIndex:   map[int64]*address.Space{1: ram, 3: constant},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output: &VarnodeTplBoundary{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x10},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 8},
			},
			Inputs: []VarnodeTplBoundary{{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(constant.Index)},
				Offset: ConstBoundary{Kind: ConstKindStart},
				Size:   ConstBoundary{Kind: ConstKindCurSpaceSize},
			}},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("unexpected lowered op count: got %d want 1", len(ops))
	}
	if ops[0].SeqNum.Address != root {
		t.Fatalf("unexpected seqnum address: got %v want %v", ops[0].SeqNum.Address, root)
	}
	if len(ops[0].Inputs) != 1 || ops[0].Inputs[0].Space != constant || ops[0].Inputs[0].Offset != active.Offset {
		t.Fatalf("unexpected COPY input from active instruction semantics: %+v", ops[0].Inputs)
	}
}

func TestLowerConstructTplRejectsUnsupportedOpcode(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := LoweringContext{Instruction: address.Address{Space: ram, Offset: 0x1000}}
	tpl := ConstructTplBoundary{Ops: []OpTplBoundary{{OpcodeID: int64(pcode.CPUI_MAX) + 1}}}

	_, err := LowerConstructTpl(tpl, ctx)
	if err == nil {
		t.Fatal("LowerConstructTpl() returned nil for unsupported opcode")
	}
}

func TestLowerConstructTplRejectsBuildDirectiveWithoutHook(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := LoweringContext{Instruction: address.Address{Space: ram, Offset: 0x1000}}
	tpl := ConstructTplBoundary{Ops: []OpTplBoundary{{OpcodeID: int64(pcode.CPUI_MULTIEQUAL), Opcode: "BUILD"}}}

	_, err := LowerConstructTpl(tpl, ctx)
	if err == nil {
		t.Fatal("LowerConstructTpl() returned nil for BUILD without runtime hook")
	}
}

func TestLowerConstructTplHandlesLabelDirectiveWithHook(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	var got uint64
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x1000},
		ConstantSpace: constSpace,
		LabelBase:     12,
		Directives: DirectiveHooks{
			OnLabel: func(labelID uint64) error {
				got = labelID
				return nil
			},
		},
	}
	tpl := ConstructTplBoundary{Ops: []OpTplBoundary{{
		OpcodeID: int64(pcode.CPUI_PTRADD),
		Opcode:   "LABELBUILD",
		Inputs: []VarnodeTplBoundary{{
			Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 3},
			Offset: ConstBoundary{Kind: ConstKindReal, Value: 5},
			Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
		}},
	}}}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 0 {
		t.Fatalf("LABELBUILD must not lower into raw ops, got %d", len(ops))
	}
	if got != 17 {
		t.Fatalf("unexpected label id: got %d want 17", got)
	}
}

func TestLoweringContextRuntimeBridge(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x401000},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		UniqueSpace:   unique,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constant},
		NextOffset:    0x401004,
		HasNext:       true,
		Next2Offset:   0x401008,
		HasNext2:      true,
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: unique,
			Offset:      0x30,
			OffsetSize:  8,
			TempSpace:   unique,
			TempOffset:  0x200,
		}},
	}

	runtime := ctx.runtimeContext()
	if runtime.Instruction.Offset != 0x401000 || runtime.CurrentSpace != ram || runtime.ConstantSpace != constant {
		t.Fatalf("unexpected runtime bridge header: %+v", runtime)
	}
	if !runtime.HasNext || runtime.Next.Offset != 0x401004 || !runtime.HasNext2 || runtime.Next2.Offset != 0x401008 {
		t.Fatalf("unexpected runtime next offsets: %+v", runtime)
	}
	if len(runtime.Handles) != 1 {
		t.Fatalf("unexpected runtime handle count: %d", len(runtime.Handles))
	}
	if runtime.Handles[0].Space != ram || runtime.Handles[0].OffsetSpace != unique || runtime.Handles[0].OffsetOffset != 0x30 {
		t.Fatalf("unexpected runtime handle bridge: %+v", runtime.Handles[0])
	}
	if runtime.Handles[0].TempSpace != unique || runtime.Handles[0].TempOffset != 0x200 || !runtime.Handles[0].IsDynamic() {
		t.Fatalf("unexpected runtime handle temp bridge: %+v", runtime.Handles[0])
	}
}

func TestNewLoweringContextCarriesUniqueBaseAndMask(t *testing.T) {
	ram := address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	uniq := address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	md := &Metadata{
		DefaultSpace: "ram",
		UniqueBase:   0x7000,
		UniqueMask:   0xff,
		Spaces:       []address.Space{ram, uniq},
	}
	ctx := NewLoweringContext(md, address.Address{Space: &md.Spaces[0], Offset: 0x1234})
	if ctx.UniqueBase != 0x7000 || ctx.UniqueMask != 0xff {
		t.Fatalf("unexpected unique base/mask: base=0x%x mask=0x%x", ctx.UniqueBase, ctx.UniqueMask)
	}
}

func TestLowerVarnodeTplRejectsDynamicHandleOffset(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:  address.Address{Space: ram, Offset: 0x1000},
		CurrentSpace: ram,
		UniqueSpace:  unique,
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
			2: unique,
		},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: ram,
			Offset:      0x4000,
			OffsetSize:  8,
			TempSpace:   unique,
			TempOffset:  0x200,
		}},
	}
	vn := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}

	_, err := lowerVarnodeTpl(vn, ctx)
	if err == nil {
		t.Fatal("lowerVarnodeTpl() returned nil for dynamic handle varnode")
	}
	if !errors.Is(err, ErrLoweringUnimplemented) {
		t.Fatalf("error = %v, want ErrLoweringUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "dynamic varnode requires op-level LOAD/STORE expansion" {
		t.Fatalf("unexpected explain text: %q", uerr.Explain)
	}
}

func TestLowerVarnodeTplStaticHandleOffsetStillLowers(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := LoweringContext{
		Instruction:  address.Address{Space: ram, Offset: 0x1000},
		CurrentSpace: ram,
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
		},
		Handles: []HandleReference{{
			Space:  ram,
			Size:   4,
			Offset: 0x88,
		}},
	}
	vn := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}

	got, err := lowerVarnodeTpl(vn, ctx)
	if err != nil {
		t.Fatalf("lowerVarnodeTpl() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("lowerVarnodeTpl() returned nil varnode")
	}
	if got.Space != ram || got.Offset != 0x88 || got.Size != 4 {
		t.Fatalf("unexpected lowered varnode: %+v", got)
	}
}

func TestLowerConstructTplExpandsDynamicInputWithLoad(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5000},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
			2: register,
			3: constant,
		},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0x80,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x40,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output: &VarnodeTplBoundary{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x10},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			},
			Inputs: []VarnodeTplBoundary{dynamic},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("unexpected op count: got %d want 2", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_LOAD {
		t.Fatalf("first opcode = %v, want LOAD", ops[0].OpCode)
	}
	if ops[0].Output == nil || ops[0].Output.Space != register || ops[0].Output.Offset != 0x40 || ops[0].Output.Size != 4 {
		t.Fatalf("unexpected LOAD output: %+v", ops[0].Output)
	}
	if len(ops[0].Inputs) != 2 {
		t.Fatalf("unexpected LOAD input count: got %d", len(ops[0].Inputs))
	}
	assertDynamicSpaceSelector(t, ops[0].Inputs[0], constant, ram)
	if ops[0].Inputs[1].Space != register || ops[0].Inputs[1].Offset != 0x80 || ops[0].Inputs[1].Size != 8 {
		t.Fatalf("unexpected LOAD pointer input: %+v", ops[0].Inputs[1])
	}
	if ops[1].OpCode != pcode.CPUI_COPY {
		t.Fatalf("second opcode = %v, want COPY", ops[1].OpCode)
	}
	if len(ops[1].Inputs) != 1 || ops[1].Inputs[0].Space != register || ops[1].Inputs[0].Offset != 0x40 || ops[1].Inputs[0].Size != 4 {
		t.Fatalf("unexpected COPY input: %+v", ops[1].Inputs)
	}
	if ops[1].Output == nil || ops[1].Output.Space != ram || ops[1].Output.Offset != 0x10 || ops[1].Output.Size != 4 {
		t.Fatalf("unexpected COPY output: %+v", ops[1].Output)
	}
}

func TestLowerConstructTplExpandsDynamicOutputWithStore(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5100},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
			2: register,
			3: constant,
		},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0x90,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x44,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output:   &dynamic,
			Inputs: []VarnodeTplBoundary{{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(constant.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 7},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			}},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("unexpected op count: got %d want 2", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("first opcode = %v, want COPY", ops[0].OpCode)
	}
	if ops[0].Output == nil || ops[0].Output.Space != register || ops[0].Output.Offset != 0x44 || ops[0].Output.Size != 4 {
		t.Fatalf("unexpected COPY output: %+v", ops[0].Output)
	}
	if ops[1].OpCode != pcode.CPUI_STORE {
		t.Fatalf("second opcode = %v, want STORE", ops[1].OpCode)
	}
	if ops[1].Output != nil {
		t.Fatalf("STORE output must be nil: %+v", ops[1].Output)
	}
	if len(ops[1].Inputs) != 3 {
		t.Fatalf("unexpected STORE input count: got %d", len(ops[1].Inputs))
	}
	assertDynamicSpaceSelector(t, ops[1].Inputs[0], constant, ram)
	if ops[1].Inputs[1].Space != register || ops[1].Inputs[1].Offset != 0x90 || ops[1].Inputs[1].Size != 8 {
		t.Fatalf("unexpected STORE pointer input: %+v", ops[1].Inputs[1])
	}
	if ops[1].Inputs[2].Space != register || ops[1].Inputs[2].Offset != 0x44 || ops[1].Inputs[2].Size != 4 {
		t.Fatalf("unexpected STORE value input: %+v", ops[1].Inputs[2])
	}
}

func TestLowerConstructTplExpandsDynamicInputWithOffsetPlusNoop(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5300},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
			2: register,
			3: constant,
		},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0x88,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x48,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 0x00020000},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output: &VarnodeTplBoundary{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x20},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			},
			Inputs: []VarnodeTplBoundary{dynamic},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("unexpected op count: got %d want 2", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_LOAD {
		t.Fatalf("first opcode = %v, want LOAD", ops[0].OpCode)
	}
	if len(ops[0].Inputs) != 2 {
		t.Fatalf("unexpected LOAD input count: got %d", len(ops[0].Inputs))
	}
	if ops[0].Inputs[1].Space != register || ops[0].Inputs[1].Offset != 0x88 || ops[0].Inputs[1].Size != 8 {
		t.Fatalf("unexpected LOAD pointer input: %+v", ops[0].Inputs[1])
	}
}

func TestLowerConstructTplExpandsDynamicOutputWithOffsetPlusNoop(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5400},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
			2: register,
			3: constant,
		},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0x98,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x4c,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 0x00010000},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output:   &dynamic,
			Inputs: []VarnodeTplBoundary{{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(constant.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 9},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			}},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("unexpected op count: got %d want 2", len(ops))
	}
	if ops[1].OpCode != pcode.CPUI_STORE {
		t.Fatalf("second opcode = %v, want STORE", ops[1].OpCode)
	}
	if len(ops[1].Inputs) != 3 {
		t.Fatalf("unexpected STORE input count: got %d", len(ops[1].Inputs))
	}
	if ops[1].Inputs[1].Space != register || ops[1].Inputs[1].Offset != 0x98 || ops[1].Inputs[1].Size != 8 {
		t.Fatalf("unexpected STORE pointer input: %+v", ops[1].Inputs[1])
	}
}

func TestLowerConstructTplExpandsDynamicInputWithOffsetPlusConstantPointer(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5500},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
			2: register,
			3: constant,
		},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: constant,
			Offset:      0x1200,
			OffsetSize:  4,
			TempSpace:   register,
			TempOffset:  0x58,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 0x10004},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output: &VarnodeTplBoundary{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x20},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			},
			Inputs: []VarnodeTplBoundary{dynamic},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("unexpected op count: got %d want 2", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_LOAD {
		t.Fatalf("first opcode = %v, want LOAD", ops[0].OpCode)
	}
	if len(ops[0].Inputs) != 2 {
		t.Fatalf("unexpected LOAD input count: got %d", len(ops[0].Inputs))
	}
	if ops[0].Inputs[1].Space != constant || ops[0].Inputs[1].Offset != 0x1204 || ops[0].Inputs[1].Size != 4 {
		t.Fatalf("unexpected LOAD pointer input after offset_plus fold: %+v", ops[0].Inputs[1])
	}
}

func TestLowerConstructTplExpandsDynamicInputOffsetPlusNonConstantPointer(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 4, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5600},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		UniqueSpace:   unique,
		UniqueBase:    0x7000,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: register, 3: constant, 4: unique},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0x90,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x70,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 0x10004},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output: &VarnodeTplBoundary{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x24},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			},
			Inputs: []VarnodeTplBoundary{dynamic},
			}},
		}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("unexpected op count: got %d want 3", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("first opcode = %v, want INT_ADD", ops[0].OpCode)
	}
	if ops[0].Output == nil || ops[0].Output.Space != unique || ops[0].Output.Offset != 0x7100 || ops[0].Output.Size != 8 {
		t.Fatalf("unexpected INT_ADD output: %+v", ops[0].Output)
	}
	if len(ops[0].Inputs) != 2 {
		t.Fatalf("unexpected INT_ADD input count: got %d", len(ops[0].Inputs))
	}
	if ops[0].Inputs[0].Space != register || ops[0].Inputs[0].Offset != 0x90 || ops[0].Inputs[0].Size != 8 {
		t.Fatalf("unexpected INT_ADD pointer input: %+v", ops[0].Inputs[0])
	}
	if ops[0].Inputs[1].Space != constant || ops[0].Inputs[1].Offset != 4 || ops[0].Inputs[1].Size != 8 {
		t.Fatalf("unexpected INT_ADD immediate input: %+v", ops[0].Inputs[1])
	}
	if ops[1].OpCode != pcode.CPUI_LOAD {
		t.Fatalf("second opcode = %v, want LOAD", ops[1].OpCode)
	}
	if len(ops[1].Inputs) != 2 {
		t.Fatalf("unexpected LOAD input count: got %d", len(ops[1].Inputs))
	}
	if ops[1].Inputs[1].Space != unique || ops[1].Inputs[1].Offset != 0x7100 || ops[1].Inputs[1].Size != 8 {
		t.Fatalf("unexpected LOAD pointer input: %+v", ops[1].Inputs[1])
	}
	if ops[2].OpCode != pcode.CPUI_COPY {
		t.Fatalf("third opcode = %v, want COPY", ops[2].OpCode)
	}
	if ops[1].Output == nil || len(ops[2].Inputs) != 1 || ops[2].Inputs[0] != *ops[1].Output {
		t.Fatalf("COPY input must use LOAD temp output: load=%+v copyInputs=%+v", ops[1].Output, ops[2].Inputs)
	}
}

func TestLowerConstructTplExpandsDynamicOutputOffsetPlusNonConstantPointer(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 4, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5610},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		UniqueSpace:   unique,
		UniqueBase:    0x7200,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: register, 3: constant, 4: unique},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0xa0,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x74,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 0x20006},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output:   &dynamic,
			Inputs: []VarnodeTplBoundary{{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(constant.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0xb},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			}},
			}},
		}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("unexpected op count: got %d want 3", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("first opcode = %v, want COPY", ops[0].OpCode)
	}
	if ops[1].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("second opcode = %v, want INT_ADD", ops[1].OpCode)
	}
	if ops[1].Output == nil || ops[1].Output.Space != unique || ops[1].Output.Offset != 0x7300 || ops[1].Output.Size != 8 {
		t.Fatalf("unexpected INT_ADD output: %+v", ops[1].Output)
	}
	if len(ops[1].Inputs) != 2 {
		t.Fatalf("unexpected INT_ADD input count: got %d", len(ops[1].Inputs))
	}
	if ops[1].Inputs[0].Space != register || ops[1].Inputs[0].Offset != 0xa0 || ops[1].Inputs[0].Size != 8 {
		t.Fatalf("unexpected INT_ADD pointer input: %+v", ops[1].Inputs[0])
	}
	if ops[1].Inputs[1].Space != constant || ops[1].Inputs[1].Offset != 6 || ops[1].Inputs[1].Size != 8 {
		t.Fatalf("unexpected INT_ADD immediate input: %+v", ops[1].Inputs[1])
	}
	if ops[2].OpCode != pcode.CPUI_STORE {
		t.Fatalf("third opcode = %v, want STORE", ops[2].OpCode)
	}
	if len(ops[2].Inputs) != 3 {
		t.Fatalf("unexpected STORE input count: got %d", len(ops[2].Inputs))
	}
	if ops[2].Inputs[1].Space != unique || ops[2].Inputs[1].Offset != 0x7300 || ops[2].Inputs[1].Size != 8 {
		t.Fatalf("unexpected STORE pointer input: %+v", ops[2].Inputs[1])
	}
	if ops[0].Output == nil || ops[2].Inputs[2] != *ops[0].Output {
		t.Fatalf("STORE value input must use COPY temp output: copyOut=%+v storeValue=%+v", ops[0].Output, ops[2].Inputs[2])
	}
}

func TestLowerConstructTplAppliesUniqueOffsetToDynamicLocationAndPointer(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x1234},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		UniqueSpace:   unique,
		UniqueMask:    0xff,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constant},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: unique,
			Offset:      0x88,
			OffsetSize:  8,
			TempSpace:   unique,
			TempOffset:  0x20,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output: &VarnodeTplBoundary{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x40},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			},
			Inputs: []VarnodeTplBoundary{dynamic},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("unexpected op count: got %d want 2", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_LOAD {
		t.Fatalf("first opcode = %v, want LOAD", ops[0].OpCode)
	}
	if ops[0].Output == nil || ops[0].Output.Space != unique || ops[0].Output.Offset != 0x3420 || ops[0].Output.Size != 4 {
		t.Fatalf("unexpected LOAD output with uniqueoffset: %+v", ops[0].Output)
	}
	if len(ops[0].Inputs) != 2 || ops[0].Inputs[1].Space != unique || ops[0].Inputs[1].Offset != 0x3488 || ops[0].Inputs[1].Size != 8 {
		t.Fatalf("unexpected LOAD pointer with uniqueoffset: %+v", ops[0].Inputs)
	}
	if len(ops[1].Inputs) != 1 || ops[1].Inputs[0].Space != unique || ops[1].Inputs[0].Offset != 0x3420 {
		t.Fatalf("unexpected main-op input with uniqueoffset temp: %+v", ops[1].Inputs)
	}
}

func TestLowerConstructTplExpandsDynamicOffsetPlusWithUniquePointerKeepsUniqueOffset(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x1234},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		UniqueSpace:   unique,
		UniqueBase:    0x7000,
		UniqueMask:    0xff,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constant},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: unique,
			Offset:      0x88,
			OffsetSize:  8,
			TempSpace:   unique,
			TempOffset:  0x20,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 0x10004},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output: &VarnodeTplBoundary{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x40},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			},
			Inputs: []VarnodeTplBoundary{dynamic},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("unexpected op count: got %d want 3", len(ops))
	}
	if ops[0].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("first opcode = %v, want INT_ADD", ops[0].OpCode)
	}
	if ops[0].Output == nil || ops[0].Output.Space != unique || ops[0].Output.Offset != 0x7100 || ops[0].Output.Size != 8 {
		t.Fatalf("unexpected INT_ADD output: %+v", ops[0].Output)
	}
	if len(ops[0].Inputs) != 2 {
		t.Fatalf("unexpected INT_ADD input count: got %d", len(ops[0].Inputs))
	}
	if ops[0].Inputs[0].Space != unique || ops[0].Inputs[0].Offset != 0x3488 || ops[0].Inputs[0].Size != 8 {
		t.Fatalf("unexpected INT_ADD pointer input with uniqueoffset: %+v", ops[0].Inputs[0])
	}
	if ops[0].Inputs[1].Space != constant || ops[0].Inputs[1].Offset != 4 || ops[0].Inputs[1].Size != 8 {
		t.Fatalf("unexpected INT_ADD immediate input: %+v", ops[0].Inputs[1])
	}
	if ops[1].OpCode != pcode.CPUI_LOAD {
		t.Fatalf("second opcode = %v, want LOAD", ops[1].OpCode)
	}
	if ops[1].Output == nil || ops[1].Output.Space != unique || ops[1].Output.Offset != 0x3424 || ops[1].Output.Size != 4 {
		t.Fatalf("unexpected LOAD output with uniqueoffset: %+v", ops[1].Output)
	}
	if len(ops[1].Inputs) != 2 || ops[1].Inputs[1].Space != unique || ops[1].Inputs[1].Offset != 0x7100 || ops[1].Inputs[1].Size != 8 {
		t.Fatalf("unexpected LOAD pointer input via runtime temp: %+v", ops[1].Inputs)
	}
	if ops[2].OpCode != pcode.CPUI_COPY {
		t.Fatalf("third opcode = %v, want COPY", ops[2].OpCode)
	}
	if len(ops[2].Inputs) != 1 || ops[1].Output == nil || ops[2].Inputs[0] != *ops[1].Output {
		t.Fatalf("unexpected COPY input from LOAD temp: %+v", ops[2].Inputs)
	}
}

func TestLowerConstructTplRejectsDynamicOffsetPlusWithoutUniqueRuntimeSpace(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5200},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: register, 3: constant},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0x90,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x44,
		}},
	}
	dynamicOffsetPlus := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 4},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Inputs:   []VarnodeTplBoundary{dynamicOffsetPlus},
		}},
	}

	_, err := LowerConstructTpl(tpl, ctx)
	if err == nil {
		t.Fatal("LowerConstructTpl() returned nil for dynamic v_offset_plus without unique runtime space")
	}
	if !errors.Is(err, ErrLoweringUnimplemented) {
		t.Fatalf("error = %v, want ErrLoweringUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "dynamic varnode v_offset_plus low16=0x4 requires unique runtime temp space" {
		t.Fatalf("unexpected explain text: %q", uerr.Explain)
	}
}

func TestLowerConstructTplExpandsDynamicOutputOffsetPlusUsesUniqueSpaceMapFallback(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 4, AddrSize: 8, WordSize: 1}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x5620},
		CurrentSpace:  ram,
		ConstantSpace: constant,
		// UniqueSpace intentionally left nil: fallback should come from SpacesByIndex.
		UniqueBase:    0x7200,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: register, 3: constant, 4: unique},
		Handles: []HandleReference{{
			Space:       ram,
			Size:        4,
			OffsetSpace: register,
			Offset:      0xa8,
			OffsetSize:  8,
			TempSpace:   register,
			TempOffset:  0x74,
		}},
	}
	dynamic := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffsetPlus, Plus: 0x20006},
		Size:   ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
	}
	tpl := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
			Output:   &dynamic,
			Inputs: []VarnodeTplBoundary{{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(constant.Index)},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0xc},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
			}},
		}},
	}

	ops, err := LowerConstructTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("LowerConstructTpl() returned unexpected error: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("unexpected op count: got %d want 3", len(ops))
	}
	if ops[1].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("second opcode = %v, want INT_ADD", ops[1].OpCode)
	}
	if ops[1].Output == nil || ops[1].Output.Space != unique || ops[1].Output.Offset != 0x7300 || ops[1].Output.Size != 8 {
		t.Fatalf("unexpected INT_ADD output under fallback unique space: %+v", ops[1].Output)
	}
	assertDynamicSpaceSelector(t, ops[2].Inputs[0], constant, ram)
}
