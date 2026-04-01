package sla

import (
	"errors"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

func TestDisassemblyCacheStoresAndRetrievesParserContext(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x401000}
	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStatePcode)

	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}
	if !cache.HasParserContext(addr) {
		t.Fatal("expected cached parser context")
	}
	got, ok := cache.GetParserContext(addr)
	if !ok || got != ctx {
		t.Fatalf("unexpected parser context lookup: ok=%v got=%p want=%p", ok, got, ctx)
	}
	if !cache.HasPcodeParserContext(addr) {
		t.Fatal("expected cached pcode parser context")
	}
	pcodeCtx, ok := cache.GetPcodeParserContext(addr)
	if !ok || pcodeCtx != ctx {
		t.Fatalf("unexpected pcode parser context lookup: ok=%v got=%p want=%p", ok, pcodeCtx, ctx)
	}
	if !cache.DeleteParserContext(addr) {
		t.Fatal("DeleteParserContext() returned false for existing context")
	}
	if cache.HasParserContext(addr) {
		t.Fatal("expected cached parser context to be removed")
	}
}

func TestDisassemblyCachePcodeStateHelpers(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x402000}
	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStateDisassembly)

	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}
	if cache.HasPcodeParserContext(addr) {
		t.Fatal("did not expect pcode parser context before state change")
	}
	if _, ok := cache.GetPcodeParserContext(addr); ok {
		t.Fatal("GetPcodeParserContext() returned a context before state change")
	}
	if err := cache.SetParserState(addr, ParseStatePcode); err != nil {
		t.Fatalf("SetParserState() error: %v", err)
	}
	if !cache.HasPcodeParserContext(addr) {
		t.Fatal("expected pcode parser context after state change")
	}
	if got, err := cache.RequirePcodeParserContext(addr); err != nil || got != ctx {
		t.Fatalf("RequirePcodeParserContext() mismatch: got=%p err=%v", got, err)
	}
}

func TestDisassemblyCacheRejectsNilInputs(t *testing.T) {
	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(address.Address{}, nil); err == nil {
		t.Fatal("SetParserContext() accepted nil parser context")
	}
	if err := cache.SetParserState(address.Address{}, ParseStatePcode); err == nil {
		t.Fatal("SetParserState() accepted missing parser context")
	}
}

func TestDisassemblyCacheObtainParserContextHashHit(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	cache := NewDisassemblyCache()
	addr := address.Address{Space: ram, Offset: 0x8000}

	first, err := cache.ObtainParserContext(addr, nil)
	if err != nil {
		t.Fatalf("ObtainParserContext() first error: %v", err)
	}
	if first == nil {
		t.Fatal("ObtainParserContext() returned nil context")
	}
	first.SetParserState(ParseStatePcode)

	second, err := cache.ObtainParserContext(addr, nil)
	if err != nil {
		t.Fatalf("ObtainParserContext() second error: %v", err)
	}
	if second != first {
		t.Fatalf("same-address obtain returned different context: got=%p want=%p", second, first)
	}
	if second.GetParserState() != ParseStatePcode {
		t.Fatalf("same-address obtain should preserve parser state, got=%d want=%d", second.GetParserState(), ParseStatePcode)
	}
}

func TestDisassemblyCacheObtainParserContextCircularReuseResetsState(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	cache := NewDisassemblyCache()
	window := uint64(defaultParserContextWindow)
	var first *ParserContext

	for i := 0; i < defaultParserContextReuse; i++ {
		addr := address.Address{Space: ram, Offset: 0x9000 + uint64(i)*window}
		ctx, err := cache.ObtainParserContext(addr, nil)
		if err != nil {
			t.Fatalf("ObtainParserContext() setup[%d] error: %v", i, err)
		}
		if i == 0 {
			first = ctx
			first.SetParserState(ParseStatePcode)
			first.SetN2addr(address.Address{Space: ram, Offset: 0xbeef})
		}
	}

	// Next miss wraps parserNext and reuses the first slot.
	wrapAddr := address.Address{Space: ram, Offset: 0x9000 + uint64(defaultParserContextReuse)*window}
	wrapped, err := cache.ObtainParserContext(wrapAddr, nil)
	if err != nil {
		t.Fatalf("ObtainParserContext() wrap error: %v", err)
	}
	if wrapped != first {
		t.Fatalf("expected circular reuse of first slot, got=%p want=%p", wrapped, first)
	}
	if wrapped.GetParserState() != ParseStateUninitialized {
		t.Fatalf("reused context parser state = %d, want %d", wrapped.GetParserState(), ParseStateUninitialized)
	}
	if wrapped.GetAddr() != wrapAddr {
		t.Fatalf("reused context addr = %v, want %v", wrapped.GetAddr(), wrapAddr)
	}
	if !wrapped.GetN2addr().IsInvalid() {
		t.Fatalf("reused context n2addr = %v, want invalid", wrapped.GetN2addr())
	}
}

type captureRawEmitter struct {
	ops []pcode.RawOp
}

func (e *captureRawEmitter) EmitRaw(op pcode.RawOp) error {
	e.ops = append(e.ops, cloneRawOp(op))
	return nil
}

func (e *captureRawEmitter) Ops() []pcode.RawOp {
	return cloneRawOps(e.ops)
}

type failRawEmitter struct {
	failAt int
	err    error
	count  int
}

func (e *failRawEmitter) EmitRaw(op pcode.RawOp) error {
	if e.count == e.failAt {
		if e.err == nil {
			e.err = errors.New("raw sink failure")
		}
		return e.err
	}
	e.count++
	return nil
}

type mutateRawEmitter struct {
	mutatedOffset uint64
}

func (e *mutateRawEmitter) EmitRaw(op pcode.RawOp) error {
	if len(op.Inputs) > 0 {
		op.Inputs[0].Offset = e.mutatedOffset
	}
	return nil
}

type mutateThenFailRawEmitter struct {
	failAt        int
	mutatedOffset uint64
	err           error
	count         int
}

func (e *mutateThenFailRawEmitter) EmitRaw(op pcode.RawOp) error {
	if len(op.Inputs) > 0 {
		op.Inputs[0].Offset = e.mutatedOffset
	}
	if e.count == e.failAt {
		if e.err == nil {
			e.err = errors.New("raw sink failure")
		}
		return e.err
	}
	e.count++
	return nil
}

func mustEmitRawBuildToCapture(t *testing.T, cache *DisassemblyCache, instruction address.Address) []pcode.RawOp {
	t.Helper()
	emitter := &captureRawEmitter{}
	if err := cache.EmitRawBuildTo(instruction, emitter); err != nil {
		t.Fatalf("EmitRawBuildTo() error: %v", err)
	}
	return emitter.Ops()
}

func TestDisassemblyCacheEmitRawBuildToSinkOrderOwnershipAndClose(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xb100}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 2); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(copy) error: %v", err)
	}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_INT_ADD,
		Inputs: []pcode.VarnodeData{
			{Space: ram, Offset: 0x20, Size: 4},
			{Space: ram, Offset: 0x24, Size: 4},
		},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(int_add) error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	emitter := &captureRawEmitter{}
	if err := cache.EmitRawBuildTo(instruction, emitter); err != nil {
		t.Fatalf("EmitRawBuildTo() error: %v", err)
	}
	if len(emitter.ops) != 2 {
		t.Fatalf("unexpected sink emission count: got %d want 2", len(emitter.ops))
	}
	if emitter.ops[0].OpCode != pcode.CPUI_COPY || emitter.ops[1].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("unexpected sink emission order: %+v", emitter.ops)
	}
	emitter.ops[0].Inputs[0].Offset = 0xdead
	stored, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing committed sink-emitted ops")
	}
	if len(stored) != 2 || stored[0].Inputs[0].Offset != 0x10 {
		t.Fatalf("cache ownership mismatch after sink mutation: %+v", stored)
	}
	if _, err := cache.RawBuildLength(instruction); err == nil {
		t.Fatal("raw build staging was not closed after EmitRawBuildTo()")
	}
}

func TestDisassemblyCacheEmitRawBuildToRequiresResolvedPhase(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xb108}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	emitter := &captureRawEmitter{}
	err := cache.EmitRawBuildTo(instruction, emitter)
	if !errors.Is(err, ErrRawBuildUnresolved) {
		t.Fatalf("EmitRawBuildTo() unresolved error mismatch: got %v", err)
	}
	if len(emitter.ops) != 0 {
		t.Fatalf("unresolved EmitRawBuildTo() unexpectedly emitted ops: %d", len(emitter.ops))
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("GetRawOps() unexpectedly contains committed ops after unresolved emit")
	}
	if got, rawErr := cache.RawBuildLength(instruction); rawErr != nil || got != 1 {
		t.Fatalf("staging was not preserved after unresolved emit: len=%d err=%v", got, rawErr)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error after unresolved emit: %v", err)
	}
	if err := cache.EmitRawBuildTo(instruction, emitter); err != nil {
		t.Fatalf("EmitRawBuildTo() error after resolve: %v", err)
	}
	if len(emitter.ops) != 1 || emitter.ops[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("unexpected sink emission after resolve: %+v", emitter.ops)
	}
}

func TestDisassemblyCacheEmitRawBuildToRequiresResolvedPhaseWithoutSinklessHelper(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xb109}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.EmitRawBuildTo(instruction, &captureRawEmitter{}); !errors.Is(err, ErrRawBuildUnresolved) {
		t.Fatalf("EmitRawBuildTo() unresolved error mismatch: got %v", err)
	}
	if got, rawErr := cache.RawBuildLength(instruction); rawErr != nil || got != 1 {
		t.Fatalf("staging was not preserved after unresolved EmitRawBuildTo(): len=%d err=%v", got, rawErr)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 || emitted[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("unexpected EmitRawBuildTo() emission after resolve: %+v", emitted)
	}
}

func TestDisassemblyCacheResolveRawBuildIsIdempotentForUnchangedState(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0xb105}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	const labelBase = uint64(8)
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild(first) error: %v", err)
	}
	state := cache.rawBuild
	if state == nil || len(state.issued) != 1 || len(state.issued[0].Inputs) != 1 {
		t.Fatalf("unexpected staged shape after first resolve: state=%v", state)
	}
	if got := state.issued[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("first resolve relative patch mismatch: got %d want 1", got)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild(second) error: %v", err)
	}
	if got := state.issued[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("second resolve changed patched relative offset: got %d want 1", got)
	}
	if got, err := cache.RawBuildLength(instruction); err != nil || got != 1 {
		t.Fatalf("RawBuildLength() mismatch after repeated resolve: len=%d err=%v", got, err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 || len(emitted[0].Inputs) != 1 || emitted[0].Inputs[0].Offset != 1 {
		t.Fatalf("emitted ops mismatch after repeated resolve: %+v", emitted)
	}
}

func TestDisassemblyCacheResolveRawBuildFailsOnUndefinedLabel(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0xb10a}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	const labelBase = uint64(0x20)
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	err := cache.ResolveRawBuild(instruction)
	if err == nil {
		t.Fatal("ResolveRawBuild() unexpectedly succeeded without a matching label")
	}
	if got, lengthErr := cache.RawBuildLength(instruction); lengthErr != nil || got != 1 {
		t.Fatalf("RawBuildLength() mismatch after undefined-label failure: len=%d err=%v", got, lengthErr)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("GetRawOps() unexpectedly returned committed ops after undefined-label failure")
	}
}

func TestDisassemblyCacheAddRawBuildLabelRejectsOversizedLabelID(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xb10b}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 0); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	oversized := uint64(^uint(0)>>1) + 1
	if err := cache.AddRawBuildLabel(instruction, oversized); err == nil {
		t.Fatalf("AddRawBuildLabel() unexpectedly accepted oversized label id %d", oversized)
	}
}

func TestDisassemblyCacheEmitRawBuildToSinkFailureKeepsStagingOpen(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xb110}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	sinkErr := errors.New("sink rejected op")
	err := cache.EmitRawBuildTo(instruction, &failRawEmitter{failAt: 0, err: sinkErr})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("EmitRawBuildTo() error mismatch: got %v want %v", err, sinkErr)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("GetRawOps() unexpectedly contains committed ops after sink failure")
	}
	if got, rawErr := cache.RawBuildLength(instruction); rawErr != nil || got != 1 {
		t.Fatalf("staging was not preserved after sink failure: len=%d err=%v", got, rawErr)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 || emitted[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("unexpected retry emission result: %+v", emitted)
	}
}

func TestDisassemblyCacheEmitRawBuildToSinkFailureDoesNotMutateStaging(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xb115}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 2); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(copy#0) error: %v", err)
	}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x20, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(copy#1) error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	sinkErr := errors.New("sink mutate+fail")
	err := cache.EmitRawBuildTo(instruction, &mutateThenFailRawEmitter{
		failAt:        1,
		mutatedOffset: 0xdead,
		err:           sinkErr,
	})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("EmitRawBuildTo() error mismatch: got %v want %v", err, sinkErr)
	}
	if got, rawErr := cache.RawBuildLength(instruction); rawErr != nil || got != 2 {
		t.Fatalf("staging was not preserved after sink failure: len=%d err=%v", got, rawErr)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 2 {
		t.Fatalf("unexpected retry emission count: got %d want 2", len(emitted))
	}
	if emitted[0].Inputs[0].Offset != 0x10 || emitted[1].Inputs[0].Offset != 0x20 {
		t.Fatalf("staged raw ops were mutated by failed sink emission: %+v", emitted)
	}
}

func TestDisassemblyCacheEmitRawBuildToSinkMutationDoesNotAffectCommittedCache(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xb120}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	if err := cache.EmitRawBuildTo(instruction, &mutateRawEmitter{mutatedOffset: 0xdead}); err != nil {
		t.Fatalf("EmitRawBuildTo() error: %v", err)
	}
	stored, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing committed ops after sink mutation")
	}
	if len(stored) != 1 || stored[0].Inputs[0].Offset != 0x10 {
		t.Fatalf("sink mutation leaked into cache-owned ops: %+v", stored)
	}
}

func TestDisassemblyCacheRawBuildUsesSingleActiveReusableState(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	first := address.Address{Space: ram, Offset: 0xc100}
	second := address.Address{Space: ram, Offset: 0xc110}
	cache := NewDisassemblyCache()
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}

	if err := cache.BeginRawBuild(first, 2); err != nil {
		t.Fatalf("BeginRawBuild(first) error: %v", err)
	}
	firstState := cache.rawBuild
	if firstState == nil {
		t.Fatal("raw build state was not allocated")
	}
	if err := cache.AppendRawBuild(first, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x11, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(first) error: %v", err)
	}
	if got, err := cache.RawBuildLength(first); err != nil || got != 1 {
		t.Fatalf("RawBuildLength(first) mismatch before replacement: len=%d err=%v", got, err)
	}

	if err := cache.BeginRawBuild(second, 1); err != nil {
		t.Fatalf("BeginRawBuild(second) error: %v", err)
	}
	secondState := cache.rawBuild
	if secondState != firstState {
		t.Fatalf("raw build state pointer changed: got=%p want=%p", secondState, firstState)
	}
	if !cache.rawBuildActive || cache.rawBuildAddr != second {
		t.Fatalf("raw build active tracking mismatch: active=%v addr=%v", cache.rawBuildActive, cache.rawBuildAddr)
	}
	if _, err := cache.RawBuildLength(first); err == nil {
		t.Fatal("first address staging remained active after second BeginRawBuild()")
	}
	if err := cache.AppendRawBuild(first, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x12, Size: 4}},
	}}, 0); err == nil {
		t.Fatal("AppendRawBuild(first) unexpectedly succeeded after replacement")
	}
	if got, err := cache.RawBuildLength(second); err != nil || got != 0 {
		t.Fatalf("RawBuildLength(second) mismatch after replacement: len=%d err=%v", got, err)
	}

	if err := cache.AppendRawBuild(second, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x22, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(second) error: %v", err)
	}
	if err := cache.ResolveRawBuild(second); err != nil {
		t.Fatalf("ResolveRawBuild(second) error: %v", err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, second)
	if len(emitted) != 1 || emitted[0].Inputs[0].Offset != 0x22 {
		t.Fatalf("EmitRawBuildTo(second) mismatch: %+v", emitted)
	}
	if cache.rawBuild != firstState {
		t.Fatalf("raw reusable state pointer changed after emit: got=%p want=%p", cache.rawBuild, firstState)
	}
	if cache.rawBuildActive {
		t.Fatal("raw build remained active after emit")
	}
	if cache.rawBuild == nil {
		t.Fatal("raw build reusable state was unexpectedly released after emit")
	}
	if _, ok := cache.GetRawOps(first); ok {
		t.Fatal("GetRawOps(first) unexpectedly returned uncommitted ops")
	}
}

func TestDisassemblyCacheRawBuildRebindAfterExpandKeepsPoolOwnership(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xc150}
	cache := NewDisassemblyCache()
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}

	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	firstOut := pcode.VarnodeData{Space: ram, Offset: 0x44, Size: 4}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x11, Size: 4}},
		Output: &firstOut,
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(first) error: %v", err)
	}
	state := cache.rawBuild
	if state == nil {
		t.Fatal("raw build state missing")
	}
	if len(state.issued) != 1 || len(state.refs) != 1 {
		t.Fatalf("unexpected raw build shape before expand: issued=%d refs=%d", len(state.issued), len(state.refs))
	}
	if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_INT_ADD,
		Inputs: []pcode.VarnodeData{
			{Space: ram, Offset: 0x20, Size: 4},
			{Space: ram, Offset: 0x24, Size: 4},
			{Space: ram, Offset: 0x28, Size: 4},
			{Space: ram, Offset: 0x2c, Size: 4},
		},
		Output: &pcode.VarnodeData{Space: ram, Offset: 0x30, Size: 4},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(second) error: %v", err)
	}
	state = cache.rawBuild
	if state == nil {
		t.Fatal("raw build state missing after expand")
	}
	if len(state.issued) != 2 || len(state.refs) != 2 {
		t.Fatalf("unexpected raw build shape after expand: issued=%d refs=%d", len(state.issued), len(state.refs))
	}
	if &state.issued[0].Inputs[0] != &state.varnodes[0] {
		t.Fatalf("first op input pointer not rebound to pool index 0: got=%p want=%p", &state.issued[0].Inputs[0], &state.varnodes[0])
	}
	if state.issued[0].Output != &state.varnodes[1] {
		t.Fatalf("first op output pointer not rebound to pool index 1: got=%p want=%p", state.issued[0].Output, &state.varnodes[1])
	}
	if state.issued[0].Inputs[0].Offset != 0x11 || state.issued[0].Output.Offset != 0x44 {
		t.Fatalf("first op payload changed after expand: input=%#v output=%#v", state.issued[0].Inputs[0], *state.issued[0].Output)
	}
}

func TestDisassemblyCacheRawBuildKeepsCommittedOpsByAddress(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	first := address.Address{Space: ram, Offset: 0xc200}
	second := address.Address{Space: ram, Offset: 0xc210}
	cache := NewDisassemblyCache()
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}

	if err := cache.BeginRawBuild(first, 1); err != nil {
		t.Fatalf("BeginRawBuild(first) error: %v", err)
	}
	if err := cache.AppendRawBuild(first, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x31, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(first) error: %v", err)
	}
	if err := cache.ResolveRawBuild(first); err != nil {
		t.Fatalf("ResolveRawBuild(first) error: %v", err)
	}
	_ = mustEmitRawBuildToCapture(t, cache, first)

	if err := cache.BeginRawBuild(second, 1); err != nil {
		t.Fatalf("BeginRawBuild(second) error: %v", err)
	}
	if err := cache.AppendRawBuild(second, source, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x41, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(second) error: %v", err)
	}
	if err := cache.ResolveRawBuild(second); err != nil {
		t.Fatalf("ResolveRawBuild(second) error: %v", err)
	}
	_ = mustEmitRawBuildToCapture(t, cache, second)

	firstOps, firstOK := cache.GetRawOps(first)
	secondOps, secondOK := cache.GetRawOps(second)
	if !firstOK || !secondOK {
		t.Fatalf("GetRawOps() missing committed ops: first=%v second=%v", firstOK, secondOK)
	}
	if len(firstOps) != 1 || firstOps[0].Inputs[0].Offset != 0x31 {
		t.Fatalf("first committed ops mismatch: %+v", firstOps)
	}
	if len(secondOps) != 1 || secondOps[0].Inputs[0].Offset != 0x41 {
		t.Fatalf("second committed ops mismatch: %+v", secondOps)
	}
}

func TestRawBuildStateInitialPoolCapacityMatchesCpp(t *testing.T) {
	// PcodeCacher::PcodeCacher() allocates 600 VarnodeData initially.
	// rawBuildState.reset() should guarantee at least defaultVarnodePoolSize.
	state := newRawBuildState(0)
	if cap(state.varnodes) < defaultVarnodePoolSize {
		t.Fatalf("initial varnode pool capacity = %d, want >= %d (C++ PcodeCacher default)",
			cap(state.varnodes), defaultVarnodePoolSize)
	}
}

func TestRawBuildStateResetKeepsGrownPoolCapacity(t *testing.T) {
	// Mirrors C++ PcodeCacher::clear() which resets curpool to poolstart
	// but never shrinks the pool allocation.
	state := newRawBuildState(0)
	initialCap := cap(state.varnodes)

	// Force pool growth beyond initial capacity.
	bigCount := initialCap + 200
	_, err := state.allocateVarnodes(bigCount)
	if err != nil {
		t.Fatalf("allocateVarnodes(%d) error: %v", bigCount, err)
	}
	grownCap := cap(state.varnodes)
	if grownCap <= initialCap {
		t.Fatalf("pool did not grow: cap=%d initial=%d", grownCap, initialCap)
	}

	// reset() should retain the grown capacity.
	state.reset(0)
	if cap(state.varnodes) < grownCap {
		t.Fatalf("reset() shrank pool: cap=%d grownCap=%d", cap(state.varnodes), grownCap)
	}
	if len(state.varnodes) != 0 {
		t.Fatalf("reset() did not clear pool length: len=%d", len(state.varnodes))
	}
}

func TestRawBuildStateAllocateInstructionReturnsSequentialIndices(t *testing.T) {
	// allocateInstruction mirrors PcodeCacher::allocateInstruction() which
	// returns a pointer to the back of the issued deque after emplace_back.
	state := newRawBuildState(4)
	for i := 0; i < 4; i++ {
		idx := state.allocateInstruction()
		if idx != i {
			t.Fatalf("allocateInstruction() = %d, want %d", idx, i)
		}
	}
	if len(state.issued) != 4 {
		t.Fatalf("issued length = %d, want 4", len(state.issued))
	}
	if len(state.refs) != 4 {
		t.Fatalf("refs length = %d, want 4", len(state.refs))
	}
}

func TestRawBuildStatePoolGrowthRebindsMultipleOps(t *testing.T) {
	// Exercises the expandPool rebind path with multiple issued ops
	// that each have inputs + outputs in the pool.
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	state := newRawBuildState(0)

	// Fill pool close to capacity with several ops.
	numOps := 50
	for i := 0; i < numOps; i++ {
		out := pcode.VarnodeData{Space: ram, Offset: uint64(0x1000 + i), Size: 4}
		err := state.appendIssued(pcode.RawOp{
			OpCode: pcode.CPUI_COPY,
			Inputs: []pcode.VarnodeData{
				{Space: ram, Offset: uint64(0x2000 + i), Size: 4},
				{Space: ram, Offset: uint64(0x3000 + i), Size: 4},
			},
			Output: &out,
		})
		if err != nil {
			t.Fatalf("appendIssued(%d) error: %v", i, err)
		}
	}

	// Force a large growth that triggers rebind.
	bigAlloc := cap(state.varnodes) + 500
	_, err := state.allocateVarnodes(bigAlloc)
	if err != nil {
		t.Fatalf("allocateVarnodes(%d) error: %v", bigAlloc, err)
	}

	// Verify all issued ops still reference correct pool data.
	for i := 0; i < numOps; i++ {
		op := state.issued[i]
		if len(op.Inputs) != 2 {
			t.Fatalf("op[%d] input count = %d, want 2", i, len(op.Inputs))
		}
		if op.Inputs[0].Offset != uint64(0x2000+i) {
			t.Fatalf("op[%d] input[0].Offset = %#x, want %#x", i, op.Inputs[0].Offset, 0x2000+i)
		}
		if op.Inputs[1].Offset != uint64(0x3000+i) {
			t.Fatalf("op[%d] input[1].Offset = %#x, want %#x", i, op.Inputs[1].Offset, 0x3000+i)
		}
		if op.Output == nil {
			t.Fatalf("op[%d] output is nil", i)
		}
		if op.Output.Offset != uint64(0x1000+i) {
			t.Fatalf("op[%d] output.Offset = %#x, want %#x", i, op.Output.Offset, 0x1000+i)
		}
		// Verify pool ownership: output pointer should reference varnodes slice.
		ref := state.refs[i]
		if op.Output != &state.varnodes[ref.outputSlot] {
			t.Fatalf("op[%d] output not rebound to pool after grow", i)
		}
		if &op.Inputs[0] != &state.varnodes[ref.inputStart] {
			t.Fatalf("op[%d] inputs not rebound to pool after grow", i)
		}
	}
}

func TestRawBuildResolveRelativesMultipleLabels(t *testing.T) {
	// Test resolveRelatives with multiple branch targets pointing at
	// different labels, verifying the (target - callingIndex) & mask formula.
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xd000}
	cache := NewDisassemblyCache()

	if err := cache.BeginRawBuild(instruction, 8); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}

	// op 0: NOP (filler)
	nopSource := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	if err := cache.AppendRawBuild(instruction, nopSource, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(nop) error: %v", err)
	}

	// op 1: BRANCH -> label 0 (at op 3)
	branchSource0 := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs:   []VarnodeTplBoundary{{Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0}}},
	}
	if err := cache.AppendRawBuild(instruction, branchSource0, []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 8}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(branch0) error: %v", err)
	}

	// op 2: NOP (filler)
	if err := cache.AppendRawBuild(instruction, nopSource, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x20, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(nop2) error: %v", err)
	}

	// label 0 at op 3
	if err := cache.AddRawBuildLabel(instruction, 0); err != nil {
		t.Fatalf("AddRawBuildLabel(0) error: %v", err)
	}

	// op 3: BRANCH -> label 1 (at op 5)
	branchSource1 := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs:   []VarnodeTplBoundary{{Offset: ConstBoundary{Kind: ConstKindRelative, Value: 1}}},
	}
	if err := cache.AppendRawBuild(instruction, branchSource1, []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 8}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(branch1) error: %v", err)
	}

	// op 4: NOP (filler)
	if err := cache.AppendRawBuild(instruction, nopSource, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x30, Size: 4}},
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(nop3) error: %v", err)
	}

	// label 1 at op 5
	if err := cache.AddRawBuildLabel(instruction, 1); err != nil {
		t.Fatalf("AddRawBuildLabel(1) error: %v", err)
	}

	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}

	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 5 {
		t.Fatalf("expected 5 emitted ops, got %d", len(emitted))
	}

	// branch0 at op 1, label 0 at op 3: relative = 3 - 1 = 2
	if emitted[1].Inputs[0].Offset != 2 {
		t.Fatalf("branch0 relative offset = %d, want 2", emitted[1].Inputs[0].Offset)
	}
	// branch1 at op 3, label 1 at op 5: relative = 5 - 3 = 2
	if emitted[3].Inputs[0].Offset != 2 {
		t.Fatalf("branch1 relative offset = %d, want 2", emitted[3].Inputs[0].Offset)
	}
}

func TestRawBuildEmitOrderMatchesCppPcodeCacher(t *testing.T) {
	// Verify emit() iterates issued in order, matching PcodeCacher::emit()
	// which does: for(iter=issued.begin();iter!=issued.end();++iter)
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xe000}
	cache := NewDisassemblyCache()

	if err := cache.BeginRawBuild(instruction, 4); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}
	opcodes := []pcode.OpCode{pcode.CPUI_COPY, pcode.CPUI_INT_ADD, pcode.CPUI_INT_SUB, pcode.CPUI_STORE}
	for _, opc := range opcodes {
		if err := cache.AppendRawBuild(instruction, source, []pcode.RawOp{{
			OpCode: opc,
			Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
		}}, 0); err != nil {
			t.Fatalf("AppendRawBuild(%v) error: %v", opc, err)
		}
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != len(opcodes) {
		t.Fatalf("emitted count = %d, want %d", len(emitted), len(opcodes))
	}
	for i, opc := range opcodes {
		if emitted[i].OpCode != opc {
			t.Fatalf("emitted[%d].OpCode = %v, want %v", i, emitted[i].OpCode, opc)
		}
	}
}
