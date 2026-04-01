package pcode

import (
	"testing"
)

// --- Edge bidirectional symmetry ---

func TestAddInEdge_BidirectionalSymmetry(t *testing.T) {
	a := &FlowBlock{}
	b := &FlowBlock{}

	b.AddInEdge(a, 0) // edge: a -> b

	if b.SizeIn() != 1 {
		t.Fatalf("expected b.SizeIn()=1, got %d", b.SizeIn())
	}
	if a.SizeOut() != 1 {
		t.Fatalf("expected a.SizeOut()=1, got %d", a.SizeOut())
	}

	inE := b.InEdge(0)
	outE := a.OutEdge(0)

	if inE.Point != a {
		t.Fatal("inEdge should point to a")
	}
	if outE.Point != b {
		t.Fatal("outEdge should point to b")
	}
	if inE.ReverseIndex != 0 {
		t.Fatalf("inEdge.ReverseIndex=%d, want 0", inE.ReverseIndex)
	}
	if outE.ReverseIndex != 0 {
		t.Fatalf("outEdge.ReverseIndex=%d, want 0", outE.ReverseIndex)
	}
}

func TestMultipleEdges_ReverseIndex(t *testing.T) {
	// Build: src -> {d0, d1, d2}
	src := &FlowBlock{}
	dsts := [3]*FlowBlock{{}, {}, {}}

	for _, d := range dsts {
		d.AddInEdge(src, 0)
	}

	if src.SizeOut() != 3 {
		t.Fatalf("expected src.SizeOut()=3, got %d", src.SizeOut())
	}

	// Verify all ReverseIndex values.
	for i := 0; i < 3; i++ {
		outE := src.OutEdge(i)
		tgt := outE.Point
		inE := tgt.InEdge(outE.ReverseIndex)
		if inE.Point != src {
			t.Fatalf("edge %d: mirror inEdge.Point != src", i)
		}
		if inE.ReverseIndex != i {
			t.Fatalf("edge %d: mirror inEdge.ReverseIndex=%d, want %d", i, inE.ReverseIndex, i)
		}
	}
}

func TestRemoveInEdge(t *testing.T) {
	// Build: src -> {a, b, c}
	src := &FlowBlock{}
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	a.AddInEdge(src, 0)
	b.AddInEdge(src, 0)
	c.AddInEdge(src, 0)

	// Remove b's incoming edge (slot 0 on b).
	b.RemoveInEdge(0)

	if b.SizeIn() != 0 {
		t.Fatalf("b.SizeIn()=%d, want 0", b.SizeIn())
	}
	if src.SizeOut() != 2 {
		t.Fatalf("src.SizeOut()=%d, want 2", src.SizeOut())
	}

	// Verify remaining edges are consistent.
	verifyEdgeConsistency(t, src)
	verifyEdgeConsistency(t, a)
	verifyEdgeConsistency(t, c)
}

func TestRemoveOutEdge(t *testing.T) {
	src := &FlowBlock{}
	a := &FlowBlock{}
	b := &FlowBlock{}
	a.AddInEdge(src, 0)
	b.AddInEdge(src, 0)

	// Remove src's first out-edge.
	src.RemoveOutEdge(0)

	if src.SizeOut() != 1 {
		t.Fatalf("src.SizeOut()=%d, want 1", src.SizeOut())
	}

	verifyEdgeConsistency(t, src)
}

func TestSwapEdges(t *testing.T) {
	src := &FlowBlock{}
	a := &FlowBlock{}
	b := &FlowBlock{}
	a.AddInEdge(src, 0)
	b.AddInEdge(src, 0)

	// Before swap: out[0]->a, out[1]->b
	if src.OutEdge(0).Point != a || src.OutEdge(1).Point != b {
		t.Fatal("pre-swap order incorrect")
	}

	src.SwapEdges()

	// After swap: out[0]->b, out[1]->a
	if src.OutEdge(0).Point != b {
		t.Fatal("after swap, out[0] should be b")
	}
	if src.OutEdge(1).Point != a {
		t.Fatal("after swap, out[1] should be a")
	}
	if !src.HasFlag(BlockFlagFlipPath) {
		t.Fatal("FlipPath flag should be set after one swap")
	}

	verifyEdgeConsistency(t, src)

	// Swap again -- flag should be cleared.
	src.SwapEdges()
	if src.HasFlag(BlockFlagFlipPath) {
		t.Fatal("FlipPath flag should be cleared after two swaps")
	}
}

func TestSetOutEdgeFlag_ClearOutEdgeFlag(t *testing.T) {
	src := &FlowBlock{}
	dst := &FlowBlock{}
	dst.AddInEdge(src, 0)

	src.SetOutEdgeFlag(0, EdgeFlagLoop)

	if src.OutEdge(0).Label&EdgeFlagLoop == 0 {
		t.Fatal("outEdge should have EdgeFlagLoop")
	}
	if dst.InEdge(0).Label&EdgeFlagLoop == 0 {
		t.Fatal("mirror inEdge should have EdgeFlagLoop")
	}

	src.ClearOutEdgeFlag(0, EdgeFlagLoop)

	if src.OutEdge(0).Label&EdgeFlagLoop != 0 {
		t.Fatal("outEdge should not have EdgeFlagLoop after clear")
	}
	if dst.InEdge(0).Label&EdgeFlagLoop != 0 {
		t.Fatal("mirror inEdge should not have EdgeFlagLoop after clear")
	}
}

// --- BlockBasic ---

func TestBlockBasic_OpOrdering(t *testing.T) {
	bb := NewBlockBasic()
	op1 := &PcodeOp{}
	op2 := &PcodeOp{}
	op3 := &PcodeOp{}
	op4 := &PcodeOp{}

	bb.AddOp(op1)
	bb.AddOp(op2)

	if bb.NumOps() != 2 {
		t.Fatalf("NumOps()=%d, want 2", bb.NumOps())
	}
	if bb.FirstOp() != op1 {
		t.Fatal("FirstOp should be op1")
	}
	if bb.LastOp() != op2 {
		t.Fatal("LastOp should be op2")
	}

	// InsertOpBefore op2.
	bb.InsertOpBefore(op3, op2)
	ops := bb.Ops()
	if len(ops) != 3 || ops[0] != op1 || ops[1] != op3 || ops[2] != op2 {
		t.Fatal("InsertOpBefore ordering wrong")
	}

	// InsertOpAfter op1.
	bb.InsertOpAfter(op4, op1)
	ops = bb.Ops()
	if len(ops) != 4 || ops[0] != op1 || ops[1] != op4 || ops[2] != op3 || ops[3] != op2 {
		t.Fatal("InsertOpAfter ordering wrong")
	}

	// InsertOpBegin.
	op5 := &PcodeOp{}
	bb.InsertOpBegin(op5)
	if bb.FirstOp() != op5 {
		t.Fatal("InsertOpBegin: first op should be op5")
	}

	// RemoveOp.
	bb.RemoveOp(op4)
	for _, o := range bb.Ops() {
		if o == op4 {
			t.Fatal("op4 should have been removed")
		}
	}
}

func TestBlockBasic_EmptyOp(t *testing.T) {
	bb := NewBlockBasic()
	if !bb.EmptyOp() {
		t.Fatal("new BlockBasic should be empty")
	}
	if bb.FirstOp() != nil {
		t.Fatal("FirstOp on empty block should be nil")
	}
	if bb.LastOp() != nil {
		t.Fatal("LastOp on empty block should be nil")
	}
}

func TestBlockBasic_NegateCondition(t *testing.T) {
	bb := NewBlockBasic()
	op := &PcodeOp{}
	bb.AddOp(op)

	bb.NegateCondition(false)

	if !op.HasFlag(PcodeOpBooleanFlip) {
		t.Fatal("PcodeOpBooleanFlip should be set")
	}
	if !op.HasFlag(PcodeOpFallthruTrue) {
		t.Fatal("PcodeOpFallthruTrue should be set")
	}

	// Negate again -- should clear.
	bb.NegateCondition(false)
	if op.HasFlag(PcodeOpBooleanFlip) {
		t.Fatal("PcodeOpBooleanFlip should be cleared after double negate")
	}
	if op.HasFlag(PcodeOpFallthruTrue) {
		t.Fatal("PcodeOpFallthruTrue should be cleared after double negate")
	}
}

func TestBlockBasic_NegateConditionTop(t *testing.T) {
	bb := NewBlockBasic()
	first := &PcodeOp{}
	last := &PcodeOp{}
	bb.AddOp(first)
	bb.AddOp(last)

	bb.NegateCondition(true)

	if !first.HasFlag(PcodeOpBooleanFlip) {
		t.Fatal("top=true should flip first op")
	}
	if last.HasFlag(PcodeOpBooleanFlip) {
		t.Fatal("top=true should NOT flip last op")
	}
}

// --- BlockGraph ---

func TestBlockGraph_AddRemoveBlock(t *testing.T) {
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	bg.AddBlock(a)
	bg.AddBlock(b)

	if bg.GetSize() != 2 {
		t.Fatalf("GetSize()=%d, want 2", bg.GetSize())
	}
	if a.Parent() != &bg.FlowBlock {
		t.Fatal("parent should be set")
	}

	bg.RemoveBlock(a)
	if bg.GetSize() != 1 {
		t.Fatalf("after remove, GetSize()=%d, want 1", bg.GetSize())
	}
}

func TestBlockGraph_AddRemoveEdge(t *testing.T) {
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	bg.AddBlock(a)
	bg.AddBlock(b)

	bg.AddEdge(a, b, 0)

	if a.SizeOut() != 1 || b.SizeIn() != 1 {
		t.Fatal("edge not added properly")
	}

	bg.RemoveEdge(a, b)

	if a.SizeOut() != 0 || b.SizeIn() != 0 {
		t.Fatal("edge not removed properly")
	}
}

func TestBlockGraph_DiamondCFG_SpanningTree(t *testing.T) {
	// Diamond: A -> B, A -> C, B -> D, C -> D
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	d := &FlowBlock{}
	bg.AddBlock(a)
	bg.AddBlock(b)
	bg.AddBlock(c)
	bg.AddBlock(d)

	bg.AddEdge(a, b, 0)
	bg.AddEdge(a, c, 0)
	bg.AddEdge(b, d, 0)
	bg.AddEdge(c, d, 0)

	bg.FindSpanningTree()

	// All blocks should have non-negative RPO indices.
	for _, bl := range []*FlowBlock{a, b, c, d} {
		if bl.Index() < 0 {
			t.Fatal("RPO index should be >= 0 after spanning tree")
		}
	}

	// A should be first in RPO (index 0).
	if a.Index() != 0 {
		t.Fatalf("A.Index()=%d, want 0", a.Index())
	}

	// D should be last in RPO (index 3).
	if d.Index() != 3 {
		t.Fatalf("D.Index()=%d, want 3", d.Index())
	}

	// B and C should be between A and D.
	if b.Index() < a.Index() || b.Index() > d.Index() {
		t.Fatalf("B.Index()=%d out of range", b.Index())
	}
	if c.Index() < a.Index() || c.Index() > d.Index() {
		t.Fatalf("C.Index()=%d out of range", c.Index())
	}
}

func TestBlockGraph_DiamondCFG_Dominators(t *testing.T) {
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	d := &FlowBlock{}
	bg.AddBlock(a)
	bg.AddBlock(b)
	bg.AddBlock(c)
	bg.AddBlock(d)

	bg.AddEdge(a, b, 0)
	bg.AddEdge(a, c, 0)
	bg.AddEdge(b, d, 0)
	bg.AddEdge(c, d, 0)

	bg.StructureLoops()

	// A dominates all.
	if !a.Dominates(a) {
		t.Fatal("A should dominate itself")
	}
	if !a.Dominates(b) {
		t.Fatal("A should dominate B")
	}
	if !a.Dominates(c) {
		t.Fatal("A should dominate C")
	}
	if !a.Dominates(d) {
		t.Fatal("A should dominate D")
	}

	// B does not dominate D (because C also reaches D).
	if b.Dominates(d) {
		t.Fatal("B should NOT dominate D")
	}
	if c.Dominates(d) {
		t.Fatal("C should NOT dominate D")
	}

	// D's immediate dominator should be A.
	if d.ImmedDom() != a {
		t.Fatalf("D.ImmedDom()=%p, want A=%p", d.ImmedDom(), a)
	}
}

func TestDominates(t *testing.T) {
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	d := &FlowBlock{}
	bg.AddBlock(a)
	bg.AddBlock(b)
	bg.AddBlock(c)
	bg.AddBlock(d)

	bg.AddEdge(a, b, 0)
	bg.AddEdge(a, c, 0)
	bg.AddEdge(b, d, 0)
	bg.AddEdge(c, d, 0)

	bg.StructureLoops()

	if !a.Dominates(d) {
		t.Fatal("A should dominate D")
	}
	if b.Dominates(d) {
		t.Fatal("B should NOT dominate D")
	}
}

func TestFindCommonBlock(t *testing.T) {
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	d := &FlowBlock{}
	bg.AddBlock(a)
	bg.AddBlock(b)
	bg.AddBlock(c)
	bg.AddBlock(d)

	bg.AddEdge(a, b, 0)
	bg.AddEdge(a, c, 0)
	bg.AddEdge(b, d, 0)
	bg.AddEdge(c, d, 0)

	bg.StructureLoops()

	common := FindCommonBlock(b, c)
	if common != a {
		t.Fatalf("FindCommonBlock(B,C) should be A, got %p (A=%p)", common, a)
	}

	// nil cases
	if FindCommonBlock(nil, b) != b {
		t.Fatal("FindCommonBlock(nil, B) should be B")
	}
	if FindCommonBlock(b, nil) != b {
		t.Fatal("FindCommonBlock(B, nil) should be B")
	}
}

func TestSpliceBlock(t *testing.T) {
	bg := NewBlockGraph()

	a := bg.NewBlockBasicInGraph()
	b := bg.NewBlockBasicInGraph()
	c := bg.NewBlockBasicInGraph()

	op1 := &PcodeOp{}
	op2 := &PcodeOp{}
	op3 := &PcodeOp{}

	a.AddOp(op1)
	b.AddOp(op2)
	c.AddOp(op3)

	// Linear chain: a -> b -> c
	bg.AddEdge(&a.FlowBlock, &b.FlowBlock, 0)
	bg.AddEdge(&b.FlowBlock, &c.FlowBlock, 0)

	// Splice b (merge b into a, reroute a -> c).
	bg.SpliceBlock(&b.FlowBlock)

	if bg.GetSize() != 2 {
		t.Fatalf("after splice, GetSize()=%d, want 2", bg.GetSize())
	}
	if a.FlowBlock.SizeOut() != 1 {
		t.Fatalf("a should have 1 out-edge, got %d", a.FlowBlock.SizeOut())
	}
	if a.FlowBlock.OutEdge(0).Point != &c.FlowBlock {
		t.Fatal("a's out-edge should point to c")
	}
}

// --- Flag constants distinctness ---

func TestBlockFlagsDistinct(t *testing.T) {
	flags := []uint32{
		BlockFlagGotoGoto, BlockFlagBreakGoto, BlockFlagContinueGoto,
		BlockFlagSwitchOut, BlockFlagUnstructuredTarg, BlockFlagMark,
		BlockFlagMark2, BlockFlagEntryPoint, BlockFlagInteriorGotoOut,
		BlockFlagInteriorGotoIn, BlockFlagLabelBumpUp, BlockFlagDoNothingLoop,
		BlockFlagDead, BlockFlagWhileDoOverflow, BlockFlagFlipPath,
		BlockFlagJoinedBlock, BlockFlagDuplicateBlock,
	}
	for i := 0; i < len(flags); i++ {
		for j := i + 1; j < len(flags); j++ {
			if flags[i] == flags[j] {
				t.Fatalf("block flags %d and %d are both 0x%x", i, j, flags[i])
			}
		}
	}
}

func TestEdgeFlagsDistinct(t *testing.T) {
	flags := []uint32{
		EdgeFlagGoto, EdgeFlagLoop, EdgeFlagDefaultSwitch,
		EdgeFlagIrreducible, EdgeFlagTree, EdgeFlagForward,
		EdgeFlagCross, EdgeFlagBack, EdgeFlagLoopExit,
	}
	for i := 0; i < len(flags); i++ {
		for j := i + 1; j < len(flags); j++ {
			if flags[i] == flags[j] {
				t.Fatalf("edge flags %d and %d are both 0x%x", i, j, flags[i])
			}
		}
	}
}

// --- Loop edge helpers ---

func TestHasLoopIn_HasLoopOut(t *testing.T) {
	src := &FlowBlock{}
	dst := &FlowBlock{}
	dst.AddInEdge(src, 0)

	if src.HasLoopOut() {
		t.Fatal("should not have loop out initially")
	}
	if dst.HasLoopIn() {
		t.Fatal("should not have loop in initially")
	}

	src.SetOutEdgeFlag(0, EdgeFlagLoop)

	if !src.HasLoopOut() {
		t.Fatal("should have loop out after set")
	}
	if !dst.HasLoopIn() {
		t.Fatal("should have loop in after set")
	}
	if !src.IsLoopOut(0) {
		t.Fatal("IsLoopOut(0) should be true")
	}
	if !dst.IsLoopIn(0) {
		t.Fatal("IsLoopIn(0) should be true")
	}
}

func TestIsGotoIn_IsGotoOut(t *testing.T) {
	src := &FlowBlock{}
	dst := &FlowBlock{}
	dst.AddInEdge(src, 0)
	src.SetOutEdgeFlag(0, EdgeFlagGoto)

	if !src.IsGotoOut(0) {
		t.Fatal("IsGotoOut(0) should be true")
	}
	if !dst.IsGotoIn(0) {
		t.Fatal("IsGotoIn(0) should be true")
	}
}

// --- GetInIndex / GetOutIndex ---

func TestGetInIndex_GetOutIndex(t *testing.T) {
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	b.AddInEdge(a, 0)
	c.AddInEdge(a, 0)

	if b.GetInIndex(a) != 0 {
		t.Fatal("GetInIndex should find a")
	}
	if b.GetInIndex(c) != -1 {
		t.Fatal("GetInIndex should return -1 for non-existent")
	}
	if a.GetOutIndex(b) != 0 {
		t.Fatal("GetOutIndex should find b")
	}
}

// --- ReplaceInEdge / ReplaceOutEdge ---

func TestReplaceInEdge(t *testing.T) {
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	b.AddInEdge(a, 0) // a -> b

	b.ReplaceInEdge(0, c) // now c -> b

	if a.SizeOut() != 0 {
		t.Fatal("a should have no out-edges after replace")
	}
	if c.SizeOut() != 1 {
		t.Fatal("c should have 1 out-edge after replace")
	}
	if b.InEdge(0).Point != c {
		t.Fatal("b's inEdge should point to c")
	}
	verifyEdgeConsistency(t, b)
	verifyEdgeConsistency(t, c)
}

func TestReplaceOutEdge(t *testing.T) {
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	b.AddInEdge(a, 0) // a -> b

	a.ReplaceOutEdge(0, c) // now a -> c

	if b.SizeIn() != 0 {
		t.Fatal("b should have no in-edges after replace")
	}
	if c.SizeIn() != 1 {
		t.Fatal("c should have 1 in-edge after replace")
	}
	if a.OutEdge(0).Point != c {
		t.Fatal("a's outEdge should point to c")
	}
	verifyEdgeConsistency(t, a)
	verifyEdgeConsistency(t, c)
}

// --- ClearVisitCount ---

func TestClearVisitCount(t *testing.T) {
	bg := NewBlockGraph()
	a := &FlowBlock{visitCount: 5}
	b := &FlowBlock{visitCount: 3}
	bg.AddBlock(a)
	bg.AddBlock(b)

	bg.ClearVisitCount()

	if a.VisitCount() != 0 || b.VisitCount() != 0 {
		t.Fatal("visit counts should be 0")
	}
}

// --- OrderBlocks ---

func TestOrderBlocks(t *testing.T) {
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	c := &FlowBlock{}
	a.SetIndex(2)
	b.SetIndex(0)
	c.SetIndex(1)
	bg.AddBlock(a)
	bg.AddBlock(b)
	bg.AddBlock(c)

	bg.OrderBlocks()

	if bg.GetBlock(0) != b || bg.GetBlock(1) != c || bg.GetBlock(2) != a {
		t.Fatal("blocks should be sorted by index")
	}
}

// --- Back edge detection ---

func TestFindSpanningTree_BackEdge(t *testing.T) {
	// Simple loop: A -> B -> A (back edge B -> A)
	bg := NewBlockGraph()
	a := &FlowBlock{}
	b := &FlowBlock{}
	bg.AddBlock(a)
	bg.AddBlock(b)

	bg.AddEdge(a, b, 0)
	bg.AddEdge(b, a, 0) // back edge

	bg.FindSpanningTree()

	// The edge B -> A should be a back edge.
	found := false
	for i := 0; i < b.SizeOut(); i++ {
		if b.OutEdge(i).Point == a && b.OutEdge(i).Label&EdgeFlagBack != 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("B -> A should be labeled as a back edge")
	}
}

// --- helper ---

func verifyEdgeConsistency(t *testing.T, bl *FlowBlock) {
	t.Helper()
	for i := 0; i < bl.SizeOut(); i++ {
		outE := bl.OutEdge(i)
		tgt := outE.Point
		revIdx := outE.ReverseIndex
		if revIdx < 0 || revIdx >= tgt.SizeIn() {
			t.Fatalf("block outEdge[%d].ReverseIndex=%d out of range (target has %d inEdges)", i, revIdx, tgt.SizeIn())
		}
		inE := tgt.InEdge(revIdx)
		if inE.Point != bl {
			t.Fatalf("outEdge[%d] mirror mismatch: inEdge[%d].Point != this block", i, revIdx)
		}
		if inE.ReverseIndex != i {
			t.Fatalf("outEdge[%d] mirror mismatch: inEdge[%d].ReverseIndex=%d, want %d", i, revIdx, inE.ReverseIndex, i)
		}
	}
	for i := 0; i < bl.SizeIn(); i++ {
		inE := bl.InEdge(i)
		src := inE.Point
		revIdx := inE.ReverseIndex
		if revIdx < 0 || revIdx >= src.SizeOut() {
			t.Fatalf("block inEdge[%d].ReverseIndex=%d out of range (source has %d outEdges)", i, revIdx, src.SizeOut())
		}
		outE := src.OutEdge(revIdx)
		if outE.Point != bl {
			t.Fatalf("inEdge[%d] mirror mismatch: outEdge[%d].Point != this block", i, revIdx)
		}
		if outE.ReverseIndex != i {
			t.Fatalf("inEdge[%d] mirror mismatch: outEdge[%d].ReverseIndex=%d, want %d", i, revIdx, outE.ReverseIndex, i)
		}
	}
}
