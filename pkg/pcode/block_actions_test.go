package pcode

import (
	"gosleigh/pkg/address"
	"testing"
)

func newStructuringFuncdata() *Funcdata {
	sp := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 0, WordSize: 1, AddrSize: 4}
	cs := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, WordSize: 1, AddrSize: 4}
	us := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, WordSize: 1, AddrSize: 4}
	return NewFuncdata("struct", address.Address{Space: sp, Offset: 0}, us, 0, cs)
}

func TestActionBlockStructureBuildsStructuredGraph(t *testing.T) {
	fd := newStructuringFuncdata()
	basic := NewBlockGraph()
	cond := newCFGBlock(basic)
	elseClause := newCFGBlock(basic)
	trueClause := newCFGBlock(basic)
	exit := newCFGBlock(basic)

	basic.AddEdge(cond, elseClause, 0)
	basic.AddEdge(cond, trueClause, 0)
	basic.AddEdge(trueClause, exit, 0)
	basic.AddEdge(elseClause, exit, 0)
	fd.SetBasicBlocks(basic)

	action := NewActionBlockStructure("analysis")
	if res := action.Apply(fd); res != 0 {
		t.Fatalf("expected ActionBlockStructure Apply to return 0, got %d", res)
	}
	structure := fd.GetStructure()
	if structure.GetSize() != 1 {
		t.Fatalf("expected structured graph with one root, got %d: %s", structure.GetSize(), describeGraph(structure))
	}
	root := structure.GetBlock(0)
	if findRecursiveType(root, BlockIfType) == nil {
		t.Fatal("expected ActionBlockStructure to produce nested if block")
	}
}

func TestActionFinalStructureOrdersButPreservesRoot(t *testing.T) {
	fd := newStructuringFuncdata()
	graph := NewBlockGraph()
	late := newCFGBlock(graph)
	early := newCFGBlock(graph)
	late.SetIndex(5)
	early.SetIndex(1)
	graph.AddEdge(early, late, 0)
	fd.SetStructureGraph(graph)

	action := NewActionFinalStructure("analysis")
	if res := action.Apply(fd); res != 0 {
		t.Fatalf("expected ActionFinalStructure Apply to return 0, got %d", res)
	}
	if fd.GetStructure().GetBlock(0) != early {
		t.Fatal("expected ActionFinalStructure to order blocks by index")
	}
}
