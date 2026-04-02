package pcode

import (
	"fmt"
	"testing"
)

func newCFGBlock(bg *BlockGraph) *FlowBlock {
	return &bg.NewBlockBasicInGraph().FlowBlock
}

func collapseGraph(bg *BlockGraph) *CollapseStructure {
	bg.StructureLoops()
	collapse := NewCollapseStructure(bg)
	collapse.CollapseAll()
	return collapse
}

func collectRecursiveBlocks(root *FlowBlock, seen map[*FlowBlock]struct{}, out *[]*FlowBlock) {
	if root == nil {
		return
	}
	if _, ok := seen[root]; ok {
		return
	}
	seen[root] = struct{}{}
	*out = append(*out, root)
	for _, child := range root.StructuredChildren() {
		collectRecursiveBlocks(child, seen, out)
	}
}

func allRecursiveBlocks(root *FlowBlock) []*FlowBlock {
	res := make([]*FlowBlock, 0)
	collectRecursiveBlocks(root, make(map[*FlowBlock]struct{}), &res)
	return res
}

func describeGraph(bg *BlockGraph) string {
	res := ""
	for i := 0; i < bg.GetSize(); i++ {
		bl := bg.GetBlock(i)
		res += fmt.Sprintf("[%d]%v in=%d out=%d children=%d ", i, bl.Type(), bl.SizeIn(), bl.SizeOut(), len(bl.StructuredChildren()))
	}
	return res
}

func findRecursiveType(root *FlowBlock, tp BlockType) *FlowBlock {
	for _, block := range allRecursiveBlocks(root) {
		if block.Type() == tp {
			return block
		}
	}
	return nil
}

func hasGotoRecursive(root *FlowBlock) bool {
	for _, block := range allRecursiveBlocks(root) {
		if block.Type() == BlockGotoType || block.Type() == BlockMultiGotoType {
			return true
		}
		for i := 0; i < block.SizeOut(); i++ {
			if block.IsGotoOut(i) {
				return true
			}
		}
	}
	return false
}

func TestCollapseStructureIfElse(t *testing.T) {
	bg := NewBlockGraph()
	cond := newCFGBlock(bg)
	elseClause := newCFGBlock(bg)
	trueClause := newCFGBlock(bg)
	exit := newCFGBlock(bg)

	bg.AddEdge(cond, elseClause, 0)
	bg.AddEdge(cond, trueClause, 0)
	bg.AddEdge(trueClause, exit, 0)
	bg.AddEdge(elseClause, exit, 0)

	collapseGraph(bg)
	if bg.GetSize() != 1 {
		t.Fatalf("expected single collapsed root, got %d: %s", bg.GetSize(), describeGraph(bg))
	}
	root := bg.GetBlock(0)
	if root.Type() != BlockListType {
		t.Fatalf("expected root BlockListType, got %v", root.Type())
	}
	ifBlock := findRecursiveType(root, BlockIfType)
	if ifBlock == nil {
		t.Fatal("expected nested if block")
	}
	if len(ifBlock.StructuredChildren()) != 3 {
		t.Fatalf("expected if/else block to own 3 children, got %d", len(ifBlock.StructuredChildren()))
	}
}

func TestCollapseStructureWhileDo(t *testing.T) {
	bg := NewBlockGraph()
	cond := newCFGBlock(bg)
	body := newCFGBlock(bg)
	exit := newCFGBlock(bg)

	bg.AddEdge(cond, exit, 0)
	bg.AddEdge(cond, body, 0)
	bg.AddEdge(body, cond, 0)

	collapseGraph(bg)
	if bg.GetSize() != 1 {
		t.Fatalf("expected single collapsed root, got %d: %s", bg.GetSize(), describeGraph(bg))
	}
	root := bg.GetBlock(0)
	loop := findRecursiveType(root, BlockWhileDoType)
	if loop == nil {
		t.Fatal("expected nested while/do block")
	}
	if len(loop.StructuredChildren()) != 2 {
		t.Fatalf("expected while/do block to own 2 children, got %d", len(loop.StructuredChildren()))
	}
}

func TestCollapseStructureDoWhile(t *testing.T) {
	bg := NewBlockGraph()
	body := newCFGBlock(bg)
	cond := newCFGBlock(bg)
	exit := newCFGBlock(bg)

	bg.AddEdge(body, cond, 0)
	bg.AddEdge(cond, body, 0)
	bg.AddEdge(cond, exit, 0)

	collapseGraph(bg)
	if bg.GetSize() != 1 {
		t.Fatalf("expected single collapsed root, got %d: %s", bg.GetSize(), describeGraph(bg))
	}
	root := bg.GetBlock(0)
	loop := findRecursiveType(root, BlockDoWhileType)
	if loop == nil {
		t.Fatal("expected nested do/while block")
	}
}

func TestCollapseStructureSwitch(t *testing.T) {
	bg := NewBlockGraph()
	switchBl := newCFGBlock(bg)
	caseA := newCFGBlock(bg)
	caseB := newCFGBlock(bg)
	exit := newCFGBlock(bg)

	switchBl.SetFlag(BlockFlagSwitchOut)
	bg.AddEdge(switchBl, caseA, 0)
	bg.AddEdge(switchBl, caseB, 0)
	bg.AddEdge(caseA, exit, 0)
	bg.AddEdge(caseB, exit, 0)

	collapseGraph(bg)
	if bg.GetSize() < 1 || bg.GetSize() > 2 {
		t.Fatalf("expected collapsed switch graph to retain 1 or 2 roots, got %d: %s", bg.GetSize(), describeGraph(bg))
	}
	root := bg.GetBlock(0)
	switchNode := findRecursiveType(root, BlockSwitchType)
	if switchNode == nil {
		t.Fatal("expected nested switch block")
	}
	if len(switchNode.StructuredChildren()) != 3 {
		t.Fatalf("expected switch block to own selector plus 2 cases, got %d", len(switchNode.StructuredChildren()))
	}
}

func TestCollapseStructureIrreducibleFallsBackToGoto(t *testing.T) {
	bg := NewBlockGraph()
	a := newCFGBlock(bg)
	b := newCFGBlock(bg)
	c := newCFGBlock(bg)
	d := newCFGBlock(bg)
	exit := newCFGBlock(bg)

	bg.AddEdge(a, b, 0)
	bg.AddEdge(a, c, 0)
	bg.AddEdge(b, d, 0)
	bg.AddEdge(c, d, 0)
	bg.AddEdge(d, b, 0)
	bg.AddEdge(d, c, 0)
	bg.AddEdge(d, exit, 0)

	collapseGraph(bg)
	if bg.GetSize() == 0 {
		t.Fatal("expected collapsed graph to remain non-empty")
	}
	root := bg.GetBlock(0)
	if !hasGotoRecursive(root) {
		t.Fatal("expected irreducible graph to preserve goto/unstructured fallback")
	}
}
