package analysis

import (
	"bytes"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

const budgetTestBase = 0x1000

func budgetTestReads(t *testing.T, code []byte) *CalleeReads {
	t.Helper()
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: budgetTestBase, Data: code, Exec: true}})
	if err != nil {
		t.Fatal(err)
	}
	return NewCalleeReads(prog)
}

func budgetTestAddress(c *CalleeReads, off uint64) address.Address {
	return address.Address{Space: c.prog.CodeSpace(), Offset: budgetTestBase + off}
}

func TestCalleeFloatReturnSharedWorkBudget(t *testing.T) {
	// The child fits on its own, but call + child + ret exceeds one query.
	code := []byte{0xe8, 1, 0, 0, 0, 0xc3}
	code = append(code, bytes.Repeat([]byte{0x90}, returnScanLimit-3)...)
	code = append(code, 0xf3, 0x0f, 0x10, 0x01, 0xc3)
	c := budgetTestReads(t, code)
	if got := c.CalleeFloatReturn(budgetTestAddress(c, 0)); got != 0 {
		t.Fatalf("partial recursive scan returned %d", got)
	}
	if len(c.insns) > returnScanLimit {
		t.Fatalf("recursive scan translated %d instructions", len(c.insns))
	}
	if got := c.CalleeFloatReturn(budgetTestAddress(c, 6)); got != 4 {
		t.Fatalf("the child's fresh query was poisoned by its parent's cutoff: %d", got)
	}
}

func TestCalleeFloatReturnBudgetVetoesPartialHint(t *testing.T) {
	// The short path returns float; the unexplored long path returns double.
	code := []byte{0x85, 0xc9, 0x0f, 0x85, 5, 0, 0, 0, 0xf3, 0x0f, 0x10, 0x01, 0xc3}
	code = append(code, bytes.Repeat([]byte{0x90}, returnScanLimit)...)
	code = append(code, 0xf2, 0x0f, 0x10, 0x01, 0xc3)
	c := budgetTestReads(t, code)
	if got := c.CalleeFloatReturn(budgetTestAddress(c, 0)); got != 0 {
		t.Fatalf("unexplored conflicting return path was locked to size %d", got)
	}
}

func TestCalleeFloatReturnExactBudget(t *testing.T) {
	code := bytes.Repeat([]byte{0x90}, returnScanLimit-2)
	code = append(code, 0xf3, 0x0f, 0x10, 0x01, 0xc3)
	c := budgetTestReads(t, code)
	if got := c.CalleeFloatReturn(budgetTestAddress(c, 0)); got != 4 {
		t.Fatalf("a complete scan at the exact budget returned %d", got)
	}
}

func TestCalleeFloatReturnDepthDoesNotPoisonFreshQuery(t *testing.T) {
	var code []byte
	for i := 0; i <= returnCallDepth; i++ {
		code = append(code, 0xe8, 3, 0, 0, 0, 0xc3, 0xcc, 0xcc)
	}
	code = append(code, 0xf3, 0x0f, 0x10, 0x01, 0xc3)
	c := budgetTestReads(t, code)
	if got := c.CalleeFloatReturn(budgetTestAddress(c, 0)); got != 0 {
		t.Fatalf("the deepest call should be outside the recursive depth: %d", got)
	}
	if got := c.CalleeFloatReturn(budgetTestAddress(c, 8)); got != 4 {
		t.Fatalf("a depth-limited inner answer leaked into a fresh query: %d", got)
	}
}

func TestCalleeTranslationCacheBound(t *testing.T) {
	c := budgetTestReads(t, bytes.Repeat([]byte{0x90}, calleeCacheOpLimit+1))
	if !c.ensureEngine(budgetTestBase) {
		t.Fatal("cannot create scan engine")
	}
	for i := 0; i <= calleeCacheOpLimit; i++ {
		at := address.Address{Space: c.code, Offset: budgetTestBase + uint64(i)}
		tr, err := c.translate(at)
		if err != nil || tr.Next.Offset != at.Offset+1 {
			t.Fatalf("translation %d changed across cache eviction: %v", i, err)
		}
		if c.insnCost > calleeCacheOpLimit {
			t.Fatalf("translation cost %d exceeds cache bound", c.insnCost)
		}
		if _, retained := c.engine.DisassemblyCache().GetRawOps(at); retained {
			t.Fatalf("the engine retains a second copy of translation %d", i)
		}
	}
	if _, retained := c.insns[budgetTestBase]; retained {
		t.Fatal("old translations were never evicted")
	}
}
