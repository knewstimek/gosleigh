package loader_test

import (
	"os"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/pcode"
)

// TestTreeOutputDiag runs the universal-action tree on gcd and dumps the current
// C output plus proto/scopelocal state. Env-gated (TREE_DIAG=1) so it stays out
// of the normal suite. Diagnostic only -- no assertions.
func TestTreeOutputDiag(t *testing.T) {
	if os.Getenv("TREE_DIAG") == "" {
		t.Skip("set TREE_DIAG=1 to run")
	}
	engine, result := buildGcd(t)
	fd := result.Funcdata

	t.Logf("pre-tree: FuncProto=%v ScopeLocal=%v", fd.GetFuncProto() != nil, fd.GetScopeLocal() != nil)

	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	act := db.SetCurrent("decompile")
	act.Perform(fd)

	fp := fd.GetFuncProto()
	var ss interface{} = nil
	if fp != nil && fp.Model() != nil {
		ss = fp.Model().StackSpace
	}
	t.Logf("post-tree: FuncProto=%v ScopeLocal=%v numParams=%d stackSpace=%v",
		fp != nil, fd.GetScopeLocal() != nil, protoNumParams(fp), ss)

	dumpSSA(t, fd, "tree-final")

	out, err := pcode.NewPrintC().
		SetRegisterNames(engine.RegisterNamesByLocation()).
		SetProcessEntry("processEntry", 2).
		SetGhidraFormat().
		Emit(fd)
	if err != nil {
		t.Fatalf("PrintC: %v", err)
	}
	t.Logf("TREE OUTPUT (ghidra/processEntry):\n%s", out)

	// Production reference: run the hand-ordered decompile driver on a fresh build
	// (mutates result.Funcdata in place) and dump its SSA for comparison.
	engine2, result2 := buildGcd(t)
	pout, perr := bridge.Decompile(engine2, result2, bridge.DecompileConfig{
		GhidraFormat: true, ProcessEntryName: "processEntry", GhostParams: 2,
	})
	if perr != nil {
		t.Fatalf("production Decompile: %v", perr)
	}
	dumpSSA(t, result2.Funcdata, "production-final")
	t.Logf("PRODUCTION OUTPUT:\n%s", pout)
}

func protoNumParams(fp *pcode.FuncProto) int {
	if fp == nil {
		return -1
	}
	return fp.NumParams()
}
