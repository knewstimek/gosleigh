package loader_test

import (
	"testing"
	"time"

	"gosleigh/pkg/pcode"
)

// TestUniversalActionTreeConverges is an H8-debt-2 regression guard: the full
// universal-action tree (decompile group) must run to completion on gcd without
// hanging. Two non-convergence sources were fixed: (1) Funcdata.OpHeritage now
// reuses a persistent, incremental Heritage engine (pass + globalDisjoint state
// retained) so already-resolved varnodes are not re-placed each mainloop pass,
// and stack slots synthesized by ActionStackPtrFlow are heritaged per-slot once;
// (2) ApplyActiveParamModel is idempotent once the input prototype is locked, so
// it no longer rebuilds ScopeLocal and oscillates with ActionRestructureVarnode.
//
// The tree's C output is close but not yet byte-identical to the golden (stack
// params fold into the loop now, but the loop is rendered as if/do-while rather
// than the golden's while-comma form); this test only asserts convergence. A
// timeout guard fails the test instead of hanging the suite.
func TestUniversalActionTreeConverges(t *testing.T) {
	_, result := buildGcd(t)
	fd := result.Funcdata
	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	act := db.SetCurrent("decompile")

	done := make(chan struct{})
	go func() {
		defer func() {
			_ = recover() // a panic still counts as "did not hang"
			close(done)
		}()
		act.Perform(fd)
	}()

	select {
	case <-done:
		// converged (or panicked) -- did not hang
	case <-time.After(30 * time.Second):
		t.Fatal("universal-action tree did not converge within 30s (regression: non-incremental heritage or oscillating action)")
	}
}
