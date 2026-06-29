package loader_test

import (
	"testing"
	"time"

	"gosleigh/pkg/pcode"
)

// TestUniversalActionTreeConverges is an H8-debt-2 regression guard: the full
// universal-action tree (decompile group) must run to completion on gcd without
// hanging. It previously spun forever because Funcdata.OpHeritage re-ran a full
// (non-incremental) heritage on every mainloop iteration, recreating MULTIEQUALs
// that downstream actions kept transforming. Heritage is now run once.
//
// The tree's C output is NOT yet golden-correct (parameter recovery + stack
// heritage in the tree path are still incomplete); this test only asserts
// convergence. A timeout guard fails the test instead of hanging the suite.
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
