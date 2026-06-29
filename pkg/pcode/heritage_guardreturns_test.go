package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

// guardReturnsFixture builds a minimal Funcdata with a single live RETURN op
// (input[0] = return-address placeholder) and a FuncProto whose model has the
// integer return register configured at (regSp, 0, 4). An active output trial is
// installed so guardReturns takes the registerTrial/append path.
func guardReturnsFixture(t *testing.T) (*Funcdata, *Heritage, *address.Space, *PcodeOp, *ParamActive) {
	t.Helper()
	regSp := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 0, WordSize: 1, AddrSize: 4}
	constSp := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, WordSize: 1, AddrSize: 4}
	uniqSp := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, WordSize: 1, AddrSize: 4}
	fd := NewFuncdata("guardreturns_test", address.Address{Space: regSp, Offset: 0}, uniqSp, 0, constSp)
	addr := address.Address{Space: constSp, Offset: 0}
	bb := NewBlockBasic()

	ret := fd.NewOp(1, addr)
	fd.OpSetOpcode(ret, CPUI_RETURN)
	fd.OpSetInput(ret, fd.NewConstant(4, 0), 0)
	fd.OpMarkAlive(ret)
	ret.SetParent(bb)
	bb.InsertOpEnd(ret)

	model := NewProtoModelFromCspec(nil, nil, nil).WithReturnReg(int(regSp.Index), 0, 4)
	fp := NewFuncProto(model)
	fd.SetFuncProto(fp)
	active := NewParamActive(false)
	fp.SetActiveOutput(active)

	h := NewHeritage(fd, []*address.Space{regSp}).WithProtoModel(model)
	return fd, h, regSp, ret, active
}

// TestGuardReturnsAppendsReturnInput verifies the exact-match register-return
// case: guardReturns appends a fresh return-register Varnode to the RETURN op,
// marks it for heritage, and registers a single output trial. This is the
// faithful mechanism that replaces the anchorReturnReg SeqNum heuristic.
func TestGuardReturnsAppendsReturnInput(t *testing.T) {
	_, h, regSp, ret, active := guardReturnsFixture(t)

	before := ret.NumInput()
	h.guardReturns(0, address.Address{Space: regSp, Offset: 0}, 4)

	if ret.NumInput() != before+1 {
		t.Fatalf("RETURN numInput=%d, want %d (one appended return input)", ret.NumInput(), before+1)
	}
	in := ret.Input(ret.NumInput() - 1)
	if in == nil {
		t.Fatal("appended RETURN input is nil")
	}
	if in.Space() != regSp || in.Offset() != 0 || in.Size() != 4 {
		t.Errorf("appended input at (%v,%d,%d), want (register,0,4)", in.Space(), in.Offset(), in.Size())
	}
	if !in.IsFree() {
		t.Errorf("appended input should be free (unrenamed) until SSA renaming connects it")
	}
	if in.addlFlags&VarnodeActiveHeritage == 0 {
		t.Errorf("appended input not marked ActiveHeritage")
	}
	if active.NumTrials() != 1 {
		t.Fatalf("active trials=%d, want 1", active.NumTrials())
	}
	tr := active.Trial(0)
	if tr.GetSize() != 4 || tr.GetAddress().Offset != 0 || tr.GetAddress().Space != regSp {
		t.Errorf("trial at (%v,%d) size %d, want (register,0) size 4", tr.GetAddress().Space, tr.GetAddress().Offset, tr.GetSize())
	}
}

// TestGuardReturnsNoActiveOutput verifies guardReturns is a no-op when no active
// output is installed (the first heritage pass, before ActionActiveReturn).
func TestGuardReturnsNoActiveOutput(t *testing.T) {
	_, h, regSp, ret, _ := guardReturnsFixture(t)
	h.fd.GetFuncProto().ClearActiveOutput()

	before := ret.NumInput()
	h.guardReturns(0, address.Address{Space: regSp, Offset: 0}, 4)
	if ret.NumInput() != before {
		t.Errorf("RETURN numInput changed without active output: %d -> %d", before, ret.NumInput())
	}
}

// TestGuardReturnsNoContainment verifies a range that does not overlap the return
// register leaves RETURN ops untouched.
func TestGuardReturnsNoContainment(t *testing.T) {
	_, h, regSp, ret, active := guardReturnsFixture(t)

	before := ret.NumInput()
	// Offset 0x40 is well away from the return register at offset 0.
	h.guardReturns(0, address.Address{Space: regSp, Offset: 0x40}, 4)
	if ret.NumInput() != before {
		t.Errorf("RETURN numInput changed for non-overlapping range: %d -> %d", before, ret.NumInput())
	}
	if active.NumTrials() != 0 {
		t.Errorf("trials registered for non-overlapping range: %d", active.NumTrials())
	}
}

// TestGuardReturnsOverlapping verifies the contained_by case: when the heritaged
// range properly contains the return register, a truncating SUBPIECE is inserted
// before each RETURN and its output (at the return register) is appended.
func TestGuardReturnsOverlapping(t *testing.T) {
	_, h, regSp, ret, active := guardReturnsFixture(t)

	before := ret.NumInput()
	// 8-byte range at offset 0 properly contains the 4-byte return register.
	h.guardReturns(0, address.Address{Space: regSp, Offset: 0}, 8)

	if ret.NumInput() != before+1 {
		t.Fatalf("RETURN numInput=%d, want %d", ret.NumInput(), before+1)
	}
	in := ret.Input(ret.NumInput() - 1)
	if in == nil || !in.IsWritten() {
		t.Fatal("appended overlapping input should be the SUBPIECE output (written)")
	}
	sub := in.Def()
	if sub == nil || sub.Code() != CPUI_SUBPIECE {
		t.Fatalf("appended input def = %v, want SUBPIECE", sub)
	}
	if in.Size() != 4 || in.Offset() != 0 || in.Space() != regSp {
		t.Errorf("SUBPIECE output at (%v,%d,%d), want (register,0,4)", in.Space(), in.Offset(), in.Size())
	}
	whole := sub.Input(0)
	if whole == nil || whole.Size() != 8 {
		t.Errorf("SUBPIECE input[0] size %v, want 8 (the oversized range)", whole)
	}
	if active.NumTrials() != 1 || active.Trial(0).GetSize() != 4 {
		t.Errorf("overlapping trial not registered at return-register size 4")
	}
}
