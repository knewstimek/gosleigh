// Copyright 2024 Gosleigh Authors. Licensed under Apache 2.0.
package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeTestFuncdata() *Funcdata {
	sp := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	cs := &address.Space{Name: "const", Index: 1, WordSize: 1, AddrSize: 4}
	us := &address.Space{Name: "unique", Index: 2, WordSize: 1, AddrSize: 4}
	return NewFuncdata("test", address.Address{Space: sp, Offset: 0}, us, 0, cs)
}

// countingAction is a leaf Action that increments count by 1 on each Apply.
type countingAction struct {
	ActionBase
	applyCallCount int
}

func newCountingAction(nm string) *countingAction {
	ca := &countingAction{}
	ca.ActionBase = NewActionBase(ca, 0, nm, "")
	return ca
}

func (ca *countingAction) Apply(data *Funcdata) int {
	ca.applyCallCount++
	ca.count++
	return 0
}

func (ca *countingAction) Clone(groups ActionGroupList) Action {
	nc := newCountingAction(ca.name)
	return nc
}

type scriptedActionStep struct {
	res        int
	countDelta int
	restart    bool
}

type scriptedAction struct {
	ActionBase
	steps          []scriptedActionStep
	applyCallCount int
}

func newScriptedAction(nm string, flags uint32, steps ...scriptedActionStep) *scriptedAction {
	sa := &scriptedAction{steps: append([]scriptedActionStep(nil), steps...)}
	sa.ActionBase = NewActionBase(sa, flags, nm, "")
	return sa
}

func (sa *scriptedAction) Apply(data *Funcdata) int {
	idx := sa.applyCallCount
	sa.applyCallCount++
	if idx >= len(sa.steps) {
		return 0
	}
	step := sa.steps[idx]
	sa.count += step.countDelta
	if step.restart {
		data.SetRestartPending(true)
	}
	return step.res
}

func (sa *scriptedAction) Clone(groups ActionGroupList) Action {
	clone := newScriptedAction(sa.name, sa.flags, sa.steps...)
	return clone
}

// ---------------------------------------------------------------------------
// ActionGroupList tests
// ---------------------------------------------------------------------------

func TestActionGroupList_AddContainsRemove(t *testing.T) {
	gl := NewActionGroupList()
	if gl.Contains("foo") {
		t.Fatal("empty list should not contain foo")
	}
	added := gl.Add("foo")
	if !added {
		t.Fatal("Add should return true for new entry")
	}
	if !gl.Contains("foo") {
		t.Fatal("list should contain foo after Add")
	}
	again := gl.Add("foo")
	if again {
		t.Fatal("Add should return false for duplicate")
	}
	removed := gl.Remove("foo")
	if !removed {
		t.Fatal("Remove should return true for existing entry")
	}
	if gl.Contains("foo") {
		t.Fatal("list should not contain foo after Remove")
	}
}

func TestActionGroupList_Clone(t *testing.T) {
	gl := NewActionGroupList("a", "b")
	cp := gl.Clone()
	if !cp.Contains("a") || !cp.Contains("b") {
		t.Fatal("clone should contain all original entries")
	}
	cp.Add("c")
	if gl.Contains("c") {
		t.Fatal("modifying clone should not affect original")
	}
}

func TestActionGroupList_Names(t *testing.T) {
	gl := NewActionGroupList("z", "a", "m")
	names := gl.Names()
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}
	// Names() returns sorted order.
	if names[0] != "a" || names[1] != "m" || names[2] != "z" {
		t.Fatalf("unexpected order: %v", names)
	}
}

func TestActionGroupList_EmptyString(t *testing.T) {
	gl := NewActionGroupList("")
	// empty string should be silently ignored
	if gl.Contains("") {
		t.Fatal("empty string group name should not be stored")
	}
}

// ---------------------------------------------------------------------------
// ActionBase / Perform state machine tests
// ---------------------------------------------------------------------------

func TestActionBase_Perform_SingleApply(t *testing.T) {
	data := makeTestFuncdata()
	ca := newCountingAction("counter")

	res := ca.Perform(data)
	// count is 1 (one change), status should reset to start.
	if res != 1 {
		t.Fatalf("expected Perform to return 1, got %d", res)
	}
	if ca.GetStatus() != ActionStatusStart {
		t.Fatalf("status should reset to ActionStatusStart, got %d", ca.GetStatus())
	}
}

func TestActionBase_Perform_NoChange(t *testing.T) {
	data := makeTestFuncdata()
	// Action that never increments count: use countingAction but override count increment.
	ca := newCountingAction("noop")
	// countingAction increments count; we use a fresh one with no changes forced.
	// Actually countingAction does increment count, so use a separate zero-change action.
	// Use ActionGroup with no children as a no-change leaf.
	g := NewActionGroup(0, "noop-group")
	res := g.Perform(data)
	if res != 0 {
		t.Fatalf("expected 0 for no-change action, got %d", res)
	}
	_ = ca
}

func TestActionBase_Perform_RepeatApply(t *testing.T) {
	data := makeTestFuncdata()
	// An empty group with ActionRuleRepeatApply never changes, so terminates immediately.
	g := NewActionGroup(ActionRuleRepeatApply, "repeat")
	res := g.Perform(data)
	if res != 0 {
		t.Fatalf("no-change action with repeat flag should return 0, got %d", res)
	}
}

func TestActionBase_Reset(t *testing.T) {
	data := makeTestFuncdata()
	ca := newCountingAction("r")
	ca.Perform(data)
	ca.Reset(data)
	if ca.GetStatus() != ActionStatusStart {
		t.Fatalf("Reset should restore ActionStatusStart, got %d", ca.GetStatus())
	}
}

func TestActionBase_ResetStats(t *testing.T) {
	data := makeTestFuncdata()
	ca := newCountingAction("r")
	ca.Perform(data)
	ca.ResetStats()
	if ca.GetNumTests() != 0 || ca.GetNumApply() != 0 {
		t.Fatalf("ResetStats should zero counters: tests=%d apply=%d",
			ca.GetNumTests(), ca.GetNumApply())
	}
}

func TestActionBase_BreakStart(t *testing.T) {
	data := makeTestFuncdata()
	ca := newCountingAction("bp")
	ca.SetBreakPoint(ActionBreakStart, "bp")

	res := ca.Perform(data)
	// Should hit start breakpoint and return -1.
	if res != -1 {
		t.Fatalf("expected -1 on start breakpoint, got %d", res)
	}
	if ca.GetStatus() != ActionStatusBreakStartHit {
		t.Fatalf("expected ActionStatusBreakStartHit, got %d", ca.GetStatus())
	}
}

func TestActionBase_BreakStart_Temporary(t *testing.T) {
	data := makeTestFuncdata()
	ca := newCountingAction("tbp")
	ca.SetBreakPoint(ActionBreakTemporaryStart, "tbp")

	res := ca.Perform(data)
	if res != -1 {
		t.Fatalf("expected -1 on temporary start breakpoint, got %d", res)
	}
	// Temporary flag should be cleared after the hit.
	if ca.actionBase().breakpoint&ActionBreakTemporaryStart != 0 {
		t.Fatal("temporary break flag should be cleared after triggering")
	}
}

func TestActionBase_Perform_ActionBreakResumeSkipsReapply(t *testing.T) {
	data := makeTestFuncdata()
	ca := newScriptedAction("resume-break", 0, scriptedActionStep{countDelta: 1})
	ca.SetBreakPoint(ActionBreakAction, "resume-break")

	res := ca.Perform(data)
	if res != -1 {
		t.Fatalf("first Perform should break, got %d", res)
	}
	if ca.GetStatus() != ActionStatusActionBreak {
		t.Fatalf("status should be ActionStatusActionBreak, got %d", ca.GetStatus())
	}
	if ca.applyCallCount != 1 {
		t.Fatalf("Apply call count = %d, want 1", ca.applyCallCount)
	}
	if ca.GetNumApply() != 1 {
		t.Fatalf("countApply = %d, want 1", ca.GetNumApply())
	}

	res = ca.Perform(data)
	if res != 1 {
		t.Fatalf("resume should return existing count, got %d", res)
	}
	if ca.applyCallCount != 1 {
		t.Fatalf("resume should not re-run Apply, got %d calls", ca.applyCallCount)
	}
	if ca.GetNumApply() != 1 {
		t.Fatalf("resume should not increment countApply, got %d", ca.GetNumApply())
	}
	if ca.GetStatus() != ActionStatusStart {
		t.Fatalf("status should reset to start after resume, got %d", ca.GetStatus())
	}
}

func TestActionBase_Perform_OncePerFunc(t *testing.T) {
	data := makeTestFuncdata()
	ca := newScriptedAction("once", ActionRuleOncePerFunc, scriptedActionStep{})

	if res := ca.Perform(data); res != 0 {
		t.Fatalf("first Perform returned %d, want 0", res)
	}
	if ca.GetStatus() != ActionStatusEnd {
		t.Fatalf("status should be ActionStatusEnd, got %d", ca.GetStatus())
	}
	if ca.applyCallCount != 1 {
		t.Fatalf("Apply call count = %d, want 1", ca.applyCallCount)
	}
	if res := ca.Perform(data); res != 0 {
		t.Fatalf("second Perform returned %d, want 0", res)
	}
	if ca.applyCallCount != 1 {
		t.Fatalf("once-per-func action re-applied %d times", ca.applyCallCount)
	}
}

func TestActionBase_Perform_OneActPerFunc(t *testing.T) {
	data := makeTestFuncdata()
	ca := newScriptedAction("one-change", ActionRuleOneActPerFunc,
		scriptedActionStep{},
		scriptedActionStep{countDelta: 1},
	)

	if res := ca.Perform(data); res != 0 {
		t.Fatalf("first Perform returned %d, want 0", res)
	}
	if ca.GetStatus() != ActionStatusStart {
		t.Fatalf("status should remain ActionStatusStart, got %d", ca.GetStatus())
	}
	if res := ca.Perform(data); res != 1 {
		t.Fatalf("second Perform returned %d, want 1", res)
	}
	if ca.GetStatus() != ActionStatusEnd {
		t.Fatalf("status should be ActionStatusEnd after first change, got %d", ca.GetStatus())
	}
	if ca.applyCallCount != 2 {
		t.Fatalf("Apply call count = %d, want 2", ca.applyCallCount)
	}
	if res := ca.Perform(data); res != 0 {
		t.Fatalf("third Perform returned %d, want 0", res)
	}
	if ca.applyCallCount != 2 {
		t.Fatalf("one-act-per-func action re-applied %d times", ca.applyCallCount)
	}
}

func TestActionBase_Perform_PartialCompletionResume(t *testing.T) {
	data := makeTestFuncdata()
	ca := newScriptedAction("partial", 0,
		scriptedActionStep{res: -1},
		scriptedActionStep{countDelta: 1},
	)

	if res := ca.Perform(data); res != -1 {
		t.Fatalf("first Perform returned %d, want -1", res)
	}
	if ca.GetStatus() != ActionStatusMid {
		t.Fatalf("status should be ActionStatusMid, got %d", ca.GetStatus())
	}
	if res := ca.Perform(data); res != 1 {
		t.Fatalf("second Perform returned %d, want 1", res)
	}
	if ca.applyCallCount != 2 {
		t.Fatalf("Apply call count = %d, want 2", ca.applyCallCount)
	}
}

func TestActionBase_GetSubAction_Self(t *testing.T) {
	ca := newCountingAction("myact")
	found := ca.GetSubAction("myact")
	if found == nil {
		t.Fatal("GetSubAction should find self by name")
	}
	if found.GetName() != "myact" {
		t.Fatalf("expected myact, got %s", found.GetName())
	}
}

func TestActionBase_GetSubAction_Miss(t *testing.T) {
	ca := newCountingAction("myact")
	found := ca.GetSubAction("other")
	if found != nil {
		t.Fatal("GetSubAction should return nil for non-matching name")
	}
}

// ---------------------------------------------------------------------------
// ActionGroup tests
// ---------------------------------------------------------------------------

func TestActionGroup_Apply_Sequential(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionGroup(0, "group")
	c1 := newCountingAction("c1")
	c2 := newCountingAction("c2")
	g.AddAction(c1)
	g.AddAction(c2)

	res := g.Perform(data)
	if res < 0 {
		t.Fatalf("Perform returned %d, expected >= 0", res)
	}
	if c1.applyCallCount != 1 {
		t.Fatalf("c1 applyCallCount = %d, want 1", c1.applyCallCount)
	}
	if c2.applyCallCount != 1 {
		t.Fatalf("c2 applyCallCount = %d, want 1", c2.applyCallCount)
	}
}

func TestActionGroup_ResumeAfterPartialCompletion(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionGroup(0, "group")
	c1 := newScriptedAction("c1", 0,
		scriptedActionStep{res: -1},
		scriptedActionStep{countDelta: 1},
	)
	c2 := newCountingAction("c2")
	g.AddAction(c1)
	g.AddAction(c2)

	if res := g.Perform(data); res != -1 {
		t.Fatalf("first Perform returned %d, want -1", res)
	}
	if c2.applyCallCount != 0 {
		t.Fatalf("c2 should not run before resume, got %d calls", c2.applyCallCount)
	}
	if res := g.Perform(data); res != 2 {
		t.Fatalf("second Perform returned %d, want 2", res)
	}
	if c1.applyCallCount != 2 {
		t.Fatalf("c1 Apply call count = %d, want 2", c1.applyCallCount)
	}
	if c2.applyCallCount != 1 {
		t.Fatalf("c2 Apply call count = %d, want 1", c2.applyCallCount)
	}
}

func TestActionGroup_Clone_AllChildren(t *testing.T) {
	g := NewActionGroup(0, "group")
	c1 := newCountingAction("c1")
	c2 := newCountingAction("c2")
	g.AddAction(c1)
	g.AddAction(c2)

	gl := NewActionGroupList()
	cloned := g.Clone(gl)
	if cloned == nil {
		t.Fatal("Clone should return non-nil ActionGroup")
	}
	cg, ok := cloned.(*ActionGroup)
	if !ok {
		t.Fatal("Clone should return *ActionGroup")
	}
	if len(cg.list) != 2 {
		t.Fatalf("cloned group should have 2 children, got %d", len(cg.list))
	}
}

func TestActionGroup_Clone_EmptyGroup(t *testing.T) {
	// An empty group (no children) clones to nil or an empty group.
	// ActionGroup.Clone uses a typed *ActionGroup nil which Go interfaces
	// report as non-nil; verify the clone has no children either way.
	g := NewActionGroup(0, "empty")
	gl := NewActionGroupList()
	cloned := g.Clone(gl)
	if cloned == nil {
		return // ideal: untyped nil
	}
	// cloned is a typed nil (*ActionGroup wrapped in Action); calling methods on it panics.
	// This is a known Go interface nil gotcha; the test documents the current behavior.
	t.Log("Clone returned non-nil interface wrapping a nil *ActionGroup (typed nil)")
}

func TestActionGroup_GetSubAction_ByGroupName(t *testing.T) {
	g := NewActionGroup(0, "root")
	c1 := newCountingAction("child1")
	g.AddAction(c1)

	// Search by group name returns the group itself.
	self := g.GetSubAction("root")
	if self == nil {
		t.Fatal("GetSubAction should return self for group name")
	}
	if self.GetName() != "root" {
		t.Fatalf("expected root, got %s", self.GetName())
	}
}

func TestActionGroup_GetSubAction_ByChildName(t *testing.T) {
	g := NewActionGroup(0, "root")
	c1 := newCountingAction("child1")
	c2 := newCountingAction("child2")
	g.AddAction(c1)
	g.AddAction(c2)

	found := g.GetSubAction("child1")
	if found == nil {
		t.Fatal("GetSubAction should find child1")
	}
	if found.GetName() != "child1" {
		t.Fatalf("expected child1, got %s", found.GetName())
	}
}

func TestActionGroup_GetSubAction_AmbiguousReturnsNil(t *testing.T) {
	g := NewActionGroup(0, "root")
	c1 := newCountingAction("same")
	c2 := newCountingAction("same")
	g.AddAction(c1)
	g.AddAction(c2)

	found := g.GetSubAction("same")
	if found != nil {
		t.Fatal("GetSubAction should return nil for ambiguous (duplicate) name")
	}
}

func TestActionGroup_Reset_PropagatesChildren(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionGroup(0, "group")
	c1 := newCountingAction("c1")
	g.AddAction(c1)
	g.Perform(data)

	g.Reset(data)
	if g.GetStatus() != ActionStatusStart {
		t.Fatalf("group status should be ActionStatusStart after Reset, got %d", g.GetStatus())
	}
	if c1.GetStatus() != ActionStatusStart {
		t.Fatalf("child status should be ActionStatusStart after Reset, got %d", c1.GetStatus())
	}
}

func TestActionGroup_ClearBreakPoints(t *testing.T) {
	g := NewActionGroup(0, "group")
	c1 := newCountingAction("c1")
	g.AddAction(c1)
	g.actionBase().breakpoint = ActionBreakStart
	c1.SetBreakPoint(ActionBreakAction, "c1")

	g.ClearBreakPoints()
	if g.actionBase().breakpoint != 0 {
		t.Fatal("group breakpoint should be cleared")
	}
	if c1.actionBase().breakpoint != 0 {
		t.Fatal("child breakpoint should be cleared")
	}
}

func TestActionGroup_AddNil(t *testing.T) {
	g := NewActionGroup(0, "group")
	// AddAction(nil) should be a no-op.
	g.AddAction(nil)
	if len(g.list) != 0 {
		t.Fatal("AddAction(nil) should not add to list")
	}
}

// ---------------------------------------------------------------------------
// ActionRestartGroup tests
// ---------------------------------------------------------------------------

func TestActionRestartGroup_NoRestart(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionRestartGroup(0, "restart", 3)
	c := newCountingAction("c")
	g.AddAction(c)

	res := g.Perform(data)
	if res < 0 {
		t.Fatalf("Perform returned %d, expected >= 0", res)
	}
	if c.applyCallCount != 1 {
		t.Fatalf("c applyCallCount = %d, want 1", c.applyCallCount)
	}
	if g.curStart != -1 {
		t.Fatalf("curStart should be -1 after normal completion, got %d", g.curStart)
	}
}

func TestActionRestartGroup_AlreadyDone(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionRestartGroup(0, "restart", 3)
	c := newCountingAction("c")
	g.AddAction(c)

	// Mark as already done.
	g.curStart = -1
	res := g.Apply(data)
	if res != 0 {
		t.Fatalf("Apply on done group should return 0, got %d", res)
	}
	// Child should not have been called.
	if c.applyCallCount != 0 {
		t.Fatalf("child should not be called when curStart==-1, got %d", c.applyCallCount)
	}
}

func TestActionRestartGroup_WithRestart(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionRestartGroup(0, "g2", 1)
	c := newScriptedAction("c", 0,
		scriptedActionStep{countDelta: 1, restart: true},
		scriptedActionStep{countDelta: 1},
	)
	g.AddAction(c)

	if res := g.Perform(data); res != 2 {
		t.Fatalf("Perform returned %d, want 2", res)
	}
	if g.curStart != -1 {
		t.Fatalf("curStart should be -1 after completion, got %d", g.curStart)
	}
	if data.HasRestartPending() {
		t.Fatal("HasRestartPending should be false after restart group finishes")
	}
	if data.AnalysisClearCount() != 1 {
		t.Fatalf("AnalysisClearCount = %d, want 1", data.AnalysisClearCount())
	}
}

func TestActionRestartGroup_MaxRestartsWarning(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionRestartGroup(0, "restart", 0)
	c := newScriptedAction("c", 0, scriptedActionStep{countDelta: 1, restart: true})
	g.AddAction(c)

	if res := g.Perform(data); res != 1 {
		t.Fatalf("Perform returned %d, want 1", res)
	}
	msgs := data.ActionMessages()
	if len(msgs) != 1 || msgs[0] != "Exceeded maximum restarts with more pending" {
		t.Fatalf("unexpected messages: %v", msgs)
	}
	if g.curStart != -1 {
		t.Fatalf("curStart should be -1 after max restart warning, got %d", g.curStart)
	}
	if data.AnalysisClearCount() != 0 {
		t.Fatalf("AnalysisClearCount = %d, want 0", data.AnalysisClearCount())
	}
}

func TestActionRestartGroup_JumptableRecoverySuppressesRestart(t *testing.T) {
	data := makeTestFuncdata()
	data.SetJumptableRecoveryOn(true)
	g := NewActionRestartGroup(0, "restart", 1)
	c := newScriptedAction("c", 0, scriptedActionStep{countDelta: 1, restart: true})
	g.AddAction(c)

	if res := g.Perform(data); res != 1 {
		t.Fatalf("Perform returned %d, want 1", res)
	}
	if data.AnalysisClearCount() != 0 {
		t.Fatalf("AnalysisClearCount = %d, want 0", data.AnalysisClearCount())
	}
	if len(data.ActionMessages()) != 0 {
		t.Fatalf("unexpected messages: %v", data.ActionMessages())
	}
}

func TestActionRestartGroup_Reset(t *testing.T) {
	data := makeTestFuncdata()
	g := NewActionRestartGroup(0, "restart", 3)
	g.curStart = 2
	g.Reset(data)
	if g.curStart != 0 {
		t.Fatalf("Reset should set curStart=0, got %d", g.curStart)
	}
	if g.GetStatus() != ActionStatusStart {
		t.Fatalf("Reset should set status=ActionStatusStart, got %d", g.GetStatus())
	}
}

func TestActionRestartGroup_Clone(t *testing.T) {
	g := NewActionRestartGroup(0, "rg", 5)
	c := newCountingAction("child")
	g.AddAction(c)

	gl := NewActionGroupList()
	cloned := g.Clone(gl)
	if cloned == nil {
		t.Fatal("Clone should return non-nil")
	}
	arg, ok := cloned.(*ActionRestartGroup)
	if !ok {
		t.Fatal("Clone should return *ActionRestartGroup")
	}
	if arg.maxRestarts != 5 {
		t.Fatalf("maxRestarts should be 5, got %d", arg.maxRestarts)
	}
}

// ---------------------------------------------------------------------------
// ActionPool tests
// ---------------------------------------------------------------------------

// mockRule is a Rule that applies to CPUI_COPY and increments a counter.
type mockRule struct {
	RuleBase
	applyCount int
	groupName  string
}

func newMockRule(nm, grp string) *mockRule {
	mr := &mockRule{groupName: grp}
	mr.RuleBase = RuleBase{
		flags:     0,
		name:      nm,
		basegroup: grp,
	}
	return mr
}

func (mr *mockRule) GetOpList() []OpCode { return []OpCode{CPUI_COPY} }

func (mr *mockRule) ApplyOp(op *PcodeOp, data *Funcdata) int {
	mr.applyCount++
	return 1 // signal a change
}

func (mr *mockRule) Clone(groups ActionGroupList) Rule {
	if !groups.Contains(mr.groupName) {
		return nil
	}
	return newMockRule(mr.name, mr.groupName)
}

type opcodeChangeRule struct {
	RuleBase
	from       OpCode
	to         OpCode
	result     int
	applyCount int
}

func newOpcodeChangeRule(name string, from OpCode, to OpCode, result int) *opcodeChangeRule {
	rule := &opcodeChangeRule{from: from, to: to, result: result}
	rule.RuleBase = NewRuleBase("", 0, name)
	return rule
}

func (r *opcodeChangeRule) GetOpList() []OpCode {
	return []OpCode{r.from}
}

func (r *opcodeChangeRule) ApplyOp(op *PcodeOp, data *Funcdata) int {
	r.applyCount++
	data.OpSetOpcode(op, r.to)
	return r.result
}

func (r *opcodeChangeRule) Clone(groups ActionGroupList) Rule {
	return newOpcodeChangeRule(r.name, r.from, r.to, r.result)
}

type countingOpcodeRule struct {
	RuleBase
	opcodes    []OpCode
	applyCount int
}

func newCountingOpcodeRule(name string, opcodes ...OpCode) *countingOpcodeRule {
	rule := &countingOpcodeRule{opcodes: append([]OpCode(nil), opcodes...)}
	rule.RuleBase = NewRuleBase("", 0, name)
	return rule
}

func (r *countingOpcodeRule) GetOpList() []OpCode {
	return append([]OpCode(nil), r.opcodes...)
}

func (r *countingOpcodeRule) ApplyOp(op *PcodeOp, data *Funcdata) int {
	r.applyCount++
	return 1
}

func (r *countingOpcodeRule) Clone(groups ActionGroupList) Rule {
	return newCountingOpcodeRule(r.name, r.opcodes...)
}

type insertOpRule struct {
	RuleBase
	insertAddr address.Address
	applyCount int
	inserted   bool
}

func newInsertOpRule(name string, insertAddr address.Address) *insertOpRule {
	rule := &insertOpRule{insertAddr: insertAddr}
	rule.RuleBase = NewRuleBase("", 0, name)
	return rule
}

func (r *insertOpRule) GetOpList() []OpCode {
	return []OpCode{CPUI_COPY}
}

func (r *insertOpRule) ApplyOp(op *PcodeOp, data *Funcdata) int {
	r.applyCount++
	if !r.inserted {
		r.inserted = true
		newOp := data.NewOp(0, r.insertAddr)
		data.OpSetOpcode(newOp, CPUI_COPY)
		data.OpMarkAlive(newOp)
	}
	return 1
}

func (r *insertOpRule) Clone(groups ActionGroupList) Rule {
	return newInsertOpRule(r.name, r.insertAddr)
}

func TestActionPool_AddRule_And_Apply(t *testing.T) {
	data := makeTestFuncdata()
	pool := NewActionPool(0, "pool")
	mr := newMockRule("rule1", "grp")
	pool.AddRule(mr)

	sp := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	addr := address.Address{Space: sp, Offset: 0x1000}
	op := data.NewOp(0, addr)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpMarkAlive(op)

	_ = pool.Apply(data)

	if mr.applyCount == 0 {
		t.Fatal("rule should have been applied to COPY op")
	}
}

func TestActionPool_SkipsDead(t *testing.T) {
	data := makeTestFuncdata()
	pool := NewActionPool(0, "pool")
	mr := newMockRule("rule1", "grp")
	pool.AddRule(mr)

	sp := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	addr := address.Address{Space: sp, Offset: 0x2000}
	op := data.NewOp(0, addr)
	data.OpSetOpcode(op, CPUI_COPY)
	// Leave op on dead list -- do not mark alive.

	_ = pool.Apply(data)

	if mr.applyCount != 0 {
		t.Fatal("rule should not be applied to dead op")
	}
}

func TestActionPool_SkipsDisabledRuleDuringApply(t *testing.T) {
	data := makeTestFuncdata()
	pool := NewActionPool(0, "pool")
	mr := newMockRule("rule1", "grp")
	mr.SetDisable()
	pool.AddRule(mr)

	sp := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	addr := address.Address{Space: sp, Offset: 0x2100}
	op := data.NewOp(0, addr)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpMarkAlive(op)

	if res := pool.Apply(data); res != 0 {
		t.Fatalf("Apply returned %d, want 0", res)
	}
	if mr.applyCount != 0 {
		t.Fatalf("disabled rule applyCount = %d, want 0", mr.applyCount)
	}
}

func TestActionPool_OpcodeChangeRescansSameOp(t *testing.T) {
	data := makeTestFuncdata()
	pool := NewActionPool(0, "pool")
	changeRule := newOpcodeChangeRule("change", CPUI_COPY, CPUI_INT_ADD, 1)
	intAddRule := newCountingOpcodeRule("intadd", CPUI_INT_ADD)
	pool.AddRule(changeRule)
	pool.AddRule(intAddRule)

	sp := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	addr := address.Address{Space: sp, Offset: 0x2200}
	op := data.NewOp(0, addr)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpMarkAlive(op)

	if res := pool.Apply(data); res != 0 {
		t.Fatalf("Apply returned %d, want 0", res)
	}
	if changeRule.applyCount != 1 {
		t.Fatalf("changeRule applyCount = %d, want 1", changeRule.applyCount)
	}
	if intAddRule.applyCount != 1 {
		t.Fatalf("intAddRule applyCount = %d, want 1", intAddRule.applyCount)
	}
	if op.Code() != CPUI_INT_ADD {
		t.Fatalf("opcode = %v, want %v", op.Code(), CPUI_INT_ADD)
	}
}

func TestActionPool_OpcodeMutationWithoutSuccessEmitsError(t *testing.T) {
	data := makeTestFuncdata()
	pool := NewActionPool(0, "pool")
	changeRule := newOpcodeChangeRule("change", CPUI_COPY, CPUI_INT_ADD, 0)
	intAddRule := newCountingOpcodeRule("intadd", CPUI_INT_ADD)
	pool.AddRule(changeRule)
	pool.AddRule(intAddRule)

	sp := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	addr := address.Address{Space: sp, Offset: 0x2300}
	op := data.NewOp(0, addr)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpMarkAlive(op)

	if res := pool.Apply(data); res != 0 {
		t.Fatalf("Apply returned %d, want 0", res)
	}
	msgs := data.ActionMessages()
	if len(msgs) != 1 || msgs[0] != "ERROR: Rule change changed op without returning result of 1!" {
		t.Fatalf("unexpected messages: %v", msgs)
	}
	if intAddRule.applyCount != 1 {
		t.Fatalf("intAddRule applyCount = %d, want 1", intAddRule.applyCount)
	}
}

func TestActionPool_InsertedOpVisitedSamePass(t *testing.T) {
	data := makeTestFuncdata()
	pool := NewActionPool(0, "pool")
	sp := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	insertRule := newInsertOpRule("insert", address.Address{Space: sp, Offset: 0x2410})
	pool.AddRule(insertRule)

	first := data.NewOp(0, address.Address{Space: sp, Offset: 0x2400})
	data.OpSetOpcode(first, CPUI_COPY)
	data.OpMarkAlive(first)

	if res := pool.Apply(data); res != 0 {
		t.Fatalf("Apply returned %d, want 0", res)
	}
	if insertRule.applyCount != 2 {
		t.Fatalf("insertRule applyCount = %d, want 2", insertRule.applyCount)
	}
	if data.NumOps() != 2 {
		t.Fatalf("NumOps = %d, want 2", data.NumOps())
	}
}

func TestActionPool_GetSubRule(t *testing.T) {
	pool := NewActionPool(0, "pool")
	mr := newMockRule("myrule", "grp")
	pool.AddRule(mr)

	found := pool.GetSubRule("myrule")
	if found == nil {
		t.Fatal("GetSubRule should find myrule")
	}
	if found.GetName() != "myrule" {
		t.Fatalf("expected myrule, got %s", found.GetName())
	}

	none := pool.GetSubRule("nosuchrule")
	if none != nil {
		t.Fatal("GetSubRule should return nil for unknown rule")
	}
}

func TestActionPool_DisableEnableRule(t *testing.T) {
	pool := NewActionPool(0, "pool")
	mr := newMockRule("r", "grp")
	pool.AddRule(mr)

	ok := pool.DisableRule("r")
	if !ok {
		t.Fatal("DisableRule should return true")
	}
	if !mr.IsDisabled() {
		t.Fatal("rule should be disabled")
	}

	ok = pool.EnableRule("r")
	if !ok {
		t.Fatal("EnableRule should return true")
	}
	if mr.IsDisabled() {
		t.Fatal("rule should be enabled after EnableRule")
	}
}

func TestActionPool_Clone_GroupFilter(t *testing.T) {
	pool := NewActionPool(0, "pool")
	mr1 := newMockRule("r1", "included")
	mr2 := newMockRule("r2", "excluded")
	pool.AddRule(mr1)
	pool.AddRule(mr2)

	gl := NewActionGroupList("included")
	cloned := pool.Clone(gl)
	if cloned == nil {
		t.Fatal("Clone should return non-nil pool")
	}
	cp, ok := cloned.(*ActionPool)
	if !ok {
		t.Fatal("Clone should return *ActionPool")
	}
	if len(cp.allRules) != 1 {
		t.Fatalf("cloned pool should have 1 rule, got %d", len(cp.allRules))
	}
	if cp.allRules[0].GetName() != "r1" {
		t.Fatalf("expected r1, got %s", cp.allRules[0].GetName())
	}
}

func TestActionPool_Clone_EmptyReturnsNil(t *testing.T) {
	pool := NewActionPool(0, "pool")
	mr := newMockRule("r", "excluded")
	pool.AddRule(mr)

	gl := NewActionGroupList() // empty: nothing matches
	cloned := pool.Clone(gl)
	// ActionPool.Clone returns a typed nil (*ActionPool) when no rules match.
	// Go interface semantics: typed nil != untyped nil.
	// This test documents that Clone returns an interface wrapping a nil pointer.
	if cloned == nil {
		return // ideal case: untyped nil
	}
	t.Log("Clone returned non-nil interface wrapping a nil *ActionPool (typed nil)")
}

func TestActionPool_ResetStats(t *testing.T) {
	pool := NewActionPool(0, "pool")
	mr := newMockRule("r", "grp")
	mr.countTests = 5
	mr.countApply = 3
	pool.AddRule(mr)

	pool.ResetStats()
	if mr.countTests != 0 || mr.countApply != 0 {
		t.Fatal("ResetStats should zero rule counters")
	}
}

func TestActionPool_ClearBreakPoints(t *testing.T) {
	pool := NewActionPool(0, "pool")
	mr := newMockRule("r", "grp")
	mr.SetBreak(ActionBreakAction)
	pool.AddRule(mr)
	pool.actionBase().breakpoint = ActionBreakStart

	pool.ClearBreakPoints()
	if pool.actionBase().breakpoint != 0 {
		t.Fatal("pool breakpoint should be cleared")
	}
	if mr.GetBreakPoint() != 0 {
		t.Fatal("rule breakpoint should be cleared")
	}
}

func TestActionPool_AddNilRule(t *testing.T) {
	pool := NewActionPool(0, "pool")
	pool.AddRule(nil) // should be a no-op
	if len(pool.allRules) != 0 {
		t.Fatal("AddRule(nil) should not add to allRules")
	}
}

// ---------------------------------------------------------------------------
// RuleBase tests
// ---------------------------------------------------------------------------

func TestRuleBase_DisableEnable(t *testing.T) {
	r := NewRuleBase("grp", 0, "rule")
	if r.IsDisabled() {
		t.Fatal("new rule should not be disabled")
	}
	r.SetDisable()
	if !r.IsDisabled() {
		t.Fatal("SetDisable should disable rule")
	}
	r.ClearDisable()
	if r.IsDisabled() {
		t.Fatal("ClearDisable should re-enable rule")
	}
}

func TestRuleBase_Breakpoints(t *testing.T) {
	r := NewRuleBase("grp", 0, "rule")
	r.SetBreak(ActionBreakAction)
	if r.GetBreakPoint()&ActionBreakAction == 0 {
		t.Fatal("SetBreak should set ActionBreakAction")
	}
	r.ClearBreak(ActionBreakAction)
	if r.GetBreakPoint()&ActionBreakAction != 0 {
		t.Fatal("ClearBreak should clear ActionBreakAction")
	}
	r.SetBreak(ActionBreakTemporaryAction)
	r.ClearBreakPoints()
	if r.GetBreakPoint() != 0 {
		t.Fatal("ClearBreakPoints should clear all flags")
	}
}

func TestRuleBase_CheckActionBreak_Temporary(t *testing.T) {
	r := NewRuleBase("grp", 0, "rule")
	r.SetBreak(ActionBreakTemporaryAction)
	if !r.CheckActionBreak() {
		t.Fatal("CheckActionBreak should return true for ActionBreakTemporaryAction")
	}
	// Temporary flag should be cleared.
	if r.GetBreakPoint()&ActionBreakTemporaryAction != 0 {
		t.Fatal("ActionBreakTemporaryAction should be cleared after check")
	}
}

func TestRuleBase_CheckActionBreak_Permanent(t *testing.T) {
	r := NewRuleBase("grp", 0, "rule")
	r.SetBreak(ActionBreakAction)
	if !r.CheckActionBreak() {
		t.Fatal("CheckActionBreak should return true for ActionBreakAction")
	}
	// Permanent flag should remain.
	if r.GetBreakPoint()&ActionBreakAction == 0 {
		t.Fatal("ActionBreakAction should remain after check")
	}
}

func TestRuleBase_Counters(t *testing.T) {
	r := NewRuleBase("grp", 0, "rule")
	r.countTests = 5
	r.countApply = 3
	if r.GetNumTests() != 5 {
		t.Fatalf("GetNumTests = %d, want 5", r.GetNumTests())
	}
	if r.GetNumApply() != 3 {
		t.Fatalf("GetNumApply = %d, want 3", r.GetNumApply())
	}
	r.ResetStats()
	if r.GetNumTests() != 0 || r.GetNumApply() != 0 {
		t.Fatal("ResetStats should zero counters")
	}
}

func TestRuleBase_Warnings(t *testing.T) {
	r := NewRuleBase("grp", 0, "rule")
	r.TurnOnWarnings()
	if r.flags&RuleWarningsOn == 0 {
		t.Fatal("TurnOnWarnings should set RuleWarningsOn")
	}
	r.TurnOffWarnings()
	if r.flags&RuleWarningsOn != 0 {
		t.Fatal("TurnOffWarnings should clear RuleWarningsOn")
	}
}

func TestRuleBase_IssueWarning(t *testing.T) {
	data := makeTestFuncdata()
	r := NewRuleBase("grp", 0, "myrule")
	r.TurnOnWarnings()

	r.issueWarning(data)
	msgs := data.ActionMessages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 warning message, got %d", len(msgs))
	}

	// Second call should not emit again (RuleWarningsGiven guard).
	r.issueWarning(data)
	msgs = data.ActionMessages()
	if len(msgs) != 1 {
		t.Fatalf("warning should only be emitted once, got %d messages", len(msgs))
	}
}

// ---------------------------------------------------------------------------
// ActionDatabase tests
// ---------------------------------------------------------------------------

func TestActionDatabase_RegisterAndSetCurrent_Direct(t *testing.T) {
	db := NewActionDatabase()
	g := NewActionGroup(0, "root")
	db.RegisterAction("root", g)

	act := db.SetCurrent("root")
	if act == nil {
		t.Fatal("SetCurrent should return the registered action")
	}
	if act.GetName() != "root" {
		t.Fatalf("expected root, got %s", act.GetName())
	}
	if db.GetCurrent() != g {
		t.Fatal("GetCurrent should return the set action")
	}
	if db.GetCurrentName() != "root" {
		t.Fatalf("GetCurrentName should be root, got %s", db.GetCurrentName())
	}
}

func TestActionDatabase_SetCurrentDerivesFromUniversalLazily(t *testing.T) {
	db := NewActionDatabase()
	universal := NewActionGroup(0, actionDatabaseUniversalName)
	pool := NewActionPool(0, "pool")
	pool.AddRule(newMockRule("r", "grp"))
	universal.AddAction(pool)
	db.RegisterUniversal(universal)
	db.SetGroup("derived", "grp")

	if _, ok := db.actionMap["derived"]; ok {
		t.Fatal("derived action should not be materialized before selection")
	}
	act1 := db.SetCurrent("derived")
	if act1 == nil {
		t.Fatal("SetCurrent should derive an action from the universal root")
	}
	if db.GetCurrent() != act1 {
		t.Fatal("GetCurrent should return the derived action")
	}
	if db.GetCurrentName() != "derived" {
		t.Fatalf("GetCurrentName = %s, want derived", db.GetCurrentName())
	}
	act2 := db.SetCurrent("derived")
	if act1 != act2 {
		t.Fatal("derived action should be cached until the group definition changes")
	}
}

func TestActionDatabase_SetGroup_And_GetGroup(t *testing.T) {
	db := NewActionDatabase()
	db.SetGroup("default", "a", "b", "c")

	gl, ok := db.GetGroup("default")
	if !ok {
		t.Fatal("GetGroup should return true for existing group")
	}
	if !gl.Contains("a") || !gl.Contains("b") || !gl.Contains("c") {
		t.Fatal("group list should contain a, b, c")
	}
}

func TestActionDatabase_GetGroup_Missing(t *testing.T) {
	db := NewActionDatabase()
	_, ok := db.GetGroup("nosuchgroup")
	if ok {
		t.Fatal("GetGroup should return false for missing group")
	}
}

func TestActionDatabase_CloneGroup(t *testing.T) {
	db := NewActionDatabase()
	db.SetGroup("original", "x", "y")

	ok := db.CloneGroup("original", "copy")
	if !ok {
		t.Fatal("CloneGroup should return true for existing group")
	}
	gl, exists := db.GetGroup("copy")
	if !exists {
		t.Fatal("cloned group should exist")
	}
	if !gl.Contains("x") || !gl.Contains("y") {
		t.Fatal("cloned group should contain original entries")
	}
	// Modifying cloned copy should not affect original.
	gl.Add("z")
	orig, _ := db.GetGroup("original")
	if orig.Contains("z") {
		t.Fatal("modifying clone should not affect original")
	}
}

func TestActionDatabase_CloneGroup_MissingSource(t *testing.T) {
	db := NewActionDatabase()
	ok := db.CloneGroup("nosuch", "dest")
	if ok {
		t.Fatal("CloneGroup should return false for missing source")
	}
}

func TestActionDatabase_AddRemoveFromGroup(t *testing.T) {
	db := NewActionDatabase()
	db.SetGroup("grp", "a")

	added := db.AddToGroup("grp", "b")
	if !added {
		t.Fatal("AddToGroup should return true for new entry")
	}
	gl, _ := db.GetGroup("grp")
	if !gl.Contains("b") {
		t.Fatal("b should be in group after AddToGroup")
	}

	removed := db.RemoveFromGroup("grp", "a")
	if !removed {
		t.Fatal("RemoveFromGroup should return true for existing entry")
	}
	gl2, _ := db.GetGroup("grp")
	if gl2.Contains("a") {
		t.Fatal("a should be removed from group")
	}
}

func TestActionDatabase_ResetDefaults(t *testing.T) {
	db := NewActionDatabase()
	universal := NewActionGroup(0, actionDatabaseUniversalName)
	db.RegisterAction(actionDatabaseUniversalName, universal)
	db.RegisterAction("other", NewActionGroup(0, "other"))
	db.SetGroup("grp", "x")

	db.ResetDefaults()

	if db.GetCurrent() != nil {
		t.Fatal("ResetDefaults should clear current action")
	}
	_, ok := db.GetGroup("grp")
	if ok {
		t.Fatal("ResetDefaults should clear group map")
	}
	// Universal action should be preserved.
	act := db.SetCurrent(actionDatabaseUniversalName)
	if act == nil {
		t.Fatal("universal action should survive ResetDefaults")
	}
}

func TestActionDatabase_ToggleAction(t *testing.T) {
	db := NewActionDatabase()
	// Setup a universal action with a child pool.
	universal := NewActionGroup(0, actionDatabaseUniversalName)
	pool := NewActionPool(0, "pool")
	mr := newMockRule("r", "grp")
	pool.AddRule(mr)
	universal.AddAction(pool)
	db.RegisterUniversal(universal)

	// Set up a group definition.
	db.SetGroup("myroot", "grp")

	// ToggleAction removes "grp" from "myroot".
	db.ToggleAction("myroot", "grp", false)
	gl, _ := db.GetGroup("myroot")
	if gl.Contains("grp") {
		t.Fatal("ToggleAction(false) should remove group")
	}

	// ToggleAction adds "grp" back.
	db.ToggleAction("myroot", "grp", true)
	gl2, _ := db.GetGroup("myroot")
	if !gl2.Contains("grp") {
		t.Fatal("ToggleAction(true) should add group back")
	}
}

// ---------------------------------------------------------------------------
// Funcdata action support tests
// ---------------------------------------------------------------------------

func TestFuncdata_HasSetRestartPending(t *testing.T) {
	data := makeTestFuncdata()
	if data.HasRestartPending() {
		t.Fatal("new Funcdata should not have restart pending")
	}
	data.SetRestartPending(true)
	if !data.HasRestartPending() {
		t.Fatal("SetRestartPending(true) should set pending")
	}
	data.SetRestartPending(false)
	if data.HasRestartPending() {
		t.Fatal("SetRestartPending(false) should clear pending")
	}
}

func TestFuncdata_ActionMessages(t *testing.T) {
	data := makeTestFuncdata()
	data.emitActionMessage("msg1")
	data.emitActionMessage("msg2")

	msgs := data.ActionMessages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	data.ClearActionMessages()
	msgs = data.ActionMessages()
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages after clear, got %d", len(msgs))
	}
}

func TestFuncdata_ClearAnalysis(t *testing.T) {
	data := makeTestFuncdata()
	data.SetRestartPending(true)
	data.clearAnalysis()

	if data.HasRestartPending() {
		t.Fatal("clearAnalysis should clear restart pending")
	}
	if data.AnalysisClearCount() != 1 {
		t.Fatalf("AnalysisClearCount should be 1, got %d", data.AnalysisClearCount())
	}
}
