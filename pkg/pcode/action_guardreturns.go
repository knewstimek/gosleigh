package pcode

// ActionGuardReturns wires the function's return value into each CPUI_RETURN op for
// the universal-action tree. It runs the faithful Heritage::guardReturns + dominance
// rename (ApplyGuardReturnsLive) once per function, after the first ActionHeritage
// pass has resolved the register/stack SSA, so the appended return-register Varnode
// reaches the dominating definition at the return site.
//
// The hand-ordered production driver (bridge/decompile.go) calls ApplyGuardReturnsLive
// directly between heritage/stack resolution and the rule mainloop. The tree has no
// such external hook, so this action reproduces that single call inside the pipeline.
// It is isolated from the main (persistent) heritage engine: ApplyGuardReturnsLive
// builds its own Heritage with BuildADT + Rename over the return range only, never
// re-running placeMultiequals, so the loop-condition snapshots (Merge.trimOpOutput)
// are untouched. C++ parity: Heritage::heritage -> guard -> guardReturns, which runs
// inside ActionHeritage each pass; Gosleigh isolates it to a single once-per-func pass.
type ActionGuardReturns struct{ ActionBase }

var _ Action = (*ActionGuardReturns)(nil)

// NewActionGuardReturns constructs ActionGuardReturns with once-per-func semantics:
// guardReturns appends exactly one fresh return Varnode per RETURN, so it must run
// at most once per function.
func NewActionGuardReturns(group string) *ActionGuardReturns {
	act := &ActionGuardReturns{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "guardreturns", group)
	return act
}

// Clone clones ActionGuardReturns for the provided group list.
func (a *ActionGuardReturns) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionGuardReturns(a.GetGroup())
}

// Apply runs ApplyGuardReturnsLive using the analysis context attached by
// bridge.Build (default model with the return register, heritage spaces, block graph).
func (a *ActionGuardReturns) Apply(data *Funcdata) int {
	model := data.DefaultModel()
	graph := data.Graph()
	spaces := data.HeritageSpaces()
	if model == nil || graph == nil || len(spaces) == 0 {
		return 0
	}
	if ApplyGuardReturnsLive(data, model, spaces, graph) {
		a.count++
	}
	return 0
}
