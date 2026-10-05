// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import (
	"sort"

	"gosleigh/pkg/address"
)

// stackSolnUnknown marks an unsolved StackSolver variable.
// C++ parity: the literal 65535 used throughout StackSolver.
const stackSolnUnknown = 65535

// stackEqn is one linear stack-pointer equation: var1 - var2 = rhs.
// C++ parity: coreaction.cc StackEqn.
type stackEqn struct {
	var1, var2 int
	rhs        int32
}

// stackSolver solves for stack-pointer changes across sub-functions whose
// extrapop is unknown, using one variable per stack-pointer Varnode.
// C++ parity: coreaction.cc StackSolver.
type stackSolver struct {
	eqs       []stackEqn
	guess     []stackEqn
	vnlist    []*Varnode
	companion []int
	soln      []int32
	missed    int
}

// indexOf returns the lower_bound position of vn in vnlist, which is sorted in
// loc order. C++ uses lower_bound with Varnode::comparePointers, so a Varnode
// outside the list maps to its insertion point rather than failing.
func (s *stackSolver) indexOf(vn *Varnode) int {
	return sort.Search(len(s.vnlist), func(i int) bool {
		return CompareLocDef(s.vnlist[i], vn) >= 0
	})
}

// propagate pushes a known solution through every equation it touches.
// C++ parity: StackSolver::propagate.
func (s *stackSolver) propagate(varnum int, val int32) {
	if s.soln[varnum] != stackSolnUnknown {
		return
	}
	s.soln[varnum] = val
	work := []int{varnum}
	for len(work) > 0 {
		varnum = work[len(work)-1]
		work = work[:len(work)-1]
		top := sort.Search(len(s.eqs), func(i int) bool { return s.eqs[i].var1 >= varnum })
		for ; top < len(s.eqs) && s.eqs[top].var1 == varnum; top++ {
			v2 := s.eqs[top].var2
			if s.soln[v2] == stackSolnUnknown {
				s.soln[v2] = s.soln[varnum] - s.eqs[top].rhs
				work = append(work, v2)
			}
		}
	}
}

// duplicate adds the negated mirror of every equation and sorts by var1.
// C++ parity: StackSolver::duplicate.
func (s *stackSolver) duplicate() {
	n := len(s.eqs)
	for i := 0; i < n; i++ {
		s.eqs = append(s.eqs, stackEqn{var1: s.eqs[i].var2, var2: s.eqs[i].var1, rhs: -s.eqs[i].rhs})
	}
	sort.SliceStable(s.eqs, func(i, j int) bool { return s.eqs[i].var1 < s.eqs[j].var1 })
}

// solve resolves the system, using guesses for underdetermined subsystems.
// C++ parity: StackSolver::solve.
func (s *stackSolver) solve() {
	s.soln = make([]int32, len(s.vnlist))
	for i := range s.soln {
		s.soln[i] = stackSolnUnknown
	}
	s.duplicate()
	s.propagate(0, 0) // The input stack pointer is the origin
	size := len(s.guess)
	lastcount := size + 2
	for {
		count := 0
		for _, g := range s.guess {
			switch {
			case s.soln[g.var1] != stackSolnUnknown && s.soln[g.var2] == stackSolnUnknown:
				s.propagate(g.var2, s.soln[g.var1]-g.rhs)
			case s.soln[g.var1] == stackSolnUnknown && s.soln[g.var2] != stackSolnUnknown:
				s.propagate(g.var1, s.soln[g.var2]+g.rhs)
			case s.soln[g.var1] == stackSolnUnknown && s.soln[g.var2] == stackSolnUnknown:
				count++
			}
		}
		if count == lastcount {
			break
		}
		lastcount = count
		if count <= 0 {
			break
		}
	}
}

// errStackInputUnused reports a stack pointer whose first loc-ordered Varnode
// is not the function input. C++ throws LowlevelError.
type errStackInputUnused struct{}

func (errStackInputUnused) Error() string { return "Input value of stackpointer is not used" }

// build collects the stack-pointer Varnodes and derives one equation (or
// guess) per defining op.
// C++ parity: StackSolver::build.
func (s *stackSolver) build(data *Funcdata, stackspace *address.Space) error {
	point := stackspace.GetSpacebase(0)
	spacebase := address.Address{Space: point.Space, Offset: point.Offset}
	for _, vn := range data.GetVarnodeBank().LocExact(spacebase, point.Size) {
		if vn.IsFree() {
			break
		}
		s.vnlist = append(s.vnlist, vn)
		s.companion = append(s.companion, -1)
	}
	if len(s.vnlist) == 0 {
		return nil
	}
	if !s.vnlist[0].IsInput() {
		return errStackInputUnused{}
	}
	atBase := func(vn *Varnode) bool { return vn.Addr() == spacebase }
	for i := 1; i < len(s.vnlist); i++ {
		op := s.vnlist[i].Def()
		switch op.Code() {
		case CPUI_INT_ADD, CPUI_INT_AND:
			othervn, constvn := op.Input(0), op.Input(1)
			if othervn.IsConstant() {
				othervn, constvn = constvn, othervn
			}
			if !constvn.IsConstant() || !atBase(othervn) {
				s.missed++
				continue
			}
			eqn := stackEqn{var1: i, var2: s.indexOf(othervn)}
			if op.Code() == CPUI_INT_ADD {
				eqn.rhs = int32(uint32(constvn.Offset()))
			} // INT_AND (stack alignment) is treated as a copy
			s.eqs = append(s.eqs, eqn)
		case CPUI_COPY:
			othervn := op.Input(0)
			if !atBase(othervn) {
				s.missed++
				continue
			}
			s.eqs = append(s.eqs, stackEqn{var1: i, var2: s.indexOf(othervn)})
		case CPUI_INDIRECT:
			othervn := op.Input(0)
			if !atBase(othervn) {
				s.missed++
				continue
			}
			eqn := stackEqn{var1: i, var2: s.indexOf(othervn)}
			s.companion[i] = eqn.var2
			if iop := op.Input(1).GetIndirectCause(); iop != nil {
				if fc := data.callSpecsForOp(iop); fc != nil && fc.GetExtraPop() != ExtrapopUnknown {
					// The deindirect process may have filled the extrapop in.
					eqn.rhs = fc.GetExtraPop()
					s.eqs = append(s.eqs, eqn)
					continue
				}
			}
			eqn.rhs = 4 // Otherwise make a guess
			s.guess = append(s.guess, eqn)
		case CPUI_MULTIEQUAL:
			for j := 0; j < op.NumInput(); j++ {
				othervn := op.Input(j)
				if !atBase(othervn) {
					s.missed++
					continue
				}
				s.eqs = append(s.eqs, stackEqn{var1: i, var2: s.indexOf(othervn)})
			}
		default:
			s.missed++
		}
	}
	return nil
}

// ActionStackPtrFlow analyzes the stack-pointer flow across sub-function calls
// whose extrapop is unknown, and repairs stack-pointer "clogs".
// C++ parity: coreaction.hh ActionStackPtrFlow.
type ActionStackPtrFlow struct {
	ActionBase
	analysisFinished bool
}

var _ Action = (*ActionStackPtrFlow)(nil)

// NewActionStackPtrFlow constructs ActionStackPtrFlow.
func NewActionStackPtrFlow(group string) *ActionStackPtrFlow {
	act := &ActionStackPtrFlow{}
	act.ActionBase = NewActionBase(act, 0, "stackptrflow", group)
	return act
}

// Clone clones ActionStackPtrFlow for the provided group list.
func (a *ActionStackPtrFlow) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionStackPtrFlow(a.GetGroup())
}

// Reset re-arms the analysis for a new function.
// C++ parity: ActionStackPtrFlow::reset.
func (a *ActionStackPtrFlow) Reset(_ *Funcdata) { a.analysisFinished = false }

// Apply repairs clogs until none remain, then solves unknown extrapops once.
// C++ parity: coreaction.cc ActionStackPtrFlow::apply (482-500).
func (a *ActionStackPtrFlow) Apply(data *Funcdata) int {
	if a.analysisFinished {
		return 0
	}
	var stackspace *address.Space
	if m := data.DefaultModel(); m != nil {
		stackspace = m.StackSpace
	}
	if stackspace == nil {
		a.analysisFinished = true // No stack to do analysis on
		return 0
	}
	numchange := stackPtrCheckClog(data, stackspace)
	if numchange > 0 {
		a.count++
	}
	if numchange == 0 {
		stackPtrAnalyzeExtraPop(data, stackspace)
		a.analysisFinished = true
	}
	return 0
}

// stackPtrAnalyzeExtraPop solves the stack-pointer system and rewrites every
// solved stack-pointer definition as `input + offset`.
// C++ parity: ActionStackPtrFlow::analyzeExtraPop. C++ consults
// evalfp_called (falling back to defaultfp); Gosleigh has a single evaluation
// model, the function default.
func stackPtrAnalyzeExtraPop(data *Funcdata, stackspace *address.Space) {
	if myfp := data.DefaultModel(); myfp == nil || myfp.GetExtraPop() != ExtrapopUnknown {
		return
	}
	var solver stackSolver
	if err := solver.build(data, stackspace); err != nil {
		data.warningHeader("Stack frame is not setup normally: " + err.Error())
		return
	}
	if len(solver.vnlist) == 0 {
		return
	}
	solver.solve()
	invn := solver.vnlist[0]
	warned := false
	for i := 1; i < len(solver.vnlist); i++ {
		vn := solver.vnlist[i]
		soln := solver.soln[i]
		if soln == stackSolnUnknown {
			if !warned {
				data.warningHeader("Unable to track spacebase fully for " + stackspace.Name)
				warned = true
			}
			continue
		}
		op := vn.Def()
		if op.Code() == CPUI_INDIRECT {
			if iop := op.Input(1).GetIndirectCause(); iop != nil {
				if fc := data.callSpecsForOp(iop); fc != nil {
					var soln2 int32
					if comp := solver.companion[i]; comp >= 0 {
						soln2 = solver.soln[comp]
					}
					fc.SetEffectiveExtraPop(soln - soln2)
				}
			}
		}
		sz := invn.Size()
		cval := uint64(int64(soln)) & sizeMask(sz)
		data.OpSetOpcode(op, CPUI_INT_ADD)
		data.OpSetAllInput(op, []*Varnode{invn, data.NewConstant(sz, cval)})
	}
}

// sizeMask returns the all-ones mask for a value of sz bytes.
func sizeMask(sz int32) uint64 {
	if sz >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (8 * uint(sz))) - 1
}

// stackPtrIsStackRelative reports whether vn is the input stack pointer plus a
// constant, passing back the constant.
// C++ parity: ActionStackPtrFlow::isStackRelative.
func stackPtrIsStackRelative(spcbasein, vn *Varnode) (uint64, bool) {
	if spcbasein == vn {
		return 0, true
	}
	if !vn.IsWritten() {
		return 0, false
	}
	addop := vn.Def()
	if addop.Code() != CPUI_INT_ADD || addop.Input(0) != spcbasein {
		return 0, false
	}
	constvn := addop.Input(1)
	if !constvn.IsConstant() {
		return 0, false
	}
	return constvn.Offset(), true
}

// stackPtrAdjustLoad turns a LOAD whose matching STORE was found into a COPY
// of the stored value.
// C++ parity: ActionStackPtrFlow::adjustLoad.
func stackPtrAdjustLoad(data *Funcdata, loadop, storeop *PcodeOp) bool {
	vn := storeop.Input(2)
	if vn.IsConstant() {
		vn = data.NewConstant(vn.Size(), vn.Offset())
	} else if vn.IsFree() {
		return false
	}
	data.OpRemoveInput(loadop, 1)
	data.OpSetOpcode(loadop, CPUI_COPY)
	data.OpSetInput(loadop, vn, 0)
	return true
}

// stackPtrRepair searches backward from a stack-relative LOAD for the STORE to
// the same stack location and, when found, converts the LOAD to a COPY.
// C++ parity: ActionStackPtrFlow::repair.
func stackPtrRepair(data *Funcdata, id *address.Space, spcbasein *Varnode, loadop *PcodeOp, constz uint64) int {
	loadsize := uint64(loadop.Output().Size())
	curblock := loadop.Parent()
	if curblock == nil {
		return 0
	}
	ops := curblock.Ops()
	idx := -1
	for i, o := range ops {
		if o == loadop {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0
	}
	for {
		if idx == 0 {
			if curblock.SizeIn() != 1 {
				return 0 // Can trace back to the previous block only if it is the sole path
			}
			curblock = asBasic(curblock.InEdge(0).Point)
			if curblock == nil {
				return 0
			}
			ops = curblock.Ops()
			idx = len(ops)
			continue
		}
		idx--
		curop := ops[idx]
		if curop.IsCall() {
			return 0 // Don't trace aliasing through a call
		}
		if curop.Code() == CPUI_STORE {
			ptrvn, datavn := curop.Input(1), curop.Input(2)
			constnew, ok := stackPtrIsStackRelative(spcbasein, ptrvn)
			if !ok {
				return 0 // Any other kind of STORE can't be solved for aliasing
			}
			dsize := uint64(datavn.Size())
			if constnew == constz && loadsize == dsize {
				if stackPtrAdjustLoad(data, loadop, curop) {
					return 1
				}
				return 0
			}
			if constnew <= constz+(loadsize-1) && constnew+(dsize-1) >= constz {
				return 0
			}
		} else if outvn := curop.Output(); outvn != nil && outvn.Space() == id {
			return 0 // Stack already traced, too late
		}
	}
}

// stackPtrCheckClog finds stack-pointer clogs -- a stack-pointer addition whose
// amount was loaded from the stack -- and hands them to repair.
// C++ parity: ActionStackPtrFlow::checkClog.
func stackPtrCheckClog(data *Funcdata, id *address.Space) int {
	point := id.GetSpacebase(0)
	spacebase := address.Address{Space: point.Space, Offset: point.Offset}
	vns := data.GetVarnodeBank().LocExact(spacebase, point.Size)
	clogcount := 0
	if len(vns) == 0 {
		return clogcount
	}
	spcbasein := vns[0]
	if !spcbasein.IsInput() {
		return clogcount
	}
	for _, outvn := range vns[1:] {
		if !outvn.IsWritten() {
			continue
		}
		addop := outvn.Def()
		if addop.Code() != CPUI_INT_ADD {
			continue
		}
		y := addop.Input(1)
		if !y.IsWritten() {
			continue // y must not be a constant
		}
		x := addop.Input(0)
		if _, ok := stackPtrIsStackRelative(spcbasein, x); !ok {
			x, y = y, addop.Input(0)
			if _, ok := stackPtrIsStackRelative(spcbasein, x); !ok {
				continue
			}
		}
		loadop := y.Def()
		if loadop.Code() == CPUI_INT_MULT { // Multiply by -1
			constvn := loadop.Input(1)
			if !constvn.IsConstant() || constvn.Offset() != sizeMask(constvn.Size()) {
				continue
			}
			y = loadop.Input(0)
			if !y.IsWritten() {
				continue
			}
			loadop = y.Def()
		}
		if loadop.Code() != CPUI_LOAD {
			continue
		}
		constz, ok := stackPtrIsStackRelative(spcbasein, loadop.Input(1))
		if !ok {
			continue
		}
		clogcount += stackPtrRepair(data, id, spcbasein, loadop, constz)
	}
	return clogcount
}
