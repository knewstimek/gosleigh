package pcode

import "gosleigh/pkg/address"

// ancestorRealistic determines whether a Varnode (read as a particular input to a
// CALL, CALLIND, or RETURN op) makes sense as parameter-passing or return-value
// storage by a depth-first backward traversal of its ancestors. A varnode whose
// ancestry traces only to unaffected/abnormal inputs or killedbycall storage is a
// sign of artificial data-flow, not a real parameter/return.
//
// C++ parity: funcdata.hh / funcdata_varnode.cc class AncestorRealistic.
type ancestorRealistic struct {
	trial            *ParamTrial   // current trial being analyzed
	stateStack       []arState     // depth-first traversal stack
	markedVn         []*Varnode    // visited varnodes, for cycle trimming
	multiDepth       int           // number of MULTIEQUAL ops on the current path
	allowFailingPath bool          // allow/test failing paths from conditional execution
}

// State flag bits. C++ parity: AncestorRealistic::State enum.
const (
	arSeenSolid0 = 1 // solid movement into the varnode on at least one path to MULTIEQUAL
	arSeenSolid1 = 2 // solid movement into anything other than slot 0
	arSeenKill   = 4 // killedbycall on at least one path to MULTIEQUAL
)

// Traversal commands. C++ parity: AncestorRealistic enum (enter_node..pop_failkill).
const (
	arEnterNode = iota
	arPopSuccess
	arPopSolid
	arPopFail
	arPopFailkill
)

// arState is a node in the depth-first ancestor traversal.
// vn = op.Input(slot). C++ parity: AncestorRealistic::State.
type arState struct {
	op     *PcodeOp
	slot   int
	flags  uint32
	offset int // offset of the (eventual) trial value within a possibly larger register
}

func (s *arState) getSolidSlot() int {
	if s.flags&arSeenSolid0 != 0 {
		return 0
	}
	return 1
}

func (s *arState) markSolid(slot int) {
	if slot == 0 {
		s.flags |= arSeenSolid0
	} else {
		s.flags |= arSeenSolid1
	}
}

func (s *arState) markKill()        { s.flags |= arSeenKill }
func (s *arState) seenSolid() bool  { return s.flags&(arSeenSolid0|arSeenSolid1) != 0 }
func (s *arState) seenKill() bool   { return s.flags&arSeenKill != 0 }

// newARStateSubpiece builds a state pulled back through a CPUI_SUBPIECE: the data in
// the SUBPIECE output originates at a non-zero offset within the input varnode.
// C++ parity: AncestorRealistic::State::State(PcodeOp*, const State&).
func newARStateSubpiece(op *PcodeOp, old arState) arState {
	return arState{
		op:     op,
		slot:   0,
		offset: old.offset + int(op.Input(1).Offset()),
	}
}

// mark records vn as visited so cycles are trimmed during traversal.
func (ar *ancestorRealistic) mark(vn *Varnode) {
	ar.markedVn = append(ar.markedVn, vn)
	vn.SetMark()
}

// enterNode analyzes the node that has just entered the traversal and returns the
// next traversal command (push enter_node, or one of the pop_* results).
// C++ parity: AncestorRealistic::enterNode.
func (ar *ancestorRealistic) enterNode() int {
	state := ar.stateStack[len(ar.stateStack)-1]
	// If already visited, truncate to prevent cycles; assume the proper result is
	// returned along the first path.
	stateVn := state.op.Input(state.slot)
	if stateVn.IsMark() {
		return arPopSuccess
	}
	if !stateVn.IsWritten() {
		if stateVn.IsInput() {
			if stateVn.IsUnaffected() {
				return arPopFail
			}
			if stateVn.IsPersist() {
				return arPopSuccess // global input, valid possibility
			}
			if !stateVn.IsDirectWrite() {
				return arPopFail
			}
		}
		return arPopSuccess // probably a normal parameter, valid
	}
	ar.mark(stateVn)
	op := stateVn.Def()
	switch op.Code() {
	case CPUI_INDIRECT:
		if op.IsIndirectCreation() { // backtracking stopped by a call
			ar.trial.SetIndCreateFormed()
			if op.Input(0).IsIndirectZero() { // true only if not a possible output
				return arPopFailkill // truncate, indicating killedbycall
			}
			return arPopSuccess
		}
		if !op.IsIndirectStore() { // flow goes THROUGH a call
			if op.Output().IsReturnAddress() {
				return arPopFail // storage address location is completely invalid
			}
			if ar.trial.IsKilledByCall() {
				return arPopFail // "likely" killedbycall is invalid
			}
		}
		ar.stateStack = append(ar.stateStack, arState{op: op, slot: 0})
		return arEnterNode
	case CPUI_SUBPIECE:
		out := op.Output()
		in0 := op.Input(0)
		// Extracting to a temporary, to the same storage location, or otherwise
		// incidental is just another node on the path.
		if (out.Space() != nil && out.Space().Kind == address.SpaceKindUnique) ||
			op.IsIncidentalCopy() || in0.IsIncidentalCopy() ||
			out.Overlap(in0) == int(op.Input(1).Offset()) {
			ar.stateStack = append(ar.stateStack, newARStateSubpiece(op, state))
			return arEnterNode
		}
		// For other SUBPIECEs, do a minimal traversal to rule out unaffected or
		// invalid inputs, but otherwise treat as valid, active movement.
		for {
			vn := op.Input(0)
			if !vn.IsMark() && vn.IsInput() {
				if vn.IsUnaffected() || !vn.IsDirectWrite() {
					return arPopFail
				}
			}
			op = vn.Def()
			if op == nil || (op.Code() != CPUI_COPY && op.Code() != CPUI_SUBPIECE) {
				break
			}
		}
		return arPopSolid
	case CPUI_COPY:
		out := op.Output()
		in0 := op.Input(0)
		// Copies to a temporary, between varnodes with same storage, or otherwise
		// incidental are just another node on the path.
		if (out.Space() != nil && out.Space().Kind == address.SpaceKindUnique) ||
			op.IsIncidentalCopy() || in0.IsIncidentalCopy() ||
			out.Addr() == in0.Addr() {
			ar.stateStack = append(ar.stateStack, arState{op: op, slot: 0})
			return arEnterNode
		}
		// For other COPIES, minimal traversal then treat as solid movement.
		vn := op.Input(0)
		for {
			if !vn.IsMark() && vn.IsInput() {
				if !vn.IsDirectWrite() {
					return arPopFail
				}
			}
			if op.IsStoreUnmapped() {
				return arPopFail
			}
			op = vn.Def()
			if op == nil {
				break
			}
			switch op.Code() {
			case CPUI_COPY, CPUI_SUBPIECE:
				vn = op.Input(0)
			case CPUI_PIECE:
				vn = op.Input(1) // follow least significant piece
			default:
				op = nil
			}
			if op == nil {
				break
			}
		}
		return arPopSolid
	case CPUI_MULTIEQUAL:
		ar.multiDepth++
		ar.stateStack = append(ar.stateStack, arState{op: op, slot: 0})
		return arEnterNode // start traversing inputs of MULTIEQUAL
	case CPUI_PIECE:
		if stateVn.Size() > ar.trial.GetSize() { // did we already pull-back from a SUBPIECE?
			// If the trial is pieced together and then truncated in a register,
			// this is evidence of artificial data-flow.
			if state.offset == 0 && op.Input(1).Size() <= ar.trial.GetSize() {
				// Truncation corresponds to least significant piece, follow slot=1.
				ar.stateStack = append(ar.stateStack, arState{op: op, slot: 1})
				return arEnterNode
			} else if state.offset == int(op.Input(1).Size()) && op.Input(0).Size() <= ar.trial.GetSize() {
				// Truncation corresponds to most significant piece, follow slot=0.
				ar.stateStack = append(ar.stateStack, arState{op: op, slot: 0})
				return arEnterNode
			}
			if stateVn.Space() == nil || stateVn.Space().Kind != address.SpaceKindStack {
				return arPopFail
			}
		}
		return arPopSolid
	default:
		return arPopSolid // any other LOAD or arith/logical op is solid movement
	}
}

// uponPop backtracks into a previously visited node, given the type of pop being
// performed, and returns the next command (push or pop).
// C++ parity: AncestorRealistic::uponPop.
func (ar *ancestorRealistic) uponPop(popCommand int) int {
	top := len(ar.stateStack) - 1
	state := &ar.stateStack[top]
	if state.op.Code() == CPUI_MULTIEQUAL { // all interesting action is at MULTIEQUAL branch points
		prevstate := &ar.stateStack[top-1]
		if popCommand == arPopFail { // always pop and pass along the fail
			ar.multiDepth--
			ar.stateStack = ar.stateStack[:top]
			return popCommand
		} else if popCommand == arPopSolid && ar.multiDepth == 1 && state.op.NumInput() == 2 {
			prevstate.markSolid(state.slot) // a "solid" that could override a "failkill"
		} else if popCommand == arPopFailkill {
			prevstate.markKill() // failkill along at least one path of MULTIEQUAL
		}
		state.slot++ // move to the next sibling
		if state.slot == state.op.NumInput() { // traversed all siblings
			if prevstate.seenSolid() { // an overriding "solid" along at least one path
				popCommand = arPopSuccess // always a success...
				if prevstate.seenKill() { // ...UNLESS we have seen a failkill
					if ar.allowFailingPath {
						if !ar.checkConditionalExe(state) { // not attributable to conditional execution
							popCommand = arPopFail
						} else {
							ar.trial.SetCondExeEffect() // slate for additional testing
						}
					} else {
						popCommand = arPopFail
					}
				}
			} else if prevstate.seenKill() { // failkill without solid movement
				popCommand = arPopFailkill // always a failure
			} else {
				popCommand = arPopSuccess // neither solid nor failkill is still a success
			}
			ar.multiDepth--
			ar.stateStack = ar.stateStack[:top]
			return popCommand
		}
		return arEnterNode
	}
	ar.stateStack = ar.stateStack[:top]
	return popCommand
}

// checkConditionalExe reports whether there are two input flows, one of which is a
// normal solid flow (the path can be attributed to conditional execution).
// Only reached when allowFailingPath is true. C++ parity:
// AncestorRealistic::checkConditionalExe.
func (ar *ancestorRealistic) checkConditionalExe(state *arState) bool {
	bl := state.op.Parent()
	if bl == nil || bl.SizeIn() != 2 {
		return false
	}
	solidBlock := bl.getIn(state.getSolidSlot())
	if solidBlock == nil || solidBlock.SizeOut() != 1 {
		return false
	}
	return true
}

// execute performs a full ancestor check on a parameter/return trial. op is the
// CALL or RETURN, slot the input index, t the corresponding trial, allowFail whether
// failing paths from conditional execution are allowed. Returns true if the varnode
// has realistic ancestors for a parameter/return location.
// C++ parity: AncestorRealistic::execute.
func (ar *ancestorRealistic) execute(op *PcodeOp, slot int, t *ParamTrial, allowFail bool) bool {
	ar.trial = t
	ar.allowFailingPath = allowFail
	ar.markedVn = ar.markedVn[:0]
	ar.stateStack = ar.stateStack[:0]
	ar.multiDepth = 0
	// If the parameter itself is an input, we don't consider this realistic; we
	// expect active movement into the parameter. This is rare to violate and a
	// failure here does not preclude later analysis from declaring it a parameter.
	if op.Input(slot).IsInput() {
		if !ar.trial.HasCondExeEffect() { // make sure we are not retesting
			return false
		}
	}
	command := arEnterNode
	ar.stateStack = append(ar.stateStack, arState{op: op, slot: slot})
	for len(ar.stateStack) > 0 {
		switch command {
		case arEnterNode:
			command = ar.enterNode()
		case arPopSuccess, arPopSolid, arPopFail, arPopFailkill:
			command = ar.uponPop(command)
		}
	}
	for _, vn := range ar.markedVn {
		vn.ClearMark()
	}
	if command == arPopSuccess {
		ar.trial.SetAncestorRealistic()
		return true
	} else if command == arPopSolid {
		ar.trial.SetAncestorRealistic()
		ar.trial.SetAncestorSolid()
		return true
	}
	return false
}
