// Copyright 2026 The Gosleigh Authors
// Licensed under the Apache License, Version 2.0.

package pcode

import "gosleigh/pkg/address"

// Indexed stack access guards. A LOAD or STORE whose pointer is the stack
// pointer plus a non-constant index (or a MULTIEQUAL of such) may touch any
// stack location in a range. Heritage records a LoadGuard for each, uses value
// set analysis to bound the range, and places COPY guards (LOAD) or INDIRECTs
// (STORE) on stack locations inside it.
// C++ parity: heritage.cc LoadGuard, Heritage::discoverIndexedStackPointers,
// generateLoadGuard, generateStoreGuard, analyzeNewLoadGuards, guardLoads,
// handleNewLoadCopies, reprocessFreeStores.

// stackNode is one element of the path from the stack pointer to a
// LOAD/STORE. C++ parity: Heritage::StackNode.
type stackNode struct {
	vn         *Varnode
	offset     uint64
	traversals uint32
	pos        int // Next descendant to visit
}

const (
	stackNodeNonconstantIndex uint32 = 1
	stackNodeMultiequal       uint32 = 2
)

func (n *stackNode) done() bool { return n.pos >= len(n.vn.descend) }

// wrapStackOffset wraps an offset into the space.
// C++ parity: AddrSpace::wrapOffset (power-of-two sized spaces).
func wrapStackOffset(spc *address.Space, off uint64) uint64 {
	return off & spaceHighestOffset(spc)
}

// opMarkSpacebasePtr / opClearSpacebasePtr: C++ parity Funcdata methods.
func opMarkSpacebasePtr(op *PcodeOp)  { op.SetFlag(PcodeOpSpacebasePtr) }
func opClearSpacebasePtr(op *PcodeOp) { op.ClearFlag(PcodeOpSpacebasePtr) }

// newLoadGuard is an unanalyzed guard that initially guards everything.
// C++ parity: LoadGuard::set.
func newLoadGuard(op *PcodeOp, spc *address.Space, off uint64) LoadGuard {
	return LoadGuard{Op: op, Spc: spc, PointerBase: off, MaximumOffset: spaceHighestOffset(spc)}
}

// establishRange turns a partial value set analysis into a guard range.
// C++ parity: LoadGuard::establishRange.
func (lg *LoadGuard) establishRange(vs *valueSetRead) {
	rng := &vs.rng
	rangeSize := rng.getSize()
	var size uint64
	switch {
	case rng.isEmpty():
		lg.MinimumOffset = lg.PointerBase
		size = 0x1000
	case rng.isFull() || rangeSize > 0xffffff:
		lg.MinimumOffset = lg.PointerBase
		size = 0x1000
		lg.AnalysisState = 1 // Don't bother doing more analysis
	default:
		lg.Step = 0
		if rangeSize == 3 { // Check for consistent step
			lg.Step = int32(rng.getStep())
		}
		size = 0x1000
		switch {
		case vs.leftIsStable:
			lg.MinimumOffset = rng.getMin()
		case vs.rightIsStable:
			if lg.PointerBase < rng.getEnd() {
				lg.MinimumOffset = lg.PointerBase
				size = rng.getEnd() - lg.PointerBase
			} else {
				lg.MinimumOffset = rng.getMin()
				size = rangeSize * uint64(rng.getStep())
			}
		default:
			lg.MinimumOffset = lg.PointerBase
		}
	}
	max := spaceHighestOffset(lg.Spc)
	if lg.MinimumOffset > max {
		lg.MinimumOffset = max
		lg.MaximumOffset = lg.MinimumOffset // Something is seriously wrong
		return
	}
	if maxSize := max - lg.MinimumOffset + 1; size > maxSize {
		size = maxSize
	}
	lg.MaximumOffset = lg.MinimumOffset + size - 1
}

// finalizeRange turns the full value set analysis into the final range.
// C++ parity: LoadGuard::finalizeRange.
func (lg *LoadGuard) finalizeRange(vs *valueSetRead) {
	lg.AnalysisState = 1 // In all cases the settings determined here are final
	rng := &vs.rng
	rangeSize := rng.getSize()
	if (rangeSize == 0x100 || rangeSize == 0x10000) && lg.Step == 0 {
		// These sizes likely come from the index's storage size; without
		// signs of iteration, don't use the range
		rangeSize = 0
	}
	if rangeSize > 1 && rangeSize < 0xffffff { // Converged to something reasonable
		lg.AnalysisState = 2
		if rangeSize > 2 {
			lg.Step = int32(rng.getStep())
		}
		lg.MinimumOffset = rng.getMin()
		lg.MaximumOffset = (rng.getEnd() - 1) & rng.getMask() // Don't subtract a whole step
		if lg.MaximumOffset < lg.MinimumOffset { // Values extend into stack parameters
			lg.MaximumOffset = spaceHighestOffset(lg.Spc)
			lg.AnalysisState = 1 // Remove the lock as we have likely overflowed
		}
	}
	highest := spaceHighestOffset(lg.Spc)
	lg.MinimumOffset = min(lg.MinimumOffset, highest)
	lg.MaximumOffset = min(lg.MaximumOffset, highest)
}

// generateLoadGuard records an indexed LOAD from the stack.
// C++ parity: Heritage::generateLoadGuard.
func (h *Heritage) generateLoadGuard(node *stackNode, op *PcodeOp, spc *address.Space) {
	if !op.UsesSpacebasePtr() {
		h.loadGuards = append(h.loadGuards, newLoadGuard(op, spc, node.offset))
		opMarkSpacebasePtr(op)
	}
}

// generateStoreGuard records an indexed STORE to the stack.
// C++ parity: Heritage::generateStoreGuard.
func (h *Heritage) generateStoreGuard(node *stackNode, op *PcodeOp, spc *address.Space) {
	if !op.UsesSpacebasePtr() {
		h.storeGuards = append(h.storeGuards, newLoadGuard(op, spc, node.offset))
		opMarkSpacebasePtr(op)
	}
}

// protectFreeStores marks STOREs whose pointer is a free Varnode of spc
// (through COPY / INT_ADD-constant) as spacebase STOREs, reporting any.
// C++ parity: Heritage::protectFreeStores.
func (h *Heritage) protectFreeStores(spc *address.Space, freeStores *[]*PcodeOp) bool {
	hasNew := false
	for _, op := range h.fd.GetPcodeOpBank().AliveOps() {
		if op.Code() != CPUI_STORE || op.IsDead() {
			continue
		}
		vn := op.Input(1)
		for vn.IsWritten() {
			defOp := vn.Def()
			if defOp.Code() == CPUI_COPY || (defOp.Code() == CPUI_INT_ADD && defOp.Input(1).IsConstant()) {
				vn = defOp.Input(0)
				continue
			}
			break
		}
		if vn.IsFree() && vn.Space() == spc {
			opMarkSpacebasePtr(op) // Mark as spacebase STORE, even though we're not sure
			*freeStores = append(*freeStores, op)
			hasNew = true
		}
	}
	return hasNew
}

// discoverIndexedStackPointers walks forward from the stack pointer to
// LOADs/STOREs through an indexed address and guards them. It reports
// incomplete STOREs (collected in freeStores) when checkFreeStores is set.
// C++ parity: Heritage::discoverIndexedStackPointers.
func (h *Heritage) discoverIndexedStackPointers(spc *address.Space, freeStores *[]*PcodeOp, checkFreeStores bool) bool {
	// Varnodes are marked independently of the depth first path to avoid
	// exponential ladders
	var markedVn []*Varnode
	var path []stackNode
	unknownStackStorage := false
	follow := func(outVn *Varnode, offset uint64, traversals uint32) {
		next := stackNode{vn: outVn, offset: offset, traversals: traversals}
		if !next.done() {
			outVn.SetMark()
			path = append(path, next)
			markedVn = append(markedVn, outVn)
		} else if outVn.Space() != nil && outVn.Space().Kind == address.SpaceKindStack {
			unknownStackStorage = true
		}
	}
	for i := 0; i < spc.NumSpacebase(); i++ {
		sp := spc.GetSpacebase(i)
		spInput := h.fd.FindVarnodeInput(sp.Size, address.Address{Space: sp.Space, Offset: sp.Offset})
		if spInput == nil {
			continue
		}
		path = append(path, stackNode{vn: spInput})
		for len(path) > 0 {
			cur := &path[len(path)-1]
			if cur.done() {
				path = path[:len(path)-1]
				continue
			}
			op := cur.vn.descend[cur.pos]
			cur.pos++
			curVn, curOffset, curTrav := cur.vn, cur.offset, cur.traversals
			outVn := op.Output()
			if outVn != nil && outVn.IsMark() {
				continue // Don't revisit Varnodes
			}
			switch op.Code() {
			case CPUI_INT_ADD:
				otherVn := op.Input(1 - op.GetSlot(curVn))
				if otherVn.IsConstant() {
					follow(outVn, wrapStackOffset(spc, curOffset+otherVn.Offset()), curTrav)
				} else {
					follow(outVn, curOffset, curTrav|stackNodeNonconstantIndex)
				}
			case CPUI_SEGMENTOP:
				if op.Input(2) != curVn {
					break // The stack pointer must come in as the inner pointer
				}
				follow(outVn, curOffset, curTrav) // Same offset, like COPY
			case CPUI_INDIRECT, CPUI_COPY:
				follow(outVn, curOffset, curTrav)
			case CPUI_MULTIEQUAL:
				follow(outVn, curOffset, curTrav|stackNodeMultiequal)
			case CPUI_LOAD:
				// If ANY path has a traversal then THIS path has one, as the
				// other path elements have only one path through
				if curTrav != 0 {
					h.generateLoadGuard(&stackNode{offset: curOffset}, op, spc)
				}
			case CPUI_STORE:
				if op.Input(1) == curVn { // The STORE pointer comes from our path
					if curTrav != 0 {
						h.generateStoreGuard(&stackNode{offset: curOffset}, op, spc)
					} else {
						// Stack pointer plus a constant: likely resolved next pass,
						// but keep the mark so the INDIRECTs aren't removed
						opMarkSpacebasePtr(op)
					}
				}
			}
		}
	}
	for _, vn := range markedVn {
		vn.ClearMark()
	}
	if unknownStackStorage && checkFreeStores {
		return h.protectFreeStores(spc, freeStores)
	}
	return false
}

// reprocessFreeStores regenerates the STORE guards after a heritage pass and
// removes the INDIRECTs of free STOREs that did not need one.
// C++ parity: Heritage::reprocessFreeStores.
func (h *Heritage) reprocessFreeStores(spc *address.Space, freeStores []*PcodeOp) {
	for _, op := range freeStores {
		opClearSpacebasePtr(op)
	}
	h.discoverIndexedStackPointers(spc, &freeStores, false)
	for _, op := range freeStores {
		if op.UsesSpacebasePtr() {
			continue // Marked appropriately to begin with
		}
		// The STORE may have triggered unnecessary INDIRECTs
		indOp := op.PreviousOp()
		for indOp != nil && indOp.Code() == CPUI_INDIRECT {
			if indOp.Input(1).GetIndirectCause() != op {
				break
			}
			nextOp := indOp.PreviousOp()
			if indOp.Output().Space() == spc {
				h.fd.TotalReplace(indOp.Output(), indOp.Input(0))
				h.fd.OpDestroy(indOp) // Get rid of the INDIRECT
			}
			indOp = nextOp
		}
	}
}

// analyzeNewLoadGuards runs value set analysis on the guards added this pass
// to settle the stack range each may touch.
// C++ parity: Heritage::analyzeNewLoadGuards.
func (h *Heritage) analyzeNewLoadGuards() {
	nothingToDo := true
	if n := len(h.loadGuards); n > 0 && h.loadGuards[n-1].AnalysisState == 0 {
		nothingToDo = false
	}
	if n := len(h.storeGuards); n > 0 && h.storeGuards[n-1].AnalysisState == 0 {
		nothingToDo = false
	}
	if nothingToDo {
		return
	}
	var sinks []*Varnode
	var reads []*PcodeOp
	loadStart := len(h.loadGuards)
	for loadStart > 0 && h.loadGuards[loadStart-1].AnalysisState == 0 {
		loadStart--
		reads = append(reads, h.loadGuards[loadStart].Op)
		sinks = append(sinks, h.loadGuards[loadStart].Op.Input(1)) // The LOAD pointer
	}
	storeStart := len(h.storeGuards)
	for storeStart > 0 && h.storeGuards[storeStart-1].AnalysisState == 0 {
		storeStart--
		reads = append(reads, h.storeGuards[storeStart].Op)
		sinks = append(sinks, h.storeGuards[storeStart].Op.Input(1)) // The STORE pointer
	}
	var stackReg *Varnode
	if stackSpc := h.fd.stackSpace(); stackSpc != nil && stackSpc.NumSpacebase() > 0 {
		stackReg = h.fd.findSpacebaseInput(stackSpc)
	}
	solver := newValueSetSolver()
	solver.establishValueSets(sinks, reads, stackReg, false)
	solver.solve(10000, newValueSetWidenerNone())
	newGuards := func() []*LoadGuard {
		var res []*LoadGuard
		for i := loadStart; i < len(h.loadGuards); i++ {
			res = append(res, &h.loadGuards[i])
		}
		for i := storeStart; i < len(h.storeGuards); i++ {
			res = append(res, &h.storeGuards[i])
		}
		return res
	}
	runFullAnalysis := false
	for _, guard := range newGuards() {
		guard.establishRange(solver.readNode(guard.Op))
		if guard.AnalysisState == 0 {
			runFullAnalysis = true
		}
	}
	if runFullAnalysis {
		solver.solve(10000, newValueSetWidenerFull())
		for _, guard := range newGuards() {
			guard.finalizeRange(solver.readNode(guard.Op))
		}
	}
	for _, vs := range solver.valueNodes {
		vs.vn.valueSet = nil
	}
}

// guardLoads puts a COPY guard for [addr,addr+size) before every guarded
// LOAD whose range holds addr.
// C++ parity: Heritage::guardLoads.
func (h *Heritage) guardLoads(fl uint32, addr address.Address, size int32) {
	if fl&VarnodeAddrTied == 0 {
		return // Not address tied: not considered for index alias
	}
	kept := h.loadGuards[:0]
	for _, guardRec := range h.loadGuards {
		if !guardRec.IsValid(CPUI_LOAD) {
			continue
		}
		kept = append(kept, guardRec)
		if guardRec.Spc != addr.Space || addr.Offset < guardRec.MinimumOffset || addr.Offset > guardRec.MaximumOffset {
			continue
		}
		copyop := h.fd.NewOp(1, guardRec.Op.Addr())
		vn := h.fd.NewVarnodeOut(size, addr, copyop)
		vn.SetActiveHeritage()
		vn.SetFlags(VarnodeAddrForce)
		h.fd.OpSetOpcode(copyop, CPUI_COPY)
		invn := h.fd.NewVarnode(size, addr)
		invn.SetActiveHeritage()
		h.fd.OpSetInput(copyop, invn, 0)
		h.fd.OpInsertBefore(copyop, guardRec.Op)
		h.loadCopyOps = append(h.loadCopyOps, copyop)
	}
	h.loadGuards = kept
}

// findAddressForces finds the last non-artificial writers whose values flow
// to the COPY sinks only through artificial COPY/MULTIEQUAL/INDIRECTs. Sinks
// grow with the artificial ops met; every op met is marked.
// C++ parity: Heritage::findAddressForces.
func findAddressForces(copySinks []*PcodeOp) ([]*PcodeOp, []*PcodeOp) {
	var forces []*PcodeOp
	for _, op := range copySinks {
		op.SetFlag(PcodeOpMark)
	}
	for pos := 0; pos < len(copySinks); pos++ {
		op := copySinks[pos]
		addr := op.Output().Addr() // Address being flowed to
		for i := 0; i < op.NumInput(); i++ {
			vn := op.Input(i)
			if !vn.IsWritten() || vn.IsAddrForce() {
				continue
			}
			newOp := vn.Def()
			if newOp.flags&PcodeOpMark != 0 {
				continue // Already visited
			}
			newOp.SetFlag(PcodeOpMark)
			isArtificial := false
			switch opc := newOp.Code(); {
			case opc == CPUI_COPY || opc == CPUI_MULTIEQUAL:
				isArtificial = true
				for j := 0; j < newOp.NumInput(); j++ {
					if newOp.Input(j).Addr() != addr {
						isArtificial = false
						break
					}
				}
			case opc == CPUI_INDIRECT && newOp.IsIndirectStore():
				// An INDIRECT caused by a STORE is artificial
				isArtificial = newOp.Input(0).Addr() == addr
			}
			if isArtificial {
				copySinks = append(copySinks, newOp)
			} else {
				forces = append(forces, newOp)
			}
		}
	}
	return copySinks, forces
}

// propagateCopyAway replaces a COPY sink's output with the earliest same
// address input and removes it. C++ parity: Heritage::propagateCopyAway.
func (h *Heritage) propagateCopyAway(op *PcodeOp) {
	inVn := op.Input(0)
	for inVn.IsWritten() {
		nextOp := inVn.Def()
		if nextOp.Code() != CPUI_COPY {
			break
		}
		nextIn := nextOp.Input(0)
		if nextIn.Addr() != inVn.Addr() {
			break
		}
		inVn = nextIn
	}
	h.fd.TotalReplace(op.Output(), inVn)
	h.fd.OpDestroy(op)
}

// handleNewLoadCopies address-forces the boundary of the load guard COPYs
// placed this pass, then removes the COPYs.
// C++ parity: Heritage::handleNewLoadCopies.
func (h *Heritage) handleNewLoadCopies() {
	if len(h.loadCopyOps) == 0 {
		return
	}
	copySinkSize := len(h.loadCopyOps)
	sinks, forces := findAddressForces(h.loadCopyOps)
	if len(forces) != 0 {
		inRange := func(a address.Address) bool {
			for i := range h.loadGuards {
				g := &h.loadGuards[i]
				if g.Spc == a.Space && a.Offset >= g.MinimumOffset && a.Offset <= g.MaximumOffset {
					return true
				}
			}
			return false
		}
		// Address force the boundary to prevent dead-code removal
		for _, op := range forces {
			if vn := op.Output(); inRange(vn.Addr()) {
				vn.SetFlags(VarnodeAddrForce)
			}
			op.ClearFlag(PcodeOpMark)
		}
	}
	for _, op := range sinks[:copySinkSize] {
		h.propagateCopyAway(op) // Load guard COPYs no longer exist
	}
	for _, op := range sinks[copySinkSize:] {
		op.ClearFlag(PcodeOpMark)
	}
	h.loadCopyOps = nil
}

// getStoreGuard is the guard of an indexed STORE, or nil.
// C++ parity: Heritage::getStoreGuard.
func (h *Heritage) getStoreGuard(op *PcodeOp) *LoadGuard {
	for i := range h.storeGuards {
		if h.storeGuards[i].Op == op {
			return &h.storeGuards[i]
		}
	}
	return nil
}
