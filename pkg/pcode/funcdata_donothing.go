package pcode

// Block-removal data-flow surgery for do-nothing (marker-only) blocks.
// C++ parity: funcdata_block.cc (pushMultiequals, opZeroMulti,
// descendantsOutside, blockRemoveInternal, removeDoNothingBlock).

// pushMultiequals forces any Varnode defined by a MULTIEQUAL in bb to be
// (re)defined in bb's single output block, patching data flow before bb is
// removed. Readers of such a Varnode that live beyond the out-block get an
// artificial MULTIEQUAL constructed in the out-block so their data flow is
// preserved once bb disappears.
// C++ parity: Funcdata::pushMultiequals (funcdata_block.cc:84)
func (fd *Funcdata) pushMultiequals(bb *BlockBasic) {
	if bb.SizeOut() == 0 {
		return
	}
	// C++ warns on sizeOut()>1; a do-nothing block always has exactly one out,
	// so that case is not exercised here.
	outblock := asBasic(bb.OutEdge(0).Point)
	outblockInd := bb.OutRevIndex(0) // index of bb into outblock's in-edges

	for _, origop := range bb.opSlice() {
		if origop.Code() != CPUI_MULTIEQUAL {
			continue
		}
		origvn := origop.Output()
		if origvn.HasNoDescend() {
			continue
		}
		needreplace := false
		neednewunique := false
		for _, op := range origvn.DescendIter() {
			if op.Code() == CPUI_MULTIEQUAL && op.Parent() == outblock {
				deadEdge := true // reference to origvn NOT through the dead edge?
				for i := 0; i < op.NumInput(); i++ {
					if i == outblockInd {
						continue // going through the dead edge
					}
					if op.Input(i) == origvn {
						deadEdge = false
						break
					}
				}
				if deadEdge {
					// origvn addrtied and feeding a same-address MULTIEQUAL in
					// outblock: any use beyond outblock that skipped this
					// MULTIEQUAL must have propagated through another register,
					// so the replacement MULTIEQUAL writes to a fresh unique.
					if origvn.Addr() == op.Output().Addr() && origvn.IsAddrTied() {
						neednewunique = true
					}
					continue
				}
			}
			needreplace = true
			break
		}
		if !needreplace {
			continue
		}

		// Construct the artificial MULTIEQUAL in outblock.
		var replacevn *Varnode
		if neednewunique {
			replacevn = fd.NewUnique(origvn.Size())
		} else {
			replacevn = fd.NewVarnode(origvn.Size(), origvn.Addr())
		}
		branches := make([]*Varnode, 0, outblock.SizeIn())
		for i := 0; i < outblock.SizeIn(); i++ {
			// The only in-edge from bb carries origvn; all other in-edges are
			// dominated by bb, so they too resolve to origvn's value, which is
			// carried by replacevn (the new MULTIEQUAL's output).
			if outblock.InEdge(i).Point == &bb.FlowBlock {
				branches = append(branches, origvn)
			} else {
				branches = append(branches, replacevn)
			}
		}
		startAddr := origop.Addr()
		if f := outblock.FirstOp(); f != nil {
			startAddr = f.Addr()
		}
		replaceop := fd.NewOp(len(branches), startAddr)
		fd.OpSetOpcode(replaceop, CPUI_MULTIEQUAL)
		fd.OpSetOutput(replaceop, replacevn)
		fd.OpSetAllInput(replaceop, branches)
		fd.OpInsertBegin(replaceop, outblock)

		// Replace obsolete origvn with replacevn in all readers, except the dead
		// edge slot of the just-created MULTIEQUAL. Snapshot the descend list
		// (now including replaceop) so mutation during the walk is safe.
		for _, op := range origvn.DescendIter() {
			for i := 0; i < op.NumInput(); i++ {
				if op.Input(i) != origvn {
					continue
				}
				if i == outblockInd && op.Parent() == outblock && op.Code() == CPUI_MULTIEQUAL {
					continue // keep origvn on the dead edge of replaceop
				}
				fd.OpSetInput(op, replacevn, i)
				break
			}
		}
	}
}

// opZeroMulti collapses a MULTIEQUAL that has lost inputs. With no inputs left
// the block is presumably unreachable and the op becomes a COPY from a fresh
// input Varnode; with a single input it becomes a plain COPY.
// C++ parity: Funcdata::opZeroMulti (funcdata_block.cc:177)
func (fd *Funcdata) opZeroMulti(op *PcodeOp) {
	switch op.NumInput() {
	case 0:
		vn := fd.NewVarnode(op.Output().Size(), op.Output().Addr())
		fd.OpInsertInput(op, vn, 0)
		fd.SetInputVarnode(op.Input(0))
		fd.OpSetOpcode(op, CPUI_COPY)
	case 1:
		fd.OpSetOpcode(op, CPUI_COPY)
	}
}

// descendantsOutside reports whether vn is read by any op living in a block that
// is NOT marked dead. Used as a safety invariant while destroying a block's ops.
// C++ parity: Funcdata::descendantsOutside (funcdata_block.cc:233)
func (fd *Funcdata) descendantsOutside(vn *Varnode) bool {
	for _, op := range vn.DescendIter() {
		if p := op.Parent(); p == nil || !p.IsDead() {
			return true
		}
	}
	return false
}

// blockRemoveInternal removes an active basic block, deleting its PcodeOps and
// patching up data-flow and control-flow. Most of the work is fixing up
// MULTIEQUAL ops and other references to Varnodes flowing through bb.
// C++ parity: Funcdata::blockRemoveInternal (funcdata_block.cc:254)
func (fd *Funcdata) blockRemoveInternal(bb *BlockBasic, unreachable bool) {
	last := bb.LastOp()
	if last != nil && last.Code() == CPUI_BRANCHIND {
		// C++ removes the associated jump table here. Not reachable from
		// removeDoNothingBlock (do-nothing blocks never end in BRANCHIND); jump
		// table removal is left unimplemented until the unreachable path is wired.
		_ = fd.FindJumpTable(last)
	}

	if !unreachable {
		fd.pushMultiequals(bb) // preserve data flow before edges are cut

		for i := 0; i < bb.SizeOut(); i++ {
			bbout := asBasic(bb.OutEdge(i).Point)
			if bbout.IsDead() {
				continue
			}
			blocknum := bbout.GetInIndex(&bb.FlowBlock) // index of bb into bbout
			for _, op := range bbout.opSlice() {
				if op.Code() != CPUI_MULTIEQUAL {
					continue
				}
				deadvn := op.Input(blocknum)
				fd.OpRemoveInput(op, blocknum) // remove the deleted block's branch
				deadop := deadvn.Def()
				if deadvn.IsWritten() && deadop.Code() == CPUI_MULTIEQUAL && deadop.Parent() == bb {
					// Splice in bb's own MULTIEQUAL branches.
					for j := 0; j < bb.SizeIn(); j++ {
						fd.OpInsertInput(op, deadop.Input(j), op.NumInput())
					}
				} else {
					// Otherwise duplicate deadvn once per bb in-edge.
					for j := 0; j < bb.SizeIn(); j++ {
						fd.OpInsertInput(op, deadvn, op.NumInput())
					}
				}
				fd.opZeroMulti(op)
			}
		}
	}

	fd.GetBasicBlocks().removeFromFlow(&bb.FlowBlock)

	// Finally destroy every op in bb. Snapshot first: OpDestroy removes each op
	// from bb's op list.
	for _, op := range bb.Ops() {
		if op.IsAssignment() { // op still owns an output Varnode
			deadvn := op.Output()
			// The unreachable path would mark stranded descendants undefined
			// (descend2Undef); not wired here since removeDoNothingBlock passes
			// unreachable=false.
			if fd.descendantsOutside(deadvn) { // descendants outside bb -> invariant break
				panic("Deleting op with descendants")
			}
		}
		// C++ deletes call specs for call ops here; do-nothing blocks contain
		// only marker/branch ops, so no call ever reaches this point.
		fd.OpDestroy(op)
	}
	fd.GetBasicBlocks().RemoveBlock(&bb.FlowBlock) // remove the block altogether
}

// RemoveDoNothingBlock removes a marker-only block (MULTIEQUAL/INDIRECT plus at
// most a single unconditional branch) from control-flow and data-flow, forcing a
// reset of the control-flow structuring hierarchy.
// C++ parity: Funcdata::removeDoNothingBlock (funcdata_block.cc:327)
func (fd *Funcdata) RemoveDoNothingBlock(bb *BlockBasic) {
	if bb.SizeOut() > 1 {
		panic("Cannot delete a reachable block unless it has 1 out or less")
	}
	bb.SetDead()
	fd.blockRemoveInternal(bb, false)
	fd.StructureReset() // delete any structure we had before
}
