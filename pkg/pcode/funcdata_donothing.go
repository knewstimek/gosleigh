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
	if last := bb.LastOp(); last != nil && last.Code() == CPUI_BRANCHIND {
		if jt := fd.FindJumpTable(last); jt != nil {
			fd.removeJumpTable(jt)
		}
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
	descWarning := false
	for _, op := range bb.Ops() {
		if op.IsAssignment() { // op still owns an output Varnode
			deadvn := op.Output()
			if unreachable && fd.descend2Undef(deadvn) && !descWarning {
				fd.warningHeader("Creating undefined varnodes in (possibly) reachable block")
				descWarning = true
			}
			if fd.descendantsOutside(deadvn) {
				panic("Deleting op with descendants")
			}
		}
		if op.IsCall() {
			fd.deleteCallSpecs(op)
		}
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

// removeFromFlowSplit removes an empty block that splits flow, wiring each
// in-edge straight through to an out-edge (swap pairs in-edge 0 with out-edge
// 1), and resets the structure.
// C++ parity: Funcdata::removeFromFlowSplit.
func (fd *Funcdata) removeFromFlowSplit(bl *BlockBasic, swap bool) {
	if len(bl.Ops()) != 0 {
		panic("Can only split the flow for an empty block")
	}
	bg := fd.GetBasicBlocks()
	bg.removeFromFlowSplit(&bl.FlowBlock, swap)
	bg.RemoveBlock(&bl.FlowBlock)
	fd.StructureReset()
}

// removeJumpTable forgets jt; its switch block is no longer a switch out.
// C++ parity: funcdata_block.cc Funcdata::removeJumpTable.
func (fd *Funcdata) removeJumpTable(jt *JumpTable) {
	remain := fd.jumpTables[:0]
	for _, t := range fd.jumpTables {
		if t != jt {
			remain = append(remain, t)
		}
	}
	fd.jumpTables = remain
	if op := jt.IndirectOp(); op != nil && op.Parent() != nil {
		op.Parent().ClearFlag(BlockFlagSwitchOut)
	}
}

// deleteCallSpecs drops the call specification attached to op.
// C++ parity: funcdata.cc Funcdata::deleteCallSpecs.
func (fd *Funcdata) deleteCallSpecs(op *PcodeOp) {
	for i, fc := range fd.callSpecs {
		if fc.GetOp() == op {
			fd.callSpecs = append(fd.callSpecs[:i], fd.callSpecs[i+1:]...)
			return
		}
	}
}

// descend2Undef replaces every read of vn outside dead blocks with the
// constant 0xBADDEF, routing it through a COPY where the reader cannot hold
// a constant. Returns true if a reader sits in a block with in-edges.
// C++ parity: funcdata_varnode.cc Funcdata::descend2Undef.
func (fd *Funcdata) descend2Undef(vn *Varnode) bool {
	res := false
	sz := vn.Size()
	for _, op := range vn.DescendIter() {
		if op.Parent().IsDead() {
			continue
		}
		if op.Parent().SizeIn() != 0 {
			res = true
		}
		i := op.GetSlot(vn)
		badconst := fd.NewConstant(sz, 0xBADDEF)
		switch op.Code() {
		case CPUI_MULTIEQUAL: // a MULTIEQUAL cannot take a constant
			inbl := asBasic(op.Parent().InEdge(i).Point)
			copyop := fd.NewOp(1, inbl.startAddr())
			inputvn := fd.NewUniqueOut(sz, copyop)
			fd.OpSetOpcode(copyop, CPUI_COPY)
			fd.OpSetInput(copyop, badconst, 0)
			fd.OpInsertEnd(copyop, inbl)
			fd.OpSetInput(op, inputvn, i)
		case CPUI_INDIRECT: // neither can an INDIRECT
			copyop := fd.NewOp(1, op.Addr())
			inputvn := fd.NewUniqueOut(sz, copyop)
			fd.OpSetOpcode(copyop, CPUI_COPY)
			fd.OpSetInput(copyop, badconst, 0)
			fd.OpInsertBefore(copyop, op)
			fd.OpSetInput(op, inputvn, i)
		default:
			fd.OpSetInput(op, badconst, i)
		}
	}
	return res
}
