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

// finalTransform lets every structured block rewrite p-code once, before
// variables are merged. Only while-do loops act: they move their iterator and
// initializer statements to where a for-loop header prints them, so the
// merge sees the live ranges the printed code implies.
// C++ parity: BlockGraph::finalTransform, BlockWhileDo::finalTransform.
func (b *FlowBlock) finalTransform(data *Funcdata) {
	for _, c := range b.StructuredChildren() {
		c.finalTransform(data)
	}
	if b.Type() == BlockWhileDoType {
		if w, ok := b.Concrete().(*BlockWhileDo); ok {
			w.finalTransform(data)
		}
	}
}

// structLastOp is the last op of the block's final basic block.
// C++ parity: FlowBlock::lastOp (BlockGraph/BlockCopy/BlockBasic).
func structLastOp(bl *FlowBlock) *PcodeOp {
	if bb := lastBasicBlock(bl); bb != nil {
		return bb.LastOp()
	}
	return nil
}

// C++ parity: BlockWhileDo::finalTransform.
func (w *BlockWhileDo) finalTransform(data *Funcdata) {
	if w.HasOverflowSyntax() {
		return
	}
	children := w.StructuredChildren()
	if len(children) < 2 {
		return
	}
	cbranch := structLastOp(children[0])
	if cbranch == nil || cbranch.Code() != CPUI_CBRANCH {
		return
	}
	// The front leaf's basic block heads the loop; read it from the op
	// that lives there, since structured leaves wrap the basic blocks.
	front := firstBasicBlock(&w.FlowBlock)
	if front == nil || front.FirstOp() == nil {
		return
	}
	head := front.FirstOp().Parent()
	lastOp := structLastOp(children[1])
	if lastOp == nil || head == nil {
		return
	}
	tail := lastOp.Parent()
	if tail == nil || tail.SizeOut() != 1 || tail.getOut(0) != &head.FlowBlock {
		return
	}
	if lastOp.IsBranch() {
		if lastOp = lastOp.PreviousOp(); lastOp == nil {
			return
		}
	}
	loopDef, iterateOp := whileDoFindLoopVariable(cbranch, head, tail, lastOp)
	if iterateOp == nil {
		return
	}
	if iterateOp != lastOp {
		data.OpUninsert(iterateOp)
		data.OpInsertAfter(iterateOp, lastOp)
	}
	initOp, initLast := whileDoFindInitializer(loopDef, head, tail.OutRevIndex(0))
	if initLast == nil || !initOp.isMoveable(initLast) {
		return
	}
	if initOp != initLast {
		data.OpUninsert(initOp)
		data.OpInsertAfter(initOp, initLast)
	}
}

// whileDoFindLoopVariable looks, at most 4 ops up the loop condition, for a
// head MULTIEQUAL whose back-edge value is computed in the tail by an op
// that can move to the end of the tail. Returns that MULTIEQUAL and op.
// C++ parity: BlockWhileDo::findLoopVariable.
func whileDoFindLoopVariable(cbranch *PcodeOp, head, tail *BlockBasic, lastOp *PcodeOp) (*PcodeOp, *PcodeOp) {
	vn := cbranch.Input(1)
	if !vn.IsWritten() {
		return nil, nil
	}
	op := vn.Def()
	if op.IsCall() || op.IsMarker() {
		return nil, nil
	}
	slot := tail.OutRevIndex(0)
	type node struct {
		op   *PcodeOp
		slot int
	}
	var path [4]node
	count := 0
	path[0] = node{op, 0}
	for count >= 0 {
		cur := &path[count]
		ind := cur.slot
		cur.slot++
		if ind >= cur.op.NumInput() {
			count--
			continue
		}
		nextVn := cur.op.Input(ind)
		if !nextVn.IsWritten() {
			continue
		}
		defOp := nextVn.Def()
		if defOp.Code() == CPUI_MULTIEQUAL {
			if defOp.Parent() != head {
				continue
			}
			itvn := defOp.Input(slot)
			if !itvn.IsWritten() {
				continue
			}
			possibleIterate := itvn.Def()
			if possibleIterate.Parent() == tail {
				if possibleIterate.IsMarker() {
					continue // no iteration in tail
				}
				if !possibleIterate.isMoveable(lastOp) {
					continue // not the final statement
				}
				return defOp, possibleIterate
			}
		} else {
			if count == 3 {
				continue
			}
			if defOp.IsCall() || defOp.IsMarker() {
				continue
			}
			count++
			path[count] = node{defOp, 0}
		}
	}
	return nil, nil
}

// whileDoFindInitializer returns the statement producing the loop variable on
// entry and the point it must move after (the last statement of the block
// flowing into the loop), or nils.
// C++ parity: BlockWhileDo::findInitializer.
func whileDoFindInitializer(loopDef *PcodeOp, head *BlockBasic, slot int) (*PcodeOp, *PcodeOp) {
	if head.SizeIn() != 2 {
		return nil, nil
	}
	slot = 1 - slot
	initVn := loopDef.Input(slot)
	if !initVn.IsWritten() {
		return nil, nil
	}
	res := initVn.Def()
	if res.IsMarker() {
		return nil, nil
	}
	initialBlock := res.Parent()
	if initialBlock == nil || &initialBlock.FlowBlock != head.getIn(slot) {
		return nil, nil // the statement must end the block flowing into head
	}
	lastOp := initialBlock.LastOp()
	if lastOp == nil || initialBlock.SizeOut() != 1 {
		return nil, nil
	}
	if lastOp.IsBranch() {
		if lastOp = lastOp.PreviousOp(); lastOp == nil {
			return nil, nil
		}
	}
	return res, lastOp
}

// isMoveable reports whether op can move to just after point in the same
// block without disturbing data-flow.
// C++ parity: PcodeOp::isMoveable.
func (op *PcodeOp) isMoveable(point *PcodeOp) bool {
	if op == point {
		return true
	}
	movingLoad := false
	if op.EvalType() == PcodeOpSpecial {
		if op.Code() != CPUI_LOAD {
			return false // don't move special ops
		}
		movingLoad = true
	}
	if op.Parent() != point.Parent() {
		return false
	}
	pos := func(o *PcodeOp) uint64 { return opBlockUIndex(o) }
	if out := op.Output(); out != nil {
		// The output cannot move past an op that reads it.
		for _, readOp := range out.DescendIter() {
			if readOp.Parent() == op.Parent() && pos(readOp) <= pos(point) {
				return false
			}
		}
	}
	// Crossing a CALL is allowed only for a normal op whose inputs and output
	// are neither address tied nor persistent.
	crossCalls := false
	if op.EvalType() != PcodeOpSpecial {
		if out := op.Output(); out != nil && !out.IsAddrTied() && !out.IsPersist() {
			crossCalls = true
			for i := 0; i < op.NumInput(); i++ {
				if vn := op.Input(i); vn.IsAddrTied() || vn.IsPersist() {
					crossCalls = false
					break
				}
			}
		}
	}
	var tiedList []*Varnode
	for i := 0; i < op.NumInput(); i++ {
		if vn := op.Input(i); vn.IsAddrTied() {
			tiedList = append(tiedList, vn)
		}
	}
	for cur := op.NextOp(); cur != nil; cur = cur.NextOp() {
		if cur.EvalType() == PcodeOpSpecial {
			switch cur.Code() {
			case CPUI_LOAD:
				if out := op.Output(); out != nil && out.IsAddrTied() {
					return false
				}
			case CPUI_STORE:
				if movingLoad || len(tiedList) != 0 {
					return false
				}
				if out := op.Output(); out != nil && out.IsAddrTied() {
					return false
				}
			case CPUI_INDIRECT, CPUI_SEGMENTOP, CPUI_CPOOLREF:
				// INDIRECTs are dealt with separately
			case CPUI_CALL, CPUI_CALLIND, CPUI_NEW:
				if !crossCalls {
					return false
				}
			default:
				return false
			}
		}
		if out := cur.Output(); out != nil {
			if movingLoad && out.IsAddrTied() {
				return false
			}
			for _, vn := range tiedList {
				if vn.Overlap(out) >= 0 || out.Overlap(vn) >= 0 {
					return false
				}
			}
		}
		if cur == point {
			return true
		}
	}
	return true
}
