/*
 * Copyright 2024 The Gosleigh Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pcode

// This file ports the JumpBasic model-recovery logic from jumptable.cc:
// findDeterminingVarnodes (data-flow back-walk into a PathMeld), the guard
// analysis (analyzeGuards / calcRange / findSmallestNormal / findNormalized),
// and the GuardRecord quasi-copy matching helpers. It is the computational
// heart of dense-switch recovery once the function is in SSA form.
//
// Scope note (b2): the paths reaching a dense 0..N switch are single-path and
// single-guard, so PathMeld::meld / internalIntersect / checkUnrolledGuard are
// not exercised. findDeterminingVarnodes therefore only ever calls PathMeld.set
// (never meld), and analyzeGuards' sizeIn>1 branch is a documented stub. The
// straight-line subset is ported faithfully; the multi-path machinery is left
// for a later phase and cannot be silently reached by the dense-switch input.

// coveringmask returns a mask covering every bit at or below the most
// significant set bit of val (the smallest 2^n-1 that is >= val).
// C++ parity: address.cc coveringmask (address.cc:1056).
func coveringmask(val uint64) uint64 {
	res := val
	for sz := uint(1); sz < 64; sz <<= 1 {
		res |= res >> sz
	}
	return res
}

// -----------------------------------------------------------------------
// PathMeld.set(path) and small accessors
// -----------------------------------------------------------------------

// SetPath initialises the container to hold a single data-flow path. The path
// is a list of PcodeOpNode edges in reverse execution order (index 0 is the
// BRANCHIND edge). C++ parity: jumptable.cc PathMeld::set(vector<PcodeOpNode>&)
// (jumptable.cc:922).
func (pm *PathMeld) SetPath(path []pcodeOpNode) {
	pm.commonVn = pm.commonVn[:0]
	pm.opMeld = pm.opMeld[:0]
	for i := range path {
		node := path[i]
		vn := node.op.Input(node.slot)
		pm.opMeld = append(pm.opMeld, pathMeldRootedOp{op: node.op, rootVn: i})
		pm.commonVn = append(pm.commonVn, vn)
	}
}

// getEarliestOp returns the earliest (executed-first) PcodeOp in this PathMeld
// that uses the common Varnode at index pos as its split point.
// C++ parity: jumptable.cc PathMeld::getEarliestOp (jumptable.cc:1023).
func (pm *PathMeld) getEarliestOp(pos int) *PcodeOp {
	for i := len(pm.opMeld) - 1; i >= 0; i-- {
		if pm.opMeld[i].rootVn == pos {
			return pm.opMeld[i].op
		}
	}
	return nil
}

// isLoadInPath reports whether a common Varnode prior to index i is defined by
// a LOAD. C++ parity: jumptable.cc PathMeld::isLoadInPath (jumptable.cc:1036).
func (pm *PathMeld) isLoadInPath(i int) bool {
	for i > 0 {
		i--
		vn := pm.commonVn[i]
		if !vn.IsWritten() {
			continue
		}
		if vn.Def().Code() == CPUI_LOAD {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------
// JumpBasic switch-variable classification helpers
// -----------------------------------------------------------------------

// isprune reports whether the data-flow back-walk should stop at vn (vn is a
// tree leaf). C++ parity: jumptable.cc JumpBasic::isprune (jumptable.cc:424).
func (m *JumpBasic) isprune(vn *Varnode) bool {
	if !vn.IsWritten() {
		return true
	}
	op := vn.Def()
	if op.IsCall() || op.IsMarker() {
		return true
	}
	if op.NumInput() == 0 {
		return true
	}
	return false
}

// ispoint reports whether vn could be the switch variable.
// C++ parity: jumptable.cc JumpBasic::ispoint (jumptable.cc:436).
func (m *JumpBasic) ispoint(vn *Varnode) bool {
	if vn.IsConstant() {
		return false
	}
	if vn.IsAnnotation() {
		return false
	}
	if vn.IsReadOnly() {
		return false
	}
	return true
}

// getStride translates known-zero least-significant bits of vn into a jumptable
// stride (1,2,4,...). C++ parity: jumptable.cc JumpBasic::getStride
// (jumptable.cc:449).
func (m *JumpBasic) getStride(vn *Varnode) int32 {
	mask := vn.NZMask()
	if (mask & 0x3f) == 0 { // Limit the maximum stride we can return
		return 32
	}
	stride := int32(1)
	for (mask & 1) == 0 {
		mask >>= 1
		stride <<= 1
	}
	return stride
}

// getMaxValue returns the maximum value vn can hold if it is restricted by an
// INT_AND mask, otherwise 0 (unrestricted). C++ parity: jumptable.cc
// JumpBasic::getMaxValue (jumptable.cc:512).
func (m *JumpBasic) getMaxValue(vn *Varnode) uint64 {
	maxValue := uint64(0) // 0 indicates maximum possible value
	if !vn.IsWritten() {
		return maxValue
	}
	op := vn.Def()
	switch op.Code() {
	case CPUI_INT_AND:
		constvn := op.Input(1)
		if constvn.IsConstant() {
			maxValue = coveringmask(constvn.Offset())
			maxValue = (maxValue + 1) & maskForSize(vn.Size())
		}
	case CPUI_MULTIEQUAL:
		// The AND may be duplicated across multiple incoming blocks.
		i := 0
		for ; i < op.NumInput(); i++ {
			subvn := op.Input(i)
			if !subvn.IsWritten() {
				break
			}
			andOp := subvn.Def()
			if andOp.Code() != CPUI_INT_AND {
				break
			}
			constvn := andOp.Input(1)
			if !constvn.IsConstant() {
				break
			}
			if maxValue < constvn.Offset() {
				maxValue = constvn.Offset()
			}
		}
		if i == op.NumInput() {
			maxValue = coveringmask(maxValue)
			maxValue = (maxValue + 1) & maskForSize(vn.Size())
		} else {
			maxValue = 0
		}
	}
	return maxValue
}

// -----------------------------------------------------------------------
// findDeterminingVarnodes
// -----------------------------------------------------------------------

// findDeterminingVarnodes calculates the set of Varnodes that might be the
// switch variable by walking the tree of inputs feeding op's slot, organizing
// them into the PathMeld. C++ parity: jumptable.cc
// JumpBasic::findDeterminingVarnodes (jumptable.cc:554).
//
// b2-scope: the dense switch has a single path, so the ispoint hit calls
// pathMeld.set(path) exactly once and pathMeld.meld is never reached.
func (m *JumpBasic) findDeterminingVarnodes(op *PcodeOp, slot int) {
	var path []pcodeOpNode
	firstpoint := false // Have not seen likely switch variable yet

	path = append(path, pcodeOpNode{op: op, slot: slot})

	// C++ is a do/while(path.size()>1): process the current tail node, then stop
	// once the path has collapsed back to (at most) the root edge.
	for len(path) >= 1 { // Traverse the tree of inputs
		node := &path[len(path)-1]
		curvn := node.op.Input(node.slot)
		if m.isprune(curvn) { // A leaf of the tree
			if m.ispoint(curvn) { // A possible switch variable
				if !firstpoint {
					m.PathMeld.SetPath(path)
					firstpoint = true
				} else {
					// Multi-path meld is out of b2 scope; a dense switch never
					// reaches a second point. Keep the first path.
					m.PathMeld.Meld(nil)
				}
			}
			path[len(path)-1].slot++
			for path[len(path)-1].slot >= path[len(path)-1].op.NumInput() {
				path = path[:len(path)-1]
				if len(path) == 0 {
					break
				}
				path[len(path)-1].slot++
			}
		} else { // Not pruned: descend into the defining op
			path = append(path, pcodeOpNode{op: curvn.Def(), slot: 0})
		}
		if len(path) <= 1 {
			break
		}
	}
	if m.PathMeld.Empty() {
		// Never found a likely point: the address looks uniquely determined but
		// the constants/readonlys were not collapsed.
		m.PathMeld.SetSingle(op, op.Input(slot))
	}
}

// -----------------------------------------------------------------------
// GuardRecord quasi-copy matching
// -----------------------------------------------------------------------

// matchingConstants reports whether both Varnodes are the same constant value.
// C++ parity: jumptable.cc matching_constants (jumptable.cc:598).
func matchingConstants(vn1, vn2 *Varnode) bool {
	if !vn1.IsConstant() {
		return false
	}
	if !vn2.IsConstant() {
		return false
	}
	return vn1.Offset() == vn2.Offset()
}

// guardQuasiCopy computes the earliest ancestor Varnode from which vn is a
// quasi-copy (a chain preserving the low bits, possibly setting upper bits),
// along with the number of preserved bits.
// C++ parity: jumptable.cc GuardRecord::quasiCopy (jumptable.cc:719).
func guardQuasiCopy(vn *Varnode) (*Varnode, int32) {
	bitsPreserved := int32(mostSigBitSet(vn.NZMask()) + 1)
	if bitsPreserved == 0 {
		return vn, bitsPreserved
	}
	mask := uint64(1) << 1
	mask <<= uint(bitsPreserved - 1)
	mask--
	op := vn.Def()
	for op != nil {
		switch op.Code() {
		case CPUI_COPY:
			vn = op.Input(0)
			op = vn.Def()
		case CPUI_INT_AND:
			constVn := op.Input(1)
			if constVn.IsConstant() && constVn.Offset() == mask {
				vn = op.Input(0)
				op = vn.Def()
			} else {
				op = nil
			}
		case CPUI_INT_OR:
			constVn := op.Input(1)
			if constVn.IsConstant() && ((constVn.Offset() | mask) == (constVn.Offset() ^ mask)) {
				vn = op.Input(0)
				op = vn.Def()
			} else {
				op = nil
			}
		case CPUI_INT_SEXT, CPUI_INT_ZEXT:
			if op.Input(0).Size()*8 >= bitsPreserved {
				vn = op.Input(0)
				op = vn.Def()
			} else {
				op = nil
			}
		case CPUI_PIECE:
			if op.Input(1).Size()*8 >= bitsPreserved {
				vn = op.Input(1)
				op = vn.Def()
			} else {
				op = nil
			}
		case CPUI_SUBPIECE:
			constVn := op.Input(1)
			if constVn.IsConstant() && constVn.Offset() == 0 {
				vn = op.Input(0)
				op = vn.Def()
			} else {
				op = nil
			}
		default:
			op = nil
		}
	}
	return vn, bitsPreserved
}

// guardOneOffMatch returns 1 if the two PcodeOps produce exactly the same value
// (up through one level of certain binary ops with a matching constant operand).
// C++ parity: jumptable.cc GuardRecord::oneOffMatch (jumptable.cc:684).
func guardOneOffMatch(op1, op2 *PcodeOp) int32 {
	if op1.Code() != op2.Code() {
		return 0
	}
	switch op1.Code() {
	case CPUI_INT_AND, CPUI_INT_ADD, CPUI_INT_XOR, CPUI_INT_OR,
		CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_MULT, CPUI_SUBPIECE:
		if op2.Input(0) != op1.Input(0) {
			return 0
		}
		if matchingConstants(op2.Input(1), op1.Input(1)) {
			return 1
		}
	}
	return 0
}

// valueMatch determines whether this guard applies to vn2 (holds the same
// value). Returns 0 (unrelated), 1 (same value), or 2 (same value pending no
// intervening writes). C++ parity: jumptable.cc GuardRecord::valueMatch
// (jumptable.cc:637).
func (g *GuardRecord) valueMatch(vn2, baseVn2 *Varnode, bitsPreserved2 int32) int32 {
	if g.Vn == vn2 {
		return 1
	}
	var loadOp, loadOp2 *PcodeOp
	if g.BitsPreserved == bitsPreserved2 {
		if g.BaseVn == baseVn2 {
			return 1
		}
		loadOp = g.BaseVn.Def()
		loadOp2 = baseVn2.Def()
	} else {
		loadOp = g.Vn.Def()
		loadOp2 = vn2.Def()
	}
	if loadOp == nil {
		return 0
	}
	if loadOp2 == nil {
		return 0
	}
	if guardOneOffMatch(loadOp, loadOp2) == 1 {
		return 1
	}
	if loadOp.Code() != CPUI_LOAD {
		return 0
	}
	if loadOp2.Code() != CPUI_LOAD {
		return 0
	}
	if loadOp.Input(0).Offset() != loadOp2.Input(0).Offset() {
		return 0
	}
	ptr := loadOp.Input(1)
	ptr2 := loadOp2.Input(1)
	if ptr == ptr2 {
		return 2
	}
	if !ptr.IsWritten() {
		return 0
	}
	if !ptr2.IsWritten() {
		return 0
	}
	addop := ptr.Def()
	if addop.Code() != CPUI_INT_ADD {
		return 0
	}
	constvn := addop.Input(1)
	if !constvn.IsConstant() {
		return 0
	}
	addop2 := ptr2.Def()
	if addop2.Code() != CPUI_INT_ADD {
		return 0
	}
	constvn2 := addop2.Input(1)
	if !constvn2.IsConstant() {
		return 0
	}
	if addop.Input(0) != addop2.Input(0) {
		return 0
	}
	if constvn.Offset() != constvn2.Offset() {
		return 0
	}
	return 2
}

// -----------------------------------------------------------------------
// Guard analysis: analyzeGuards / calcRange / findSmallestNormal
// -----------------------------------------------------------------------

// checkUnrolledGuard handles guards duplicated across multiple predecessor
// blocks (a switch variable spread over a MULTIEQUAL). It is not exercised by
// dense switches (which have a single path to the BRANCHIND) and is left
// unported; when reached it simply records no additional guard, which is the
// conservative (recovery-fails) outcome. C++ parity: jumptable.cc
// JumpBasic::checkUnrolledGuard (jumptable.cc:1355) -- b2-scope stub.
func (m *JumpBasic) checkUnrolledGuard(_ *BlockBasic, _ int, _ bool) {}

// analyzeGuards inspects the CBRANCHs leading to the switch block and records a
// GuardRecord for each range restriction that lets control reach the switch.
// C++ parity: jumptable.cc JumpBasic::analyzeGuards (jumptable.cc:1061).
func (m *JumpBasic) analyzeGuards(bl *BlockBasic, pathout int) {
	const maxbranch = 2 // Maximum number of CBRANCHs to consider
	const maxpullback = 2
	usenzmask := !m.jt.IsPartial()

	m.SelectGuards = nil
	var prevbl *BlockBasic
	var indpath int

	for i := 0; i < maxbranch; i++ {
		if pathout >= 0 && bl.SizeOut() == 2 {
			prevbl = bl
			bl = asBasic(prevbl.OutEdge(pathout).Point)
			indpath = pathout
			pathout = -1
		} else {
			pathout = -1 // Make sure not to use pathout next time around
			done := false
			for {
				if bl.SizeIn() != 1 {
					if bl.SizeIn() > 1 {
						m.checkUnrolledGuard(bl, maxpullback, usenzmask)
					}
					done = true
					break
				}
				// Only 1 flow path to the switch.
				prevbl = asBasic(bl.InEdge(0).Point)
				if prevbl == nil || prevbl.SizeOut() != 1 {
					break // May deviate from the switch path in this block
				}
				bl = prevbl // Otherwise back up to the next block
			}
			if done {
				return
			}
			indpath = bl.InRevIndex(0)
		}
		if prevbl == nil {
			break
		}
		cbranch := prevbl.LastOp()
		if cbranch == nil || cbranch.Code() != CPUI_CBRANCH {
			break
		}
		if i != 0 {
			// Check that this CBRANCH is not protecting some other switch.
			otherbl := asBasic(prevbl.OutEdge(1 - indpath).Point)
			if otherbl != nil {
				otherop := otherbl.LastOp()
				if otherop != nil && otherop.Code() == CPUI_BRANCHIND {
					if otherop != m.jt.IndirectOp() {
						break
					}
				}
			}
		}
		toswitchval := (indpath == 1)
		if cbranch.HasFlag(PcodeOpBooleanFlip) {
			toswitchval = !toswitchval
		}
		bl = prevbl
		vn := cbranch.Input(1)
		rng := newCircleRangeBoolean(toswitchval)

		// The boolean variable could conceivably be the switch variable.
		indpathstore := indpath
		if prevbl.HasFlag(BlockFlagFlipPath) {
			indpathstore = 1 - indpath
		}
		m.SelectGuards = append(m.SelectGuards,
			NewGuardRecord(cbranch, cbranch, int32(indpathstore), rng, vn, false))
		for j := 0; j < maxpullback; j++ {
			var markup *Varnode // Throw away markup information
			if !vn.IsWritten() {
				break
			}
			readOp := vn.Def()
			vn = rng.pullBack(readOp, &markup, usenzmask)
			if vn == nil {
				break
			}
			if rng.isEmpty() {
				break
			}
			m.SelectGuards = append(m.SelectGuards,
				NewGuardRecord(cbranch, readOp, int32(indpathstore), rng, vn, false))
		}
	}
}

// calcRange computes the range of values vn can hold at the switch, starting
// from its size/type and intersecting every applicable guard restriction.
// C++ parity: jumptable.cc JumpBasic::calcRange (jumptable.cc:1135).
func (m *JumpBasic) calcRange(vn *Varnode) circleRange {
	// Initial range from the size/type of vn.
	stride := int32(1)
	var rng circleRange
	if vn.IsConstant() {
		rng = newCircleRangeSingle(vn.Offset(), vn.Size())
	} else if vn.IsWritten() && vn.Def().IsBoolOutput() {
		rng = newCircleRangeBounds(0, 2, 1, 1) // Only 0 or 1 possible
	} else {
		maxValue := m.getMaxValue(vn)
		stride = m.getStride(vn)
		rng = newCircleRangeBounds(0, maxValue, vn.Size(), stride)
	}

	// Intersect any guard ranges which apply to vn.
	baseVn, bitsPreserved := guardQuasiCopy(vn)
	for _, guard := range m.SelectGuards {
		matchval := guard.valueMatch(vn, baseVn, bitsPreserved)
		if matchval == 0 {
			continue
		}
		gr := guard.GetRange()
		if rng.intersect(gr) != 0 {
			continue
		}
	}

	// The switch value may be assumed positive without an explicit guard: if the
	// range is too big, try only positive values.
	if rng.getSize() > 0x10000 {
		positive := newCircleRangeBounds(0, (rng.getMask()>>1)+1, vn.Size(), stride)
		positive.intersect(rng)
		if !positive.isEmpty() {
			rng = positive
		}
	}
	return rng
}

// findSmallestNormal selects the common Varnode with the smallest reaching
// range as the normalized switch variable and sets up the JumpValues iterator.
// C++ parity: jumptable.cc JumpBasic::findSmallestNormal (jumptable.cc:1180).
func (m *JumpBasic) findSmallestNormal(matchsize uint32) {
	m.VarnodeIndex = 0
	rng := m.calcRange(m.PathMeld.Varnode(0))
	m.Range.SetRange(rng)
	m.Range.SetStartVn(m.PathMeld.Varnode(0))
	m.Range.SetStartOp(m.PathMeld.Op(0))
	maxsize := rng.getSize()
	for i := 1; i < m.PathMeld.NumCommonVarnode(); i++ {
		if maxsize == uint64(matchsize) { // Found a variable of the recovered size
			return
		}
		rng = m.calcRange(m.PathMeld.Varnode(i))
		sz := rng.getSize()
		if sz < maxsize {
			// Do not accept a 1-byte switch variable unless there is an explicit
			// guard or a table lookup between the byte and the indirect jump.
			if sz != 256 || m.PathMeld.Varnode(i).Size() != 1 || m.PathMeld.isLoadInPath(i) {
				m.VarnodeIndex = i
				maxsize = sz
				m.Range.SetRange(rng)
				m.Range.SetStartVn(m.PathMeld.Varnode(i))
				m.Range.SetStartOp(m.PathMeld.getEarliestOp(i))
			}
		}
	}
}

// findNormalized recovers the normalized switch variable: analyze guards, pick
// the smallest range, then apply the read-only single-branch special case.
// C++ parity: jumptable.cc JumpBasic::findNormalized (jumptable.cc:1221).
func (m *JumpBasic) findNormalized(fd *Funcdata, rootbl *BlockBasic, pathout int, matchsize, maxtablesize uint32) {
	if rootbl == nil {
		return
	}
	m.analyzeGuards(rootbl, pathout)
	m.findSmallestNormal(matchsize)
	sz := m.Range.Size()
	if sz > uint64(maxtablesize) && m.PathMeld.NumCommonVarnode() == 1 {
		// Jump through a read-only variable: for a single-branch table we insist
		// the entry be read-only (the LoadImage value is otherwise unreliable).
		vn := m.PathMeld.Varnode(0)
		if vn.IsReadOnly() {
			reader := fd.ImageReader()
			if reader != nil {
				if val, err := reader(vn.Addr(), int(vn.Size())); err == nil {
					m.VarnodeIndex = 0
					m.Range.SetRange(newCircleRangeSingle(val&maskForSize(vn.Size()), vn.Size()))
					m.Range.SetStartVn(vn)
					m.Range.SetStartOp(m.PathMeld.Op(0))
				}
			}
		}
	}
}

// -----------------------------------------------------------------------
// findUnnormalized / foldInGuards support (marks, reverse emulation, folding)
// -----------------------------------------------------------------------

// markModel (un)marks every model PcodeOp: the path ops up to the switch
// variable plus the guard read ops. The mark is used by flowsOnlyToModel to
// confirm a candidate switch variable feeds nothing but the model.
// C++ parity: jumptable.cc JumpBasic::markModel (jumptable.cc:1271).
func (m *JumpBasic) markModel(val bool) {
	m.PathMeld.MarkPaths(val, m.VarnodeIndex)
	for _, guard := range m.SelectGuards {
		if guard.GetBranch() == nil {
			continue
		}
		readOp := guard.GetReadOp()
		if readOp == nil {
			continue
		}
		if val {
			readOp.SetFlag(PcodeOpMark)
		} else {
			readOp.ClearFlag(PcodeOpMark)
		}
	}
}

// flowsOnlyToModel reports whether every descendant of vn (except an optional
// known trail op) is marked, i.e. flows only into the current model. The model
// ops must have been marked by markModel(true) first.
// C++ parity: jumptable.cc JumpBasic::flowsOnlyToModel (jumptable.cc:1291).
func (m *JumpBasic) flowsOnlyToModel(vn *Varnode, trailOp *PcodeOp) bool {
	for _, op := range vn.DescendIter() {
		if op == trailOp {
			continue
		}
		if !op.HasFlag(PcodeOpMark) {
			return false
		}
	}
	return true
}

// backup2Switch reverse-emulates output from outvn back to invn, undoing each
// normalization op along the way, to recover the original switch value used as
// a case label. C++ parity: jumptable.cc JumpBasic::backup2Switch (jumptable.cc:472).
//
// Known gap: reverse evaluation of a binary/unary normalization op needs
// TypeOp::recoverInputBinary/recoverInputUnary, which are not ported. For dense
// switches the normalized variable is the switch variable (outvn == invn), so
// the loop never runs; any non-trivial normalization chain returns
// errBadSwitchNorm, which BuildLabels maps to JumpValueNoLabel (the C++
// EvaluationError arm).
func (m *JumpBasic) backup2Switch(_ *Funcdata, output uint64, outvn, invn *Varnode) (uint64, error) {
	curvn := outvn
	for curvn != invn {
		return 0, errBadSwitchNorm
	}
	return output, nil
}

// foldInOneGuard folds a single guard CBRANCH into the switch's default edge:
// either rerouting the guard's non-switch branch into the switch block as a new
// default destination, or pinning the guard's condition to a constant so the
// existing default edge is always taken.
// C++ parity: jumptable.cc JumpBasic::foldInOneGuard (jumptable.cc:1390).
func (m *JumpBasic) foldInOneGuard(fd *Funcdata, guard *GuardRecord, jump *JumpTable) bool {
	cbranch := guard.GetBranch()
	cbranchblock := cbranch.Parent()
	// The guard branch may have been converted between switch recovery and now.
	if cbranchblock.SizeOut() != 2 {
		return false
	}
	indpath := int(guard.GetPath()) // Stored path to indirect block
	if cbranchblock.HasFlag(BlockFlagFlipPath) {
		indpath = 1 - indpath // Out branches flipped: get actual path to indirect block
	}
	switchbl := jump.IndirectOp().Parent()
	if cbranchblock.OutEdge(indpath).Point != &switchbl.FlowBlock { // Guard must go directly into switch block
		return false
	}
	guardtargetFB := cbranchblock.OutEdge(1 - indpath).Point
	pos := 0
	for ; pos < switchbl.SizeOut(); pos++ {
		if switchbl.OutEdge(pos).Point == guardtargetFB {
			break
		}
	}
	if jump.HasFoldedDefault() && int(jump.DefaultBlock()) != pos { // There can be only one folded target
		return false
	}
	if !switchbl.NoInterveningStatement() {
		return false
	}
	if pos == switchbl.SizeOut() {
		guardtarget := asBasic(guardtargetFB)
		jump.AddBlockToSwitch(guardtarget, JumpValueNoLabel) // New destination without a label
		jump.SetLastAsDefault()                              // treating it as the default case or an exit
		fd.PushBranch(cbranchblock, 1-indpath, switchbl)     // Turn branch target into switch target
	} else {
		var val uint64
		if (indpath == 0) != cbranch.HasFlag(PcodeOpBooleanFlip) {
			val = 0
		} else {
			val = 1
		}
		fd.OpSetInput(cbranch, fd.NewConstant(cbranch.Input(0).Size(), val), 1)
		jump.SetDefaultBlock(int32(pos)) // A guard branch generally targets the default case
	}
	jump.SetFoldedDefault() // Default branch folded (and cannot take a label)
	guard.Clear()
	return true
}

// markFoldableGuards clears guards that are not truly part of the model so they
// will not be folded out of the CFG later. C++ parity: jumptable.cc
// JumpBasic::markFoldableGuards (jumptable.cc:1256).
func (m *JumpBasic) markFoldableGuards() {
	if m.PathMeld.NumCommonVarnode() == 0 {
		return
	}
	vn := m.PathMeld.Varnode(m.VarnodeIndex)
	baseVn, bitsPreserved := guardQuasiCopy(vn)
	for _, guard := range m.SelectGuards {
		if guard.valueMatch(vn, baseVn, bitsPreserved) == 0 || guard.IsUnrolled() {
			guard.Clear() // Guard not used or should not be folded
		}
	}
}
