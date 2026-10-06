// Copyright 2026 The Gosleigh Authors
// Licensed under the Apache License, Version 2.0.

package pcode

// Value set analysis: iterate integer ranges (CircleRange) through a
// data-flow system until a fixed point, with optional widening and branch
// constraints. Heritage uses it to bound indexed stack LOAD/STORE accesses.
// C++ parity: rangeutil.hh/.cc ValueSet, ValueSetRead, Partition, Widener,
// ValueSetSolver.

// valueSetMaxStep is the largest step inferred for a value set.
// C++ parity: ValueSet::MAX_STEP.
const valueSetMaxStep = 32

// valueSetEquation constrains the values arriving on one input slot.
// C++ parity: ValueSet::Equation.
type valueSetEquation struct {
	slot     int
	typeCode int // 0=absolute 1=relative to a spacebase register
	rng      circleRange
}

// valueSet is the range of values a Varnode can take.
// C++ parity: class ValueSet.
type valueSet struct {
	typeCode      int // 0=pure constant 1=stack relative
	numParams     int
	count         int // depth first numbering / widening count
	opCode        OpCode
	leftIsStable  bool
	rightIsStable bool
	vn            *Varnode
	rng           circleRange
	equations     []valueSetEquation
	partHead      *valueSetPartition
	next          *valueSet
}

// opCodeNone marks a value set with no defining op (C++ CPUI_MAX).
const opCodeNone OpCode = CPUI_MAX

// setVarnode attaches the set to v and seeds it: a constant gets its value,
// a relative root offset 0, another input everything, a written Varnode
// starts empty. C++ parity: ValueSet::setVarnode.
func (vs *valueSet) setVarnode(v *Varnode, tCode int) {
	vs.typeCode = tCode
	vs.vn = v
	v.valueSet = vs
	vs.rng = newCircleRangeEmpty()
	switch {
	case vs.typeCode != 0:
		vs.opCode = opCodeNone
		vs.numParams = 0
		vs.rng.setRangeSingle(0, v.Size()) // Offset 0 relative to the special value
		vs.leftIsStable = true
		vs.rightIsStable = true
	case v.IsWritten():
		op := v.Def()
		vs.opCode = op.Code()
		if vs.opCode == CPUI_INDIRECT { // Treat INDIRECT as COPY
			vs.numParams = 1
			vs.opCode = CPUI_COPY
		} else {
			vs.numParams = op.NumInput()
		}
		vs.leftIsStable = false
		vs.rightIsStable = false
	case v.IsConstant():
		vs.opCode = opCodeNone
		vs.numParams = 0
		vs.rng.setRangeSingle(v.Offset(), v.Size())
		vs.leftIsStable = true
		vs.rightIsStable = true
	default: // Some other form of input
		vs.opCode = opCodeNone
		vs.numParams = 0
		vs.typeCode = 0
		vs.rng.setFull(v.Size())
		vs.leftIsStable = false
		vs.rightIsStable = false
	}
}

// setFullSet marks the set as possibly holding any value.
// C++ parity: ValueSet::setFull.
func (vs *valueSet) setFullSet() {
	vs.rng.setFull(vs.vn.Size())
	vs.typeCode = 0
}

// addEquation inserts a constraint, keeping the list ordered on slot.
// C++ parity: ValueSet::addEquation.
func (vs *valueSet) addEquation(slot, typ int, constraint circleRange) {
	at := 0
	for at < len(vs.equations) && vs.equations[at].slot <= slot {
		at++
	}
	vs.equations = append(vs.equations, valueSetEquation{})
	copy(vs.equations[at+1:], vs.equations[at:])
	vs.equations[at] = valueSetEquation{slot: slot, typeCode: typ, rng: constraint}
}

// addLandmark records a widening landmark. C++ parity: ValueSet::addLandmark.
func (vs *valueSet) addLandmark(typ int, constraint circleRange) {
	vs.addEquation(vs.numParams, typ, constraint)
}

// doesEquationApply: equation num constrains slot for this set's type.
// C++ parity: ValueSet::doesEquationApply.
func (vs *valueSet) doesEquationApply(num, slot int) bool {
	return num < len(vs.equations) && vs.equations[num].slot == slot && vs.equations[num].typeCode == vs.typeCode
}

// computeTypeCode decides whether the set is relative, reporting an
// indeterminate combination. C++ parity: ValueSet::computeTypeCode.
func (vs *valueSet) computeTypeCode() bool {
	relCount := 0
	lastTypeCode := 0
	op := vs.vn.Def()
	for i := 0; i < vs.numParams; i++ {
		if in := op.Input(i).valueSet; in.typeCode != 0 {
			relCount++
			lastTypeCode = in.typeCode
		}
	}
	if relCount == 0 {
		vs.typeCode = 0
		return false
	}
	// Only certain operations can propagate a relative value set
	switch vs.opCode {
	case CPUI_PTRSUB, CPUI_PTRADD, CPUI_INT_ADD, CPUI_INT_SUB:
		if relCount != 1 {
			return true
		}
		vs.typeCode = lastTypeCode
	case CPUI_CAST, CPUI_COPY, CPUI_INDIRECT, CPUI_MULTIEQUAL:
		vs.typeCode = lastTypeCode
	default:
		return true
	}
	return false
}

// constrained is the range of in, intersected with equation eq when that
// yields one piece, else the equation's range.
func valueSetConstrained(in circleRange, eq *valueSetEquation) circleRange {
	if in.intersect(eq.rng) != 0 {
		return eq.rng
	}
	return in
}

// iterate recomputes the set by pushing the input sets through the
// defining op, reporting a change. C++ parity: ValueSet::iterate.
func (vs *valueSet) iterate(widener valueSetWidener) bool {
	if !vs.vn.IsWritten() {
		return false
	}
	if widener.checkFreeze(vs) {
		return false
	}
	if vs.count == 0 && vs.computeTypeCode() {
		vs.setFullSet()
		return true
	}
	vs.count++ // Count this iteration
	res := newCircleRangeEmpty()
	op := vs.vn.Def()
	eqPos := 0
	switch {
	case vs.opCode == CPUI_MULTIEQUAL:
		pieces := 0
		for i := 0; i < vs.numParams; i++ {
			inSet := op.Input(i).valueSet
			if vs.doesEquationApply(eqPos, i) {
				pieces = res.circleUnion(valueSetConstrained(inSet.rng, &vs.equations[eqPos]))
				eqPos++ // Equation was used
			} else {
				pieces = res.circleUnion(inSet.rng)
			}
			if pieces == 2 && res.minimalContainer(&inSet.rng, valueSetMaxStep) {
				break // Could not get clean union, force it
			}
		}
		if res.circleUnion(vs.rng) != 0 { // Union with the previous iteration's set
			res.minimalContainer(&vs.rng, valueSetMaxStep)
		}
		if !vs.rng.isEmpty() && !res.isEmpty() {
			vs.leftIsStable = vs.rng.getMin() == res.getMin()
			vs.rightIsStable = vs.rng.getEnd() == res.getEnd()
		}
	case vs.numParams == 1:
		inSet1 := op.Input(0).valueSet
		in1 := inSet1.rng
		if vs.doesEquationApply(eqPos, 0) {
			in1 = valueSetConstrained(inSet1.rng, &vs.equations[eqPos])
		}
		if !res.pushForwardUnary(vs.opCode, &in1, inSet1.vn.Size(), vs.vn.Size()) {
			vs.setFullSet()
			return true
		}
		vs.leftIsStable = inSet1.leftIsStable
		vs.rightIsStable = inSet1.rightIsStable
	case vs.numParams == 2:
		inSet1, inSet2 := op.Input(0).valueSet, op.Input(1).valueSet
		range1, range2 := inSet1.rng, inSet2.rng
		if len(vs.equations) != 0 {
			if vs.doesEquationApply(eqPos, 0) {
				range1 = valueSetConstrained(range1, &vs.equations[eqPos])
				eqPos++
			}
			if vs.doesEquationApply(eqPos, 1) {
				range2 = valueSetConstrained(range2, &vs.equations[eqPos])
			}
		}
		if !res.pushForwardBinary(vs.opCode, &range1, &range2, inSet1.vn.Size(), vs.vn.Size(), valueSetMaxStep) {
			vs.setFullSet()
			return true
		}
		vs.leftIsStable = inSet1.leftIsStable && inSet2.leftIsStable
		vs.rightIsStable = inSet1.rightIsStable && inSet2.rightIsStable
	case vs.numParams == 3:
		inSet1, inSet2, inSet3 := op.Input(0).valueSet, op.Input(1).valueSet, op.Input(2).valueSet
		range1, range2 := inSet1.rng, inSet2.rng
		if vs.doesEquationApply(eqPos, 0) {
			range1 = valueSetConstrained(range1, &vs.equations[eqPos])
			eqPos++
		}
		if vs.doesEquationApply(eqPos, 1) {
			range2 = valueSetConstrained(range2, &vs.equations[eqPos])
		}
		if !res.pushForwardTrinary(vs.opCode, &range1, &range2, &inSet3.rng, inSet1.vn.Size(), vs.vn.Size(), valueSetMaxStep) {
			vs.setFullSet()
			return true
		}
		vs.leftIsStable = inSet1.leftIsStable && inSet2.leftIsStable
		vs.rightIsStable = inSet1.rightIsStable && inSet2.rightIsStable
	default:
		return false // No way to change this value set
	}
	if res.equals(&vs.rng) {
		return false
	}
	if vs.partHead != nil {
		if !widener.doWidening(vs, &vs.rng, &res) {
			vs.setFullSet()
		}
	} else {
		vs.rng = res
	}
	return true
}

// getLandMark is any equation range usable as a widening landmark.
// C++ parity: ValueSet::getLandMark.
func (vs *valueSet) getLandMark() *circleRange {
	for i := range vs.equations {
		if vs.equations[i].typeCode == vs.typeCode {
			return &vs.equations[i].rng
		}
	}
	return nil
}

// valueSetPartition is one component of the iteration order.
// C++ parity: class Partition.
type valueSetPartition struct {
	startNode *valueSet
	stopNode  *valueSet
	isDirty   bool
}

// valueSetRead is the value set seen by one read site, possibly further
// constrained by control flow. C++ parity: class ValueSetRead.
type valueSetRead struct {
	typeCode           int
	slot               int
	op                 *PcodeOp
	rng                circleRange
	equationConstraint circleRange
	equationTypeCode   int
	leftIsStable       bool
	rightIsStable      bool
}

// setPcodeOp establishes the read site. C++ parity: ValueSetRead::setPcodeOp.
func (r *valueSetRead) setPcodeOp(o *PcodeOp, slt int) {
	r.typeCode = 0
	r.op = o
	r.slot = slt
	r.equationTypeCode = -1
}

// addEquation records a constraint on the read slot.
// C++ parity: ValueSetRead::addEquation.
func (r *valueSetRead) addEquation(slt, typ int, constraint circleRange) {
	if r.slot == slt {
		r.equationTypeCode = typ
		r.equationConstraint = constraint
	}
}

// compute takes the read Varnode's set and applies the equation.
// C++ parity: ValueSetRead::compute.
func (r *valueSetRead) compute() {
	set := r.op.Input(r.slot).valueSet
	r.typeCode = set.typeCode
	r.rng = set.rng
	r.leftIsStable = set.leftIsStable
	r.rightIsStable = set.rightIsStable
	if r.typeCode == r.equationTypeCode && r.rng.intersect(r.equationConstraint) != 0 {
		r.rng = r.equationConstraint
	}
}

// valueSetWidener is a widening strategy. C++ parity: class Widener.
type valueSetWidener interface {
	determineIterationReset(vs *valueSet) int
	checkFreeze(vs *valueSet) bool
	doWidening(vs *valueSet, rng *circleRange, newRange *circleRange) bool
}

// valueSetWidenerFull widens at a landmark, then goes full.
// C++ parity: class WidenerFull.
type valueSetWidenerFull struct {
	widenIteration int
	fullIteration  int
}

func newValueSetWidenerFull() *valueSetWidenerFull {
	return &valueSetWidenerFull{widenIteration: 2, fullIteration: 5}
}

func (w *valueSetWidenerFull) determineIterationReset(vs *valueSet) int {
	if vs.count >= w.widenIteration {
		return w.widenIteration // Reset to point just after any widening
	}
	return 0 // Delay widening, if we haven't performed it yet
}

func (w *valueSetWidenerFull) checkFreeze(vs *valueSet) bool { return vs.rng.isFull() }

func (w *valueSetWidenerFull) doWidening(vs *valueSet, rng *circleRange, newRange *circleRange) bool {
	switch {
	case vs.count < w.widenIteration:
		*rng = *newRange
		return true
	case vs.count == w.widenIteration:
		if landmark := vs.getLandMark(); landmark != nil {
			leftIsStable := rng.getMin() == newRange.getMin()
			*rng = *newRange // Preserve any new step information
			if landmark.containsRange(rng) {
				rng.widen(landmark, leftIsStable)
				return true
			}
			constraint := *landmark
			constraint.invert()
			if constraint.containsRange(rng) {
				rng.widen(&constraint, leftIsStable)
				return true
			}
		}
	case vs.count < w.fullIteration:
		*rng = *newRange
		return true
	}
	return false // Constrained widening failed (set to full)
}

// valueSetWidenerNone freezes after a few iterations without widening.
// C++ parity: class WidenerNone.
type valueSetWidenerNone struct{ freezeIteration int }

func newValueSetWidenerNone() *valueSetWidenerNone { return &valueSetWidenerNone{freezeIteration: 3} }

func (w *valueSetWidenerNone) determineIterationReset(vs *valueSet) int {
	if vs.count >= w.freezeIteration {
		return w.freezeIteration
	}
	return vs.count
}

func (w *valueSetWidenerNone) checkFreeze(vs *valueSet) bool {
	return vs.rng.isFull() || vs.count >= w.freezeIteration
}

func (w *valueSetWidenerNone) doWidening(vs *valueSet, rng *circleRange, newRange *circleRange) bool {
	*rng = *newRange
	return true
}

// valueSetSolver iterates the value sets of a data-flow system.
// C++ parity: class ValueSetSolver.
type valueSetSolver struct {
	valueNodes      []*valueSet
	readNodes       map[*PcodeOp]*valueSetRead
	orderPartition  valueSetPartition
	rootNodes       []*valueSet
	nodeStack       []*valueSet
	depthFirstIndex int
	numIterations   int
	maxIterations   int
}

func newValueSetSolver() *valueSetSolver {
	return &valueSetSolver{readNodes: make(map[*PcodeOp]*valueSetRead)}
}

// readNode returns (creating) the read site record for op.
func (s *valueSetSolver) readNode(op *PcodeOp) *valueSetRead {
	r := s.readNodes[op]
	if r == nil {
		r = &valueSetRead{rng: newCircleRangeEmpty(), equationConstraint: newCircleRangeEmpty()}
		s.readNodes[op] = r
	}
	return r
}

// getValueSetRead is the value set at a read site.
// C++ parity: ValueSetSolver::getValueSetRead.
func (s *valueSetSolver) getValueSetRead(op *PcodeOp) *valueSetRead { return s.readNodes[op] }

// newValueSet attaches a new set to vn. C++ parity: ValueSetSolver::newValueSet.
func (s *valueSetSolver) newValueSet(vn *Varnode, tCode int) {
	vs := &valueSet{}
	vs.setVarnode(vn, tCode)
	s.valueNodes = append(s.valueNodes, vs)
}

// valueSetEdges iterates a node's successors: the sets of marked outputs
// of the Varnode's readers, or the root list for the simulated root.
// C++ parity: ValueSetSolver::ValueSetEdge.
type valueSetEdges struct {
	roots   []*valueSet
	rootPos int
	vn      *Varnode
	desc    []*PcodeOp
	pos     int
}

func newValueSetEdges(node *valueSet, roots []*valueSet) *valueSetEdges {
	if node.vn == nil { // The simulated root
		return &valueSetEdges{roots: roots}
	}
	return &valueSetEdges{vn: node.vn, desc: node.vn.DescendIter()}
}

func (e *valueSetEdges) getNext() *valueSet {
	if e.vn == nil {
		if e.rootPos < len(e.roots) {
			res := e.roots[e.rootPos]
			e.rootPos++
			return res
		}
		return nil
	}
	for e.pos < len(e.desc) {
		op := e.desc[e.pos]
		e.pos++
		if out := op.Output(); out != nil && out.IsMark() {
			return out.valueSet
		}
	}
	return nil
}

// partitionPrepend puts vertex at the front of part.
// C++ parity: ValueSetSolver::partitionPrepend(ValueSet*,Partition&).
func partitionPrependNode(vertex *valueSet, part *valueSetPartition) {
	vertex.next = part.startNode
	part.startNode = vertex
	if part.stopNode == nil {
		part.stopNode = vertex
	}
}

// partitionPrependPart puts all of head at the front of part.
// C++ parity: ValueSetSolver::partitionPrepend(const Partition&,Partition&).
func partitionPrependPart(head *valueSetPartition, part *valueSetPartition) {
	head.stopNode.next = part.startNode
	part.startNode = head.startNode
	if part.stopNode == nil {
		part.stopNode = head.stopNode
	}
}

// partitionSurround stores part as the component headed by its start.
// C++ parity: ValueSetSolver::partitionSurround.
func (s *valueSetSolver) partitionSurround(part *valueSetPartition) {
	stored := *part
	part.startNode.partHead = &stored
}

// component builds the partition component headed by vertex.
// C++ parity: ValueSetSolver::component.
func (s *valueSetSolver) component(vertex *valueSet, part *valueSetPartition) {
	edges := newValueSetEdges(vertex, s.rootNodes)
	for succ := edges.getNext(); succ != nil; succ = edges.getNext() {
		if succ.count == 0 {
			s.visit(succ, part)
		}
	}
	partitionPrependNode(vertex, part)
	s.partitionSurround(part)
}

// visit walks the data-flow graph building the nested partitions.
// C++ parity: ValueSetSolver::visit.
func (s *valueSetSolver) visit(vertex *valueSet, part *valueSetPartition) int {
	s.nodeStack = append(s.nodeStack, vertex)
	s.depthFirstIndex++
	vertex.count = s.depthFirstIndex
	head := s.depthFirstIndex
	loop := false
	edges := newValueSetEdges(vertex, s.rootNodes)
	for succ := edges.getNext(); succ != nil; succ = edges.getNext() {
		var m int
		if succ.count == 0 {
			m = s.visit(succ, part)
		} else {
			m = succ.count
		}
		if m <= head {
			head = m
			loop = true
		}
	}
	if head == vertex.count {
		vertex.count = 0x7fffffff // Set to "infinity"
		element := s.nodeStack[len(s.nodeStack)-1]
		s.nodeStack = s.nodeStack[:len(s.nodeStack)-1]
		if loop {
			for element != vertex {
				element.count = 0
				element = s.nodeStack[len(s.nodeStack)-1]
				s.nodeStack = s.nodeStack[:len(s.nodeStack)-1]
			}
			var compPart valueSetPartition
			s.component(vertex, &compPart)
			partitionPrependPart(&compPart, part)
		} else {
			partitionPrependNode(vertex, part)
		}
	}
	return head
}

// establishTopologicalOrder orders the sets for chaotic iteration
// (Bourdoncle). C++ parity: ValueSetSolver::establishTopologicalOrder.
func (s *valueSetSolver) establishTopologicalOrder() {
	for _, vs := range s.valueNodes {
		vs.count = 0
		vs.next = nil
		vs.partHead = nil
	}
	rootNode := &valueSet{}
	s.depthFirstIndex = 0
	s.visit(rootNode, &s.orderPartition)
	s.orderPartition.startNode = s.orderPartition.startNode.next // Remove simulated root
}

// generateTrueEquation attaches "only true values reach slot of op".
// C++ parity: ValueSetSolver::generateTrueEquation.
func (s *valueSetSolver) generateTrueEquation(vn *Varnode, op *PcodeOp, slot, typ int, rng circleRange) {
	if vn != nil {
		vn.valueSet.addEquation(slot, typ, rng)
	} else {
		s.readNode(op).addEquation(slot, typ, rng) // Special read site
	}
}

// generateFalseEquation attaches the complement of a true constraint.
// C++ parity: ValueSetSolver::generateFalseEquation.
func (s *valueSetSolver) generateFalseEquation(vn *Varnode, op *PcodeOp, slot, typ int, rng circleRange) {
	falseRange := rng
	falseRange.invert()
	if vn != nil {
		vn.valueSet.addEquation(slot, typ, falseRange)
	} else {
		s.readNode(op).addEquation(slot, typ, falseRange) // Special read site
	}
}

// restrictedByConditional: every path into b from cond's dominance region
// passes through the out-edge of cond into b.
// C++ parity: FlowBlock::restrictedByConditional.
func restrictedByConditional(b, cond *FlowBlock) bool {
	if b.SizeIn() == 1 {
		return true // Impossible for any path to come through a sibling
	}
	if b.ImmedDom() != cond {
		return false // Not dominated by the conditional block at all
	}
	seenCond := false
	for i := 0; i < b.SizeIn(); i++ {
		inBlock := b.InEdge(i).Point
		if inBlock == cond {
			if seenCond {
				return false // Multiple direct edges from cond
			}
			seenCond = true
			continue
		}
		for inBlock != b {
			if inBlock == cond {
				return false // Must have come through a sibling
			}
			inBlock = inBlock.ImmedDom()
		}
	}
	return true
}

// applyConstraints adds the constraint (or its complement) to the reads of
// vn dominated by the branch's true (false) side.
// C++ parity: ValueSetSolver::applyConstraints.
func (s *valueSetSolver) applyConstraints(vn *Varnode, typ int, rng circleRange, cbranch *PcodeOp) {
	splitPoint := &cbranch.Parent().FlowBlock
	trueBlock, falseBlock := splitPoint.TrueOut(), splitPoint.FalseOut()
	if cbranch.flags&PcodeOpBooleanFlip != 0 {
		trueBlock, falseBlock = falseBlock, trueBlock
	}
	trueIsRestricted := restrictedByConditional(trueBlock, splitPoint)
	falseIsRestricted := restrictedByConditional(falseBlock, splitPoint)
	if vn.IsWritten() {
		if vSet := vn.valueSet; vSet.opCode == CPUI_MULTIEQUAL {
			vSet.addLandmark(typ, rng) // Leave landmark for widening
		}
	}
	for _, op := range vn.DescendIter() {
		var outVn *Varnode
		if op.flags&PcodeOpMark == 0 { // Not a special read site
			outVn = op.Output()
			if outVn == nil || !outVn.IsMark() {
				continue
			}
		}
		curBlock := &op.Parent().FlowBlock
		slot := op.GetSlot(vn)
		if op.Code() == CPUI_MULTIEQUAL {
			switch curBlock {
			case trueBlock:
				// Only the input along the exact true edge is restricted unless
				// trueBlock is only reachable that way
				if trueIsRestricted || trueBlock.InEdge(slot).Point == splitPoint {
					s.generateTrueEquation(outVn, op, slot, typ, rng)
				}
				continue
			case falseBlock:
				if falseIsRestricted || falseBlock.InEdge(slot).Point == splitPoint {
					s.generateFalseEquation(outVn, op, slot, typ, rng)
				}
				continue
			}
			curBlock = curBlock.InEdge(slot).Point // MULTIEQUAL input is really only from one in-block
		}
		for {
			if curBlock == trueBlock {
				if trueIsRestricted {
					s.generateTrueEquation(outVn, op, slot, typ, rng)
				}
				break
			}
			if curBlock == falseBlock {
				if falseIsRestricted {
					s.generateFalseEquation(outVn, op, slot, typ, rng)
				}
				break
			}
			if curBlock == splitPoint || curBlock == nil {
				break
			}
			curBlock = curBlock.ImmedDom()
		}
	}
}

// constraintsFromPath lifts the range from startVn back to endVn, then
// applies it along endVn's defining chain.
// C++ parity: ValueSetSolver::constraintsFromPath.
func (s *valueSetSolver) constraintsFromPath(typ int, lift *circleRange, startVn, endVn *Varnode, cbranch *PcodeOp) {
	for startVn != endVn {
		var constVn *Varnode
		startVn = lift.pullBack(startVn.Def(), &constVn, false)
		if startVn == nil {
			return // Couldn't pull all the way back to our value set
		}
	}
	for {
		var constVn *Varnode
		s.applyConstraints(endVn, typ, *lift, cbranch)
		if !endVn.IsWritten() {
			break
		}
		op := endVn.Def()
		if op.IsCall() || op.IsMarker() {
			break
		}
		endVn = lift.pullBack(op, &constVn, false)
		if endVn == nil || !endVn.IsMark() {
			break
		}
	}
}

// constraintsFromCBranch lifts the branch condition to a Varnode in the
// system and constrains its reads. C++ parity: ValueSetSolver::constraintsFromCBranch.
func (s *valueSetSolver) constraintsFromCBranch(cbranch *PcodeOp) {
	vn := cbranch.Input(1) // The Varnode deciding the condition
	for !vn.IsMark() {
		if !vn.IsWritten() {
			break
		}
		op := vn.Def()
		if op.IsCall() || op.IsMarker() {
			break
		}
		num := op.NumInput()
		if num == 0 || num > 2 {
			break
		}
		vn = op.Input(0)
		if num == 2 {
			if vn.IsConstant() {
				vn = op.Input(1)
			} else if !op.Input(1).IsConstant() {
				// Both inputs are non-constant
				s.generateRelativeConstraint(op, cbranch)
				return
			}
		}
	}
	if vn.IsMark() {
		lift := newCircleRangeBoolean(true)
		s.constraintsFromPath(0, &lift, cbranch.Input(1), vn, cbranch)
	}
}

// generateConstraints collects the blocks around the system and derives
// constraints from every conditional branch entering them.
// C++ parity: ValueSetSolver::generateConstraints.
func (s *valueSetSolver) generateConstraints(worklist []*Varnode, reads []*PcodeOp) {
	var blockList []*FlowBlock
	markUp := func(bl *FlowBlock) {
		for bl != nil && !bl.HasFlag(BlockFlagMark) {
			bl.SetFlag(BlockFlagMark)
			blockList = append(blockList, bl)
			bl = bl.ImmedDom()
		}
	}
	// Collect all blocks that contain a system op (input) or dominate a container
	for _, vn := range worklist {
		op := vn.Def()
		if op == nil {
			continue
		}
		bl := &op.Parent().FlowBlock
		if op.Code() == CPUI_MULTIEQUAL {
			for j := 0; j < bl.SizeIn(); j++ {
				markUp(bl.InEdge(j).Point)
			}
		} else {
			markUp(bl)
		}
	}
	for _, op := range reads {
		markUp(&op.Parent().FlowBlock)
	}
	for _, bl := range blockList {
		bl.ClearFlag(BlockFlagMark)
	}
	var finalList []*FlowBlock
	// Now go through input blocks to the previously calculated blocks
	for _, bl := range blockList {
		for j := 0; j < bl.SizeIn(); j++ {
			splitPoint := bl.InEdge(j).Point
			if splitPoint.HasFlag(BlockFlagMark) || splitPoint.SizeOut() != 2 {
				continue
			}
			bb, ok := splitPoint.Concrete().(*BlockBasic)
			if !ok {
				continue
			}
			if lastOp := bb.LastOp(); lastOp != nil && lastOp.Code() == CPUI_CBRANCH {
				splitPoint.SetFlag(BlockFlagMark)
				finalList = append(finalList, splitPoint)
				s.constraintsFromCBranch(lastOp) // Try to generate constraints from this split
			}
		}
	}
	for _, bl := range finalList {
		bl.ClearFlag(BlockFlagMark)
	}
}

// checkRelativeConstant: vn is a COPY/INT_ADD-constant chain from the
// relative base register; reports the base type and the offset.
// C++ parity: ValueSetSolver::checkRelativeConstant.
func (s *valueSetSolver) checkRelativeConstant(vn *Varnode) (typeCode int, value uint64, ok bool) {
	for {
		if vn.IsMark() {
			if set := vn.valueSet; set.typeCode != 0 {
				return set.typeCode, value, true
			}
		}
		if !vn.IsWritten() {
			return 0, 0, false
		}
		op := vn.Def()
		switch op.Code() {
		case CPUI_COPY, CPUI_INDIRECT:
			vn = op.Input(0)
		case CPUI_INT_ADD, CPUI_PTRSUB:
			constVn := op.Input(1)
			if !constVn.IsConstant() {
				return 0, 0, false
			}
			value = (value + constVn.Offset()) & maskForSize(constVn.Size())
			vn = op.Input(0)
		default:
			return 0, 0, false
		}
	}
}

// generateRelativeConstraint turns a comparison against a relative
// constant into a relative equation.
// C++ parity: ValueSetSolver::generateRelativeConstraint.
func (s *valueSetSolver) generateRelativeConstraint(compOp, cbranch *PcodeOp) {
	opc := compOp.Code()
	switch opc {
	case CPUI_INT_LESS:
		opc = CPUI_INT_SLESS // Unsigned pointer comparisons are signed relative to the base
	case CPUI_INT_LESSEQUAL:
		opc = CPUI_INT_SLESSEQUAL
	case CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
	default:
		return
	}
	inVn0, inVn1 := compOp.Input(0), compOp.Input(1)
	lift := newCircleRangeBoolean(true)
	var vn *Varnode
	var typeCode int
	if tc, value, ok := s.checkRelativeConstant(inVn0); ok {
		typeCode = tc
		vn = inVn1
		if !lift.pullBackBinary(opc, value, 1, vn.Size(), 1) {
			return
		}
	} else if tc, value, ok := s.checkRelativeConstant(inVn1); ok {
		typeCode = tc
		vn = inVn0
		if !lift.pullBackBinary(opc, value, 0, vn.Size(), 1) {
			return
		}
	} else {
		return // Neither side looks like a relative constant
	}
	endVn := vn
	for !endVn.IsMark() {
		if !endVn.IsWritten() {
			return
		}
		op := endVn.Def()
		switch op.Code() {
		case CPUI_COPY, CPUI_PTRSUB:
			endVn = op.Input(0)
		case CPUI_INT_ADD: // Can pull back through INT_ADD with a constant
			if !op.Input(1).IsConstant() {
				return
			}
			endVn = op.Input(0)
		default:
			return
		}
	}
	s.constraintsFromPath(typeCode, &lift, vn, endVn, cbranch)
}

// establishValueSets builds the system feeding sinks and the read sites.
// C++ parity: ValueSetSolver::establishValueSets.
func (s *valueSetSolver) establishValueSets(sinks []*Varnode, reads []*PcodeOp, stackReg *Varnode, indirectAsCopy bool) {
	var worklist []*Varnode
	workPos := 0
	if stackReg != nil {
		s.newValueSet(stackReg, 1) // Establish stack pointer as special
		stackReg.SetMark()
		worklist = append(worklist, stackReg)
		workPos++
		s.rootNodes = append(s.rootNodes, stackReg.valueSet)
	}
	for _, vn := range sinks {
		s.newValueSet(vn, 0)
		vn.SetMark()
		worklist = append(worklist, vn)
	}
	addInput := func(inVn *Varnode) {
		s.newValueSet(inVn, 0)
		inVn.SetMark()
		worklist = append(worklist, inVn)
	}
	for workPos < len(worklist) {
		vn := worklist[workPos]
		workPos++
		if !vn.IsWritten() {
			if vn.IsConstant() {
				// Constants feeding binary ops are picked up through the
				// other input, except a PTRSUB from a spacebase constant.
				if vn.IsSpaceBase() || vn.LoneDescend().NumInput() == 1 {
					s.rootNodes = append(s.rootNodes, vn.valueSet)
				}
			} else {
				s.rootNodes = append(s.rootNodes, vn.valueSet)
			}
			continue
		}
		op := vn.Def()
		switch op.Code() { // Ops where we can never predict an integer range
		case CPUI_INDIRECT:
			if indirectAsCopy || op.IsIndirectStore() {
				if inVn := op.Input(0); !inVn.IsMark() {
					addInput(inVn)
				}
			} else {
				vn.valueSet.setFullSet()
				s.rootNodes = append(s.rootNodes, vn.valueSet)
			}
		case CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER, CPUI_LOAD, CPUI_NEW, CPUI_SEGMENTOP, CPUI_CPOOLREF,
			CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
			CPUI_FLOAT_SQRT, CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_TRUNC, CPUI_FLOAT_CEIL,
			CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND:
			vn.valueSet.setFullSet()
			s.rootNodes = append(s.rootNodes, vn.valueSet)
		default:
			for i := 0; i < op.NumInput(); i++ {
				inVn := op.Input(i)
				if inVn.IsMark() || inVn.IsAnnotation() {
					continue
				}
				addInput(inVn)
			}
		}
	}
	for _, op := range reads {
		for slot := 0; slot < op.NumInput(); slot++ {
			if op.Input(slot).IsMark() {
				s.readNode(op).setPcodeOp(op, slot)
				op.SetFlag(PcodeOpMark) // Mark read ops for equation generation
				break                   // Only 1 read allowed
			}
		}
	}
	s.generateConstraints(worklist, reads)
	for _, op := range reads {
		op.ClearFlag(PcodeOpMark)
	}
	s.establishTopologicalOrder()
	for _, vn := range worklist {
		vn.ClearMark()
	}
}

// solve iterates the sets in topological order, looping components until
// stable or max iterations. C++ parity: ValueSetSolver::solve.
func (s *valueSetSolver) solve(max int, widener valueSetWidener) {
	s.maxIterations = max
	s.numIterations = 0
	for _, vs := range s.valueNodes {
		vs.count = 0
	}
	var componentStack []*valueSetPartition
	var curComponent *valueSetPartition
	curSet := s.orderPartition.startNode
	for curSet != nil {
		s.numIterations++
		if s.numIterations > s.maxIterations {
			break // Quit if max iterations exceeded
		}
		if curSet.partHead != nil && curSet.partHead != curComponent {
			componentStack = append(componentStack, curSet.partHead)
			curComponent = curSet.partHead
			curComponent.isDirty = false
			// Reset component counter upon entry
			curComponent.startNode.count = widener.determineIterationReset(curComponent.startNode)
		}
		if curComponent == nil {
			curSet.iterate(widener)
			curSet = curSet.next
			continue
		}
		if curSet.iterate(widener) {
			curComponent.isDirty = true
		}
		if curComponent.stopNode != curSet {
			curSet = curSet.next
			continue
		}
		for {
			if curComponent.isDirty {
				curComponent.isDirty = false
				curSet = curComponent.startNode
				if len(componentStack) > 1 { // Mark parent dirty when restarting a dirty child
					componentStack[len(componentStack)-2].isDirty = true
				}
				break
			}
			componentStack = componentStack[:len(componentStack)-1]
			if len(componentStack) == 0 {
				curComponent = nil
				curSet = curSet.next
				break
			}
			curComponent = componentStack[len(componentStack)-1]
			if curComponent.stopNode != curSet {
				curSet = curSet.next
				break
			}
		}
	}
	for _, r := range s.readNodes {
		r.compute() // Calculate any follow-on value sets
	}
}
