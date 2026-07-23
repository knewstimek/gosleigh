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

// ActionInferTypes is the C++-parity data-flow type propagation pass.
//
// C++ parity: coreaction.cc ActionInferTypes (apply 5385, buildLocaltypes 5019,
// writeBack 5054, propagateTypeEdge 5085, PropagationState 5126, propagateOneType
// 5183, propagateAcrossReturns 5353) + varnode.cc getLocalType (900) / updateType
// (456).
//
// Unlike the legacy committed-type-seeded pass (action_infertypes_legacy.go),
// this implementation re-derives each Varnode's provisional type every sweep
// purely from the op grammar (getLocalType) and pushes types along op edges via
// the PropagationState DFS. Crucially apply() runs exactly ONE sweep per call and
// always returns 0 -- the mainloop drives repetition, and reporting no data-flow
// change is precisely the mechanism that lets a later ActionRestructureVarnode
// snapshot the pre-typeprop (TYPE_UNKNOWN) committed types of stack locals.
//
// This faithful pass is registered only on the tree mainloop (action.go). The
// production linear pipeline (bridge/decompile.go) keeps the legacy pass.
type ActionInferTypes struct {
	ActionBase
	// localcount counts sweeps performed for the current function.
	// C++ parity: ActionInferTypes::localcount (coreaction.hh:964), reset per
	// function in reset().
	localcount int
}

// NewActionInferTypes creates the faithful ActionInferTypes in the given group.
func NewActionInferTypes(group string) *ActionInferTypes {
	a := &ActionInferTypes{}
	// C++ parity: ActionInferTypes uses flags=0 (coreaction.hh:974); it re-runs
	// every mainloop pass so late-created Varnodes still get typed.
	a.ActionBase = NewActionBase(a, 0, "infertypes", group)
	return a
}

// Clone returns a copy of the action if it belongs to one of the requested groups.
func (a *ActionInferTypes) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionInferTypes(a.GetGroup())
}

// Reset prepares the action for a new function.
// C++ parity: ActionInferTypes::reset (coreaction.hh:975) -> localcount = 0.
func (a *ActionInferTypes) Reset(data *Funcdata) {
	a.ActionBase.Reset(data)
	a.localcount = 0
}

// Apply runs exactly one propagation sweep and always returns 0.
// C++ parity: ActionInferTypes::apply (coreaction.cc:5385-5427).
func (a *ActionInferTypes) Apply(data *Funcdata) int {
	// Make sure spacebase is accurate or bases could get typed and then ptrarithed.
	if !data.HasTypeRecoveryStarted() {
		return 0
	}
	tf := sharedTypeFactory

	if a.localcount >= 7 { // This constant arrived at empirically (C++ coreaction.cc:5401)
		if a.localcount == 7 {
			data.warningHeader("Type propagation algorithm not settling")
			// C++ also calls data.setTypeRecoveryExceeded(); that flag is not
			// modelled in Gosleigh yet (only gates a downstream warning path).
			a.localcount++
		}
		return 0
	}

	// C++ also runs data.getScopeLocal()->applyTypeRecommendations() here; the
	// register type-recommendation table is not modelled yet (TODO).
	inferBuildLocaltypes(data, tf)

	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if !inferProcessed(vn) {
			continue
		}
		inferPropagateOneType(data, tf, vn)
	}
	inferPropagateAcrossReturns(data, tf)

	// C++ also runs propagateSpacebaseRef here (pointer/alias recovery off the
	// spacebase register). That is out of scope for this slice (like the
	// AliasChecker path in ScopeLocal::restructure) -- TODO.

	if inferWriteBack(data) {
		// count += 1;			// Do not consider this a data-flow change (C++:5423)
		a.localcount++
	}
	return 0
}

// inferProcessed mirrors the C++ buildLocaltypes/writeBack skip filter:
// skip annotations and Varnodes that are neither written nor read.
// C++ parity: coreaction.cc:5029-5030 / 5064-5065.
func inferProcessed(vn *Varnode) bool {
	if vn.IsAnnotation() {
		return false
	}
	if !vn.IsWritten() && vn.HasNoDescend() {
		return false
	}
	return true
}

// inferGetLocalType makes an initial determination of a Varnode's data-type from
// the ops that read and write it. Returns the type plus whether up-propagation
// through the definition must be blocked.
// C++ parity: Varnode::getLocalType (varnode.cc:900-936).
func inferGetLocalType(vn *Varnode, tf *TypeFactory) (Datatype, bool) {
	if vn.IsTypeLock() { // Our type is locked, don't change
		return vn.Type(), false
	}
	var ct Datatype
	if def := vn.Def(); def != nil {
		if to := def.GetOpcode(); to != nil {
			ct = to.OutputTypeLocal(def, tf)
		}
		if def.HasStopTypePropagation() {
			return ct, true
		}
	}
	for _, op := range vn.DescendIter() {
		if op == nil {
			continue
		}
		to := op.GetOpcode()
		if to == nil {
			continue
		}
		slot := op.GetSlot(vn)
		newct := to.InputTypeLocal(op, slot, tf)
		if newct == nil {
			continue
		}
		if ct == nil {
			ct = newct
		} else if TypeOrder(newct, ct) < 0 {
			ct = newct
		}
	}
	if ct == nil {
		// C++ throws LowlevelError("NULL local type"); processed Varnodes always
		// have a def or a descendant, so ct is normally non-nil. Fall back to a
		// sized unknown rather than panic if a degenerate op provided no local.
		ct = tf.GetBase(vn.Size(), TYPE_UNKNOWN, "unknown")
	}
	return ct, false
}

// inferBuildLocaltypes seeds tempType on each processed Varnode from getLocalType.
// C++ parity: ActionInferTypes::buildLocaltypes (coreaction.cc:5019-5048).
func inferBuildLocaltypes(data *Funcdata, tf *TypeFactory) {
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if !inferProcessed(vn) {
			continue
		}
		// C++ additionally consults a type-locked parent Symbol's getExactPiece
		// here (coreaction.cc:5032-5038). Recovered stack locals are not
		// symbol-type-locked, so that sub-case is not ported (TODO).
		ct, needsBlock := inferGetLocalType(vn, tf)
		if needsBlock {
			vn.SetAddlFlags(VarnodeStopUpPropagation)
		}
		vn.SetTempType(ct)
	}
}

// inferWriteBack copies each processed Varnode's tempType into its permanent type.
// Returns true if any Varnode's data-type changed this sweep.
// C++ parity: ActionInferTypes::writeBack (coreaction.cc:5054-5071) +
// Varnode::updateType (varnode.cc:456-464).
func inferWriteBack(data *Funcdata) bool {
	change := false
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if !inferProcessed(vn) {
			continue
		}
		ct := vn.GetTempType()
		if ct == nil {
			continue
		}
		if vn.IsTypeLock() { // Don't change a locked Datatype
			continue
		}
		if vn.Type() == ct { // No change
			continue
		}
		SetVarnodeType(vn, ct)
		if hv := vn.High(); hv != nil {
			hv.SetType(ct)
		}
		change = true
	}
	return change
}

// propagationState iterates the propagation edges rooted at a Varnode: first
// through the Varnode's descendant PcodeOps, then its defining PcodeOp; and for
// each op from the output Varnode through the input Varnodes.
// C++ parity: struct PropagationState (coreaction.cc:5126-5171).
type propagationState struct {
	vn      *Varnode
	descend []*PcodeOp
	iterIdx int
	op      *PcodeOp
	slot    int
	inslot  int
}

func newPropagationState(vn *Varnode) *propagationState {
	p := &propagationState{vn: vn, descend: vn.DescendIter()}
	if len(p.descend) > 0 {
		p.op = p.descend[0]
		p.iterIdx = 1
		if p.op.Output() != nil {
			p.slot = -1
		} else {
			p.slot = 0
		}
		p.inslot = p.op.GetSlot(vn)
	} else {
		p.op = vn.Def()
		p.inslot = -1
		p.slot = 0
	}
	return p
}

func (p *propagationState) valid() bool { return p.op != nil }

// step advances to the next propagation edge.
// C++ parity: PropagationState::step (coreaction.cc:5150-5171).
func (p *propagationState) step() {
	p.slot++
	if p.slot < p.op.NumInput() {
		return
	}
	if p.iterIdx < len(p.descend) {
		p.op = p.descend[p.iterIdx]
		p.iterIdx++
		if p.op.Output() != nil {
			p.slot = -1
		} else {
			p.slot = 0
		}
		p.inslot = p.op.GetSlot(p.vn)
		return
	}
	if p.inslot == -1 {
		p.op = nil
	} else {
		p.op = p.vn.Def()
	}
	p.inslot = -1
	p.slot = 0
}

// inferPropagateOneType pushes a Varnode's tempType as far as possible through
// the data-flow graph, visiting each Varnode at most once.
// C++ parity: ActionInferTypes::propagateOneType (coreaction.cc:5183-5209).
func inferPropagateOneType(data *Funcdata, tf *TypeFactory, root *Varnode) {
	stack := []*propagationState{newPropagationState(root)}
	root.SetMark()
	for len(stack) > 0 {
		ptr := stack[len(stack)-1]
		if !ptr.valid() {
			ptr.vn.ClearMark()
			stack = stack[:len(stack)-1]
			continue
		}
		if inferPropagateTypeEdge(data, tf, ptr.op, ptr.inslot, ptr.slot) {
			var nextvn *Varnode
			if ptr.slot == -1 {
				nextvn = ptr.op.Output()
			} else {
				nextvn = ptr.op.Input(ptr.slot)
			}
			ptr.step() // Make sure to step before pushing
			stack = append(stack, newPropagationState(nextvn))
			nextvn.SetMark()
		} else {
			ptr.step()
		}
	}
}

// inferPropagateTypeEdge attempts to propagate a data-type across one PcodeOp edge
// and updates the output Varnode's tempType. Returns true if the pushed type is
// new and the output is not already on the DFS path.
// C++ parity: ActionInferTypes::propagateTypeEdge (coreaction.cc:5085-5123).
func inferPropagateTypeEdge(data *Funcdata, tf *TypeFactory, op *PcodeOp, inslot, outslot int) bool {
	var invn *Varnode
	if inslot == -1 {
		invn = op.Output()
	} else {
		invn = op.Input(inslot)
	}
	if invn == nil {
		return false
	}
	alttype := invn.GetTempType()
	if alttype == nil {
		return false
	}
	// C++ gives a needsResolution() incoming type a chance to resolveInFlow here
	// (union field resolution). Unions are out of scope for this slice (TODO).
	if inslot == outslot {
		return false // don't backtrack
	}
	var outvn *Varnode
	if outslot < 0 {
		outvn = op.Output()
	} else {
		outvn = op.Input(outslot)
		if outvn == nil || outvn.IsAnnotation() {
			return false
		}
	}
	if outvn == nil {
		return false
	}
	if outvn.IsTypeLock() {
		return false // Can't propagate through typelock
	}
	if outvn.HasAddlFlags(VarnodeStopUpPropagation) && outslot >= 0 {
		return false // Propagation is blocked
	}
	if alttype.Metatype() == TYPE_BOOL { // Only propagate boolean
		if outvn.NZMask() > 1 { // output can take non-boolean values
			return false
		}
	}
	newtype := inferPropagateEdge(data, tf, op, invn, outvn, inslot, outslot, alttype)
	if newtype == nil {
		return false
	}
	// C++ compares against outvn->getTempType(), which buildLocaltypes always
	// seeds. A Varnode reached across an edge but not seeded (e.g. one outside
	// the loc-set the seeding pass iterated) has a nil tempType; treat nil as the
	// least-specific type so the incoming type wins.
	cur := outvn.GetTempType()
	if cur == nil || TypeOrder(newtype, cur) < 0 {
		outvn.SetTempType(newtype)
		return !outvn.IsMark()
	}
	return false
}

// inferPropagateEdge is the per-opcode edge transform. It mirrors each
// TypeOpXxx::propagateType override; every opcode not handled here propagates
// nothing (TypeOp::propagateType default, typeop.cc:318).
//
// C++ parity: typeop.cc TypeOpCopy(412), TypeOpLoad(488), TypeOpStore(559),
// TypeOpEqual/NotEqual/IntLess/IntLessEqual::propagateAcrossCompare(965),
// TypeOpIntSless(1035)/IntSlessEqual(1061), TypeOpIntAdd(1183), TypeOpMulti(1953),
// TypeOpIndirect(2007).
func inferPropagateEdge(data *Funcdata, tf *TypeFactory, op *PcodeOp, invn, outvn *Varnode, inslot, outslot int, alttype Datatype) Datatype {
	switch op.Code() {
	case CPUI_PTRSUB:
		// Mirror TypeOpPtrsub::propagateType (typeop.cc L2368-2380): a pointer
		// input propagates to the output through propagateAddIn2Out. This is the
		// mechanism that keeps a spacebase PTRSUB output typed as a pointer to
		// the referenced symbol across every InferTypes pass (the local seed is
		// TYPE_INT, so without this the &symbol pointer would be lost).
		if inslot != -1 && outslot != -1 {
			return nil // Must propagate input <-> output
		}
		if alttype.Metatype() != TYPE_PTR {
			return nil
		}
		if inslot == -1 {
			return nil // Don't propagate pointer types output -> input
		}
		if altPtr, ok := alttype.(*Pointer); ok {
			return inferPropagateAddIn2Out(data, tf, altPtr, op, inslot)
		}
		return nil
	case CPUI_COPY, CPUI_MULTIEQUAL:
		if inslot != -1 && outslot != -1 {
			return nil // Must propagate input <-> output
		}
		if invn.IsSpaceBase() {
			// C++ turns a spacebase into a pointer-to-unknown here. Spacebase
			// type propagation is not modelled in this slice (TODO).
			return nil
		}
		return alttype
	case CPUI_INDIRECT:
		if op.IsIndirectCreation() {
			return nil
		}
		if inslot == 1 || outslot == 1 {
			return nil
		}
		if inslot != -1 && outslot != -1 {
			return nil // Must propagate input <-> output
		}
		if invn.IsSpaceBase() {
			return nil // spacebase pointer not modelled (TODO)
		}
		return alttype
	case CPUI_LOAD:
		if inslot == 0 || outslot == 0 {
			return nil // Don't propagate along this edge
		}
		if invn.IsSpaceBase() {
			return nil
		}
		if inslot == -1 { // Propagating output to input (value to ptr)
			return inferPropagateToPointer(tf, alttype, outvn.Size(), inferLoadStoreWordSize(op))
		}
		return inferPropagateFromPointer(tf, alttype, outvn.Size())
	case CPUI_STORE:
		if inslot == 0 || outslot == 0 {
			return nil
		}
		if invn.IsSpaceBase() {
			return nil
		}
		if inslot == 2 { // Propagating value to ptr
			return inferPropagateToPointer(tf, alttype, outvn.Size(), inferLoadStoreWordSize(op))
		}
		return inferPropagateFromPointer(tf, alttype, outvn.Size())
	case CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL:
		if inslot == -1 || outslot == -1 {
			return nil // Must propagate input <-> input
		}
		if alttype.Metatype() != TYPE_INT {
			return nil // Only propagate signed things
		}
		return alttype
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL:
		return inferPropagateAcrossCompare(tf, invn, outvn, inslot, outslot, alttype)
	case CPUI_INT_ADD:
		return inferPropagateIntAdd(data, tf, op, invn, outvn, inslot, outslot, alttype)
	default:
		return nil
	}
}

// inferPropagateAcrossCompare handles the input<->input propagation shared by the
// equality/unsigned comparison ops.
// C++ parity: TypeOpEqual::propagateAcrossCompare (typeop.cc:965-988).
func inferPropagateAcrossCompare(tf *TypeFactory, invn, outvn *Varnode, inslot, outslot int, alttype Datatype) Datatype {
	if inslot == -1 || outslot == -1 {
		return nil
	}
	if invn.IsSpaceBase() {
		return nil // spacebase pointer not modelled (TODO)
	}
	// C++ also special-cases a PointerRel into the middle of a struct here; that
	// is out of scope for this slice (TODO).
	return alttype
}

// inferPropagateIntAdd handles the INT_ADD edge.
// C++ parity: TypeOpIntAdd::propagateType (typeop.cc:1183-1203).
func inferPropagateIntAdd(data *Funcdata, tf *TypeFactory, op *PcodeOp, invn, outvn *Varnode, inslot, outslot int, alttype Datatype) Datatype {
	meta := alttype.Metatype()
	if meta != TYPE_PTR {
		if meta != TYPE_INT && meta != TYPE_UINT {
			return nil
		}
		if outslot != 1 || op.NumInput() < 2 || op.Input(1) == nil || !op.Input(1).IsConstant() {
			return nil
		}
	} else if inslot != -1 && outslot != -1 {
		return nil // Must propagate input <-> output for pointers
	}
	if outvn.IsConstant() && alttype.Metatype() != TYPE_PTR {
		return alttype
	}
	if inslot == -1 {
		return nil // Don't propagate pointer types this direction
	}
	altPtr, ok := alttype.(*Pointer)
	if !ok {
		return nil
	}
	return inferPropagateAddIn2Out(data, tf, altPtr, op, inslot)
}

// inferPropagateAddIn2Out mirrors TypeOpIntAdd::propagateAddIn2Out (typeop.cc
// L1217-1255) for the case a pointer flows from input slot inslot of an
// add-like op (PTRSUB/PTRADD/INT_ADD) to the op output.
//
// Ported: the "propagates through untransformed" command (no downChain needed),
// and the spacebase downChain -- the referenced symbol is resolved
// (TypeSpacebase::getSubType) and a stripped pointer to the symbol's data-type
// is returned; a still-spacebase result degrades to unknown1 * (C++ L1250-1253).
//
// Not ported: non-spacebase downChain navigation into struct/array fields and
// the TypePointerRel it builds (also the `within != 0` spacebase sub-object
// case below). Those return nil, i.e. no propagation -- a known mismatch.
func inferPropagateAddIn2Out(data *Funcdata, tf *TypeFactory, alt *Pointer, op *PcodeOp, inslot int) Datatype {
	ptrTo := alt.Pointee()
	if ptrTo == nil {
		return nil
	}
	off, command := propagateAddPointer(op, inslot, ptrTo.AlignSize())
	if command == 2 {
		return nil // Doesn't look like a good pointer add
	}
	if command == 3 {
		// Input data-type propagates through untransformed: C++ skips the
		// downChain loop entirely (typeop.cc:1226) and, with no parent, falls
		// straight through to the spacebase degrade check below.
		return inferSpacebaseDegrade(tf, alt, op, inslot)
	}
	baseVn := op.Input(inslot)
	if baseVn == nil || !baseVn.IsSpaceBase() {
		return nil // Only spacebase pointer-forward downChain is ported (TODO)
	}
	// downChain at the spacebase level: convert the address-unit offset to bytes
	// and resolve the containing symbol.
	ws := int64(1)
	if alt.WordSize() > 0 {
		ws = int64(alt.WordSize())
	}
	typeOffset := off * ws // AddrSpace::addressToByteInt
	symType, within := data.ResolveSpacebaseSymbol(baseVn.GetSpaceFromConst(), typeOffset)
	if symType == nil {
		return nil
	}
	if within != 0 {
		// Offset lands in the interior of a struct/array symbol; C++ would build
		// a TypePointerRel here. Not ported for this slice -- leave the output at
		// its locally-derived type (TODO).
		return nil
	}
	res := tf.GetPointerStripArray(alt.Size(), symType, alt.WordSize())
	return inferSpacebaseDegrade(tf, res, op, inslot)
}

// inferSpacebaseDegrade is the tail of propagateAddIn2Out (typeop.cc:1250-1253):
// when the pointer input is the spacebase register itself and the result would
// still be a pointer-to-spacebase, hand back a plain unknown1 * instead. This
// is what keeps `RSP + <non-constant>` from re-typing as the frame itself.
func inferSpacebaseDegrade(tf *TypeFactory, res *Pointer, op *PcodeOp, inslot int) Datatype {
	if in := op.Input(inslot); in != nil && in.IsSpaceBase() {
		if res.Pointee() != nil && res.Pointee().Metatype() == TYPE_SPACEBASE {
			return tf.GetPointer(res.Size(), tf.GetBase(1, TYPE_UNKNOWN, "unknown"), res.WordSize())
		}
	}
	return res
}

// propagateAddPointer mirrors TypeOpIntAdd::propagateAddPointer (typeop.cc
// L1270-1315): classify how a pointer at input slot propagates through an
// add-like op, returning the constant offset and a command code:
//   0 add-zero, 1 add-const, 2 no-propagate, 3 untransformed.
func propagateAddPointer(op *PcodeOp, slot int, sz int32) (int64, int) {
	switch op.Code() {
	case CPUI_PTRADD:
		if slot != 0 {
			return 0, 2
		}
		constvn := op.Input(1)
		mult := int64(op.Input(2).Offset())
		if constvn.IsConstant() {
			off := int64(truncateToSize(uint64(int64(constvn.Offset())*mult), constvn.Size()))
			if off == 0 {
				return 0, 0
			}
			return off, 1
		}
		if sz != 0 && mult%int64(sz) != 0 {
			return 0, 2
		}
		return 0, 3
	case CPUI_PTRSUB:
		if slot != 0 {
			return 0, 2
		}
		off := int64(op.Input(1).Offset())
		if off == 0 {
			return 0, 0
		}
		return off, 1
	case CPUI_INT_ADD:
		// C++ typeop.cc:1290-1315.
		othervn := op.Input(1 - slot)
		if othervn == nil {
			return 0, 2
		}
		if !othervn.IsConstant() { // Check if othervn is an offset
			if othervn.IsWritten() {
				if multop := othervn.Def(); multop != nil && multop.Code() == CPUI_INT_MULT {
					if constvn := multop.Input(1); constvn != nil && constvn.IsConstant() {
						mult := constvn.Offset()
						if mult == maskForSize(constvn.Size()) { // If multiplying by -1
							return 0, 2 // Assume this is a pointer difference and don't propagate
						}
						if sz != 0 && mult%uint64(sz) != 0 {
							return 0, 2
						}
					}
					return 0, 3
				}
			}
			if sz == 1 {
				return 0, 3
			}
			return 0, 2
		}
		if tt := othervn.GetTempType(); tt != nil && tt.Metatype() == TYPE_PTR {
			return 0, 2 // Check if othervn marked as ptr
		}
		off := int64(othervn.Offset())
		if off == 0 {
			return 0, 0
		}
		return off, 1
	default:
		return 0, 2
	}
}

// inferLoadStoreWordSize returns the word size associated with a LOAD/STORE
// pointer, taken from the space-id constant in input(0).
// C++ parity: op->getIn(0)->getSpaceFromConst()->getWordSize() (typeop.cc:495/566).
// Falls back to 1 (the default data-space word size) when the space-id constant
// was not bound onto the Varnode, so pointer typing still propagates.
func inferLoadStoreWordSize(op *PcodeOp) uint32 {
	if op.NumInput() > 0 && op.Input(0) != nil {
		if spc := op.Input(0).GetSpaceFromConst(); spc != nil {
			return uint32(spc.WordSize)
		}
	}
	return 1
}

// inferPropagateToPointer builds a pointer-to-dt of the given pointer size.
// C++ parity: TypeOp::propagateToPointer (typeop.cc:187-199).
func inferPropagateToPointer(tf *TypeFactory, dt Datatype, sz int32, wordsz uint32) Datatype {
	if sz <= 0 {
		return nil
	}
	if dt.Metatype() == TYPE_PTR {
		dt = tf.GetBase(dt.Size(), TYPE_UNKNOWN, "unknown") // Pass back unknown *
	}
	// C++ also unwraps TYPE_PARTIALSTRUCT here (not modelled).
	return tf.GetPointer(sz, dt, wordsz)
}

// inferPropagateFromPointer dereferences a pointer type to its element type.
// C++ parity: TypeOp::propagateFromPointer (typeop.cc:207-227, enum tail elided).
func inferPropagateFromPointer(tf *TypeFactory, dt Datatype, sz int32) Datatype {
	ptr, ok := dt.(*Pointer)
	if !ok {
		return nil
	}
	ptrto := ptr.Pointee()
	if ptrto == nil {
		return nil
	}
	if ptrto.Size() == sz {
		return ptrto
	}
	// Size mismatch: C++ only propagates (partial) enumerations here, which are
	// out of scope for this slice (TODO).
	return nil
}

// inferCanonicalReturnOp returns the non-dead, non-halt CPUI_RETURN op whose
// value input carries the most specialized tempType.
// C++ parity: ActionInferTypes::canonicalReturnOp (coreaction.cc:5322-5347).
func inferCanonicalReturnOp(data *Funcdata) *PcodeOp {
	var res *PcodeOp
	var bestdt Datatype
	for _, op := range data.allOpsOrdered() {
		if op.Code() != CPUI_RETURN || op.IsDead() || op.HaltType() != 0 {
			continue
		}
		if op.NumInput() > 1 {
			ct := op.Input(1).GetTempType()
			if ct == nil {
				continue
			}
			if bestdt == nil || TypeOrder(ct, bestdt) < 0 {
				res = op
				bestdt = ct
			}
		}
	}
	return res
}

// inferPropagateAcrossReturns lets data-types propagate between the value inputs
// of multiple CPUI_RETURN ops (a function returns a single data-type).
// C++ parity: ActionInferTypes::propagateAcrossReturns (coreaction.cc:5353-5383).
func inferPropagateAcrossReturns(data *Funcdata, tf *TypeFactory) {
	if data.GetFuncProto() != nil && data.GetFuncProto().IsOutputLocked() {
		return
	}
	op := inferCanonicalReturnOp(data)
	if op == nil {
		return
	}
	baseVn := op.Input(1)
	ct := baseVn.GetTempType()
	if ct == nil {
		return
	}
	baseSize := baseVn.Size()
	isBool := ct.Metatype() == TYPE_BOOL
	for _, retop := range data.allOpsOrdered() {
		if retop == op || retop.Code() != CPUI_RETURN || retop.IsDead() || retop.HaltType() != 0 {
			continue
		}
		if retop.NumInput() > 1 {
			vn := retop.Input(1)
			if vn.Size() != baseSize {
				continue
			}
			if isBool && vn.NZMask() > 1 { // Don't propagate bool if value isn't 0/1
				continue
			}
			if vn.GetTempType() == ct { // Already propagated
				continue
			}
			vn.SetTempType(ct)
			inferPropagateOneType(data, tf, vn)
		}
	}
}
