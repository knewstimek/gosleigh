package pcode

import "gosleigh/pkg/address"

var sharedTypeFactory = NewTypeFactory()

func SetVarnodeType(vn *Varnode, dt Datatype) {
	if vn == nil {
		return
	}
	if dt != nil {
		dt = sharedTypeFactory.Intern(dt)
	}
	vn.typ = dt
}

func (vn *Varnode) Type() Datatype {
	if vn == nil {
		return nil
	}
	return vn.typ
}

func (vn *Varnode) TypeReadFacing(op *PcodeOp) Datatype {
	if vn == nil {
		return nil
	}
	if dt := vn.Type(); dt != nil {
		// C++ parity: Varnode::getTypeReadFacing (findResolve of the read).
		if dt.NeedsResolution() && op != nil {
			return findResolve(dt, op, op.GetSlot(vn))
		}
		return dt
	}
	if vn.IsConstant() {
		return sharedTypeFactory.GetBase(vn.Size(), TYPE_UINT, "uint")
	}
	return sharedTypeFactory.GetBase(vn.Size(), TYPE_UNKNOWN, "unknown")
}

// HighTypeReadFacing is the data-type of vn's HighVariable when read by op,
// falling back to vn's own type before highs are assigned (unions are not
// modelled, so there is no field resolution).
// C++ parity: Varnode::getHighTypeReadFacing.
func (vn *Varnode) HighTypeReadFacing(op *PcodeOp) Datatype {
	if h := vn.High(); h != nil {
		if dt := h.Type(); dt != nil {
			// C++ parity: Varnode::getHighTypeReadFacing.
			if dt.NeedsResolution() && op != nil {
				return findResolve(dt, op, op.GetSlot(vn))
			}
			return dt
		}
	}
	return vn.TypeReadFacing(op)
}

// HighTypeDefFacing is the data-type of vn's HighVariable at its definition.
// C++ parity: Varnode::getHighTypeDefFacing.
func (vn *Varnode) HighTypeDefFacing() Datatype {
	ct := vn.HighTypeReadFacing(nil)
	// C++ parity: Varnode::getHighTypeDefFacing (findResolve of the write).
	if ct != nil && ct.NeedsResolution() && vn.Def() != nil {
		return findResolve(ct, vn.Def(), -1)
	}
	return ct
}

// TypeDefFacing is vn's data-type as written by its defining op.
// C++ parity: Varnode::getTypeDefFacing.
func (vn *Varnode) TypeDefFacing() Datatype {
	ct := vn.TypeReadFacing(nil)
	if ct != nil && ct.NeedsResolution() && vn.Def() != nil {
		return findResolve(ct, vn.Def(), -1)
	}
	return ct
}

func (vn *Varnode) UpdateType(dt Datatype) {
	SetVarnodeType(vn, dt)
}

// UpdateTypeLock changes the Varnode's data-type and lock state under the same
// guard conditions as C++ Varnode::updateType(ct,lock,override):
//   - an UNKNOWN data-type is never locked
//   - a previously locked type is not changed unless override is set
//   - identical (type,lock) is a no-op
//
// Returns true if the type or lock setting changed.
// C++ parity: varnode.cc Varnode::updateType (L474-489).
func (vn *Varnode) UpdateTypeLock(ct Datatype, lock, override bool) bool {
	if vn == nil || ct == nil {
		return false
	}
	if ct.Metatype() == TYPE_UNKNOWN { // Unknown data type is ALWAYS unlocked
		lock = false
	}
	if vn.IsTypeLock() && !override {
		return false // Type is locked
	}
	if vn.Type() == ct && vn.IsTypeLock() == lock {
		return false // No change
	}
	vn.ClearFlags(VarnodeTypeLock)
	if lock {
		vn.SetFlags(VarnodeTypeLock)
	}
	SetVarnodeType(vn, ct)
	if hv := vn.High(); hv != nil {
		hv.SetType(ct) // C++ high->typeDirty()
	}
	return true
}

func BindSpaceConstant(vn *Varnode, spc *address.Space) {
	if vn == nil {
		return
	}
	vn.spaceConst = spc
}

func (vn *Varnode) GetSpaceFromConst() *address.Space {
	if vn == nil {
		return nil
	}
	return vn.spaceConst
}

// BindIndirectCause attaches the PcodeOp that a CPUI_INDIRECT's input(1)
// refers to (the CALL/CALLIND/STORE causing the indirect effect).
// C++ parity: op.hh PcodeOp::getOpFromConst / funcdata_varnode.cc
// Funcdata::newVarnodeIop (line 176). C++ encodes op's raw host pointer as
// the varnode's offset in the dedicated iop address space (IPTR_IOP) and
// decodes it back with a bare (PcodeOp *)(uintp)offset cast. That round-trip
// is unsafe in Go: a plain uintptr does not keep the referenced PcodeOp
// reachable for the garbage collector, and Go gives no guarantee the bits
// still name a live object by the time they are cast back. Gosleigh instead
// keeps the varnode a plain zero constant -- structurally identical to every
// other consumer that expects a CPUI_INDIRECT's input(1) to be IsConstant()
// -- and binds the real cause-op reference through the same side-table idiom
// already used for AddrSpace* references (BindSpaceConstant/GetSpaceFromConst
// above).
func BindIndirectCause(vn *Varnode, op *PcodeOp) {
	if vn == nil {
		return
	}
	vn.indirectCause = op
}

// GetIndirectCause decodes the PcodeOp referenced by a CPUI_INDIRECT's
// input(1) annotation varnode. Returns nil if vn was not created via
// Funcdata.NewVarnodeIop (e.g. a plain constant, or an INDIRECT input(1)
// built by a code path that has not yet been ported to use NewVarnodeIop).
// C++ parity: PcodeOp::getOpFromConst (op.hh:249).
func (vn *Varnode) GetIndirectCause() *PcodeOp {
	if vn == nil {
		return nil
	}
	return vn.indirectCause
}

func BindSpacebase(vn *Varnode, spc *address.Space) {
	if vn == nil {
		return
	}
	vn.SetFlags(VarnodeSpaceBase)
	vn.spacebase = spc
}

func (vn *Varnode) AssociatedSpacebase() *address.Space {
	if vn == nil {
		return nil
	}
	return vn.spacebase
}

func (vn *Varnode) SetStackStore() {
	vn.SetAddlFlags(VarnodeStackStore)
}

func (vn *Varnode) IsStackStore() bool {
	return vn.HasAddlFlags(VarnodeStackStore)
}

func (vn *Varnode) SetSpacebasePlaceholder() {
	vn.SetAddlFlags(VarnodeSpacebasePlaceholder)
}

func (vn *Varnode) ClearSpacebasePlaceholder() {
	vn.ClearAddlFlags(VarnodeSpacebasePlaceholder)
}

func (vn *Varnode) IsSpacebasePlaceholder() bool {
	return vn.HasAddlFlags(VarnodeSpacebasePlaceholder)
}

func (vn *Varnode) SetPtrFlow() {
	vn.SetAddlFlags(VarnodePtrFlow)
}

func (vn *Varnode) ClearPtrFlow() {
	vn.ClearAddlFlags(VarnodePtrFlow)
}

func (vn *Varnode) HasPtrFlow() bool {
	return vn.HasAddlFlags(VarnodePtrFlow)
}

func (op *PcodeOp) SetStopTypePropagation() {
	op.SetAdditionalFlag(PcodeOpStopTypePropagation)
}

func (op *PcodeOp) ClearStopTypePropagation() {
	op.ClearAdditionalFlag(PcodeOpStopTypePropagation)
}

func (op *PcodeOp) HasStopTypePropagation() bool {
	return op.addlFlags&PcodeOpStopTypePropagation != 0
}

func (op *PcodeOp) SetPtrFlow() {
	op.SetFlag(PcodeOpPtrFlow)
}

func (op *PcodeOp) ClearPtrFlow() {
	op.ClearFlag(PcodeOpPtrFlow)
}

func (op *PcodeOp) HasPtrFlow() bool {
	return op.HasFlag(PcodeOpPtrFlow)
}

func (fd *Funcdata) HasTypeRecoveryStarted() bool {
	return fd.HasFlag(FuncTypeRecoveryStart)
}

func (fd *Funcdata) NewSpaceIDConst(spc *address.Space) *Varnode {
	size := int32(1)
	if spc != nil && spc.AddrSize > 0 {
		size = int32(spc.AddrSize)
	}
	// The offset is the space index, the encoding the bridge gives every raw
	// LOAD/STORE space id, so two ids of one space compare equal by offset as
	// C++ AddrSpace pointers do (checkImpliedCover, CSE).
	var off uint64
	if spc != nil {
		off = uint64(spc.Index)
	}
	vn := fd.NewConstant(size, off)
	BindSpaceConstant(vn, spc)
	return vn
}

// NewVarnodeIop creates a special annotation Varnode that lets a
// CPUI_INDIRECT refer to the PcodeOp causing its indirect effect. This is
// always input(1) of a CPUI_INDIRECT (see NewIndirectOp / NewIndirectCreation
// in funcdata.go).
// C++ parity: funcdata_varnode.cc Funcdata::newVarnodeIop (line 176). See
// BindIndirectCause above for why Gosleigh represents the cause-op reference
// through a side-table instead of literally re-encoding op's address.
func (fd *Funcdata) NewVarnodeIop(op *PcodeOp) *Varnode {
	vn := fd.NewConstant(4, 0)
	BindIndirectCause(vn, op)
	return vn
}

// NewOpBefore creates a new op and splices it into before's basic block, right
// ahead of before.
//
// C++ parity: Funcdata::newOpBefore (funcdata_op.cc:656). The C++ original ends
// with opInsertBefore(newop,follow); Gosleigh used to only opMarkAlive() the new
// op, which left every AddTreeState/SplitFlow-created op detached (parent ==
// nil). A detached op still renders (PrintC walks def chains) but it has no
// block index, so Cover/HighVariable liveness for its output is computed against
// a nil parent -- the merge phase then cannot reason about it and compensates
// with extra trim COPYs. Inserting here restores the C++ block structure.
func (fd *Funcdata) NewOpBefore(before *PcodeOp, opcode OpCode, inputs ...*Varnode) *PcodeOp {
	addr := fd.BaseAddr()
	if before != nil {
		addr = before.Addr()
	}
	op := fd.NewOp(len(inputs), addr)
	fd.OpSetOpcode(op, opcode)
	for i, vn := range inputs {
		fd.OpSetInput(op, vn, i)
	}
	if before != nil && before.Parent() != nil {
		fd.OpInsertBefore(op, before)
	} else {
		fd.OpMarkAlive(op)
	}
	return op
}

func (fd *Funcdata) NewTypedOpBefore(before *PcodeOp, opcode OpCode, outSize int32, outType Datatype, inputs ...*Varnode) *PcodeOp {
	op := fd.NewOpBefore(before, opcode, inputs...)
	out := fd.NewUniqueOut(outSize, op)
	SetVarnodeType(out, outType)
	return op
}

// newUntypedOpBefore is Funcdata::newOpBefore: the output is a fresh unique
// with the default (undefined) data-type.
func (fd *Funcdata) newUntypedOpBefore(before *PcodeOp, opcode OpCode, outSize int32, inputs ...*Varnode) *PcodeOp {
	op := fd.NewOpBefore(before, opcode, inputs...)
	fd.NewUniqueOut(outSize, op)
	return op
}

func (fd *Funcdata) OpSetAllInput(op *PcodeOp, inputs []*Varnode) {
	replaceInputs(fd, op, inputs...)
}

func (fd *Funcdata) OpRemoveInput(op *PcodeOp, slot int) {
	if op == nil || slot < 0 || slot >= op.NumInput() {
		return
	}
	vn := op.Input(slot)
	if vn != nil {
		vn.EraseDescend(op)
	}
	op.RemoveInput(slot)
}

// OpUndoPtradd turns a PTRADD back into an INT_ADD of the scaled index. The
// output Varnode (and its data-type) is kept; with finalize, a new scaled
// constant or INT_MULT output takes the index's type and the product is
// implied.
// C++ parity: Funcdata::opUndoPtradd.
func (fd *Funcdata) OpUndoPtradd(op *PcodeOp, finalize bool) {
	if op == nil || op.NumInput() < 3 {
		return
	}
	multVn := op.Input(2)
	multSize := multVn.Offset() // Size the PTRADD thinks we are pointing
	fd.OpRemoveInput(op, 2)
	fd.OpSetOpcode(op, CPUI_INT_ADD)
	if multSize == 1 {
		return // No multiplier, we are done
	}
	offVn := op.Input(1)
	if offVn.IsConstant() {
		newVal := truncateToSize(multSize*offVn.Offset(), offVn.Size())
		newOffVn := fd.NewConstant(offVn.Size(), newVal)
		if finalize {
			newOffVn.UpdateType(offVn.TypeReadFacing(op))
		}
		fd.OpSetInput(op, newOffVn, 1)
		return
	}
	multOp := fd.NewOp(2, op.Addr())
	fd.OpSetOpcode(multOp, CPUI_INT_MULT)
	addVn := fd.NewUniqueOut(offVn.Size(), multOp)
	if finalize {
		addVn.UpdateType(multVn.Type())
		addVn.SetImplied()
	}
	fd.OpSetInput(multOp, offVn, 0)
	fd.OpSetInput(multOp, multVn, 1)
	fd.OpSetInput(op, addVn, 1)
	fd.OpInsertBefore(multOp, op)
}

func signExtendToInt64(val uint64, size int32) int64 {
	bits := uint(size) * 8
	if bits == 0 {
		return 0
	}
	if bits >= 64 {
		return int64(val)
	}
	shift := 64 - bits
	return int64(val<<shift) >> shift
}

func addressUnitsToBytes(units uint64, wordSize uint32) int32 {
	if wordSize == 0 {
		wordSize = 1
	}
	return int32(units * uint64(wordSize))
}

func bytesToAddressUnits(bytes int32, wordSize uint32) uint64 {
	if wordSize == 0 {
		wordSize = 1
	}
	if bytes <= 0 {
		return 0
	}
	return uint64(bytes) / uint64(wordSize)
}

func normalizeArrayHint(hint uint64) int32 {
	if hint > uint64(^uint32(0)) {
		return 0
	}
	return int32(hint)
}

// structLowerBoundField is the index of the last field starting at or before
// off, or -1. C++ parity: TypeStruct::getLowerBoundField.
func structLowerBoundField(fields []TypeField, off int64) int {
	idx := -1
	for i, f := range fields {
		if int64(f.Offset) > off {
			break
		}
		idx = i
	}
	return idx
}

// nearestArrayedComponentBackward finds the closest array at or before off,
// returning its distance (-1 if none within max), the offset relative to it
// and its element size. C++ parity: Datatype/TypeStruct/TypeArray
// ::nearestArrayedComponentBackward.
func nearestArrayedComponentBackward(dt Datatype, off, max int64) (int64, int64, int64) {
	switch t := dt.(type) {
	case *Array:
		if off < 0 || t.Element() == nil {
			return -1, 0, 0
		}
		elSize := int64(t.Element().AlignSize())
		if off <= int64(t.Size()) {
			return int64(t.Size()) - off, off, elSize
		}
		return off - int64(t.Size()), off, elSize
	case *Struct:
		fields := t.Fields()
		firstIndex := structLowerBoundField(fields, off)
		for i := firstIndex; i >= 0; i-- {
			diff := off - int64(fields[i].Offset)
			subtype := fields[i].Type
			remain := diff
			if i != firstIndex {
				remain = int64(subtype.Size())
			}
			if diff-remain > max {
				break
			}
			distance, _, elSize := nearestArrayedComponentBackward(subtype, remain, max)
			if distance >= 0 {
				distance += diff - remain
				if distance > max {
					break
				}
				return distance, diff, elSize
			}
		}
	}
	return -1, 0, 0
}

// nearestArrayedComponentForward finds the closest array at or after off.
// C++ parity: Datatype/TypeStruct/TypeArray::nearestArrayedComponentForward.
func nearestArrayedComponentForward(dt Datatype, off, max int64) (int64, int64, int64) {
	switch t := dt.(type) {
	case *Array:
		if off > 0 || t.Element() == nil {
			return -1, 0, 0 // skip if we are in the middle of the array
		}
		return -off, off, int64(t.Element().AlignSize())
	case *Struct:
		fields := t.Fields()
		i := structLowerBoundField(fields, off)
		var remain int64
		if i < 0 { // no component starting before off
			i = 0
		} else {
			remain = off - int64(fields[i].Offset)
		}
		for ; i < len(fields); i++ {
			diff := int64(fields[i].Offset) - off // the first field may have a negative diff
			if diff+remain > max {
				break
			}
			distance, _, elSize := nearestArrayedComponentForward(fields[i].Type, remain, max)
			if distance >= 0 {
				distance += diff + remain
				if distance > max {
					break
				}
				return distance, -diff, elSize
			}
			remain = 0
		}
	}
	return -1, 0, 0
}

// hasMatchingSubType reports whether off falls in a component of base and
// returns the offset relative to that component (the extra part a PTRSUB
// does not cover). An array hint steers toward a nearby arrayed component.
// C++ parity: AddTreeState::hasMatchingSubType.
func hasMatchingSubType(base Datatype, off int64, arrayHint uint64) (int64, bool) {
	return matchSubType(subTypeOps{
		sub:  func(off int64) (Datatype, int64) { return datatypeSubType(base, off) },
		back: func(off, max int64) (int64, int64, int64) { return nearestArrayedComponentBackward(base, off, max) },
		fwd:  func(off, max int64) (int64, int64, int64) { return nearestArrayedComponentForward(base, off, max) },
	}, off, arrayHint)
}

// subTypeOps are a base data-type's getSubType and
// nearestArrayedComponentBackward/Forward, so a TypeSpacebase (whose
// components are the scope's symbols) shares hasMatchingSubType.
type subTypeOps struct {
	sub       func(off int64) (Datatype, int64)
	back, fwd func(off, max int64) (int64, int64, int64)
}

// matchSubType is AddTreeState::hasMatchingSubType over subTypeOps.
func matchSubType(o subTypeOps, off int64, arrayHint uint64) (int64, bool) {
	if arrayHint == 0 {
		sub, newoff := o.sub(off)
		return newoff, sub != nil
	}
	typeBefore, offBefore, elSizeBefore := o.back(off, 128)
	typeAfter, offAfter, elSizeAfter := o.fwd(off, 128)
	if typeBefore < 0 && typeAfter < 0 {
		sub, newoff := o.sub(off)
		return newoff, sub != nil
	}
	if typeBefore < 0 {
		return offAfter, true // only an array after
	}
	if typeAfter < 0 {
		return offBefore, true // only an array before
	}
	if offAfter == offBefore {
		return offAfter, true
	}
	// There is an array before and after the offset point.
	if arrayHint != 1 && elSizeBefore != elSizeAfter {
		if uint64(elSizeBefore) == arrayHint {
			return offBefore, true
		}
		if uint64(elSizeAfter) == arrayHint {
			return offAfter, true
		}
	}
	if sub, newoff := o.sub(off); sub != nil {
		if newoff == offBefore || newoff == offAfter {
			return newoff, true // contained in one of the arrayed components
		}
	}
	distBefore, distAfter := absInt64(offBefore), absInt64(offAfter)
	if distAfter < distBefore {
		return offAfter, true
	}
	return offBefore, true
}

func pointerSubtypeType(ptr *Pointer, subtype Datatype) Datatype {
	if ptr == nil {
		return subtype
	}
	if subtype == nil {
		return ptr
	}
	return sharedTypeFactory.GetPointer(ptr.Size(), subtype, ptr.WordSize())
}

type addTreeMultiple struct {
	vn    *Varnode
	coeff int64
}

// AddTreeState is the analysis of an additive expression on a pointer that
// RulePtrArith rewrites into PTRADD/PTRSUB form.
// C++ parity: class AddTreeState (ruleaction.cc).
type AddTreeState struct {
	data                *Funcdata
	baseOp              *PcodeOp
	ptr                 *Varnode
	ptrType             *Pointer // ct
	pRelType            *Pointer // the formal relative pointer, if ptrType is one
	baseType            Datatype
	ptrSize             int32
	wordSize            uint32
	elemSize            uint64 // size
	baseSlot            int
	ptrMask             uint64
	offset              uint64
	correct             uint64
	multsum             uint64
	nonmultsum          uint64
	biggestNonMultCoeff uint64
	multiple            []addTreeMultiple
	nonmult             []*Varnode
	distributeOp        *PcodeOp // first INT_MULT whose coefficient was distributed
	valid               bool
	preventDistribution bool
	isDistributeUsed    bool
	isSubtype           bool
	isDegenerate        bool
}

// NewAddTreeState prepares the analysis of op with the pointer at slot.
// C++ parity: AddTreeState::AddTreeState.
func NewAddTreeState(data *Funcdata, op *PcodeOp, slot int) *AddTreeState {
	ptr := op.Input(slot)
	ptrType, _ := ptr.TypeReadFacing(op).(*Pointer)
	s := &AddTreeState{
		data:     data,
		baseOp:   op,
		ptr:      ptr,
		ptrType:  ptrType,
		ptrSize:  ptr.Size(),
		baseSlot: slot,
		ptrMask:  maskForSize(ptr.Size()),
		valid:    ptrType != nil,
		wordSize: 1,
	}
	if ptrType == nil {
		return s
	}
	s.wordSize = ptrType.WordSize()
	if s.wordSize == 0 {
		s.wordSize = 1
	}
	s.baseType = ptrType.Pointee()
	if ptrType.IsFormalPointerRel() {
		s.pRelType = ptrType
		s.baseType = ptrType.Parent()
		s.nonmultsum = s.relAddressOffset() & s.ptrMask
	}
	s.setBaseSize()
	return s
}

// relAddressOffset is TypePointerRel::getAddressOffset.
func (s *AddTreeState) relAddressOffset() uint64 {
	return bytesToAddressUnits(s.pRelType.ByteOffset(), s.wordSize)
}

// setBaseSize computes size and isDegenerate from baseType.
func (s *AddTreeState) setBaseSize() {
	s.elemSize = 0
	if s.baseType != nil && s.baseType.AlignSize() > 0 {
		s.elemSize = bytesToAddressUnits(s.baseType.AlignSize(), s.wordSize)
	}
	unitSize := addressUnitsToBytes(1, s.wordSize)
	s.isDegenerate = s.baseType != nil && s.baseType.AlignSize() <= unitSize && s.baseType.AlignSize() > 0
}

// clear resets the accumulated terms. C++ parity: AddTreeState::clear.
func (s *AddTreeState) clear() {
	s.multsum = 0
	s.nonmultsum = 0
	s.biggestNonMultCoeff = 0
	if s.pRelType != nil {
		s.nonmultsum = s.relAddressOffset() & s.ptrMask
	}
	s.multiple = s.multiple[:0]
	s.nonmult = s.nonmult[:0]
	s.correct = 0
	s.offset = 0
	s.valid = s.ptrType != nil
	s.isDistributeUsed = false
	s.isSubtype = false
	s.distributeOp = nil
}

// initAlternateForm retries a relative pointer as a plain pointer to its
// pointed-to type. C++ parity: AddTreeState::initAlternateForm.
func (s *AddTreeState) initAlternateForm() bool {
	if s.pRelType == nil {
		return false
	}
	s.pRelType = nil
	s.baseType = s.ptrType.Pointee()
	s.setBaseSize()
	s.preventDistribution = false
	s.clear()
	return true
}

// checkMultTerm accumulates a term defined by INT_MULT with a constant.
// C++ parity: AddTreeState::checkMultTerm.
func (s *AddTreeState) checkMultTerm(vn *Varnode, op *PcodeOp, treeCoeff uint64) bool {
	vnconst := op.Input(1)
	vnterm := op.Input(0)
	if vnterm.IsFree() {
		s.valid = false
		return false
	}
	if vnconst.IsConstant() {
		val := (vnconst.Offset() * treeCoeff) & s.ptrMask
		sval := signExtendToInt64(val, vn.Size())
		rem := sval
		if s.elemSize != 0 {
			rem = sval % int64(s.elemSize)
		}
		if rem != 0 {
			if val >= s.elemSize && s.elemSize != 0 {
				s.valid = false // Size is too big: pointer type must be wrong
				return false
			}
			if !s.preventDistribution && vnterm.IsWritten() && vnterm.Def().Code() == CPUI_INT_ADD {
				if s.distributeOp == nil {
					s.distributeOp = op
				}
				return s.spanAddTree(vnterm.Def(), val)
			}
			if vncoeff := uint64(uint32(absInt64(sval))); vncoeff > s.biggestNonMultCoeff {
				s.biggestNonMultCoeff = vncoeff
			}
			return true
		}
		if treeCoeff != 1 {
			s.isDistributeUsed = true
		}
		s.multiple = append(s.multiple, addTreeMultiple{vn: vnterm, coeff: sval})
		return false
	}
	if treeCoeff > s.biggestNonMultCoeff {
		s.biggestNonMultCoeff = treeCoeff
	}
	return true
}

// checkTerm accumulates one term; it reports true when the sub-tree holds no
// multiple of the base size. C++ parity: AddTreeState::checkTerm.
func (s *AddTreeState) checkTerm(vn *Varnode, treeCoeff uint64) bool {
	if vn == s.ptr {
		return false
	}
	if vn.IsConstant() {
		val := vn.Offset() * treeCoeff
		sval := signExtendToInt64(truncateToSize(val, vn.Size()), vn.Size())
		rem := sval
		if s.elemSize != 0 {
			rem = sval % int64(s.elemSize)
		}
		if rem != 0 { // Constant is not a multiple of the size
			if treeCoeff != 1 {
				// An offset into the base data-type needs subcomponents.
				if m := s.baseType.Metatype(); m == TYPE_ARRAY || m == TYPE_STRUCT {
					s.isDistributeUsed = true
				}
			}
			s.nonmultsum = (s.nonmultsum + val) & s.ptrMask
			return true
		}
		if treeCoeff != 1 {
			s.isDistributeUsed = true
		}
		s.multsum = (s.multsum + val) & s.ptrMask
		return false
	}
	if vn.IsWritten() {
		def := vn.Def()
		switch def.Code() {
		case CPUI_INT_ADD:
			return s.spanAddTree(def, treeCoeff)
		case CPUI_COPY: // Not finished reducing yet
			s.valid = false
			return false
		case CPUI_INT_MULT: // Check for a constant coefficient indicating size
			return s.checkMultTerm(vn, def, treeCoeff)
		}
	} else if vn.IsFree() {
		s.valid = false
		return false
	}
	if treeCoeff > s.biggestNonMultCoeff {
		s.biggestNonMultCoeff = treeCoeff
	}
	return true
}

// spanAddTree walks the additive sub-tree rooted at op.
// C++ parity: AddTreeState::spanAddTree.
func (s *AddTreeState) spanAddTree(op *PcodeOp, treeCoeff uint64) bool {
	oneIsNon := s.checkTerm(op.Input(0), treeCoeff)
	if !s.valid {
		return false
	}
	twoIsNon := s.checkTerm(op.Input(1), treeCoeff)
	if !s.valid {
		return false
	}
	if s.pRelType != nil {
		if s.multsum != 0 || s.nonmultsum >= s.elemSize || len(s.multiple) != 0 {
			s.valid = false
			return false
		}
	}
	if oneIsNon && twoIsNon {
		return true
	}
	if oneIsNon {
		s.nonmult = append(s.nonmult, op.Input(0))
	}
	if twoIsNon {
		s.nonmult = append(s.nonmult, op.Input(1))
	}
	return false // At least one side contains multiples
}

// calcSubtype decides whether the sum points into a sub data-type of the
// base, producing a PTRSUB. C++ parity: AddTreeState::calcSubtype.
func (s *AddTreeState) calcSubtype() {
	tmpoff := (s.multsum + s.nonmultsum) & s.ptrMask
	if s.elemSize == 0 || tmpoff < s.elemSize {
		s.offset = tmpoff
	} else {
		// A sum outside the data-type is presumably an array index plus a
		// constant, at this level or lower.
		stmpoff := signExtendToInt64(tmpoff, s.ptrSize) % int64(s.elemSize)
		if stmpoff >= 0 {
			s.offset = uint64(stmpoff) // An array index at this level
		} else if s.baseType.Metatype() == TYPE_STRUCT && s.biggestNonMultCoeff != 0 && s.multsum == 0 {
			s.offset = tmpoff // An array index at a lower level
		} else {
			s.offset = uint64(stmpoff+int64(s.elemSize)) & s.ptrMask
		}
	}
	s.correct = s.nonmultsum // Non-multiple constants are double counted
	s.multsum = (tmpoff - s.offset) & s.ptrMask
	ws := int64(s.wordSize)
	switch {
	case len(s.nonmult) == 0:
		if s.multsum == 0 && len(s.multiple) == 0 { // Is there anything at all
			s.valid = false
			return
		}
		s.isSubtype = false // There are no offsets INTO the pointer
	case s.baseType.Metatype() == TYPE_SPACEBASE:
		offsetBytes := int64(s.offset) * ws
		extra, ok := matchSubType(s.data.spacebaseSubTypeOps(s.ptr.GetSpaceFromConst()), offsetBytes, s.biggestNonMultCoeff)
		if !ok {
			s.valid = false // Cannot find mapped variable but nonmult is non-empty
			return
		}
		units := uint64(extra / ws)
		s.offset = (s.offset - units) & s.ptrMask
		s.correct = (s.correct - units) & s.ptrMask
		s.isSubtype = true
	case s.baseType.Metatype() == TYPE_STRUCT:
		offsetBytes := signExtendToInt64(s.offset, s.ptrSize) * ws
		extra, ok := hasMatchingSubType(s.baseType, offsetBytes, s.biggestNonMultCoeff)
		if !ok {
			if offsetBytes < 0 || offsetBytes >= int64(s.baseType.Size()) {
				s.valid = false // Out of structure's bounds
				return
			}
			extra = 0 // No field, but pretend there is something there
		}
		units := uint64(extra / ws)
		s.offset = (s.offset - units) & s.ptrMask
		s.correct = (s.correct - units) & s.ptrMask
		if s.pRelType != nil && s.offset == s.relAddressOffset() {
			// The offset falls within the basic pointed-to type.
			if !s.pRelType.EvaluateThruParent(0) {
				s.valid = false // Use the basic (alternate) form
				return
			}
		}
		s.isSubtype = true
	case s.baseType.Metatype() == TYPE_ARRAY:
		s.isSubtype = true
		s.correct = (s.correct - s.offset) & s.ptrMask
		s.offset = 0
	default:
		s.valid = false // There is substructure we don't know about
	}
	if s.pRelType != nil {
		ptrOff := s.relAddressOffset()
		s.offset = (s.offset - ptrOff) & s.ptrMask
		s.correct = (s.correct - ptrOff) & s.ptrMask
	}
}

func (s *AddTreeState) buildMultiples() *Varnode {
	if s.elemSize == 0 {
		return nil
	}
	var result *Varnode
	sumCoeff := signExtendToInt64(s.multsum, s.ptrSize) / int64(s.elemSize)
	if sumCoeff != 0 {
		result = s.data.NewConstant(s.ptrSize, truncateToSize(uint64(sumCoeff), s.ptrSize))
	}
	for _, term := range s.multiple {
		finalCoeff := term.coeff / int64(s.elemSize)
		vn := term.vn
		if finalCoeff != 1 {
			mulOp := s.data.newUntypedOpBefore(s.baseOp, CPUI_INT_MULT, s.ptrSize, vn, s.data.NewConstant(s.ptrSize, truncateToSize(uint64(finalCoeff), s.ptrSize)))
			vn = mulOp.Output()
		}
		if result == nil {
			result = vn
			continue
		}
		addOp := s.data.newUntypedOpBefore(s.baseOp, CPUI_INT_ADD, s.ptrSize, vn, result)
		result = addOp.Output()
	}
	return result
}

func (s *AddTreeState) buildExtra() *Varnode {
	var result *Varnode
	correct := s.correct
	for _, vn := range s.nonmult {
		if vn == nil {
			continue
		}
		if vn.IsConstant() {
			correct = truncateToSize(correct-vn.Offset(), s.ptrSize)
			continue
		}
		if result == nil {
			result = vn
			continue
		}
		addOp := s.data.newUntypedOpBefore(s.baseOp, CPUI_INT_ADD, s.ptrSize, vn, result)
		result = addOp.Output()
	}
	if correct != 0 {
		neg := negateConstForSize(correct, s.ptrSize)
		correction := s.data.NewConstant(s.ptrSize, neg)
		if result == nil {
			result = correction
		} else {
			addOp := s.data.newUntypedOpBefore(s.baseOp, CPUI_INT_ADD, s.ptrSize, correction, result)
			result = addOp.Output()
		}
	}
	return result
}

func (s *AddTreeState) buildDegenerate() bool {
	if s.ptrType == nil || s.baseType == nil {
		return false
	}
	if s.baseType.AlignSize() < addressUnitsToBytes(1, s.wordSize) {
		return false
	}
	out := s.baseOp.Output()
	if out == nil {
		return false
	}
	// The pointer must propagate through the INT_ADD (a pointer difference
	// typed as an integer stays an INT_ADD).
	// C++ parity: AddTreeState::buildDegenerate (getTypeDefFacing() != TYPE_PTR).
	if dt := out.TypeDefFacing(); dt == nil || dt.Metatype() != TYPE_PTR {
		return false
	}
	dataSize := s.data.NewConstant(s.ptrSize, 1)
	s.data.OpSetAllInput(s.baseOp, []*Varnode{s.ptr, s.baseOp.Input(1 - s.baseSlot), dataSize})
	s.data.OpSetOpcode(s.baseOp, CPUI_PTRADD)
	return true // The output keeps its data-type
}

// assignPropagatedType types the output of a new PTRADD or PTRSUB from its
// pointer input once type propagation has stopped settling, as no later
// propagation pass will. C++ parity: AddTreeState::assignPropagatedType
// (called when Funcdata::isTypeRecoveryExceeded).
func (s *AddTreeState) assignPropagatedType(op *PcodeOp) {
	if !s.data.HasFlag(FuncTypeRecoveryExceeded) {
		return
	}
	vn := op.Input(0)
	inType := vn.TypeReadFacing(op)
	if inType == nil {
		return
	}
	if nt := inferPropagateEdge(s.data, sharedTypeFactory, op, vn, op.Output(), 0, -1, inType); nt != nil {
		op.Output().UpdateType(nt)
	}
}

func (s *AddTreeState) buildTree() {
	oldOut := s.baseOp.Output()
	if oldOut == nil {
		return
	}
	// C++ parity: AddTreeState::buildTree (ruleaction.cc:6510). buildMultiples and
	// buildExtra both run before any PTRADD/PTRSUB is created, so the term ops are
	// spliced into the block ahead of the address ops, and the LAST op created --
	// PTRADD, PTRSUB or the INT_ADD that folds the extra terms back in -- inherits
	// baseOp's output varnode. Gosleigh used to append a CPUI_COPY whenever there
	// were no extra terms, which put the pointer expression in a fresh unique and
	// left the original (usually register) varnode on a COPY; that COPY became an
	// extra phi input on loop-carried pointers.
	multNode := s.buildMultiples()
	extra := s.buildExtra()
	current := s.ptr
	var newop *PcodeOp
	if multNode != nil {
		newop = s.data.newUntypedOpBefore(s.baseOp, CPUI_PTRADD, s.ptrSize, s.ptr, multNode, s.data.NewConstant(s.ptrSize, s.elemSize))
		s.assignPropagatedType(newop)
		current = newop.Output()
	}
	if s.isSubtype {
		newop = s.data.newUntypedOpBefore(s.baseOp, CPUI_PTRSUB, s.ptrSize, current, s.data.NewConstant(s.ptrSize, s.offset))
		// C++ ruleaction.cc:6531 only stops propagation when the pointed-to
		// data-type has a size (size != 0). For a spacebase base (size 0) the
		// PTRSUB output must stay open to TypeOpPtrsub::propagateType so it can
		// be refined to the mapped symbol's type.
		s.assignPropagatedType(newop)
		if s.elemSize != 0 {
			newop.SetStopTypePropagation()
		}
		current = newop.Output()
	}
	if extra != nil {
		// newOpBefore gives it a fresh unique even though baseOp's output
		// replaces it below; the allocation keeps later temporaries at the
		// C++ offsets (printed unnamed locations such as unique0x1000083a).
		newop = s.data.newUntypedOpBefore(s.baseOp, CPUI_INT_ADD, current.Size(), current, extra)
	}
	if newop == nil {
		// C++ emits a "ptrarith problems" warning here and leaves baseOp alone.
		return
	}
	s.data.OpUnsetOutput(s.baseOp)
	s.data.OpSetOutput(newop, oldOut)
	s.data.OpDestroy(s.baseOp)
}

// Apply rewrites the expression when the analysis succeeds. A distributed
// coefficient is reverted when no term needed it; otherwise the INT_MULT is
// distributed for real and the tree analysed again.
// C++ parity: AddTreeState::apply.
func (s *AddTreeState) Apply() bool {
	if !s.valid || s.ptrType == nil || s.baseOp == nil || s.baseOp.Code() != CPUI_INT_ADD {
		return false
	}
	if s.isDegenerate {
		return s.buildDegenerate()
	}
	s.spanAddTree(s.baseOp, 1)
	if !s.valid {
		return false // Were there any show stoppers
	}
	if s.distributeOp != nil && !s.isDistributeUsed {
		s.clear()
		s.preventDistribution = true
		s.spanAddTree(s.baseOp, 1)
	}
	s.calcSubtype()
	if !s.valid {
		return false
	}
	for s.valid && s.distributeOp != nil {
		if !s.data.distributeIntMultAdd(s.distributeOp) {
			s.valid = false
			break
		}
		// Collapse any z = (x * #c) * #d expressions produced by the distribute
		s.data.collapseIntMultMult(s.distributeOp.Input(0))
		s.data.collapseIntMultMult(s.distributeOp.Input(1))
		s.clear()
		s.spanAddTree(s.baseOp, 1)
		if s.distributeOp != nil && !s.isDistributeUsed {
			s.clear()
			s.preventDistribution = true
			s.spanAddTree(s.baseOp, 1)
		}
		s.calcSubtype()
	}
	if !s.valid {
		// Distribution transforms were made
		s.data.warningHeader("Problems distributing in pointer arithmetic at " + PrintRawAddr(s.baseOp.Addr()))
		return true
	}
	s.buildTree()
	return true
}

// collapseIntMultMult folds z = (x * #c) * #d into z = x * #(c*d).
// C++ parity: Funcdata::collapseIntMultMult.
func (fd *Funcdata) collapseIntMultMult(vn *Varnode) bool {
	if !vn.IsWritten() {
		return false
	}
	op := vn.Def()
	if op.Code() != CPUI_INT_MULT {
		return false
	}
	constVnFirst := op.Input(1)
	if !constVnFirst.IsConstant() || !op.Input(0).IsWritten() {
		return false
	}
	otherMultOp := op.Input(0).Def()
	if otherMultOp.Code() != CPUI_INT_MULT {
		return false
	}
	constVnSecond := otherMultOp.Input(1)
	if !constVnSecond.IsConstant() {
		return false
	}
	invn := otherMultOp.Input(0)
	if invn.IsFree() {
		return false
	}
	sz := invn.Size()
	val := (constVnFirst.Offset() * constVnSecond.Offset()) & maskForSize(sz)
	fd.OpSetInput(op, fd.NewConstant(sz, val), 1)
	fd.OpSetInput(op, invn, 0)
	return true
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
