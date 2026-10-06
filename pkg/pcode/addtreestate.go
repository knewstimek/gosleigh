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

func (vn *Varnode) TypeReadFacing(*PcodeOp) Datatype {
	if vn == nil {
		return nil
	}
	if dt := vn.Type(); dt != nil {
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
			return dt
		}
	}
	return vn.TypeReadFacing(op)
}

// HighTypeDefFacing is the data-type of vn's HighVariable at its definition.
// C++ parity: Varnode::getHighTypeDefFacing.
func (vn *Varnode) HighTypeDefFacing() Datatype {
	return vn.HighTypeReadFacing(nil)
}

func (vn *Varnode) TypeDefFacing() Datatype {
	return vn.TypeReadFacing(nil)
}

func (vn *Varnode) UpdateType(dt Datatype) {
	SetVarnodeType(vn, dt)
}

// UpdateTypeLock changes the Varnode's data-type and lock state under the same
// guard conditions as C++ Varnode::updateType(ct,lock,override):
//   - an UNKNOWN data-type is never locked
//   - a previously locked type is not changed unless override is set
//   - identical (type,lock) is a no-op
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
	vn := fd.NewConstant(size, 0)
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

func (fd *Funcdata) OpUndoPtradd(op *PcodeOp, allowCopy bool) {
	if op == nil || op.NumInput() < 3 {
		return
	}
	base := op.Input(0)
	index := op.Input(1)
	scaleVn := op.Input(2)
	scale, ok := constantValue(scaleVn)
	if !ok {
		scale = 1
	}
	outType := base.TypeReadFacing(op)
	if indexVal, ok := constantValue(index); ok {
		product := truncateToSize(indexVal*scale, base.Size())
		if product == 0 && allowCopy {
			rewriteToCopy(fd, op, base)
			SetVarnodeType(op.Output(), outType)
			return
		}
		rewriteOp(fd, op, CPUI_INT_ADD, base, fd.NewConstant(base.Size(), product))
		SetVarnodeType(op.Output(), outType)
		return
	}
	if scale == 1 {
		if allowCopy && isZeroConst(index) {
			rewriteToCopy(fd, op, base)
		} else {
			rewriteOp(fd, op, CPUI_INT_ADD, base, index)
		}
		SetVarnodeType(op.Output(), outType)
		return
	}
	mulType := sharedTypeFactory.GetBase(index.Size(), TYPE_INT, "int")
	mulOp := fd.NewTypedOpBefore(op, CPUI_INT_MULT, index.Size(), mulType, index, fd.NewConstant(index.Size(), truncateToSize(scale, index.Size())))
	rewriteOp(fd, op, CPUI_INT_ADD, base, mulOp.Output())
	SetVarnodeType(op.Output(), outType)
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
	if arrayHint == 0 {
		sub, newoff := datatypeSubType(base, off)
		return newoff, sub != nil
	}
	typeBefore, offBefore, elSizeBefore := nearestArrayedComponentBackward(base, off, 128)
	typeAfter, offAfter, elSizeAfter := nearestArrayedComponentForward(base, off, 128)
	if typeBefore < 0 && typeAfter < 0 {
		sub, newoff := datatypeSubType(base, off)
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
	if sub, newoff := datatypeSubType(base, off); sub != nil {
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

type AddTreeState struct {
	data                *Funcdata
	baseOp              *PcodeOp
	ptr                 *Varnode
	ptrType             *Pointer
	baseType            Datatype
	ptrSize             int32
	wordSize            uint32
	elemSize            uint64
	baseSlot            int
	ptrMask             uint64
	offset              uint64
	correct             uint64
	multsum             uint64
	nonmultsum          uint64
	biggestNonMultCoeff uint64
	multiple            []addTreeMultiple
	nonmult             []*Varnode
	valid               bool
	isSubtype           bool
	isDegenerate        bool
}

func NewAddTreeState(data *Funcdata, op *PcodeOp, slot int) *AddTreeState {
	ptr := op.Input(slot)
	ptrType, _ := ptr.TypeReadFacing(op).(*Pointer)
	baseType := Datatype(nil)
	wordSize := uint32(1)
	if ptrType != nil {
		baseType = ptrType.Pointee()
		wordSize = ptrType.WordSize()
		if wordSize == 0 {
			wordSize = 1
		}
	}
	elemSize := uint64(0)
	if baseType != nil && baseType.AlignSize() > 0 {
		elemSize = bytesToAddressUnits(baseType.AlignSize(), wordSize)
	}
	isDegenerate := false
	if baseType != nil {
		unitSize := addressUnitsToBytes(1, wordSize)
		isDegenerate = baseType.AlignSize() <= unitSize && baseType.AlignSize() > 0
	}
	return &AddTreeState{
		data:         data,
		baseOp:       op,
		ptr:          ptr,
		ptrType:      ptrType,
		baseType:     baseType,
		ptrSize:      ptr.Size(),
		wordSize:     wordSize,
		elemSize:     elemSize,
		baseSlot:     slot,
		ptrMask:      maskForSize(ptr.Size()),
		valid:        ptrType != nil,
		isDegenerate: isDegenerate,
	}
}

func (s *AddTreeState) clear() {
	s.multsum = 0
	s.nonmultsum = 0
	s.biggestNonMultCoeff = 0
	s.multiple = s.multiple[:0]
	s.nonmult = s.nonmult[:0]
	s.correct = 0
	s.offset = 0
	s.valid = s.ptrType != nil
	s.isSubtype = false
}

func (s *AddTreeState) initAlternateForm() bool {
	return false
}

func (s *AddTreeState) checkMultTerm(vn *Varnode, op *PcodeOp, treeCoeff uint64) bool {
	if op == nil || op.NumInput() != 2 {
		return true
	}
	constSlot := -1
	if op.Input(0) != nil && op.Input(0).IsConstant() {
		constSlot = 0
	} else if op.Input(1) != nil && op.Input(1).IsConstant() {
		constSlot = 1
	}
	if constSlot < 0 {
		if treeCoeff > s.biggestNonMultCoeff {
			s.biggestNonMultCoeff = treeCoeff
		}
		return true
	}
	term := op.Input(1 - constSlot)
	if term.IsFree() {
		s.valid = false
		return false
	}
	multVal := truncateToSize(op.Input(constSlot).Offset()*treeCoeff, vn.Size())
	signed := signExtendToInt64(multVal, vn.Size())
	rem := signed
	if s.elemSize != 0 {
		rem = signed % int64(s.elemSize)
	}
	if rem != 0 {
		if s.elemSize != 0 && multVal >= s.elemSize {
			s.valid = false
			return false
		}
		if term.IsWritten() && term.Def().Code() == CPUI_INT_ADD {
			return s.spanAddTree(term.Def(), multVal)
		}
		if absInt64(signed) > int64(s.biggestNonMultCoeff) {
			s.biggestNonMultCoeff = uint64(absInt64(signed))
		}
		return true
	}
	s.multiple = append(s.multiple, addTreeMultiple{vn: term, coeff: signed})
	return false
}

func (s *AddTreeState) checkTerm(vn *Varnode, treeCoeff uint64) bool {
	if vn == nil {
		return true
	}
	if vn == s.ptr {
		return false
	}
	if vn.IsConstant() {
		val := truncateToSize(vn.Offset()*treeCoeff, vn.Size())
		signed := signExtendToInt64(val, vn.Size())
		rem := signed
		if s.elemSize != 0 {
			rem = signed % int64(s.elemSize)
		}
		if rem != 0 {
			s.nonmultsum = truncateToSize(s.nonmultsum+val, s.ptrSize)
			if absInt64(signed) > int64(s.biggestNonMultCoeff) {
				s.biggestNonMultCoeff = uint64(absInt64(signed))
			}
			return true
		}
		s.multsum = truncateToSize(s.multsum+val, s.ptrSize)
		return false
	}
	if vn.IsWritten() {
		def := vn.Def()
		switch def.Code() {
		case CPUI_INT_ADD:
			return s.spanAddTree(def, treeCoeff)
		case CPUI_COPY:
			s.valid = false
			return false
		case CPUI_INT_MULT:
			return s.checkMultTerm(vn, def, treeCoeff)
		}
	}
	if vn.IsFree() {
		s.valid = false
		return false
	}
	if treeCoeff > s.biggestNonMultCoeff {
		s.biggestNonMultCoeff = treeCoeff
	}
	return true
}

func (s *AddTreeState) spanAddTree(op *PcodeOp, treeCoeff uint64) bool {
	leftNon := s.checkTerm(op.Input(0), treeCoeff)
	if !s.valid {
		return false
	}
	rightNon := s.checkTerm(op.Input(1), treeCoeff)
	if !s.valid {
		return false
	}
	if leftNon && rightNon {
		return true
	}
	if leftNon {
		s.nonmult = append(s.nonmult, op.Input(0))
	}
	if rightNon {
		s.nonmult = append(s.nonmult, op.Input(1))
	}
	return false
}

func (s *AddTreeState) calcSubtype() {
	tmpoff := truncateToSize(s.multsum+s.nonmultsum, s.ptrSize)
	if s.elemSize == 0 || tmpoff < s.elemSize {
		s.offset = tmpoff
	} else {
		// A sum outside the data-type is presumably an array index plus a
		// constant, at this level or lower.
		stmpoff := signExtendToInt64(tmpoff, s.ptrSize) % int64(s.elemSize)
		if stmpoff >= 0 {
			s.offset = uint64(stmpoff) // an array index at this level
		} else if s.baseType.Metatype() == TYPE_STRUCT && s.biggestNonMultCoeff != 0 && s.multsum == 0 {
			s.offset = tmpoff // an array index at a lower level
		} else {
			s.offset = truncateToSize(uint64(stmpoff+int64(s.elemSize)), s.ptrSize)
		}
	}
	s.correct = s.nonmultsum // non-multiple constants are double counted
	s.multsum = truncateToSize(tmpoff-s.offset, s.ptrSize)
	if len(s.nonmult) == 0 {
		s.valid = s.multsum != 0 || len(s.multiple) != 0
		s.isSubtype = false // no offsets INTO the pointer
		return
	}
	ws := int64(s.wordSize)
	if ws <= 0 {
		ws = 1
	}
	switch s.baseType.Metatype() {
	case TYPE_STRUCT:
		offsetBytes := signExtendToInt64(s.offset, s.ptrSize) * ws
		extra, ok := hasMatchingSubType(s.baseType, offsetBytes, s.biggestNonMultCoeff)
		if !ok {
			if offsetBytes < 0 || offsetBytes >= int64(s.baseType.Size()) {
				s.valid = false // out of the structure's bounds
				return
			}
			extra = 0 // no field, but pretend there is something there
		}
		extraUnits := uint64(extra / ws)
		s.offset = truncateToSize(s.offset-extraUnits, s.ptrSize)
		s.correct = truncateToSize(s.correct-extraUnits, s.ptrSize)
		s.isSubtype = true
	case TYPE_ARRAY:
		s.isSubtype = true
		s.correct = truncateToSize(s.correct-s.offset, s.ptrSize)
		s.offset = 0
	case TYPE_SPACEBASE:
		// C++ ruleaction.cc:6306-6317. hasMatchingSubType resolves the mapped
		// variable containing `offset` (TypeSpacebase::getSubType -- Gosleigh's
		// Funcdata.ResolveSpacebaseSymbol) and passes back the offset within it.
		// Known mismatch: the arrayHint (biggestNonMultCoeff) branch of
		// hasMatchingSubType, which searches nearby arrayed components, is not
		// ported -- only the plain getSubType lookup is.
		signedOffset := signExtendToInt64(s.offset, s.ptrSize)
		ws := int64(s.wordSize)
		if ws <= 0 {
			ws = 1
		}
		symType, extraBytes := s.data.ResolveSpacebaseSymbol(s.ptr.GetSpaceFromConst(), signedOffset*ws)
		if symType == nil {
			s.valid = false
			return
		}
		extra := bytesToAddressUnits(int32(extraBytes), s.wordSize)
		s.offset = truncateToSize(s.offset-extra, s.ptrSize)
		s.correct = truncateToSize(s.correct-extra, s.ptrSize)
		s.isSubtype = true
	default:
		s.valid = false
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
	SetVarnodeType(out, s.ptrType)
	return true
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
		current = newop.Output()
	}
	if s.isSubtype {
		newop = s.data.newUntypedOpBefore(s.baseOp, CPUI_PTRSUB, s.ptrSize, current, s.data.NewConstant(s.ptrSize, s.offset))
		// C++ ruleaction.cc:6531 only stops propagation when the pointed-to
		// data-type has a size (size != 0). For a spacebase base (size 0) the
		// PTRSUB output must stay open to TypeOpPtrsub::propagateType so it can
		// be refined to the mapped symbol's type.
		if s.elemSize != 0 {
			newop.SetStopTypePropagation()
		}
		current = newop.Output()
	}
	if extra != nil {
		newop = s.data.NewOpBefore(s.baseOp, CPUI_INT_ADD, current, extra)
	}
	if newop == nil {
		// C++ emits a "ptrarith problems" warning here and leaves baseOp alone.
		return
	}
	s.data.OpUnsetOutput(s.baseOp)
	s.data.OpSetOutput(newop, oldOut)
	s.data.OpDestroy(s.baseOp)
}

func (s *AddTreeState) Apply() bool {
	if !s.valid || s.ptrType == nil || s.baseOp == nil || s.baseOp.Code() != CPUI_INT_ADD {
		return false
	}
	if s.isDegenerate {
		return s.buildDegenerate()
	}
	s.clear()
	s.spanAddTree(s.baseOp, 1)
	if !s.valid {
		return false
	}
	s.calcSubtype()
	if !s.valid {
		return false
	}
	s.buildTree()
	return true
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
