package pcode

import (
	"sync"

	"gosleigh/pkg/address"
)

var sharedTypeFactory = NewTypeFactory()

type pcodeMetadataState struct {
	mu             sync.RWMutex
	varTypes       map[*Varnode]Datatype
	spaceIDs       map[*Varnode]*address.Space
	spacebases     map[*Varnode]*address.Space
	indirectCauses map[*Varnode]*PcodeOp
}

var pcodeMetadata = pcodeMetadataState{
	varTypes:       make(map[*Varnode]Datatype),
	spaceIDs:       make(map[*Varnode]*address.Space),
	spacebases:     make(map[*Varnode]*address.Space),
	indirectCauses: make(map[*Varnode]*PcodeOp),
}

func SetVarnodeType(vn *Varnode, dt Datatype) {
	if vn == nil {
		return
	}
	pcodeMetadata.mu.Lock()
	defer pcodeMetadata.mu.Unlock()
	if dt == nil {
		delete(pcodeMetadata.varTypes, vn)
		return
	}
	pcodeMetadata.varTypes[vn] = sharedTypeFactory.Intern(dt)
}

func (vn *Varnode) Type() Datatype {
	if vn == nil {
		return nil
	}
	pcodeMetadata.mu.RLock()
	defer pcodeMetadata.mu.RUnlock()
	return pcodeMetadata.varTypes[vn]
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
	pcodeMetadata.mu.Lock()
	defer pcodeMetadata.mu.Unlock()
	if spc == nil {
		delete(pcodeMetadata.spaceIDs, vn)
		return
	}
	pcodeMetadata.spaceIDs[vn] = spc
}

func (vn *Varnode) GetSpaceFromConst() *address.Space {
	if vn == nil {
		return nil
	}
	pcodeMetadata.mu.RLock()
	defer pcodeMetadata.mu.RUnlock()
	return pcodeMetadata.spaceIDs[vn]
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
	pcodeMetadata.mu.Lock()
	defer pcodeMetadata.mu.Unlock()
	if op == nil {
		delete(pcodeMetadata.indirectCauses, vn)
		return
	}
	pcodeMetadata.indirectCauses[vn] = op
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
	pcodeMetadata.mu.RLock()
	defer pcodeMetadata.mu.RUnlock()
	return pcodeMetadata.indirectCauses[vn]
}

func BindSpacebase(vn *Varnode, spc *address.Space) {
	if vn == nil {
		return
	}
	vn.SetFlags(VarnodeSpaceBase)
	pcodeMetadata.mu.Lock()
	defer pcodeMetadata.mu.Unlock()
	if spc == nil {
		delete(pcodeMetadata.spacebases, vn)
		return
	}
	pcodeMetadata.spacebases[vn] = spc
}

func (vn *Varnode) AssociatedSpacebase() *address.Space {
	if vn == nil {
		return nil
	}
	pcodeMetadata.mu.RLock()
	defer pcodeMetadata.mu.RUnlock()
	return pcodeMetadata.spacebases[vn]
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
	return fd.HasFlag(FuncTypeRecoveryOn)
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
	fd.OpMarkAlive(op)
	return op
}

func (fd *Funcdata) NewTypedOpBefore(before *PcodeOp, opcode OpCode, outSize int32, outType Datatype, inputs ...*Varnode) *PcodeOp {
	op := fd.NewOpBefore(before, opcode, inputs...)
	out := fd.NewUniqueOut(outSize, op)
	SetVarnodeType(out, outType)
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

func matchSubtype(base Datatype, offsetBytes int32, arrayHint uint64) (Datatype, int32, bool) {
	if base == nil {
		return nil, 0, false
	}
	switch typed := base.(type) {
	case *Struct:
		if field, ok := typed.FieldAt(offsetBytes); ok && field.Type != nil {
			return field.Type, field.Offset, true
		}
		if offsetBytes == 0 {
			fields := typed.Fields()
			if len(fields) > 0 && fields[0].Type != nil {
				return fields[0].Type, fields[0].Offset, true
			}
		}
	case *Array:
		elem := typed.Element()
		if elem == nil || elem.AlignSize() <= 0 {
			return nil, 0, false
		}
		elemSize := elem.AlignSize()
		if hinted := normalizeArrayHint(arrayHint); hinted > 1 && hinted == elemSize {
			if offsetBytes >= 0 && offsetBytes < typed.Size() {
				return elem, (offsetBytes / elemSize) * elemSize, true
			}
		}
		if offsetBytes >= 0 && offsetBytes < typed.Size() && offsetBytes%elemSize == 0 {
			return elem, offsetBytes, true
		}
	}
	return nil, 0, false
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
	subType             Datatype
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
	s.subType = nil
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
		s.offset = tmpoff % s.elemSize
	}
	s.correct = s.nonmultsum
	s.multsum = truncateToSize(tmpoff-s.offset, s.ptrSize)
	if len(s.nonmult) == 0 {
		s.valid = s.multsum != 0 || len(s.multiple) != 0
		s.isSubtype = false
		return
	}
	switch s.baseType.Metatype() {
	case TYPE_STRUCT, TYPE_ARRAY:
		offsetBytes := addressUnitsToBytes(s.offset, s.wordSize)
		subType, actualBytes, ok := matchSubtype(s.baseType, offsetBytes, s.biggestNonMultCoeff)
		if !ok {
			if offsetBytes < 0 || offsetBytes >= s.baseType.Size() {
				s.valid = false
				return
			}
			actualBytes = 0
			subType = s.baseType
		}
		actual := bytesToAddressUnits(actualBytes, s.wordSize)
		s.offset = truncateToSize(s.offset-actual, s.ptrSize)
		s.correct = truncateToSize(s.correct-actual, s.ptrSize)
		s.subType = subType
		s.isSubtype = true
	case TYPE_SPACEBASE:
		s.isSubtype = true
	default:
		s.valid = false
	}
}

func (s *AddTreeState) assignPropagatedType(op *PcodeOp) {
	if op == nil || op.Output() == nil || op.NumInput() == 0 {
		return
	}
	SetVarnodeType(op.Output(), op.Input(0).TypeReadFacing(op))
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
			intType := sharedTypeFactory.GetBase(s.ptrSize, TYPE_INT, "int")
			mulOp := s.data.NewTypedOpBefore(s.baseOp, CPUI_INT_MULT, s.ptrSize, intType, vn, s.data.NewConstant(s.ptrSize, truncateToSize(uint64(finalCoeff), s.ptrSize)))
			vn = mulOp.Output()
		}
		if result == nil {
			result = vn
			continue
		}
		intType := sharedTypeFactory.GetBase(s.ptrSize, TYPE_INT, "int")
		addOp := s.data.NewTypedOpBefore(s.baseOp, CPUI_INT_ADD, s.ptrSize, intType, vn, result)
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
		intType := sharedTypeFactory.GetBase(s.ptrSize, TYPE_INT, "int")
		addOp := s.data.NewTypedOpBefore(s.baseOp, CPUI_INT_ADD, s.ptrSize, intType, vn, result)
		result = addOp.Output()
	}
	if correct != 0 {
		neg := negateConstForSize(correct, s.ptrSize)
		correction := s.data.NewConstant(s.ptrSize, neg)
		if result == nil {
			result = correction
		} else {
			intType := sharedTypeFactory.GetBase(s.ptrSize, TYPE_INT, "int")
			addOp := s.data.NewTypedOpBefore(s.baseOp, CPUI_INT_ADD, s.ptrSize, intType, correction, result)
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
	current := s.ptr
	if multNode := s.buildMultiples(); multNode != nil {
		ptrAdd := s.data.NewTypedOpBefore(s.baseOp, CPUI_PTRADD, s.ptrSize, s.ptrType, s.ptr, multNode, s.data.NewConstant(s.ptrSize, s.elemSize))
		current = ptrAdd.Output()
	}
	if s.isSubtype {
		subType := pointerSubtypeType(s.ptrType, s.subType)
		ptrSub := s.data.NewTypedOpBefore(s.baseOp, CPUI_PTRSUB, s.ptrSize, subType, current, s.data.NewConstant(s.ptrSize, s.offset))
		ptrSub.SetStopTypePropagation()
		current = ptrSub.Output()
	}
	extra := s.buildExtra()
	s.data.OpUnsetOutput(s.baseOp)
	var finalOp *PcodeOp
	if extra != nil {
		finalOp = s.data.NewOpBefore(s.baseOp, CPUI_INT_ADD, current, extra)
		s.data.OpSetOutput(finalOp, oldOut)
		SetVarnodeType(oldOut, current.TypeReadFacing(finalOp))
	} else {
		finalOp = s.data.NewOpBefore(s.baseOp, CPUI_COPY, current)
		s.data.OpSetOutput(finalOp, oldOut)
		SetVarnodeType(oldOut, current.TypeReadFacing(finalOp))
	}
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
