// Copyright 2026 The Gosleigh Authors
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

// Package pcode -- bitfield transform infrastructure.
// C++ parity: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/bitfield.hh
// and bitfield.cc. The transform family walks backward (insert) or forward
// (pull) from a container Varnode to find places where individual bitfields
// are read or written, and rewrites those sites in terms of the explicit
// INSERT/ZPULL/SPULL p-code ops.
//
// The walker infrastructure (BitFieldNodeState, establishFields,
// buildPartialType, findOverwrite) is ported as real Go code. The per-op
// backward/forward dispatch helpers (processBackward / processForward and
// their handle* relatives) are still TODO: doTrace seeds the worklist, but
// the op-level fan-out returns false until those are ported. Because
// RuleBitField*Apply short-circuits on a false DoTrace, this is a safe
// intermediate state: the rules are reachable and the type-model path is
// wired, so enabling a struct with bitfield members does not crash the
// pipeline, it just does not yet rewrite reads/writes into explicit
// INSERT/ZPULL/SPULL ops.
package pcode

// BitRange represents a contiguous run of bits within some Varnode.
// C++ parity: class BitRange in transform.hh (used by bitfield.hh).
type BitRange struct {
	// LeastSigBit is the zero-based index of the least significant bit of
	// the range within its enclosing Varnode.
	LeastSigBit int32
	// NumBits is the width of the range in bits.
	NumBits int32
}

// NewBitRange constructs a BitRange with the given least-significant bit and width.
// C++ parity: BitRange::BitRange.
func NewBitRange(leastSig, numBits int32) BitRange {
	return BitRange{LeastSigBit: leastSig, NumBits: numBits}
}

// MostSigBit returns the exclusive upper bound of the range (leastSig + numBits).
// C++ parity: BitRange::getMostSigBit (transform.cc) -- inclusive upper.
func (b BitRange) MostSigBit() int32 {
	if b.NumBits <= 0 {
		return b.LeastSigBit
	}
	return b.LeastSigBit + b.NumBits - 1
}

// Mask returns a bitmask covering the described range.
// C++ parity: BitRange::getMask helper used throughout bitfield.cc.
func (b BitRange) Mask() uint64 {
	if b.NumBits <= 0 || b.NumBits >= 64 {
		if b.NumBits >= 64 {
			return ^uint64(0)
		}
		return 0
	}
	m := (uint64(1) << uint(b.NumBits)) - 1
	return m << uint(b.LeastSigBit)
}

// TypeBitField is a placeholder for the Ghidra TypeBitField type.
// C++ parity: class TypeBitField in type.hh.
// TODO(bitfield-typemodel): Replace with a real type that carries signedness,
// containing struct, byte offset and bit offset within container, and the
// primitive logical type. The current struct exists only so BitFieldNodeState
// can compile.
type TypeBitField struct {
	LogicalType Datatype
	BitOffset   int32
	BitSize     int32
	IsSigned    bool
}

// GetMetatype returns the logical metatype -- TYPE_INT for signed bitfields,
// TYPE_UINT otherwise.
// C++ parity: TypeBitField::getMetatype.
func (t *TypeBitField) GetMetatype() metatype {
	if t.IsSigned {
		return TYPE_INT
	}
	return TYPE_UINT
}

// BitFieldNodeState tracks a single Varnode the transform is walking through
// along with which bits of it are interesting and which bitfield is being
// followed.
// C++ parity: class BitFieldNodeState in bitfield.hh.
type BitFieldNodeState struct {
	// BitsUsed is the portion of node the transform still cares about.
	BitsUsed BitRange
	// BitsField is the slice of the bitfield currently being tracked.
	BitsField BitRange
	// Node is the Varnode holding (partial) bitfield data.
	Node *Varnode
	// Field is the bitfield descriptor being followed (may be nil for holes).
	Field *TypeBitField
	// OrigLeastSigBit remembers the original position of the least significant
	// bit of the field when the walk began.
	OrigLeastSigBit int32
	// IsSignExtended records whether the field has been sign-extended into
	// Node along the walk so far.
	IsSignExtended bool
}

// NewBitFieldNodeStateForField constructs a state for a Varnode that carries
// the given bitfield.
// C++ parity: BitFieldNodeState::BitFieldNodeState(BitRange,Varnode,TypeBitField).
func NewBitFieldNodeStateForField(used BitRange, vn *Varnode, fld *TypeBitField) BitFieldNodeState {
	return BitFieldNodeState{
		BitsUsed:        used,
		BitsField:       BitRange{LeastSigBit: 0, NumBits: used.NumBits},
		Node:            vn,
		Field:           fld,
		OrigLeastSigBit: used.LeastSigBit,
	}
}

// NewBitFieldNodeStateForHole constructs a state for a run of bits that the
// enclosing type says are not part of any bitfield (padding / holes).
// C++ parity: BitFieldNodeState::BitFieldNodeState(BitRange,Varnode,int4,int4).
func NewBitFieldNodeStateForHole(used BitRange, vn *Varnode, leastSig, numBits int32) BitFieldNodeState {
	return BitFieldNodeState{
		BitsUsed:        used,
		BitsField:       BitRange{LeastSigBit: leastSig, NumBits: numBits},
		Node:            vn,
		Field:           nil,
		OrigLeastSigBit: used.LeastSigBit,
	}
}

// IsFieldAligned reports whether the current node can be treated as an
// isolated bitfield (the full bitsUsed range matches the tracked field).
// C++ parity: BitFieldNodeState::isFieldAligned.
func (s BitFieldNodeState) IsFieldAligned() bool {
	return s.BitsField.LeastSigBit == 0 && s.BitsField.NumBits == s.BitsUsed.NumBits
}

// DoesSignExtensionMatch reports whether the signedness of the tracked field
// matches the extension the walker has observed.
// C++ parity: BitFieldNodeState::doesSignExtensionMatch.
func (s BitFieldNodeState) DoesSignExtensionMatch() bool {
	if s.Field == nil {
		return !s.IsSignExtended
	}
	return s.IsSignExtended == (s.Field.GetMetatype() == TYPE_INT)
}

// bitFieldTransform is the common base carrying the walk state for both the
// insert and pull variants.
// C++ parity: class BitFieldTransform in bitfield.hh.
type bitFieldTransform struct {
	// fd is the containing function.
	fd *Funcdata
	// parentStruct owns the bitfields being transformed.
	// TODO(bitfield-typemodel): Once the Go type model grows TypeStruct with
	// real bitfield members, this should point at the *Struct that drives
	// establishFields.
	parentStruct *Struct
	// workList contains nodes the transform is still walking.
	workList []BitFieldNodeState
	// initialOffset is the byte offset of the root container into the parent.
	initialOffset int32
	// containerSize is the size (in bytes) of the root container Varnode.
	containerSize int32
	// isBigEndian remembers the endianness of the container.
	isBigEndian bool
}

// newBitFieldTransform records basic info about a bitfield container.
// initialOffset is the byte offset of the root container into the parent
// structure. The Go port collapses TypePartialStruct and TypeStruct handling
// into a single path -- the caller passes whichever Datatype it holds, and
// the transform resolves the underlying *Struct and adjusts initialOffset.
// C++ parity: BitFieldTransform::BitFieldTransform(Funcdata,Datatype,int4).
func newBitFieldTransform(fd *Funcdata, dt Datatype, off int32) bitFieldTransform {
	var parent *Struct
	var sz int32
	if s, ok := dt.(*Struct); ok {
		parent = s
		sz = s.Size()
	} else if dt != nil {
		// TypePartialStruct is not yet modelled in Go; if and when it lands,
		// unwrap it here and add part.Offset() into off like the C++ code at
		// bitfield.cc ~L107 does.
		sz = dt.Size()
	}
	return bitFieldTransform{
		fd:            fd,
		parentStruct:  parent,
		initialOffset: off,
		containerSize: sz,
	}
}

// containerFieldLSB translates a bitfield member's least-significant bit
// into the container frame whose byte extent is [initialOffset,
// initialOffset+containerSize). This is the Go-idiomatic collapse of
// BitRange::translateLSB: both endians reduce to a byte-delta plus the
// field's intrinsic bit offset. The containerSize parameter is only used
// for big-endian translation (the frame's most-significant end).
// C++ parity: BitRange::translateLSB (address.cc ~L660).
func containerFieldLSB(initialOffset, containerSize int32, isBigEndian bool, f TypeField) int32 {
	// The byte run that owns the bitfield is [f.Offset, f.Offset+f.Type.Size()).
	runSize := int32(0)
	if f.Type != nil {
		runSize = f.Type.Size()
	}
	if isBigEndian {
		thisPos := initialOffset + containerSize
		op2Pos := f.Offset + runSize
		return f.BitOffset + 8*(thisPos-op2Pos)
	}
	return f.BitOffset + 8*(f.Offset-initialOffset)
}

// bitfieldOverlapsContainer reports whether any portion of the bitfield sits
// inside the [initialOffset, initialOffset+containerSize) byte window.
// Used by establishFields to skip fields that are entirely outside the root
// container Varnode (the C++ code relies on collectBitFields' upper_bound
// prefilter; the Go port walks fields linearly and filters here).
func bitfieldOverlapsContainer(initialOffset, containerSize int32, f TypeField) bool {
	runSize := int32(0)
	if f.Type != nil {
		runSize = f.Type.Size()
	}
	if f.Offset+runSize <= initialOffset {
		return false
	}
	if f.Offset >= initialOffset+containerSize {
		return false
	}
	return true
}

// establishFields populates workList with one BitFieldNodeState per bitfield
// (and each hole when followHoles is set) overlapping the given Varnode.
// The worklist is seeded in ascending order of bit position, least
// significant first, mirroring the C++ loop.
// C++ parity: BitFieldTransform::establishFields (bitfield.cc ~L57) plus
// TypeStruct::collectBitFields (type.cc ~L1789) and BitFieldTriple::compare
// (type.cc ~L932). The Go port collapses both into a single pass over the
// parent struct's TypeField vector because the Go type model stores bitfield
// metadata inline on TypeField instead of in a parallel TypeBitField list.
func (t *bitFieldTransform) establishFields(vn *Varnode, followHoles bool) {
	t.workList = t.workList[:0]
	if vn == nil || t.parentStruct == nil {
		return
	}
	if vn.Space() != nil {
		t.isBigEndian = vn.Space().BigEndian
	}
	vnBitSize := vn.Size() * 8
	if vnBitSize <= 0 {
		return
	}
	container := BitRange{LeastSigBit: 0, NumBits: vnBitSize}

	// Collect overlapping bitfield members (no nested struct recursion yet;
	// the Go type model stores nested structs as plain TypeField entries, so
	// if/when nested struct traversal is needed, it gets threaded here).
	type fieldSlot struct {
		field    TypeField
		fieldPos int32
		fieldEnd int32
	}
	overlaps := make([]fieldSlot, 0, len(t.parentStruct.fields))
	for _, f := range t.parentStruct.fields {
		if !f.IsBitfield {
			continue
		}
		if !bitfieldOverlapsContainer(t.initialOffset, t.containerSize, f) {
			continue
		}
		lsb := containerFieldLSB(t.initialOffset, t.containerSize, t.isBigEndian, f)
		overlaps = append(overlaps, fieldSlot{
			field:    f,
			fieldPos: lsb,
			fieldEnd: lsb + f.BitSize,
		})
	}
	// Sort least-significant first. C++ BitFieldTriple::compare uses byte
	// offsets with endian flipping; here we already have each field's LSB
	// translated into the container frame, so a direct ascending sort yields
	// the same order.
	for i := 1; i < len(overlaps); i++ {
		for j := i; j > 0 && overlaps[j-1].fieldPos > overlaps[j].fieldPos; j-- {
			overlaps[j-1], overlaps[j] = overlaps[j], overlaps[j-1]
		}
	}

	pos := int32(0)
	for _, slot := range overlaps {
		fieldPos := slot.fieldPos
		fieldEnd := slot.fieldEnd
		if fieldPos > vnBitSize {
			fieldPos = vnBitSize
		}
		if fieldEnd > vnBitSize {
			fieldEnd = vnBitSize
		}
		if fieldPos > pos { // hole before this field
			if followHoles {
				t.workList = append(t.workList,
					NewBitFieldNodeStateForHole(container, vn, pos, fieldPos-pos))
			}
			pos = fieldPos
		}
		// The C++ overlap code classifies the field relative to the container
		// frame: code 0 (equal) and code 3 (op2 contained in this) are the
		// "field fully inside vn" cases. After truncating fieldPos/fieldEnd to
		// [0, vnBitSize), the field is fully contained iff its untruncated
		// extent did not exceed the container bits. We recompute that here.
		origPos := slot.fieldPos
		origEnd := slot.fieldEnd
		contained := origPos >= 0 && origEnd <= vnBitSize
		if contained {
			// Convert TypeField into a transient TypeBitField descriptor so
			// downstream walker logic has something to point at.
			fld := &TypeBitField{
				LogicalType: slot.field.Type,
				BitOffset:   slot.field.BitOffset,
				BitSize:     slot.field.BitSize,
				IsSigned:    slot.field.Type != nil && slot.field.Type.Metatype() == TYPE_INT,
			}
			bitsUsed := BitRange{LeastSigBit: fieldPos, NumBits: fieldEnd - fieldPos}
			t.workList = append(t.workList, NewBitFieldNodeStateForField(bitsUsed, vn, fld))
		} else if followHoles {
			t.workList = append(t.workList,
				NewBitFieldNodeStateForHole(container, vn, pos, fieldEnd-pos))
		}
		pos = fieldEnd
	}
	if pos < vnBitSize && followHoles {
		t.workList = append(t.workList,
			NewBitFieldNodeStateForHole(container, vn, pos, vnBitSize-pos))
	}
}

// buildPartialType returns the data-type associated with the root bitfield
// container. When the container Varnode covers the full parent struct it is
// the struct itself; otherwise the C++ code returns a TypePartialStruct.
// C++ parity: BitFieldTransform::buildPartialType (bitfield.cc ~L547).
// TODO(bitfield-typemodel): TypePartialStruct is not yet ported, so the
// partial case falls back to the parent struct. The processBackward /
// processForward helpers that consume this value are themselves TODOs, so
// the fallback never feeds rewriting output today.
func (t *bitFieldTransform) buildPartialType() Datatype {
	if t.parentStruct == nil {
		return nil
	}
	if t.containerSize == t.parentStruct.Size() {
		return t.parentStruct
	}
	return t.parentStruct
}

// findOverwrite walks forward from a Varnode within a single basic block to
// check whether an unspecified bit range is subsequently overwritten by an
// INDIRECT op whose output covers the same storage. Returns true only when
// every tracked bit is dead at the overwrite point.
// C++ parity: BitFieldTransform::findOverwrite (bitfield.cc ~L562).
func (bitFieldTransform) findOverwrite(vn *Varnode, bl *BlockBasic, r BitRange) bool {
	if vn == nil || bl == nil {
		return false
	}
	for _, startOp := range vn.DescendIter() {
		curVn := vn
		curRange := r
		op := startOp
		for op != nil {
			if op.Parent() != bl {
				// Leaving the block with bits still live -- cannot prove dead.
				if curRange.NumBits != 0 {
					return false
				}
				break
			}
			switch op.Code() {
			case CPUI_PIECE:
				// PIECE widens the range. We do not yet track byteOffset in
				// the Go BitRange, so PIECE is handled conservatively: if
				// curVn is the low input we shift the LSB past the high
				// operand's bits; otherwise we leave it alone.
				if op.NumInput() > 1 && op.Input(0) == curVn && op.Input(1) != nil {
					curRange.LeastSigBit += op.Input(1).Size() * 8
				}
			case CPUI_INT_LEFT:
				cvn := op.Input(1)
				if cvn == nil || !cvn.IsConstant() {
					return false
				}
				curRange.LeastSigBit += int32(cvn.Offset())
			case CPUI_INT_RIGHT:
				cvn := op.Input(1)
				if cvn == nil || !cvn.IsConstant() {
					return false
				}
				curRange.LeastSigBit -= int32(cvn.Offset())
				if curRange.LeastSigBit < 0 {
					curRange.NumBits += curRange.LeastSigBit
					curRange.LeastSigBit = 0
					if curRange.NumBits < 0 {
						curRange.NumBits = 0
					}
				}
			case CPUI_COPY, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_NEGATE:
				// Remaining bits still live through the op.
			case CPUI_INT_AND:
				cvn := op.Input(1)
				if cvn != nil && cvn.IsConstant() {
					// Masking out bits shrinks the live range. Approximate
					// by intersecting against the constant.
					mask := curRange.Mask() & cvn.Offset()
					if mask == 0 {
						curRange.NumBits = 0
					}
				}
			case CPUI_INSERT:
				// An INSERT kills the inserted bit range. Without a rich
				// BitRange we conservatively clear numBits when the insert's
				// position/size cover our range.
				if op.NumInput() >= 4 {
					posVn := op.Input(2)
					bitsVn := op.Input(3)
					if posVn != nil && posVn.IsConstant() && bitsVn != nil && bitsVn.IsConstant() {
						insPos := int32(posVn.Offset())
						insBits := int32(bitsVn.Offset())
						if insPos <= curRange.LeastSigBit &&
							insPos+insBits >= curRange.LeastSigBit+curRange.NumBits {
							curRange.NumBits = 0
						}
					}
				}
			case CPUI_INDIRECT:
				out := op.Output()
				if out != nil && out.Addr() == vn.Addr() && out.Size() == vn.Size() {
					return curRange.NumBits == 0
				}
				return false
			default:
				if curRange.NumBits != 0 {
					return false
				}
				op = nil
			}
			if op == nil {
				break
			}
			curVn = op.Output()
			if curVn == nil {
				break
			}
			if curVn.Addr() == vn.Addr() && curVn.Size() == vn.Size() {
				if curRange.NumBits == 0 {
					return true
				}
			}
			if curVn.HasNoDescend() {
				break
			}
			op = curVn.LoneDescend()
		}
	}
	return false
}

// insertRecord captures a point that can be treated as a single-field write.
// C++ parity: BitFieldInsertTransform::InsertRecord.
type insertRecord struct {
	vn          *Varnode
	constVal    uint64
	dt          Datatype
	pos         int32
	numBits     int32
	shiftAmount int32
	isConstant  bool
}

// newInsertRecordVarnode constructs a record for a Varnode-sourced insertion.
// C++ parity: InsertRecord(Varnode,Datatype,int4,int4,int4).
func newInsertRecordVarnode(vn *Varnode, dt Datatype, pos, numBits, shiftAmount int32) insertRecord {
	return insertRecord{vn: vn, dt: dt, pos: pos, numBits: numBits, shiftAmount: shiftAmount}
}

// newInsertRecordConstant constructs a record for a constant-sourced insertion.
// C++ parity: InsertRecord(uintb,Datatype,int4,int4).
func newInsertRecordConstant(val uint64, dt Datatype, pos, numBits int32) insertRecord {
	return insertRecord{constVal: val, dt: dt, pos: pos, numBits: numBits, isConstant: true}
}

// BitFieldInsertTransform walks backward from a terminating op to collect
// writes that can be rewritten as explicit INSERT operations.
// C++ parity: class BitFieldInsertTransform in bitfield.hh.
type BitFieldInsertTransform struct {
	bitFieldTransform
	// finalWriteOp is the STORE or op whose output is the bitfield container.
	finalWriteOp *PcodeOp
	// originalValue is the pre-insertion container value.
	originalValue *Varnode
	// mappedVn is the container Varnode being written to.
	mappedVn *Varnode
	// insertList accumulates the actions the apply step will materialize.
	insertList []insertRecord
}

// NewBitFieldInsertTransform constructs the backward tracer from a terminating op.
// C++ parity: BitFieldInsertTransform::BitFieldInsertTransform(Funcdata,PcodeOp,Datatype,int4).
func NewBitFieldInsertTransform(fd *Funcdata, op *PcodeOp, dt Datatype, off int32) *BitFieldInsertTransform {
	t := &BitFieldInsertTransform{
		bitFieldTransform: newBitFieldTransform(fd, dt, off),
		finalWriteOp:      op,
	}
	// For a STORE the value being written lives at input slot 2; for any
	// other op we follow the output. Determining mappedVn precisely requires
	// the full Funcdata::getVarnodeType path, which is not yet ported.
	if op != nil {
		if op.Code() == CPUI_STORE {
			if op.NumInput() > 2 {
				t.mappedVn = op.Input(2)
			}
		} else {
			t.mappedVn = op.Output()
		}
	}
	return t
}

// DoTrace walks backward from the terminating op to discover one InsertRecord
// per bitfield write, stopping once all bits of the container are accounted
// for. Returns true if the caller should invoke Apply.
// C++ parity: BitFieldInsertTransform::doTrace (bitfield.cc ~L794).
// TODO(bitfield-backward-dispatch): establishFields now seeds the worklist
// with real BitFieldNodeState entries, but the per-op backward dispatch
// (processBackward + handleAndBack / handleOrBack / handleAddBack /
// handleLeftBack / handleRightBack / handleZextBack / handleMultBack /
// handleSubpieceBack) is not yet ported. doTrace therefore walks the seeded
// worklist without consuming it and reports failure. Apply is never reached
// in the current state, but the seeding path is observably correct.
func (t *BitFieldInsertTransform) DoTrace() bool {
	if t.mappedVn == nil {
		return false
	}
	t.establishFields(t.mappedVn, true)
	if len(t.workList) == 0 {
		return false
	}
	// TODO(bitfield-backward-dispatch): drain t.workList, dispatch each state
	// through processBackward, and accumulate insertList entries. The C++
	// implementation lives at bitfield.cc ~L794 and is roughly 250 lines.
	return false
}

// Apply materializes INSERT operations for every collected record.
// C++ parity: BitFieldInsertTransform::apply.
// TODO(bitfield-backward-dispatch): pair with DoTrace port.
func (t *BitFieldInsertTransform) Apply() {
	// Walks insertList emitting INSERT p-code ops via t.fd.NewOp +
	// OpSetOpcode(CPUI_INSERT), wires pos/numBits constants, and destroys the
	// collapsed producer chain. insertList is always empty today because
	// DoTrace short-circuits before populating it.
}

// pullRecordKind is the discriminator for PullRecord.
// C++ parity: anonymous enum in BitFieldPullTransform::PullRecord.
type pullRecordKind int32

const (
	pullRecordNormal  pullRecordKind = 0
	pullRecordEqual   pullRecordKind = 1
	pullRecordAborted pullRecordKind = 2
)

// pullRecord captures a read site that can be treated as isolating a
// single bitfield.
// C++ parity: BitFieldPullTransform::PullRecord.
type pullRecord struct {
	readVn    *Varnode
	readOp    *PcodeOp
	dt        Datatype
	kind      pullRecordKind
	pos       int32
	numBits   int32
	leftShift int32
	mask      uint64
}

// BitFieldPullTransform traces forward from a bitfield container Varnode to
// find descendants that isolate individual fields, producing ZPULL/SPULL
// rewrites.
// C++ parity: class BitFieldPullTransform in bitfield.hh.
type BitFieldPullTransform struct {
	bitFieldTransform
	// root is the Varnode holding the bitfield container.
	root *Varnode
	// loadOp is the optional LOAD that produced root.
	loadOp *PcodeOp
	// pullList accumulates the pull actions the apply step will perform.
	pullList []pullRecord
}

// NewBitFieldPullTransform constructs the forward tracer rooted at vn.
// C++ parity: BitFieldPullTransform::BitFieldPullTransform(Funcdata,Varnode,Datatype,int4).
func NewBitFieldPullTransform(fd *Funcdata, vn *Varnode, dt Datatype, off int32) *BitFieldPullTransform {
	t := &BitFieldPullTransform{
		bitFieldTransform: newBitFieldTransform(fd, dt, off),
		root:              vn,
	}
	if vn != nil && vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_LOAD {
		t.loadOp = vn.Def()
	}
	return t
}

// DoTrace walks forward from the root Varnode collecting pullRecords until
// every bit of the container has been claimed. Returns true if the caller
// should invoke Apply.
// C++ parity: BitFieldPullTransform::doTrace (bitfield.cc ~L1600).
// TODO(bitfield-forward-dispatch): establishFields seeds the worklist with
// real entries, but the per-op forward dispatch (processForward +
// handleLeftForward / handleRightForward / handleAndForward /
// handleExtForward / handleMultForward / handleSubpieceForward /
// handleInsertForward / handleLessForward / handleLeastSigOp /
// handleEqualForward) is not yet ported. doTrace therefore returns false
// without populating pullList.
func (t *BitFieldPullTransform) DoTrace() bool {
	if t.root == nil {
		return false
	}
	t.establishFields(t.root, false) // false: do not follow holes
	if len(t.workList) == 0 {
		return false
	}
	// TODO(bitfield-forward-dispatch): drain t.workList via processForward.
	return false
}

// Apply materializes ZPULL or SPULL operations for every collected record.
// C++ parity: BitFieldPullTransform::apply.
// TODO(bitfield-forward-dispatch): pair with DoTrace port.
func (t *BitFieldPullTransform) Apply() {
	// Walks pullList, emits ZPULL / SPULL ops, then destroys dead
	// descendants. pullList is empty today because DoTrace short-circuits.
}

// insertExpressionLSBMask returns a mask over the least-significant numBits
// of an INSERT op's destination slice.
// C++ parity: InsertExpression::getLSBMask in bitfield.cc.
// The C++ helper walks nested INSERT ops; this port is the leaf case, which
// is all RuleInsertAbsorb currently requires.
func insertExpressionLSBMask(insertOp *PcodeOp) uint64 {
	if insertOp == nil || insertOp.NumInput() < 4 {
		return 0
	}
	bitsVn := insertOp.Input(3)
	if bitsVn == nil || !bitsVn.IsConstant() {
		return 0
	}
	nb := int32(bitsVn.Offset())
	if nb <= 0 {
		return 0
	}
	if nb >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(nb)) - 1
}
