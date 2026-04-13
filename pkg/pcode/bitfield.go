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
// NOTE: The rule-level entry points (RuleBitField* and RulePullAbsorb /
// RuleInsertAbsorb) are ported as real Go code that mirrors the C++ control
// flow. However, the trace machinery bottoms out at Datatype.HasBitfields(),
// which currently always returns false because the Go type model does not yet
// carry TypeBitField struct members. Until that type-system work lands, the
// transforms are reachable but do_trace short-circuits cleanly. See
// datatype.go TODO(bitfield-typemodel).
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
// C++ parity: BitFieldTransform::BitFieldTransform(Funcdata,Datatype,int4).
func newBitFieldTransform(fd *Funcdata, dt Datatype, off int32) bitFieldTransform {
	var parent *Struct
	var sz int32
	if s, ok := dt.(*Struct); ok {
		parent = s
		sz = s.Size()
	} else if dt != nil {
		sz = dt.Size()
	}
	return bitFieldTransform{
		fd:            fd,
		parentStruct:  parent,
		initialOffset: off,
		containerSize: sz,
	}
}

// establishFields populates workList with one BitFieldNodeState per bitfield
// or hole that overlaps the given Varnode.
// C++ parity: BitFieldTransform::establishFields.
// TODO(bitfield-typemodel): Without bitfield struct members, this always
// yields an empty workList and therefore fails the trace.
func (t *bitFieldTransform) establishFields(vn *Varnode, followHoles bool) {
	// Real port placeholder: once *Struct carries bitfield members, iterate
	// them and emit a BitFieldNodeState for each overlapping range (and a
	// hole state in the gaps when followHoles is set). The current type model
	// has no bitfields, so the resulting workList is empty and doTrace
	// callers correctly bail out.
	_ = vn
	_ = followHoles
	t.workList = t.workList[:0]
}

// buildPartialType constructs the partial data-type backing the root container.
// C++ parity: BitFieldTransform::buildPartialType.
// TODO(bitfield-typemodel): Depends on TypePartialStruct, which is not yet
// ported. Returns nil for now and callers must treat nil as failure.
func (t *bitFieldTransform) buildPartialType() Datatype {
	return nil
}

// findOverwrite tests whether a subsequent write in the same basic block
// covers the same range, which would make the current write dead.
// C++ parity: BitFieldTransform::findOverwrite.
func (bitFieldTransform) findOverwrite(vn *Varnode, bl *BlockBasic, r BitRange) bool {
	// Real port placeholder: the C++ walks the block forward looking for a
	// dominating write of the same field. Until the walker state ports are
	// wired through the rules, returning false is the conservative answer --
	// it never suppresses an otherwise-valid transform.
	_ = vn
	_ = bl
	_ = r
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
// C++ parity: BitFieldInsertTransform::doTrace.
// TODO(bitfield-typemodel): Without bitfield struct members, establishFields
// yields an empty worklist and the trace reports failure.
func (t *BitFieldInsertTransform) DoTrace() bool {
	if t.mappedVn == nil {
		return false
	}
	t.establishFields(t.mappedVn, true)
	if len(t.workList) == 0 {
		return false
	}
	// Real port placeholder: pop states from workList, dispatch on the
	// defining op code, and accumulate insertRecords. Because establishFields
	// currently produces no states, this loop is never taken. The structure
	// is retained so a future type-model change flips the transform on
	// without re-writing call sites.
	return false
}

// Apply materializes INSERT operations for every collected record.
// C++ parity: BitFieldInsertTransform::apply.
func (t *BitFieldInsertTransform) Apply() {
	// Real port placeholder: walk insertList, allocate INSERT p-code ops via
	// t.fd.NewOp / OpSetOpcode(CPUI_INSERT), wire pos/numBits constants, and
	// destroy the collapsed producer chain. insertList is always empty today
	// because DoTrace bails early.
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
// C++ parity: BitFieldPullTransform::doTrace.
// TODO(bitfield-typemodel): Short-circuits until establishFields has real
// bitfield members to iterate.
func (t *BitFieldPullTransform) DoTrace() bool {
	if t.root == nil {
		return false
	}
	t.establishFields(t.root, false)
	if len(t.workList) == 0 {
		return false
	}
	// Real port placeholder: process each state in workList by dispatching on
	// descendant op codes (INT_LEFT, INT_RIGHT, INT_AND, subpiece, ...). The
	// full op-level fan-out is ~600 lines of C++ and each helper needs a
	// real TransformState; they will be ported alongside the type model.
	return false
}

// Apply materializes ZPULL or SPULL operations for every collected record.
// C++ parity: BitFieldPullTransform::apply.
func (t *BitFieldPullTransform) Apply() {
	// Real port placeholder: mirrors BitFieldPullTransform::apply -- walks
	// pullList, emits ZPULL/SPULL ops, then destroys dead descendants. The
	// list is empty today.
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
