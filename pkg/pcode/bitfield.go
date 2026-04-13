/* ###
 * IP: GHIDRA
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

// BitRange is the Go port of ghidra::BitRange in bitfield.cc.
type BitRange struct {
	ByteOffset  int32
	ByteSize    int32
	LeastSigBit int32
	NumBits     int32
	IsBigEndian bool
}

// BitFieldNodeState is the Go port of ghidra::BitFieldNodeState in bitfield.cc.
type BitFieldNodeState struct {
	BitsUsed        BitRange
	BitsField       BitRange
	Node            *Varnode
	Field           Datatype
	OrigLeastSigBit int32
	IsSignExtended  bool
}

// BitFieldTransform is the Go port of ghidra::BitFieldTransform in bitfield.cc.
// The full tracing machinery is intentionally conservative in Gosleigh until
// the richer bitfield datatype metadata is available.
type BitFieldTransform struct {
	Func          *Funcdata
	ParentStruct  *Struct
	WorkList      []BitFieldNodeState
	InitialOffset int32
	ContainerSize int32
	IsBigEndian   bool
}

// InsertRecord is the Go port of ghidra::BitFieldInsertTransform::InsertRecord in bitfield.cc.
type InsertRecord struct {
	Vn          *Varnode
	ConstVal    uint64
	Dt          Datatype
	Pos         int32
	NumBits     int32
	ShiftAmount int32
}

// BitFieldInsertTransform is the Go port of ghidra::BitFieldInsertTransform in bitfield.cc.
// Gosleigh keeps this structure as a conservative scaffold until full bitfield
// datatype metadata and tracing are available.
type BitFieldInsertTransform struct {
	BitFieldTransform
	FinalWriteOp  *PcodeOp
	OriginalValue *Varnode
	MappedVn      *Varnode
	InsertList    []InsertRecord
}

// PullRecord is the Go port of ghidra::BitFieldPullTransform::PullRecord in bitfield.cc.
type PullRecord struct {
	ReadVn    *Varnode
	ReadOp    *PcodeOp
	Dt        Datatype
	Type      int32
	Pos       int32
	NumBits   int32
	LeftShift int32
	Mask      uint64
}

// BitFieldPullTransform is the Go port of ghidra::BitFieldPullTransform in bitfield.cc.
// Gosleigh keeps this structure as a conservative scaffold until full bitfield
// datatype metadata and tracing are available.
type BitFieldPullTransform struct {
	BitFieldTransform
	Root     *Varnode
	LoadOp   *PcodeOp
	PullList []PullRecord
}

// bitfieldHasBitfields is the conservative Gosleigh replacement for
// ghidra::Datatype::hasBitfields in bitfield.cc.
func bitfieldHasBitfields(dt Datatype) bool {
	_ = dt
	return false
}

// bitfieldPtrInto is the conservative Gosleigh replacement for
// ghidra::Datatype::getPtrInto in bitfield.cc.
func bitfieldPtrInto(dt Datatype, off int32) (Datatype, int32) {
	ptr, ok := dt.(*Pointer)
	if !ok || ptr == nil {
		return nil, 0
	}
	base := ptr.Pointee()
	if base == nil {
		return nil, 0
	}
	if _, ok := base.(*Struct); !ok {
		return nil, 0
	}
	if off < 0 || off > base.Size() {
		return nil, 0
	}
	return base, off
}
