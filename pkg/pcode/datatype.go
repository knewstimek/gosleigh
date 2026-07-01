package pcode

import (
	"hash/fnv"
)

// metatype mirrors Ghidra's type_metatype values exactly.
type metatype uint8

const (
	TYPE_VOID          metatype = 17
	TYPE_SPACEBASE     metatype = 16
	TYPE_UNKNOWN       metatype = 15
	TYPE_INT           metatype = 14
	TYPE_UINT          metatype = 13
	TYPE_BOOL          metatype = 12
	TYPE_CODE          metatype = 11
	TYPE_FLOAT         metatype = 10
	TYPE_PTR           metatype = 9
	TYPE_PTRREL        metatype = 8
	TYPE_ARRAY         metatype = 7
	TYPE_ENUM_UINT     metatype = 6
	TYPE_ENUM_INT      metatype = 5
	TYPE_STRUCT        metatype = 4
	TYPE_UNION         metatype = 3
	TYPE_PARTIALENUM   metatype = 2
	TYPE_PARTIALSTRUCT metatype = 1
	TYPE_PARTIALUNION  metatype = 0
)

// subMetatype mirrors Ghidra's sub_metatype values exactly.
type subMetatype uint8

const (
	SUB_VOID             subMetatype = 23
	SUB_SPACEBASE        subMetatype = 22
	SUB_UNKNOWN          subMetatype = 21
	SUB_PARTIALSTRUCT    subMetatype = 20
	SUB_INT_CHAR         subMetatype = 19
	SUB_UINT_CHAR        subMetatype = 18
	SUB_INT_PLAIN        subMetatype = 17
	SUB_UINT_PLAIN       subMetatype = 16
	SUB_INT_ENUM         subMetatype = 15
	SUB_UINT_PARTIALENUM subMetatype = 14
	SUB_UINT_ENUM        subMetatype = 13
	SUB_INT_UNICODE      subMetatype = 12
	SUB_UINT_UNICODE     subMetatype = 11
	SUB_BOOL             subMetatype = 10
	SUB_CODE             subMetatype = 9
	SUB_FLOAT            subMetatype = 8
	SUB_PTRREL_UNK       subMetatype = 7
	SUB_PTR              subMetatype = 6
	SUB_PTRREL           subMetatype = 5
	SUB_PTR_STRUCT       subMetatype = 4
	SUB_ARRAY            subMetatype = 3
	SUB_STRUCT           subMetatype = 2
	SUB_UNION            subMetatype = 1
	SUB_PARTIALUNION     subMetatype = 0
)

var base2sub = [...]subMetatype{
	SUB_PARTIALUNION,
	SUB_PARTIALSTRUCT,
	SUB_UINT_PARTIALENUM,
	SUB_UNION,
	SUB_STRUCT,
	SUB_INT_ENUM,
	SUB_UINT_ENUM,
	SUB_ARRAY,
	SUB_PTRREL,
	SUB_PTR,
	SUB_FLOAT,
	SUB_CODE,
	SUB_BOOL,
	SUB_UINT_PLAIN,
	SUB_INT_PLAIN,
	SUB_UNKNOWN,
	SUB_SPACEBASE,
	SUB_VOID,
}

type datatypeFlags uint32

const (
	datatypeCoreType        datatypeFlags = 0x1
	datatypeEnumType        datatypeFlags = 0x4
	datatypeTypeIncomplete  datatypeFlags = 0x400
	datatypeNeedsResolution datatypeFlags = 0x800
	datatypePointerToArray  datatypeFlags = 0x10000
)

// Datatype is the common surface shared by the supported p-code data-types.
type Datatype interface {
	ID() uint64
	Size() int32
	Alignment() int32
	AlignSize() int32
	Name() string
	DisplayName() string
	Metatype() metatype
	SubMeta() subMetatype
	Flags() datatypeFlags
	IsCoreType() bool
	IsEnumType() bool
	IsIncomplete() bool
	NeedsResolution() bool
	IsPointerToArray() bool
	// HasBitfields reports whether any field of a composite type is a bitfield.
	// C++ parity: Datatype::hasBitfields (type.hh). Default: false.
	HasBitfields() bool
}

// HasBitfields is the base implementation returning false for all primitive types.
// C++ parity: Datatype::hasBitfields default in type.hh. Composite types that
// carry bitfield members (currently *Struct) override this.
func (d datatypeBase) HasBitfields() bool { return false }

// HasBitfields scans the struct's fields and reports whether any are modelled
// as bitfields, or whether any field type itself contains bitfields.
// C++ parity: Datatype::hasBitfields combined with the has_bitfields flag bit
// that TypeStruct::assignFieldOffsets lights up when it finds a bitfield
// member (type.cc ~L2383, L2745, L2107). We evaluate lazily instead of caching
// a flag so struct construction does not need to be threaded through the
// TypeFactory path used by the C++ code.
func (s *Struct) HasBitfields() bool {
	for _, f := range s.fields {
		if f.IsBitfield {
			return true
		}
		if f.Type != nil && f.Type.HasBitfields() {
			return true
		}
	}
	return false
}

// GetPtrInto unwraps a Pointer or PointerRel to its pointee, yielding a byte
// offset into the containing object.
// C++ parity: Datatype::getPtrInto (type.hh default + TypePointer::getPtrInto
// + TypePointerRel::getPtrInto in type.cc ~L3018). For a plain pointer the
// offset is zero. For a relative pointer, if the pointee is a structured
// type the offset is zero and the pointee is returned; otherwise the offset
// is the stored byte offset and the parent container is returned.
// Returns (nil, 0) if the receiver is not a pointer-like type.
func GetPtrInto(dt Datatype) (Datatype, int32) {
	if dt == nil {
		return nil, 0
	}
	switch ptr := dt.(type) {
	case *PointerRel:
		if ptr.to != nil {
			meta := ptr.to.Metatype()
			if meta == TYPE_STRUCT || meta == TYPE_UNION {
				return ptr.to, 0
			}
		}
		return ptr.parent, ptr.offset
	case *Pointer:
		return ptr.Pointee(), 0
	}
	return nil, 0
}

type datatypeBase struct {
	id          uint64
	size        int32
	alignment   int32
	alignSize   int32
	name        string
	displayName string
	metatype    metatype
	submeta     subMetatype
	flags       datatypeFlags
}

func newDatatypeBase(size int32, align int32, meta metatype, name string) datatypeBase {
	return datatypeBase{
		id:          hashName(name),
		size:        size,
		alignment:   align,
		alignSize:   calcAlignSize(size, align),
		name:        name,
		displayName: name,
		metatype:    meta,
		submeta:     subMetaForMetatype(meta),
	}
}

func (d datatypeBase) ID() uint64             { return d.id }
func (d datatypeBase) Size() int32            { return d.size }
func (d datatypeBase) Alignment() int32       { return d.alignment }
func (d datatypeBase) AlignSize() int32       { return d.alignSize }
func (d datatypeBase) Name() string           { return d.name }
func (d datatypeBase) DisplayName() string    { return d.displayName }
func (d datatypeBase) Metatype() metatype     { return d.metatype }
func (d datatypeBase) SubMeta() subMetatype   { return d.submeta }
func (d datatypeBase) Flags() datatypeFlags   { return d.flags }
func (d datatypeBase) IsCoreType() bool       { return d.flags&datatypeCoreType != 0 }
func (d datatypeBase) IsEnumType() bool       { return d.flags&datatypeEnumType != 0 }
func (d datatypeBase) IsIncomplete() bool     { return d.flags&datatypeTypeIncomplete != 0 }
func (d datatypeBase) NeedsResolution() bool  { return d.flags&datatypeNeedsResolution != 0 }
func (d datatypeBase) IsPointerToArray() bool { return d.flags&datatypePointerToArray != 0 }

// Base is the primitive leaf type for unknown, integer, boolean, and float classes.
type Base struct {
	datatypeBase
}

func NewBase(size int32, meta metatype, name string) *Base {
	return &Base{datatypeBase: newDatatypeBase(size, -1, meta, name)}
}

// Void is the canonical zero-sized void type.
type Void struct {
	datatypeBase
}

func NewVoid() *Void {
	base := newDatatypeBase(0, 1, TYPE_VOID, "void")
	base.flags |= datatypeCoreType
	return &Void{datatypeBase: base}
}

// Pointer is a plain pointer to another data-type.
type Pointer struct {
	datatypeBase
	to       Datatype
	wordSize uint32
}

func NewPointer(size int32, to Datatype, wordSize uint32) *Pointer {
	base := newDatatypeBase(size, -1, TYPE_PTR, "")
	if to != nil {
		base.flags = to.Flags() & datatypeCoreType
		base.submeta = SUB_PTR
		switch to.Metatype() {
		case TYPE_STRUCT:
			if !to.NeedsResolution() {
				base.submeta = SUB_PTR_STRUCT
			}
		case TYPE_UNION:
			base.submeta = SUB_PTR_STRUCT
		case TYPE_ARRAY:
			base.flags |= datatypePointerToArray
		}
		if to.NeedsResolution() && to.Metatype() != TYPE_PTR {
			base.flags |= datatypeNeedsResolution
		}
	}
	return &Pointer{
		datatypeBase: base,
		to:           to,
		wordSize:     wordSize,
	}
}

func (p *Pointer) Pointee() Datatype { return p.to }
func (p *Pointer) WordSize() uint32  { return p.wordSize }

// Array is a repeated sequence of a single element type.
type Array struct {
	datatypeBase
	elem  Datatype
	count int32
}

func NewArray(count int32, elem Datatype) *Array {
	align := int32(-1)
	size := int32(0)
	if elem != nil {
		align = elem.Alignment()
		size = count * elem.AlignSize()
	}
	base := newDatatypeBase(size, align, TYPE_ARRAY, "")
	if count == 1 {
		base.flags |= datatypeNeedsResolution
	}
	return &Array{
		datatypeBase: base,
		elem:         elem,
		count:        count,
	}
}

func (a *Array) Element() Datatype { return a.elem }
func (a *Array) Count() int32      { return a.count }

// TypeField describes one field within a struct or union. Byte-aligned
// fields leave BitOffset/BitSize zero and clear IsBitfield. Bitfield members
// set IsBitfield and use BitOffset (least significant bit within the
// containing byte run) and BitSize (width in bits).
// C++ parity: class TypeField in type.hh plus the TypeBitField side-table
// that TypeStruct::assignFieldOffsets folds in (type.cc ~L2360). The Go port
// stores the bitfield description inline because struct members and
// bitfields share a single field vector downstream.
type TypeField struct {
	Ident      int32
	Offset     int32
	Name       string
	Type       Datatype
	BitOffset  int32
	BitSize    int32
	IsBitfield bool
}

func (f TypeField) End() int32 {
	if f.Type == nil {
		return f.Offset
	}
	return f.Offset + f.Type.Size()
}

// Struct is a composite type with non-overlapping fields.
type Struct struct {
	datatypeBase
	fields []TypeField
}

func NewStruct(name string, fields []TypeField) *Struct {
	fieldsCopy := cloneFields(fields)
	align := maxFieldAlignment(fieldsCopy)
	size := int32(0)
	for _, field := range fieldsCopy {
		if end := field.End(); end > size {
			size = end
		}
	}
	base := newDatatypeBase(size, align, TYPE_STRUCT, name)
	if len(fieldsCopy) == 0 {
		base.flags |= datatypeTypeIncomplete
	} else if len(fieldsCopy) == 1 && fieldsCopy[0].Offset == 0 && fieldsCopy[0].Type != nil && fieldsCopy[0].Type.Size() == size {
		base.flags |= datatypeNeedsResolution
	}
	base.alignSize = calcAlignSize(size, align)
	return &Struct{
		datatypeBase: base,
		fields:       fieldsCopy,
	}
}

func (s *Struct) Fields() []TypeField { return cloneFields(s.fields) }
func (s *Struct) FieldAt(offset int32) (TypeField, bool) {
	for _, field := range s.fields {
		if field.Type == nil {
			continue
		}
		if offset >= field.Offset && offset < field.Offset+field.Type.Size() {
			return field, true
		}
	}
	return TypeField{}, false
}

// Union is a composite type with overlapping fields.
type Union struct {
	datatypeBase
	fields []TypeField
}

func NewUnion(name string, fields []TypeField) *Union {
	fieldsCopy := cloneFields(fields)
	align := maxFieldAlignment(fieldsCopy)
	size := int32(0)
	for _, field := range fieldsCopy {
		if field.Type != nil && field.Type.Size() > size {
			size = field.Type.Size()
		}
	}
	base := newDatatypeBase(size, align, TYPE_UNION, name)
	base.flags |= datatypeNeedsResolution
	if len(fieldsCopy) == 0 {
		base.flags |= datatypeTypeIncomplete
	}
	base.alignSize = calcAlignSize(size, align)
	return &Union{
		datatypeBase: base,
		fields:       fieldsCopy,
	}
}

func (u *Union) Fields() []TypeField { return cloneFields(u.fields) }

// Enum is an integer-like type with named values.
type Enum struct {
	datatypeBase
	values map[uint64]string
}

func NewEnum(size int32, enumMeta metatype, name string, values map[uint64]string) *Enum {
	actualMeta := TYPE_UINT
	switch enumMeta {
	case TYPE_ENUM_INT:
		actualMeta = TYPE_INT
	case TYPE_ENUM_UINT:
		actualMeta = TYPE_UINT
	default:
		panic("enum metatype must be TYPE_ENUM_INT or TYPE_ENUM_UINT")
	}

	base := newDatatypeBase(size, -1, actualMeta, name)
	base.submeta = subMetaForMetatype(enumMeta)
	base.flags |= datatypeEnumType
	return &Enum{
		datatypeBase: base,
		values:       cloneEnumValues(values),
	}
}

func (e *Enum) Values() map[uint64]string { return cloneEnumValues(e.values) }
func (e *Enum) HasNamedValue(value uint64) bool {
	_, ok := e.values[value]
	return ok
}

// Code is a callable type with an optional signature.
type Code struct {
	datatypeBase
	returnType Datatype
	params     []Datatype
	variadic   bool
}

func NewCode(name string, returnType Datatype, params []Datatype, variadic bool) *Code {
	base := newDatatypeBase(1, 1, TYPE_CODE, name)
	return &Code{
		datatypeBase: base,
		returnType:   returnType,
		params:       cloneDatatypes(params),
		variadic:     variadic,
	}
}

func (c *Code) ReturnType() Datatype       { return c.returnType }
func (c *Code) ParameterTypes() []Datatype { return cloneDatatypes(c.params) }
func (c *Code) IsVariadic() bool           { return c.variadic }

// PointerRel is a pointer that points \e into a larger container at a known
// byte offset. Downstream rules use it to recover struct-field style accesses
// where the raw pointer value is (basePtr + offset).
// C++ parity: class TypePointerRel in type.hh. The Go port models the minimum
// state GetPtrInto needs today: the final pointee, the containing parent,
// the byte offset, and the plain pointer size/word-size.
type PointerRel struct {
	datatypeBase
	to       Datatype
	parent   Datatype
	offset   int32
	wordSize uint32
}

// NewPointerRel constructs a relative pointer with the given byte offset into
// parent. pointee is the data-type the pointer targets through the offset.
// C++ parity: TypePointerRel::TypePointerRel(int4,Datatype*,uint4,Datatype*,int4).
func NewPointerRel(size int32, pointee Datatype, wordSize uint32, parent Datatype, off int32) *PointerRel {
	base := newDatatypeBase(size, -1, TYPE_PTRREL, "")
	base.submeta = SUB_PTRREL
	if pointee != nil {
		base.flags = pointee.Flags() & datatypeCoreType
	}
	return &PointerRel{
		datatypeBase: base,
		to:           pointee,
		parent:       parent,
		offset:       off,
		wordSize:     wordSize,
	}
}

// Pointee returns the immediate target of the relative pointer.
// C++ parity: TypePointer::getPtrTo via TypePointerRel.
func (p *PointerRel) Pointee() Datatype { return p.to }

// Parent returns the containing data-type the offset is measured within.
// C++ parity: TypePointerRel::getParent.
func (p *PointerRel) Parent() Datatype { return p.parent }

// ByteOffset returns the byte offset into the parent container.
// C++ parity: TypePointerRel::getByteOffset.
func (p *PointerRel) ByteOffset() int32 { return p.offset }

// WordSize returns the word size of the relative pointer.
// C++ parity: TypePointer::getWordSize.
func (p *PointerRel) WordSize() uint32 { return p.wordSize }

// TypeOrder orders two data-types for the type propagation algorithm.
// Bigger types come earlier; more specific types come earlier.
// C++ parity: Datatype::typeOrder (type.hh:295) which forwards to
// Datatype::compare(op,10) (type.cc:216-222): identical pointers order 0;
// otherwise submeta ascending (lower submeta = more specific = earlier),
// then size descending (larger size = earlier). A negative result means a
// is more specific / larger than b.
//
// This models the base Datatype::compare only. Pointer/Array/Struct override
// compare with additional recursive levels; the primitive leaf types that the
// type-propagation sweep touches never descend past the base comparison, so the
// override levels are intentionally not ported here.
func TypeOrder(a, b Datatype) int {
	if a == b {
		return 0
	}
	if a.SubMeta() != b.SubMeta() {
		if a.SubMeta() < b.SubMeta() {
			return -1
		}
		return 1
	}
	if a.Size() != b.Size() {
		return int(b.Size() - a.Size())
	}
	return 0
}

func subMetaForMetatype(meta metatype) subMetatype {
	if int(meta) >= len(base2sub) {
		return SUB_UNKNOWN
	}
	return base2sub[meta]
}

func calcAlignSize(size int32, align int32) int32 {
	if size <= 0 || align <= 1 {
		return size
	}
	remainder := size % align
	if remainder == 0 {
		return size
	}
	return size + align - remainder
}

func hashName(name string) uint64 {
	if name == "" {
		return 0
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(name))
	return hasher.Sum64()
}

func cloneFields(fields []TypeField) []TypeField {
	if len(fields) == 0 {
		return nil
	}
	out := make([]TypeField, len(fields))
	copy(out, fields)
	return out
}

func cloneDatatypes(in []Datatype) []Datatype {
	if len(in) == 0 {
		return nil
	}
	out := make([]Datatype, len(in))
	copy(out, in)
	return out
}

func cloneEnumValues(in map[uint64]string) map[uint64]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[uint64]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func maxFieldAlignment(fields []TypeField) int32 {
	align := int32(-1)
	for _, field := range fields {
		if field.Type == nil {
			continue
		}
		cur := field.Type.Alignment()
		if cur <= 0 {
			cur = 1
		}
		if cur > align {
			align = cur
		}
	}
	return align
}
