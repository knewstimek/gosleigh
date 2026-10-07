package pcode

import (
	"hash/fnv"
	"sort"
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
	// datatypeTypedef marks a host typedef name over a base type (DWORD,
	// UINT): it prints by its own name. C++ parity: Datatype::typedefImm set.
	datatypeTypedef datatypeFlags = 0x20000
	// datatypeHostNamed marks a base type the host named (ulong for a 4-byte
	// unsigned): its name is printed as is. Gosleigh-made base types are
	// renamed to the core names instead (normalizedBaseType).
	datatypeHostNamed datatypeFlags = 0x40000
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
	if ptr, ok := dt.(*Pointer); ok {
		if !ptr.IsPointerRel() {
			return ptr.Pointee(), 0
		}
		if ptr.to != nil {
			meta := ptr.to.Metatype()
			if meta == TYPE_STRUCT || meta == TYPE_UNION {
				return ptr.to, 0
			}
		}
		return ptr.relParent, ptr.relOffset
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
	// typedefOf is the data-type a typedef names. C++ parity: Datatype::typedefImm.
	typedefOf Datatype
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

func (d datatypeBase) ID() uint64           { return d.id }
func (d datatypeBase) Size() int32          { return d.size }
func (d datatypeBase) Alignment() int32     { return d.alignment }
func (d datatypeBase) AlignSize() int32     { return d.alignSize }
func (d datatypeBase) Name() string         { return d.name }
func (d datatypeBase) DisplayName() string  { return d.displayName }
func (d datatypeBase) Metatype() metatype   { return d.metatype }
func (d datatypeBase) SubMeta() subMetatype { return d.submeta }
func (d datatypeBase) Flags() datatypeFlags { return d.flags }

// Typedef returns the data-type this typedef names, or nil.
// C++ parity: Datatype::getTypedef.
func (d datatypeBase) Typedef() Datatype      { return d.typedefOf }
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

	// Relative pointer state (C++ TypePointerRel, a TypePointer subclass):
	// relParent is the containing data-type, relOffset the byte offset of to
	// within it, relStripped the plain form of an ephemeral one.
	relParent   Datatype
	relOffset   int32
	relStripped *Pointer
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

// PartialStruct is the type of a piece of a structure or array that matches
// no component exactly (4 bytes of a char[17] string). Variables never keep
// it: a HighVariable uses the stripped undefined type.
// C++ parity: TypePartialStruct.
type PartialStruct struct {
	datatypeBase
	container Datatype
	offset    int64
	stripped  Datatype
}

// Container returns the structure or array this is a piece of.
func (p *PartialStruct) Container() Datatype { return p.container }

// Offset returns the byte offset within the container.
func (p *PartialStruct) Offset() int64 { return p.offset }

// Stripped returns the undefined type used where a formal type is needed.
func (p *PartialStruct) Stripped() Datatype { return p.stripped }

// componentForPtr is the type a pointer to this piece points to: the array
// element when the piece starts on one, else the stripped type.
// C++ parity: TypePartialStruct::getComponentForPtr.
func (p *PartialStruct) componentForPtr() Datatype {
	if arr, ok := p.container.(*Array); ok {
		if el := arr.Element(); el != nil && el.Metatype() != TYPE_UNKNOWN && el.AlignSize() > 0 && p.offset%int64(el.AlignSize()) == 0 {
			return el
		}
	}
	return p.stripped
}

// PartialUnion is the type of a piece of a union that is not the whole of a
// field starting at the union's base. Each read or write resolves it to the
// field the piece falls in; a variable uses the stripped undefined type.
// C++ parity: TypePartialUnion.
type PartialUnion struct {
	datatypeBase
	container *Union
	offset    int64
	stripped  Datatype
}

// Container returns the union this is a piece of.
func (p *PartialUnion) Container() *Union { return p.container }

// Offset returns the byte offset within the union.
func (p *PartialUnion) Offset() int64 { return p.offset }

// Stripped returns the undefined type used where a formal type is needed.
func (p *PartialUnion) Stripped() Datatype { return p.stripped }

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
	// A partial enumeration is a piece of parent starting offset bytes in;
	// a variable uses the stripped undefined type. C++ parity: TypePartialEnum.
	parent   *Enum
	offset   int64
	stripped Datatype
}

// IsPartialEnum reports a piece of an enumeration.
func (e *Enum) IsPartialEnum() bool { return e.parent != nil }

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

// Matches returns the names whose OR represents val, and whether they
// represent its complement instead. No names means no representation. Each
// step takes the biggest named value matching the most significant
// remaining bits.
// C++ parity: TypeEnum::getMatches.
func (e *Enum) Matches(val uint64) ([]string, bool) {
	if e.parent != nil {
		// C++ parity: TypePartialEnum::getMatches (value shifted into place).
		// Known mismatch: a piece past byte 0 needs the shift printed
		// (Representation::shiftAmount), so it is left unrepresented.
		if e.offset != 0 {
			return nil, false
		}
		return e.parent.Matches(val)
	}
	keys := make([]uint64, 0, len(e.values))
	for k := range e.values {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	full := ^uint64(0)
	if e.size < 8 {
		full = uint64(1)<<uint(8*e.size) - 1
	}
	for count := 0; count < 2; count++ {
		var names []string
		allmatch := true
		if val == 0 { // Zero handled specially
			if nm, ok := e.values[val]; ok {
				names = append(names, nm)
			} else {
				allmatch = false
			}
		} else {
			bitsleft, target := val, val
			for target != 0 {
				// The biggest named value less than or equal to target
				idx := sort.Search(len(keys), func(i int) bool { return keys[i] > target })
				if idx == 0 {
					break // All named values are greater than target
				}
				curval := keys[idx-1]
				diff := coveringMask(bitsleft ^ curval)
				if diff >= bitsleft {
					break // Could not match the most significant bit of bitsleft
				}
				if curval&diff == 0 {
					names = append(names, e.values[curval]) // Accept the name
					bitsleft ^= curval
					target = bitsleft
				} else {
					// Bits above diff are the most one named value can match
					target = curval &^ diff
				}
			}
			allmatch = bitsleft == 0
		}
		if allmatch {
			return names, count == 1
		}
		val ^= full // Try the complement
	}
	return nil, false
}

func (e *Enum) Values() map[uint64]string {
	if e.parent != nil {
		if e.offset != 0 {
			return nil
		}
		return e.parent.Values()
	}
	return cloneEnumValues(e.values)
}

// HasNamedValue reports a name for value. C++ parity: TypeEnum /
// TypePartialEnum::hasNamedValue.
func (e *Enum) HasNamedValue(value uint64) bool {
	if e.parent != nil {
		return e.parent.HasNamedValue(value << uint(8*e.offset))
	}
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

// HasPrototype reports whether this code type carries a resolved function
// signature. A prototype-less code type (no return, no params, non-variadic) is
// the bare "code" type Ghidra creates via TypeFactory::getTypeCode() for an
// indirect-call target of unknown signature; it renders by name ("code") rather
// than as a synthesized "void (*)(void)".
// C++ parity: TypeCode with proto==(FuncProto*)0 (type.hh TypeCode::getPrototype).
func (c *Code) HasPrototype() bool {
	if c == nil {
		return false
	}
	return c.returnType != nil || len(c.params) > 0 || c.variadic
}

// IsPointerRel reports whether p is a relative pointer: it points at Pointee
// which sits at ByteOffset inside the Parent container.
// C++ parity: Datatype::isPointerRel (TypePointerRel is a TypePointer).
func (p *Pointer) IsPointerRel() bool { return p.relParent != nil }

// IsFormalPointerRel reports a relative pointer that is not ephemeral.
// C++ parity: Datatype::isFormalPointerRel.
func (p *Pointer) IsFormalPointerRel() bool { return p.relParent != nil && p.relStripped == nil }

// Parent returns the container a relative pointer points into.
// C++ parity: TypePointerRel::getParent.
func (p *Pointer) Parent() Datatype { return p.relParent }

// ByteOffset returns a relative pointer's byte offset within its parent.
// C++ parity: TypePointerRel::getByteOffset.
func (p *Pointer) ByteOffset() int32 { return p.relOffset }

// EvaluateThruParent reports whether an access at addrOff past this relative
// pointer is better expressed through its parent structure.
// C++ parity: TypePointerRel::evaluateThruParent.
func (p *Pointer) EvaluateThruParent(addrOff uint64) bool {
	ws := uint64(p.wordSize)
	if ws == 0 {
		ws = 1
	}
	byteOff := addrOff * ws // addressToByte
	if pt := p.Pointee(); pt != nil && pt.Metatype() == TYPE_STRUCT && byteOff < uint64(pt.Size()) {
		return false
	}
	byteOff = (byteOff + uint64(int64(p.relOffset))) & maskForSize(p.Size())
	return p.relParent != nil && byteOff < uint64(p.relParent.Size())
}

// Stripped returns the plain pointer an ephemeral relative pointer stands
// for in formal declarations, nil otherwise.
// C++ parity: TypePointerRel::getStripped.
func (p *Pointer) Stripped() *Pointer { return p.relStripped }

// TypeOrder orders two data-types for the type propagation algorithm.
// Bigger types come earlier; more specific types come earlier.
// C++ parity: Datatype::typeOrder (type.hh:295) which forwards to
// Datatype::compare(op,10) (type.cc:216-222): identical pointers order 0;
// otherwise submeta ascending (lower submeta = more specific = earlier),
// then size descending (larger size = earlier). A negative result means a
// is more specific / larger than b.
//
// This models the base Datatype::compare plus the TypePointer, TypeArray,
// TypeStruct, TypeUnion and TypeEnum overrides.
// Known mismatch: the final id tie-break uses Gosleigh's name-hash ids, and
// TypeCode/partial types compare as the base.
func TypeOrder(a, b Datatype) int {
	return typeOrderLevel(a, b, 10)
}

// typeOrderLevel orders two data-types, recursing through pointer pointees with a
// depth budget (level) to break cycles. Mirrors C++ Datatype::typeOrder ->
// compare(op,10): the base compares submeta then size; TypePointer::compare adds
// wordsize and a recursive pointee compare (type.cc TypePointer::compare). Without
// the pointee recursion, ptr-to-int and ptr-to-undefined4 order equal, so a later
// more-specific int* cannot displace an already-applied undefined4* during type
// inference (probe_find_max: the array pointer stays undefined4*).
func typeOrderLevel(a, b Datatype, level int) int {
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
	// TypePointer::compare: equal submeta/size pointers compare wordsize, then the
	// pointee recursively. Gosleigh's Pointer has no address-space field, so the
	// C++ spaceid tie-break is omitted (all pointers share the default data space
	// in this slice).
	pa, aok := a.(*Pointer)
	pb, bok := b.(*Pointer)
	if aok && bok {
		if pa.WordSize() != pb.WordSize() {
			if pa.WordSize() < pb.WordSize() {
				return -1
			}
			return 1
		}
		level--
		if level < 0 {
			return 0
		}
		if res := typeOrderLevel(pa.Pointee(), pb.Pointee(), level); res != 0 || !pa.IsPointerRel() || !pb.IsPointerRel() {
			return res
		}
		// C++ parity: TypePointerRel::compare prefers the formal version.
		if (pa.relStripped == nil) != (pb.relStripped == nil) {
			if pa.relStripped == nil {
				return -1
			}
			return 1
		}
		return 0
	}
	if a.Metatype() == TYPE_CODE && b.Metatype() == TYPE_CODE {
		return compareCode(a, b, level)
	}
	switch ta := a.(type) {
	case *Array: // C++ parity: TypeArray::compare
		tb, ok := b.(*Array)
		if !ok {
			return 0
		}
		if level--; level < 0 {
			return compareTypeID(a, b)
		}
		return typeOrderLevel(ta.Element(), tb.Element(), level)
	case *Struct: // C++ parity: TypeStruct::compare
		tb, ok := b.(*Struct)
		if !ok {
			return 0
		}
		return compareFieldLists(a, b, ta.fields, tb.fields, level, true)
	case *Union: // C++ parity: TypeUnion::compare
		tb, ok := b.(*Union)
		if !ok {
			return 0
		}
		return compareFieldLists(a, b, ta.fields, tb.fields, level, false)
	case *PartialUnion: // C++ parity: TypePartialUnion::compare
		tb, ok := b.(*PartialUnion)
		if !ok {
			return 0
		}
		if ta.offset != tb.offset {
			if ta.offset < tb.offset {
				return -1
			}
			return 1
		}
		if level--; level < 0 {
			return compareTypeID(a, b)
		}
		return typeOrderLevel(ta.container, tb.container, level)
	case *Enum: // C++ parity: TypeEnum::compare (compareDependency)
		tb, ok := b.(*Enum)
		if !ok {
			return 0
		}
		if len(ta.values) != len(tb.values) {
			if len(ta.values) < len(tb.values) {
				return -1
			}
			return 1
		}
		ka, kb := sortedEnumKeys(ta.values), sortedEnumKeys(tb.values)
		for i := range ka {
			if ka[i] != kb[i] {
				if ka[i] < kb[i] {
					return -1
				}
				return 1
			}
			if na, nb := ta.values[ka[i]], tb.values[kb[i]]; na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

// codeProtoOf is the prototype a function data-type carries: a host
// function type's, or a Code built with parameters, nil for plain code.
func codeProtoOf(dt Datatype) *HostFunction {
	if hf := sharedTypeFactory.codeProto(dt); hf != nil {
		return hf
	}
	c, ok := dt.(*Code)
	if !ok || !c.HasPrototype() {
		return nil
	}
	hf := &HostFunction{Dotdotdot: c.variadic}
	for _, p := range c.params {
		hf.Params = append(hf.Params, HostParam{Type: p})
	}
	if c.returnType != nil {
		hf.Output = &HostParam{Type: c.returnType}
	}
	return hf
}

// compareCode orders two function data-types: one with a prototype comes
// first, then by model, parameter count, flags, parameter and return types.
// C++ parity: TypeCode::compare / TypeCode::compareBasic.
func compareCode(a, b Datatype, level int) int {
	pa, pb := codeProtoOf(a), codeProtoOf(b)
	switch {
	case pa == nil && pb == nil:
		return 0
	case pa == nil:
		return 1
	case pb == nil:
		return -1
	}
	if (pa.Model == "") != (pb.Model == "") {
		if pa.Model == "" {
			return 1
		}
		return -1
	}
	if pa.Model != pb.Model {
		if pa.Model < pb.Model {
			return -1
		}
		return 1
	}
	if len(pa.Params) != len(pb.Params) {
		if len(pb.Params) < len(pa.Params) {
			return -1
		}
		return 1
	}
	if pa.Dotdotdot != pb.Dotdotdot { // getComparableFlags (dotdotdot)
		if !pa.Dotdotdot {
			return -1
		}
		return 1
	}
	if level--; level < 0 {
		return compareTypeID(a, b)
	}
	for i := range pa.Params {
		if c := typeOrderLevel(pa.Params[i].Type, pb.Params[i].Type, level); c != 0 {
			return c
		}
	}
	var oa, ob Datatype
	if pa.Output != nil {
		oa = pa.Output.Type
	}
	if pb.Output != nil {
		ob = pb.Output.Type
	}
	switch {
	case oa == nil && ob == nil:
		return 0
	case oa == nil:
		return 1
	case ob == nil:
		return -1
	}
	return typeOrderLevel(oa, ob, level)
}

// compareTypeID is the last tie-break between two equal-looking data-types.
func compareTypeID(a, b Datatype) int {
	if a.ID() == b.ID() {
		return 0
	}
	if a.ID() < b.ID() {
		return -1
	}
	return 1
}

// compareFieldLists orders two structures (byOffset) or unions by their
// fields: count (more fields first), then each field's offset (structures
// only), name and metatype, then the field types themselves.
// C++ parity: TypeStruct::compare (TypeField::compare) / TypeUnion::compare.
func compareFieldLists(a, b Datatype, fa, fb []TypeField, level int, byOffset bool) int {
	if len(fa) != len(fb) {
		return len(fb) - len(fa)
	}
	for i := range fa {
		if byOffset && fa[i].Offset != fb[i].Offset {
			if fa[i].Offset < fb[i].Offset {
				return -1
			}
			return 1
		}
		if fa[i].Name != fb[i].Name {
			if fa[i].Name < fb[i].Name {
				return -1
			}
			return 1
		}
		ma, mb := metatypeOf(fa[i].Type), metatypeOf(fb[i].Type)
		if ma != mb {
			if ma < mb {
				return -1
			}
			return 1
		}
	}
	if level--; level < 0 {
		return compareTypeID(a, b)
	}
	// Still equal: go down into each field type
	for i := range fa {
		if fa[i].Type != fb[i].Type && fa[i].Type != nil && fb[i].Type != nil { // Short circuit recursive loops
			if c := typeOrderLevel(fa[i].Type, fb[i].Type, level); c != 0 {
				return c
			}
		}
	}
	return 0
}

func metatypeOf(dt Datatype) metatype {
	if dt == nil {
		return TYPE_UNKNOWN
	}
	return dt.Metatype()
}

func sortedEnumKeys(m map[uint64]string) []uint64 {
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
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
