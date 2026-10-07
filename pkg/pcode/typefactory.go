package pcode

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"gosleigh/pkg/address"
)

// TypeFactory interns structurally identical data-types into canonical instances.
type TypeFactory struct {
	mu     sync.Mutex
	intern map[string]Datatype
	// canon holds every instance Intern has returned. Interning is
	// idempotent, so a canonical instance comes straight back instead of
	// rebuilding the key of its whole (possibly huge) structure graph.
	canon map[Datatype]struct{}
	// codeProtos are the prototypes of named function types.
	codeProtos map[Datatype]*HostFunction
}

func NewTypeFactory() *TypeFactory {
	return &TypeFactory{
		intern: make(map[string]Datatype),
		canon:  make(map[Datatype]struct{}),
	}
}

func (f *TypeFactory) Intern(dt Datatype) Datatype {
	if dt == nil {
		return nil
	}
	f.mu.Lock()
	_, ok := f.canon[dt]
	f.mu.Unlock()
	if ok {
		return dt
	}
	out := f.internSlow(dt)
	if out != nil {
		f.mu.Lock()
		f.canon[out] = struct{}{}
		f.mu.Unlock()
	}
	return out
}

func (f *TypeFactory) internSlow(dt Datatype) Datatype {
	switch typed := dt.(type) {
	case *Base:
		if typed.Flags()&datatypeTypedef != 0 {
			return typed
		}
		if (typed.SubMeta() == SUB_INT_CHAR || typed.SubMeta() == SUB_UINT_CHAR) && typed.Size() == 1 {
			return f.GetCharMeta(typed.Name(), typed.Metatype())
		}
		if typed.SubMeta() == SUB_INT_UNICODE || typed.SubMeta() == SUB_UINT_UNICODE {
			return f.GetUnicode(typed.Name(), typed.Size(), typed.Metatype())
		}
		return f.GetBase(typed.Size(), typed.Metatype(), typed.Name())
	case *Void:
		return f.GetVoid()
	case *Pointer:
		if typed.Flags()&datatypeTypedef != 0 || typed.IsPointerRel() {
			return typed
		}
		return f.GetPointer(typed.Size(), typed.Pointee(), typed.WordSize())
	case *Array:
		return f.GetArray(typed.Count(), typed.Element())
	case *PartialStruct, *PartialUnion:
		return typed
	case *Struct:
		if typed.Flags()&(datatypeTypedef|datatypeHostNamed) != 0 {
			return typed // A typedef or a host structure is its own identity
		}
		return f.GetStructSized(typed.Name(), typed.Size(), typed.Fields()) // keep a declared size beyond the fields (incomplete structs)
	case *Union:
		return f.GetUnion(typed.Name(), typed.Fields())
	case *Enum:
		if typed.parent != nil {
			return typed // A partial enumeration is interned by its parent
		}
		enumMeta := TYPE_ENUM_UINT
		if typed.SubMeta() == SUB_INT_ENUM {
			enumMeta = TYPE_ENUM_INT
		}
		return f.GetEnum(typed.Size(), enumMeta, typed.Name(), typed.Values())
	case *Code:
		return f.GetCode(typed.Name(), typed.ReturnType(), typed.ParameterTypes(), typed.IsVariadic())
	default:
		panic(fmt.Sprintf("unsupported datatype %T", dt))
	}
}

func (f *TypeFactory) GetBase(size int32, meta metatype, name string) Datatype {
	if size == 1 && meta == TYPE_INT && (name == "" || name == "int" || name == "char") {
		// C++ parity: TypeFactory::cacheCoreTypes -- the ASCII char is the
		// preferred size-1 TYPE_INT, so getBase(1,TYPE_INT) yields char.
		return f.GetChar("char")
	}
	// A value wider than any base type is an array of unknown bytes
	// (undefined1 [16] for an XMM register); a float keeps its core type.
	// Explicit host names are not generic and stay as named.
	// C++ parity: TypeFactory::getBase (max_basetype_size = 10).
	if size > maxBasetypeSize && meta != TYPE_FLOAT && isGenericBaseName(name, size) {
		return f.GetArray(size, f.GetBase(1, TYPE_UNKNOWN, ""))
	}
	if meta == TYPE_FLOAT {
		name = coreFloatName(name, size)
	}
	key := fmt.Sprintf("base:%d:%d:%s", size, meta, name)
	if core, ok := coreBaseName(size, meta, name); ok {
		// An unnamed request and every alias of the core type's name are one
		// cache slot: getBase(4,TYPE_INT) is the "int" core type, so values
		// typed through either spelling share the identical data-type. The
		// unnamed spelling keeps the empty display name it always printed by.
		// C++ parity: TypeFactory::getBase (typecache[size][meta]).
		key = fmt.Sprintf("base:%d:%d:core", size, meta)
		name = ""
		value := NewBase(size, meta, name)
		value.name = core
		value.alignSize = primitiveAlignSize(size)
		value.alignment = primitiveAlignment(value.alignSize)
		return f.internBase(key, value)
	}
	value := NewBase(size, meta, name)
	value.alignSize = primitiveAlignSize(size)
	value.alignment = primitiveAlignment(value.alignSize)
	return f.internBase(key, value)
}

// getSpelling returns a base type that only carries a declaration spelling of
// a core slot (long on LP64); it never takes part in typing.
// C++ parity: on LP64 cacheCoreTypes fills the 8-byte slot with "long".
func (f *TypeFactory) getSpelling(size int32, meta metatype, name string) Datatype {
	value := NewBase(size, meta, name)
	value.alignSize = primitiveAlignSize(size)
	value.alignment = primitiveAlignment(value.alignSize)
	out := f.internBase(fmt.Sprintf("spell:%d:%d:%s", size, meta, name), value)
	f.mu.Lock()
	f.canon[out] = struct{}{} // Intern keeps it rather than folding it into the core slot
	f.mu.Unlock()
	return out
}

// coreBaseName reports whether name ("" for unnamed) spells the core type in
// the (size, meta) cache slot, and the name that type carries. The 8-byte
// slot holds one core type whichever of long/longlong/int it is asked by, so
// every 8-byte integer (and every pointer to one) is the same data-type.
// Its stored name is "longlong"/"ulonglong"; the declaration spelling
// (long on LP64) is chosen by normalizedBaseType from the model's long size.
// C++ parity: TypeFactory::getBase (typecache[8][meta] from cacheCoreTypes).
func coreBaseName(size int32, meta metatype, name string) (string, bool) {
	var names []string
	switch meta {
	case TYPE_INT:
		switch size {
		case 2:
			names = []string{"short"}
		case 4:
			names = []string{"int"}
		case 8:
			names = []string{"longlong", "long", "int"}
		}
	case TYPE_UINT:
		switch size {
		case 1:
			names = []string{"byte"}
		case 2:
			names = []string{"ushort"}
		case 4:
			names = []string{"uint"}
		case 8:
			names = []string{"ulonglong", "ulong", "uint"}
		}
	case TYPE_UNKNOWN:
		if size >= 1 && size <= 8 {
			names = []string{fmt.Sprintf("undefined%d", size), "unknown"}
		}
	case TYPE_BOOL:
		if size == 1 {
			names = []string{"bool"}
		}
	}
	if len(names) == 0 {
		return "", false
	}
	if name == "" {
		return names[0], true
	}
	for _, n := range names {
		if n == name {
			return names[0], true
		}
	}
	return "", false
}

// primitiveAlignMap is the alignment of a primitive by size. The x86 cspecs'
// size_alignment_map (1,2,4,8) decodes to the same table as the default.
// C++ parity: TypeFactory::setDefaultAlignmentMap / decodeAlignmentMap.
// Known mismatch: the map is not read from the cspec.
var primitiveAlignMap = [...]int32{1, 1, 2, 2, 4, 4, 4, 4, 8}

// primitiveAlignment is the expected alignment of a primitive of the given
// aligned size. C++ parity: TypeFactory::getAlignment.
func primitiveAlignment(size int32) int32 {
	if size < 0 || int(size) >= len(primitiveAlignMap) {
		return primitiveAlignMap[len(primitiveAlignMap)-1]
	}
	return primitiveAlignMap[size]
}

// primitiveAlignSize is the room a primitive takes in memory (sizeof).
// C++ parity: TypeFactory::getPrimitiveAlignSize.
func primitiveAlignSize(size int32) int32 {
	if size <= 0 {
		return size
	}
	align := primitiveAlignment(size)
	if mod := size % align; mod != 0 {
		size += align - mod
	}
	return size
}

// maxBasetypeSize is the widest base data-type. C++ parity:
// Architecture::max_basetype_size.
const maxBasetypeSize = 10

// isGenericBaseName reports whether name is one TypeFactory itself would
// give a base of this size (no host-supplied name).
// coreFloatName is the core floating-point type of a size, which a generic
// float request resolves to (float/8 is double). Other names stay.
// C++ parity: TypeFactory::getBase looks the core type up by size and
// metatype (cacheCoreTypes).
func coreFloatName(name string, size int32) string {
	switch name {
	case "", "float", "double", "float2", "float10", "float16", "unknown", fmt.Sprintf("undefined%d", size):
	default:
		return name
	}
	switch size {
	case 2:
		return "float2"
	case 4:
		return "float"
	case 8:
		return "double"
	case 10:
		return "float10"
	case 16:
		return "float16"
	}
	return name
}

func isGenericBaseName(name string, size int32) bool {
	switch name {
	case "", "unknown", "int", "uint", "bool", fmt.Sprintf("undefined%d", size), fmt.Sprintf("int%d", size), fmt.Sprintf("uint%d", size):
		return true
	}
	return false
}

// GetTypedefBase returns base under a typedef name. It prints by that name.
// C++ parity: TypeFactory::getTypedef (base types only).
// GetTypedefPointer returns pointer p under a typedef name (LPCWSTR); it
// behaves as the pointer and prints by its name.
// C++ parity: TypeFactory::getTypedef over a TypePointer.
func (f *TypeFactory) GetTypedefPointer(name string, p *Pointer) *Pointer {
	key := "typedefptr:" + name
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*Pointer); ok {
		return v
	}
	value := *p
	value.datatypeBase.name = name
	value.datatypeBase.flags |= datatypeTypedef
	value.datatypeBase.typedefOf = p
	f.intern[key] = &value
	return &value
}

// GetTypedefStruct returns structure s under a typedef name (RECT over
// tagRECT): same layout, printed by the typedef's name.
// C++ parity: TypeFactory::getTypedef over a TypeStruct.
func (f *TypeFactory) GetTypedefStruct(name string, s *Struct) *Struct {
	key := "typedefstruct:" + name
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*Struct); ok {
		return v
	}
	value := *s
	value.datatypeBase.name = name
	value.datatypeBase.flags |= datatypeTypedef
	value.datatypeBase.typedefOf = s
	f.intern[key] = &value
	return &value
}

// GetTypedefUnion returns a typedef of union u: the same union under the
// typedef's name. C++ parity: TypeFactory::getTypedef (decodeTypedef).
func (f *TypeFactory) GetTypedefUnion(name string, u *Union) *Union {
	key := "typedefunion:" + name
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*Union); ok {
		return v
	}
	value := *u
	value.datatypeBase.name = name
	value.datatypeBase.flags |= datatypeTypedef
	value.datatypeBase.typedefOf = u
	f.intern[key] = &value
	return &value
}

// GetPartialStruct returns the piece of size bytes at offset of container.
// C++ parity: TypeFactory::getTypePartialStruct.
func (f *TypeFactory) GetPartialStruct(container Datatype, offset int64, size int32) *PartialStruct {
	if p, ok := container.(*PartialStruct); ok {
		container = p.container
		offset += p.offset
	}
	stripped := f.GetBase(size, TYPE_UNKNOWN, "")
	key := fmt.Sprintf("partialstruct:%p:%d:%d", container, offset, size)
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*PartialStruct); ok {
		return v
	}
	base := newDatatypeBase(size, 1, TYPE_PARTIALSTRUCT, stripped.Name())
	base.submeta = SUB_PARTIALSTRUCT
	v := &PartialStruct{datatypeBase: base, container: container, offset: offset, stripped: stripped}
	f.intern[key] = v
	return v
}

// setCodeProto attaches the prototype of a named function type.
// C++ parity: TypeCode::setPrototype.
func (f *TypeFactory) setCodeProto(code Datatype, proto *HostFunction) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codeProtos == nil {
		f.codeProtos = make(map[Datatype]*HostFunction)
	}
	f.codeProtos[code] = proto
}

// codeProto is the prototype a function type carries, or nil.
// C++ parity: TypeCode::getPrototype.
func (f *TypeFactory) codeProto(code Datatype) *HostFunction {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codeProtos[code]
}

// GetPartialEnum returns the piece of size bytes at offset of enumeration
// parent. C++ parity: TypeFactory::getTypePartialEnum.
func (f *TypeFactory) GetPartialEnum(parent *Enum, offset int64, size int32) *Enum {
	stripped := f.GetBase(size, TYPE_UNKNOWN, "")
	key := fmt.Sprintf("partialenum:%p:%d:%d", parent, offset, size)
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*Enum); ok {
		return v
	}
	// The sub-metatype marks the piece; the metatype is TYPE_UINT, as for
	// every enumeration not built signed. C++ parity: TypePartialEnum ->
	// TypeEnum(sz, TYPE_PARTIALENUM) (metatype = TYPE_UINT).
	base := newDatatypeBase(size, 1, TYPE_UINT, stripped.Name())
	base.submeta = subMetaForMetatype(TYPE_PARTIALENUM)
	base.flags |= datatypeEnumType
	v := &Enum{datatypeBase: base, parent: parent, offset: offset, stripped: stripped}
	f.intern[key] = v
	return v
}

// GetPartialUnion returns the piece of size bytes at offset of container.
// C++ parity: TypeFactory::getTypePartialUnion.
func (f *TypeFactory) GetPartialUnion(container *Union, offset int64, size int32) *PartialUnion {
	stripped := f.GetBase(size, TYPE_UNKNOWN, "")
	key := fmt.Sprintf("partialunion:%p:%d:%d", container, offset, size)
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*PartialUnion); ok {
		return v
	}
	base := newDatatypeBase(size, 1, TYPE_PARTIALUNION, stripped.Name())
	base.submeta = SUB_PARTIALUNION
	base.flags |= datatypeNeedsResolution
	v := &PartialUnion{datatypeBase: base, container: container, offset: offset, stripped: stripped}
	f.intern[key] = v
	return v
}

func (f *TypeFactory) GetTypedefBase(name string, base *Base) *Base {
	value := NewBase(base.Size(), base.Metatype(), name)
	value.submeta = base.SubMeta()
	value.flags |= datatypeTypedef
	value.typedefOf = base
	return f.internBase("typedef:"+name, value)
}

// GetUnicode returns a wide character type (prints as L'c').
// C++ parity: TypeUnicode (utf16/utf32 flags, SUB_*_UNICODE).
func (f *TypeFactory) GetUnicode(name string, size int32, meta metatype) *Base {
	value := NewBase(size, meta, name)
	value.submeta = SUB_INT_UNICODE
	if meta == TYPE_UINT {
		value.submeta = SUB_UINT_UNICODE
	}
	return f.internBase("unicode:"+name, value)
}

// GetChar returns the 1-byte character type (prints as a character / string).
// C++ parity: TypeChar (TypeBase(1,TYPE_INT) with submeta SUB_INT_CHAR).
func (f *TypeFactory) GetChar(name string) *Base {
	return f.GetCharMeta(name, TYPE_INT)
}

// GetCharMeta returns a 1-byte character type of the given signedness: an
// unsigned host char (uchar) is TYPE_UINT with SUB_UINT_CHAR.
// C++ parity: TypeChar::decode.
func (f *TypeFactory) GetCharMeta(name string, meta metatype) *Base {
	sub, key := SUB_INT_CHAR, "char:"
	if meta == TYPE_UINT {
		sub, key = SUB_UINT_CHAR, "uchar:"
	} else {
		meta = TYPE_INT
	}
	value := NewBase(1, meta, name)
	value.submeta = sub
	return f.internBase(key+name, value)
}

// GetStructSized returns a named structure of an explicit size (a host
// type: its size is authoritative even with no or partial fields).
// C++ parity: TypeStruct decoded from the host's <type metatype="struct">.
func (f *TypeFactory) GetStructSized(name string, size int32, fields []TypeField) *Struct {
	canonicalFields := f.internFields(fields)
	value := NewStruct(name, canonicalFields)
	if size > value.size {
		value.size = size
		value.alignSize = calcAlignSize(size, value.alignment)
	}
	key := fmt.Sprintf("struct:%s:%d:%s", name, size, fieldsKey(canonicalFields))
	return f.internStruct(key, value)
}

func (f *TypeFactory) GetVoid() *Void {
	value := NewVoid()
	return f.internVoid("void", value)
}

// GetTypeSpacebase returns the synthetic spacebase data-type for the given
// address space. The C++ TypeFactory builds a dedicated TypeSpacebase that
// carries the AddrSpace pointer and a function-scope address. Gosleigh does
// not yet model TypeSpacebase as a distinct datatype class, so we return a
// shared Base type carrying TYPE_SPACEBASE / SUB_SPACEBASE; callers wrap it
// in a Pointer (via GetPointer) for the same downstream behavior.
// C++ parity: type.cc TypeFactory::getTypeSpacebase ~L4413
// TODO known mismatch: function-scope address (the second C++ argument) is
// dropped; once a TypeSpacebase class lands the (space, scope_addr) tuple
// will key the intern map.
func (f *TypeFactory) GetTypeSpacebase(_ *address.Space) Datatype {
	// Size 0 matches the C++ TypeSpacebase, which is Datatype(0,1,TYPE_SPACEBASE)
	// -- size and therefore alignSize are 0. The wrapping Pointer carries the
	// real width. The size matters: TypeOpIntAdd::propagateAddPointer and
	// AddTreeState both branch on getPtrTo()->getAlignSize(), and a size-1
	// stand-in makes the frame look like a byte array (AddTreeState's
	// isDegenerate path, which emits PTRADD(sp,x,1) instead of the
	// PTRSUB(sp,off)+PTRADD(.,i,elem) pair C++ builds).
	return f.GetBase(0, TYPE_SPACEBASE, "spacebase")
}

func (f *TypeFactory) GetPointer(size int32, to Datatype, wordSize uint32) *Pointer {
	canonicalTo := f.Intern(to)
	value := NewPointer(size, canonicalTo, wordSize)
	key := fmt.Sprintf("ptr:%d:%d:%x", size, wordSize, datatypeIdentity(canonicalTo))
	return f.internPointer(key, value)
}

// GetPointerStripArray creates a pointer to pt, stripping an outer array so the
// result points at the array element data-type. Used when a spacebase constant
// is retyped onto the pointed-to symbol's data-type.
// C++ parity: type.cc TypeFactory::getTypePointerStripArray (L4270-4281). The
// getStripped() typedef step is not modelled (Gosleigh has no typedef layer).
func (f *TypeFactory) GetPointerStripArray(size int32, pt Datatype, wordSize uint32) *Pointer {
	if arr, ok := pt.(*Array); ok && arr.Element() != nil {
		pt = arr.Element() // Strip the first ARRAY type
	}
	return f.GetPointer(size, pt, wordSize)
}

func (f *TypeFactory) GetArray(count int32, elem Datatype) *Array {
	canonicalElem := f.Intern(elem)
	value := NewArray(count, canonicalElem)
	key := fmt.Sprintf("array:%d:%x", count, datatypeIdentity(canonicalElem))
	return f.internArray(key, value)
}

func (f *TypeFactory) GetStruct(name string, fields []TypeField) *Struct {
	canonicalFields := f.internFields(fields)
	value := NewStruct(name, canonicalFields)
	key := "struct:" + name + ":" + fieldsKey(canonicalFields)
	return f.internStruct(key, value)
}

// NewBitfieldTypeField constructs a TypeField describing a bitfield member.
// C++ parity: the TypeStruct decoder in type.cc (decodeStructure ~L2360) sets
// the bitfield marker while parsing <field> elements that carry a bit offset
// and bit size. Gosleigh's .sla / XML decoder for composites is still pending,
// so this helper is the programmatic surrogate -- callers that build struct
// types from code (tests, host integrators) route bitfield members through
// it so the downstream Struct.HasBitfields check lights up.
// logicalType is the containing integer type, byteOffset is the offset of the
// underlying byte run inside the struct, bitOffset is the least significant
// bit of the field within that run, and bitSize is the field width.
func NewBitfieldTypeField(ident int32, byteOffset int32, name string, logicalType Datatype, bitOffset, bitSize int32) TypeField {
	return TypeField{
		Ident:      ident,
		Offset:     byteOffset,
		Name:       name,
		Type:       logicalType,
		BitOffset:  bitOffset,
		BitSize:    bitSize,
		IsBitfield: true,
	}
}

// GetBitfieldStruct is the typefactory entry point for composite types that
// contain one or more bitfield members. It is the Go-level counterpart of the
// C++ TypeFactory::decodeStructure branch that folds a TypeBitField side
// table into the containing TypeStruct (see type.cc L2383 where the
// has_bitfields flag is promoted). Because the Go type model stores bitfield
// metadata inline on TypeField rather than in a parallel TypeBitField list,
// the bitfield path shares GetStruct internment exactly, and the bitfield
// descriptor (IsBitfield/BitOffset/BitSize) is part of the intern key via
// fieldsKey. Callers must tag bitfield members with IsBitfield=true (use
// NewBitfieldTypeField) before handing them to this function -- otherwise
// Struct.HasBitfields will report false and the BitField rules will skip
// the struct.
// C++ parity: TypeFactory::decodeStructure + TypeStruct::decodeBitField
// (type.cc ~L2127) plus the has_bitfields promotion in
// TypeStruct::assignFieldOffsets.
func (f *TypeFactory) GetBitfieldStruct(name string, fields []TypeField) *Struct {
	return f.GetStruct(name, fields)
}

func (f *TypeFactory) GetUnion(name string, fields []TypeField) *Union {
	canonicalFields := f.internFields(fields)
	value := NewUnion(name, canonicalFields)
	key := "union:" + name + ":" + fieldsKey(canonicalFields)
	return f.internUnion(key, value)
}

func (f *TypeFactory) GetEnum(size int32, enumMeta metatype, name string, values map[uint64]string) *Enum {
	value := NewEnum(size, enumMeta, name, values)
	key := fmt.Sprintf("enum:%d:%d:%s:%s", size, enumMeta, name, enumValuesKey(value.Values()))
	return f.internEnum(key, value)
}

// GetPointerTo is a convenience wrapper around GetPointer for the common case
// where wordSize defaults to 1. ptrSize is the byte-width of the pointer itself.
func (f *TypeFactory) GetPointerTo(pointee Datatype, ptrSize int32) *Pointer {
	return f.GetPointer(ptrSize, pointee, 1)
}

// GetPointerRelEphemeral returns the ephemeral relative pointer to ptrTo at
// byte offset off inside the container parentPtr points to. It propagates
// like a pointer into the container but declares as a plain pointer.
// C++ parity: TypeFactory::getTypePointerRel(TypePointer*,Datatype*,int4)
// with TypePointerRel::markEphemeral.
func (f *TypeFactory) GetPointerRelEphemeral(parentPtr *Pointer, ptrTo Datatype, off int32) *Pointer {
	size, ws, parent := parentPtr.Size(), parentPtr.WordSize(), parentPtr.Pointee()
	stripped := f.GetPointer(size, ptrTo, ws)
	key := fmt.Sprintf("ptrrel-eph:%d:%d:%d:%x:%x", size, ws, off, datatypeIdentity(ptrTo), datatypeIdentity(parent))
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*Pointer); ok {
		return v
	}
	value := NewPointer(size, ptrTo, ws)
	value.submeta = SUB_PTRREL
	if ptrTo.Metatype() == TYPE_UNKNOWN {
		value.submeta = SUB_PTRREL_UNK // propagates differently from a formal one
	}
	value.relParent = parent
	value.relOffset = off
	value.relStripped = stripped
	f.intern[key] = value
	return value
}

// GetExactType returns the interned Base type with the given size and metatype.
// Only TYPE_INT, TYPE_UINT, TYPE_BOOL, and TYPE_UNKNOWN are meaningful here.
// Returns nil for unsupported metatypes or zero size.
func (f *TypeFactory) GetExactType(size int32, meta metatype) Datatype {
	if size <= 0 {
		return nil
	}
	var name string
	switch meta {
	case TYPE_INT:
		name = "int"
	case TYPE_UINT:
		name = "uint"
	case TYPE_BOOL:
		name = "bool"
	case TYPE_UNKNOWN:
		name = "unknown"
	default:
		return nil
	}
	return f.GetBase(size, meta, name)
}

func (f *TypeFactory) GetCode(name string, returnType Datatype, params []Datatype, variadic bool) *Code {
	var canonicalReturn Datatype
	if returnType != nil {
		canonicalReturn = f.Intern(returnType)
	}
	canonicalParams := make([]Datatype, len(params))
	for i, param := range params {
		canonicalParams[i] = f.Intern(param)
	}
	value := NewCode(name, canonicalReturn, canonicalParams, variadic)
	key := fmt.Sprintf("code:%s:%t:%x:%s", name, variadic, datatypeIdentity(canonicalReturn), paramKey(canonicalParams))
	return f.internCode(key, value)
}

func (f *TypeFactory) internFields(fields []TypeField) []TypeField {
	if len(fields) == 0 {
		return nil
	}
	out := make([]TypeField, len(fields))
	for i, field := range fields {
		out[i] = field
		if field.Type != nil {
			out[i].Type = f.Intern(field.Type)
		}
	}
	return out
}

func (f *TypeFactory) internBase(key string, value *Base) *Base {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Base)
	}
	f.intern[key] = value
	return value
}

func (f *TypeFactory) internVoid(key string, value *Void) *Void {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Void)
	}
	f.intern[key] = value
	return value
}

func (f *TypeFactory) internPointer(key string, value *Pointer) *Pointer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Pointer)
	}
	f.intern[key] = value
	return value
}

func (f *TypeFactory) internArray(key string, value *Array) *Array {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Array)
	}
	f.intern[key] = value
	return value
}

func (f *TypeFactory) internStruct(key string, value *Struct) *Struct {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Struct)
	}
	f.intern[key] = value
	return value
}

func (f *TypeFactory) internUnion(key string, value *Union) *Union {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Union)
	}
	f.intern[key] = value
	return value
}

func (f *TypeFactory) internEnum(key string, value *Enum) *Enum {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Enum)
	}
	f.intern[key] = value
	return value
}

func (f *TypeFactory) internCode(key string, value *Code) *Code {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*Code)
	}
	f.intern[key] = value
	return value
}

func datatypeIdentity(dt Datatype) uintptr {
	if dt == nil {
		return 0
	}
	return reflect.ValueOf(dt).Pointer()
}

func fieldsKey(fields []TypeField) string {
	if len(fields) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, field := range fields {
		// Include the bitfield descriptor so two structs that only differ in
		// bit layout hash to distinct keys. Non-bitfield members encode the
		// zero descriptor ("|0|0|0") which is harmless.
		bit := byte('0')
		if field.IsBitfield {
			bit = '1'
		}
		builder.WriteString(fmt.Sprintf("%d:%s:%x|%c|%d|%d;",
			field.Offset, field.Name, datatypeIdentity(field.Type),
			bit, field.BitOffset, field.BitSize))
	}
	return builder.String()
}

func enumValuesKey(values map[uint64]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]uint64, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(fmt.Sprintf("%d=%s;", key, values[key]))
	}
	return builder.String()
}

func paramKey(params []Datatype) string {
	if len(params) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, param := range params {
		builder.WriteString(fmt.Sprintf("%x;", datatypeIdentity(param)))
	}
	return builder.String()
}

// exactPiece is the data-type of exactly size bytes at offset within ct, or
// nil when no component fits.
// The descent stops at the first component the range runs past, so a piece
// straddling two array elements is a partial of the array, not of the
// element where it starts.
// C++ parity: TypeFactory::getExactPiece.
func (f *TypeFactory) exactPiece(ct Datatype, offset int64, size int32) Datatype {
	var lastType Datatype
	var lastOff int64
	curOff := offset
	for ct != nil {
		if int64(ct.Size()) < int64(size)+curOff {
			break // Range is beyond end of current data-type
		}
		if ct.Size() == size {
			return ct // Perfect size match
		}
		if u, ok := ct.(*Union); ok {
			return f.GetPartialUnion(u, curOff, size)
		}
		lastType, lastOff = ct, curOff
		ct, curOff = datatypeSubType(ct, curOff)
	}
	if lastType != nil {
		// lastType is bigger than size
		switch lastType.Metatype() {
		case TYPE_STRUCT, TYPE_ARRAY, TYPE_PARTIALSTRUCT:
			return f.GetPartialStruct(lastType, lastOff, size)
		}
		if en, ok := lastType.(*Enum); ok && en.parent == nil {
			return f.GetPartialEnum(en, lastOff, size)
		}
	}
	return nil
}

// HostStructStub returns the structure the host knows by id, creating it
// empty the first time; created reports whether this call made it.
// C++ parity: TypeFactory::decodeStruct (findAdd of a stub before the fields,
// so a field may point back to the structure).
func (f *TypeFactory) HostStructStub(id, name string, size int32) (st *Struct, created bool) {
	key := "hoststruct:" + id
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.intern[key].(*Struct); ok {
		return v, false
	}
	st = NewStruct(name, nil)
	st.flags |= datatypeHostNamed
	st.size = size
	st.alignSize = calcAlignSize(size, st.alignment)
	f.intern[key] = st
	f.canon[st] = struct{}{}
	return st, true
}

// SetHostStructFields completes a stub from HostStructStub.
// C++ parity: TypeFactory::setFields.
func (f *TypeFactory) SetHostStructFields(st *Struct, fields []TypeField) {
	canonical := f.internFields(fields)
	full := NewStruct(st.name, canonical)
	size := st.size
	*st = *full
	st.flags |= datatypeHostNamed
	if size > st.size {
		st.size = size
	}
	st.alignSize = calcAlignSize(st.size, st.alignment)
}
