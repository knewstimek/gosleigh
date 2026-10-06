package pcode

import "gosleigh/pkg/address"

// HostData is a global symbol the host reports at an address: a data
// variable (DAT_..., a named global, a vftable) or a code label (LAB_...).
// C++ parity: the <mapsym> answers ScopeGhidra receives from Java
// DecompileCallback.getMappedSymbols (Symbol / LabSymbol in database.hh).
type HostData struct {
	Name string
	// Namespace is the "::"-joined namespace path; "" is the global namespace.
	Namespace string
	// NamespacePath is the same path one scope name per element, when the
	// host keeps the scopes apart (a scope name may itself contain "::").
	NamespacePath []string
	Addr      address.Address
	Size      int32
	// Type is the symbol's data-type; nil means undefined of Size bytes.
	Type     Datatype
	Label    bool
	ReadOnly bool
}

// HostDataScope is implemented by a HostScope that also knows the program's
// global data symbols.
// HostTypeWarnings is a host that reports the data-type warnings the core's
// TypeFactory collected while decoding the host's types (an enum whose values
// do not have unique names), in decoding order.
// C++ parity: TypeFactory::warnings (insertWarning at decode time).
type HostTypeWarnings interface {
	DatatypeWarnings() []string
}

type HostDataScope interface {
	// QueryData returns the symbol whose storage contains addr.
	QueryData(addr address.Address) (HostData, bool)
}

// HostTypeDesc is a host data-type description as the host encodes it
// (Ghidra <type>/<typeref> elements), resolved by ResolveHostType.
type HostTypeDesc struct {
	Name string
	// Meta is the Ghidra metatype name: "unknown", "int", "uint", "bool",
	// "float", "code", "void", "ptr", "array", "struct", "union", ...
	Meta  string
	Size  int32
	Count int32 // array element count
	Elem  *HostTypeDesc
	// Char marks a character type (Ghidra char="true").
	Char bool
	// Utf marks a wide character type (Ghidra utf="true").
	Utf bool
	// Typedef is the name of a typedef over this type ("" = none).
	Typedef string
	// Fields are a structure's members.
	Fields []HostFieldDesc
	// ID is the host's id of a named type: one structure per id, however
	// often it is referenced (and from itself).
	ID string
	// EnumValues are an enumeration's names by value (the first name of a
	// value wins). C++ parity: TypeEnum::decode.
	EnumValues map[uint64]string
}

// HostFieldDesc is one member of a host structure.
type HostFieldDesc struct {
	Name   string
	Offset int32
	Type   *HostTypeDesc
}

var hostMetatypes = map[string]metatype{
	"void": TYPE_VOID, "unknown": TYPE_UNKNOWN, "int": TYPE_INT, "uint": TYPE_UINT,
	"bool": TYPE_BOOL, "code": TYPE_CODE, "float": TYPE_FLOAT,
}

// unionsInProgress breaks a cycle through a host union's own fields.
var unionsInProgress = map[*HostTypeDesc]bool{}

// ResolveHostType builds the Datatype a host description names.
func ResolveHostType(d *HostTypeDesc) Datatype {
	if d == nil {
		return nil
	}
	tf := sharedTypeFactory
	// A typedef of a base type is that base under the typedef's name, which
	// is what prints (DWORD_PTR, MCIDEVICEID).
	// TODO known mismatch: typedefs of arrays, unions and enums resolve to the
	// underlying type.
	if d.Typedef != "" {
		under := *d
		under.Typedef = ""
		switch t := ResolveHostType(&under).(type) {
		case *Base:
			return tf.GetTypedefBase(d.Typedef, t)
		case *Pointer:
			return tf.GetTypedefPointer(d.Typedef, t)
		case *Struct:
			return tf.GetTypedefStruct(d.Typedef, t)
		case *Union:
			return tf.GetTypedefUnion(d.Typedef, t)
		default:
			return t
		}
	}
	switch d.Meta {
	case "ptr":
		elem := ResolveHostType(d.Elem)
		if elem == nil {
			elem = tf.GetBase(1, TYPE_UNKNOWN, "")
		}
		return tf.GetPointer(d.Size, elem, 1)
	case "array":
		elem := ResolveHostType(d.Elem)
		if elem == nil || d.Count <= 0 {
			return tf.GetBase(d.Size, TYPE_UNKNOWN, "")
		}
		return tf.GetArray(d.Count, elem)
	case "void":
		return tf.GetVoid()
	case "enum_uint", "enum_int":
		meta := TYPE_ENUM_UINT
		if d.Meta == "enum_int" {
			meta = TYPE_ENUM_INT
		}
		return tf.GetEnum(d.Size, meta, d.Name, d.EnumValues)
	case "struct":
		if d.ID != "" {
			st, created := tf.HostStructStub(d.ID, d.Name, d.Size)
			if created {
				var fields []TypeField
				for i, fd := range d.Fields {
					if ft := ResolveHostType(fd.Type); ft != nil {
						fields = append(fields, TypeField{Ident: int32(i), Offset: fd.Offset, Name: fd.Name, Type: ft})
					}
				}
				tf.SetHostStructFields(st, fields)
			}
			return st
		}
		var fields []TypeField
		for i, fd := range d.Fields {
			if ft := ResolveHostType(fd.Type); ft != nil {
				fields = append(fields, TypeField{Ident: int32(i), Offset: fd.Offset, Name: fd.Name, Type: ft})
			}
		}
		return tf.GetStructSized(d.Name, d.Size, fields)
	case "union":
		// C++ parity: TypeFactory::decodeUnion (fields all at offset 0).
		if unionsInProgress[d] {
			return tf.GetBase(d.Size, TYPE_UNKNOWN, "")
		}
		unionsInProgress[d] = true
		var fields []TypeField
		for i, fd := range d.Fields {
			if ft := ResolveHostType(fd.Type); ft != nil {
				fields = append(fields, TypeField{Ident: int32(i), Offset: fd.Offset, Name: fd.Name, Type: ft})
			}
		}
		delete(unionsInProgress, d)
		if len(fields) == 0 {
			return tf.GetBase(d.Size, TYPE_UNKNOWN, "")
		}
		u := tf.GetUnion(d.Name, fields)
		u.flags |= datatypeHostNamed
		return u
	}
	if d.Char && d.Size == 1 {
		meta := TYPE_INT
		if d.Meta == "uint" {
			meta = TYPE_UINT
		}
		return tf.GetCharMeta(d.Name, meta)
	}
	if d.Utf {
		meta := TYPE_INT
		if d.Meta == "uint" {
			meta = TYPE_UINT
		}
		return tf.GetUnicode(d.Name, d.Size, meta)
	}
	if m, ok := hostMetatypes[d.Meta]; ok {
		bt := tf.GetBase(d.Size, m, d.Name)
		// Base types intern by name, so an internally made type sharing the
		// name also prints it -- which is the core name anyway.
		if b, ok := bt.(*Base); ok && d.Name != "" && b.Name() == d.Name {
			b.flags |= datatypeHostNamed
		}
		return bt
	}
	return tf.GetBase(d.Size, TYPE_UNKNOWN, "")
}
