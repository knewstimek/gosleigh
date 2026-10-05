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
	Addr      address.Address
	Size      int32
	// Type is the symbol's data-type; nil means undefined of Size bytes.
	Type     Datatype
	Label    bool
	ReadOnly bool
}

// HostDataScope is implemented by a HostScope that also knows the program's
// global data symbols.
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
	// Typedef is the name of a typedef over this type ("" = none).
	Typedef string
	// Fields are a structure's members.
	Fields []HostFieldDesc
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

// ResolveHostType builds the Datatype a host description names.
// TODO known mismatch: host unions and enums resolve to an undefined blob of
// their size.
func ResolveHostType(d *HostTypeDesc) Datatype {
	if d == nil {
		return nil
	}
	tf := sharedTypeFactory
	// A typedef of a base type is that base under the typedef's name, which
	// is what prints (DWORD_PTR, MCIDEVICEID).
	// TODO known mismatch: typedefs of pointers/aggregates resolve to the
	// underlying type (TypeFactory::getTypedef not modeled).
	if d.Typedef != "" {
		under := *d
		under.Typedef = ""
		if b, ok := ResolveHostType(&under).(*Base); ok {
			return tf.GetTypedefBase(d.Typedef, b)
		}
		return ResolveHostType(&under)
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
	case "struct":
		var fields []TypeField
		for i, fd := range d.Fields {
			if ft := ResolveHostType(fd.Type); ft != nil {
				fields = append(fields, TypeField{Ident: int32(i), Offset: fd.Offset, Name: fd.Name, Type: ft})
			}
		}
		return tf.GetStructSized(d.Name, d.Size, fields)
	}
	if d.Char && d.Size == 1 {
		return tf.GetChar(d.Name)
	}
	if m, ok := hostMetatypes[d.Meta]; ok {
		return tf.GetBase(d.Size, m, d.Name)
	}
	return tf.GetBase(d.Size, TYPE_UNKNOWN, "")
}
