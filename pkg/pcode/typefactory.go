package pcode

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// TypeFactory interns structurally identical data-types into canonical instances.
type TypeFactory struct {
	mu     sync.Mutex
	intern map[string]Datatype
}

func NewTypeFactory() *TypeFactory {
	return &TypeFactory{
		intern: make(map[string]Datatype),
	}
}

func (f *TypeFactory) Intern(dt Datatype) Datatype {
	if dt == nil {
		return nil
	}

	switch typed := dt.(type) {
	case *Base:
		return f.GetBase(typed.Size(), typed.Metatype(), typed.Name())
	case *Void:
		return f.GetVoid()
	case *Pointer:
		return f.GetPointer(typed.Size(), typed.Pointee(), typed.WordSize())
	case *PointerRel:
		return f.GetPointerRel(typed.Size(), typed.Pointee(), typed.WordSize(), typed.Parent(), typed.ByteOffset())
	case *Array:
		return f.GetArray(typed.Count(), typed.Element())
	case *Struct:
		return f.GetStruct(typed.Name(), typed.Fields())
	case *Union:
		return f.GetUnion(typed.Name(), typed.Fields())
	case *Enum:
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

func (f *TypeFactory) GetBase(size int32, meta metatype, name string) *Base {
	value := NewBase(size, meta, name)
	key := fmt.Sprintf("base:%d:%d:%s", value.Size(), value.Metatype(), value.Name())
	return f.internBase(key, value)
}

func (f *TypeFactory) GetVoid() *Void {
	value := NewVoid()
	return f.internVoid("void", value)
}

func (f *TypeFactory) GetPointer(size int32, to Datatype, wordSize uint32) *Pointer {
	canonicalTo := f.Intern(to)
	value := NewPointer(size, canonicalTo, wordSize)
	key := fmt.Sprintf("ptr:%d:%d:%x", size, wordSize, datatypeIdentity(canonicalTo))
	return f.internPointer(key, value)
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

// GetPointerRel interns a relative pointer pointing into a larger container.
// C++ parity: TypeFactory::getTypePointerRel (type.hh declared; type.cc def).
func (f *TypeFactory) GetPointerRel(size int32, pointee Datatype, wordSize uint32, parent Datatype, offset int32) *PointerRel {
	canonicalTo := f.Intern(pointee)
	canonicalParent := f.Intern(parent)
	value := NewPointerRel(size, canonicalTo, wordSize, canonicalParent, offset)
	key := fmt.Sprintf("ptrrel:%d:%d:%d:%x:%x", size, wordSize, offset, datatypeIdentity(canonicalTo), datatypeIdentity(canonicalParent))
	return f.internPointerRel(key, value)
}

func (f *TypeFactory) internPointerRel(key string, value *PointerRel) *PointerRel {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.intern[key]; ok {
		return existing.(*PointerRel)
	}
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
		builder.WriteString(fmt.Sprintf("%d:%s:%x;", field.Offset, field.Name, datatypeIdentity(field.Type)))
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
