package pcode

import (
	"fmt"
	"sort"
	"strings"
)

// CDeclRenderer renders C type spellings and declarators directly from existing p-code datatypes.
type CDeclRenderer struct{}

func NewCDeclRenderer() *CDeclRenderer {
	return &CDeclRenderer{}
}

func CTypeString(dt Datatype) string {
	return NewCDeclRenderer().TypeString(dt)
}

func CDeclString(dt Datatype, name string) string {
	return NewCDeclRenderer().Declaration(dt, name)
}

func CVarDeclString(vn *Varnode, name string) string {
	return NewCDeclRenderer().VariableDeclaration(vn, name)
}

func CFuncSignatureString(name string, fn *Code, paramNames []string) string {
	return NewCDeclRenderer().FunctionSignature(name, fn, paramNames)
}

func CTypeDefinitionString(dt Datatype) string {
	return NewCDeclRenderer().TypeDefinition(dt)
}

func DefaultVarnodeName(vn *Varnode) string {
	return NewCDeclRenderer().VarnodeName(vn)
}

func (r *CDeclRenderer) TypeString(dt Datatype) string {
	return r.Declaration(dt, "")
}

func (r *CDeclRenderer) Declaration(dt Datatype, name string) string {
	spec, decl := r.renderDeclaration(dt, name)
	if decl == "" {
		return spec
	}
	if spec == "" {
		return decl
	}
	return spec + " " + decl
}

func (r *CDeclRenderer) VariableDeclaration(vn *Varnode, name string) string {
	if vn == nil {
		return r.Declaration(nil, name)
	}
	if name == "" {
		name = r.VarnodeName(vn)
	}
	return r.Declaration(vn.TypeDefFacing(), name)
}

func (r *CDeclRenderer) FunctionSignature(name string, fn *Code, paramNames []string) string {
	if fn == nil {
		return r.Declaration(nil, name)
	}
	return r.codeDeclaration(fn, name, paramNames)
}

func (r *CDeclRenderer) TypeDefinition(dt Datatype) string {
	switch typed := dt.(type) {
	case *Struct:
		return r.structDefinition(typed)
	case *Union:
		return r.unionDefinition(typed)
	case *Enum:
		return r.enumDefinition(typed)
	default:
		return ""
	}
}

func (r *CDeclRenderer) VarnodeName(vn *Varnode) string {
	if vn == nil {
		return "var_0"
	}
	if vn.Space() != nil {
		switch {
		case vn.Space().IsUnique():
			return fmt.Sprintf("tmp_%d", vn.CreateIndex())
		case vn.IsInput():
			return fmt.Sprintf("param_%d", vn.CreateIndex())
		default:
			return fmt.Sprintf("%s_%x", sanitizeIdentifier(vn.Space().Name), vn.Offset())
		}
	}
	return fmt.Sprintf("var_%d", vn.CreateIndex())
}

func (r *CDeclRenderer) renderDeclaration(dt Datatype, name string) (string, string) {
	if dt == nil {
		return "void", name
	}
	switch typed := dt.(type) {
	case *Pointer:
		inner := "*" + name
		if needsWrappedDeclarator(typed.Pointee()) {
			inner = "(" + inner + ")"
		}
		return r.renderDeclaration(typed.Pointee(), inner)
	case *Array:
		inner := name + fmt.Sprintf("[%d]", typed.Count())
		return r.renderDeclaration(typed.Element(), inner)
	case *Code:
		return r.renderCodeDeclaration(typed, name, nil)
	default:
		return r.typeSpecifier(dt), name
	}
}

func (r *CDeclRenderer) codeDeclaration(fn *Code, name string, paramNames []string) string {
	spec, decl := r.renderCodeDeclaration(fn, name, paramNames)
	if decl == "" {
		return spec
	}
	if spec == "" {
		return decl
	}
	return spec + " " + decl
}

func (r *CDeclRenderer) renderCodeDeclaration(fn *Code, name string, paramNames []string) (string, string) {
	returnType := Datatype(NewVoid())
	if fn != nil && fn.ReturnType() != nil {
		returnType = fn.ReturnType()
	}
	inner := nameWithParams(name, r.parameterList(fn, paramNames))
	return r.renderDeclaration(returnType, inner)
}

func needsWrappedDeclarator(dt Datatype) bool {
	switch dt.(type) {
	case *Array, *Code:
		return true
	default:
		return false
	}
}

func (r *CDeclRenderer) typeSpecifier(dt Datatype) string {
	if dt == nil {
		return "void"
	}
	switch typed := dt.(type) {
	case *Void:
		return "void"
	case *Base:
		return baseTypeName(typed)
	case *Struct:
		return r.structSpecifier(typed)
	case *Union:
		return r.unionSpecifier(typed)
	case *Enum:
		return r.enumSpecifier(typed)
	case *Pointer, *Array, *Code:
		spec, _ := r.renderDeclaration(dt, "")
		return spec
	default:
		if name := dt.DisplayName(); name != "" {
			return name
		}
		if name := dt.Name(); name != "" {
			return name
		}
		return fmt.Sprintf("undefined%d", dt.Size())
	}
}

func baseTypeName(dt Datatype) string {
	if dt == nil {
		return "void"
	}
	if name := dt.DisplayName(); name != "" {
		return name
	}
	if name := dt.Name(); name != "" {
		return name
	}
	switch dt.Metatype() {
	case TYPE_VOID:
		return "void"
	case TYPE_BOOL:
		return "bool"
	case TYPE_FLOAT:
		switch dt.Size() {
		case 4:
			return "float"
		case 8:
			return "double"
		default:
			return fmt.Sprintf("float%d", dt.Size()*8)
		}
	case TYPE_INT:
		return fmt.Sprintf("int%d_t", dt.Size()*8)
	case TYPE_UINT:
		return fmt.Sprintf("uint%d_t", dt.Size()*8)
	case TYPE_UNKNOWN:
		return fmt.Sprintf("undefined%d", dt.Size())
	default:
		return fmt.Sprintf("type_%d", dt.ID())
	}
}

func (r *CDeclRenderer) structSpecifier(dt *Struct) string {
	if dt == nil {
		return "struct"
	}
	if dt.Name() != "" {
		return "struct " + dt.Name()
	}
	return "struct { " + r.fieldList(dt.Fields()) + " }"
}

func (r *CDeclRenderer) unionSpecifier(dt *Union) string {
	if dt == nil {
		return "union"
	}
	if dt.Name() != "" {
		return "union " + dt.Name()
	}
	return "union { " + r.fieldList(dt.Fields()) + " }"
}

func (r *CDeclRenderer) enumSpecifier(dt *Enum) string {
	if dt == nil {
		return "enum"
	}
	if dt.Name() != "" {
		return "enum " + dt.Name()
	}
	return "enum { " + r.enumBody(dt) + " }"
}

func (r *CDeclRenderer) structDefinition(dt *Struct) string {
	if dt == nil {
		return "struct { }"
	}
	name := "struct"
	if dt.Name() != "" {
		name += " " + dt.Name()
	}
	return name + " { " + r.fieldList(dt.Fields()) + " }"
}

func (r *CDeclRenderer) unionDefinition(dt *Union) string {
	if dt == nil {
		return "union { }"
	}
	name := "union"
	if dt.Name() != "" {
		name += " " + dt.Name()
	}
	return name + " { " + r.fieldList(dt.Fields()) + " }"
}

func (r *CDeclRenderer) enumDefinition(dt *Enum) string {
	if dt == nil {
		return "enum { }"
	}
	name := "enum"
	if dt.Name() != "" {
		name += " " + dt.Name()
	}
	return name + " { " + r.enumBody(dt) + " }"
}

func (r *CDeclRenderer) fieldList(fields []TypeField) string {
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for i, field := range fields {
		fieldName := field.Name
		if fieldName == "" {
			fieldName = fmt.Sprintf("field_%d", i)
			if field.Offset != 0 {
				fieldName = fmt.Sprintf("field_%d", field.Offset)
			}
		}
		parts = append(parts, r.Declaration(field.Type, fieldName)+";")
	}
	return strings.Join(parts, " ")
}

func (r *CDeclRenderer) enumBody(dt *Enum) string {
	values := dt.Values()
	if len(values) == 0 {
		return ""
	}
	keys := make([]uint64, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s = %d", values[key], key))
	}
	return strings.Join(parts, ", ")
}

func (r *CDeclRenderer) parameterList(fn *Code, paramNames []string) string {
	if fn == nil {
		return "void"
	}
	params := fn.ParameterTypes()
	if len(params) == 0 && !fn.IsVariadic() {
		return "void"
	}
	parts := make([]string, 0, len(params)+1)
	named := len(paramNames) > 0
	for i, param := range params {
		name := ""
		if i < len(paramNames) {
			name = paramNames[i]
		}
		if name == "" && named {
			name = fmt.Sprintf("param%d", i)
		}
		parts = append(parts, r.Declaration(param, name))
	}
	if fn.IsVariadic() {
		parts = append(parts, "...")
	}
	if len(parts) == 0 {
		return "void"
	}
	return strings.Join(parts, ", ")
}

func nameWithParams(name string, params string) string {
	return name + "(" + params + ")"
}

func sanitizeIdentifier(text string) string {
	if text == "" {
		return "var"
	}
	var builder strings.Builder
	for i, r := range text {
		isAlpha := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		if isAlpha || r == '_' || (i > 0 && isDigit) {
			builder.WriteRune(r)
			continue
		}
		builder.WriteByte('_')
	}
	out := builder.String()
	if out == "" {
		return "var"
	}
	if out[0] >= '0' && out[0] <= '9' {
		return "_" + out
	}
	return out
}
