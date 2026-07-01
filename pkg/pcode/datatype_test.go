package pcode

import (
	"reflect"
	"testing"
)

func TestMetatypeParity(t *testing.T) {
	metaTests := []struct {
		name string
		got  metatype
		want metatype
	}{
		{"TYPE_VOID", TYPE_VOID, 17},
		{"TYPE_SPACEBASE", TYPE_SPACEBASE, 16},
		{"TYPE_UNKNOWN", TYPE_UNKNOWN, 15},
		{"TYPE_INT", TYPE_INT, 14},
		{"TYPE_UINT", TYPE_UINT, 13},
		{"TYPE_BOOL", TYPE_BOOL, 12},
		{"TYPE_CODE", TYPE_CODE, 11},
		{"TYPE_FLOAT", TYPE_FLOAT, 10},
		{"TYPE_PTR", TYPE_PTR, 9},
		{"TYPE_PTRREL", TYPE_PTRREL, 8},
		{"TYPE_ARRAY", TYPE_ARRAY, 7},
		{"TYPE_ENUM_UINT", TYPE_ENUM_UINT, 6},
		{"TYPE_ENUM_INT", TYPE_ENUM_INT, 5},
		{"TYPE_STRUCT", TYPE_STRUCT, 4},
		{"TYPE_UNION", TYPE_UNION, 3},
		{"TYPE_PARTIALENUM", TYPE_PARTIALENUM, 2},
		{"TYPE_PARTIALSTRUCT", TYPE_PARTIALSTRUCT, 1},
		{"TYPE_PARTIALUNION", TYPE_PARTIALUNION, 0},
	}
	for _, test := range metaTests {
		if test.got != test.want {
			t.Fatalf("%s = %d, want %d", test.name, test.got, test.want)
		}
	}

	subTests := []struct {
		name string
		got  subMetatype
		want subMetatype
	}{
		{"SUB_VOID", SUB_VOID, 23},
		{"SUB_SPACEBASE", SUB_SPACEBASE, 22},
		{"SUB_UNKNOWN", SUB_UNKNOWN, 21},
		{"SUB_PARTIALSTRUCT", SUB_PARTIALSTRUCT, 20},
		{"SUB_INT_CHAR", SUB_INT_CHAR, 19},
		{"SUB_UINT_CHAR", SUB_UINT_CHAR, 18},
		{"SUB_INT_PLAIN", SUB_INT_PLAIN, 17},
		{"SUB_UINT_PLAIN", SUB_UINT_PLAIN, 16},
		{"SUB_INT_ENUM", SUB_INT_ENUM, 15},
		{"SUB_UINT_PARTIALENUM", SUB_UINT_PARTIALENUM, 14},
		{"SUB_UINT_ENUM", SUB_UINT_ENUM, 13},
		{"SUB_INT_UNICODE", SUB_INT_UNICODE, 12},
		{"SUB_UINT_UNICODE", SUB_UINT_UNICODE, 11},
		{"SUB_BOOL", SUB_BOOL, 10},
		{"SUB_CODE", SUB_CODE, 9},
		{"SUB_FLOAT", SUB_FLOAT, 8},
		{"SUB_PTRREL_UNK", SUB_PTRREL_UNK, 7},
		{"SUB_PTR", SUB_PTR, 6},
		{"SUB_PTRREL", SUB_PTRREL, 5},
		{"SUB_PTR_STRUCT", SUB_PTR_STRUCT, 4},
		{"SUB_ARRAY", SUB_ARRAY, 3},
		{"SUB_STRUCT", SUB_STRUCT, 2},
		{"SUB_UNION", SUB_UNION, 1},
		{"SUB_PARTIALUNION", SUB_PARTIALUNION, 0},
	}
	for _, test := range subTests {
		if test.got != test.want {
			t.Fatalf("%s = %d, want %d", test.name, test.got, test.want)
		}
	}
}

func TestBaseToSubmetaMapping(t *testing.T) {
	tests := []struct {
		meta metatype
		want subMetatype
	}{
		{TYPE_PARTIALUNION, SUB_PARTIALUNION},
		{TYPE_PARTIALSTRUCT, SUB_PARTIALSTRUCT},
		{TYPE_PARTIALENUM, SUB_UINT_PARTIALENUM},
		{TYPE_UNION, SUB_UNION},
		{TYPE_STRUCT, SUB_STRUCT},
		{TYPE_ENUM_INT, SUB_INT_ENUM},
		{TYPE_ENUM_UINT, SUB_UINT_ENUM},
		{TYPE_ARRAY, SUB_ARRAY},
		{TYPE_PTRREL, SUB_PTRREL},
		{TYPE_PTR, SUB_PTR},
		{TYPE_FLOAT, SUB_FLOAT},
		{TYPE_CODE, SUB_CODE},
		{TYPE_BOOL, SUB_BOOL},
		{TYPE_UINT, SUB_UINT_PLAIN},
		{TYPE_INT, SUB_INT_PLAIN},
		{TYPE_UNKNOWN, SUB_UNKNOWN},
		{TYPE_SPACEBASE, SUB_SPACEBASE},
		{TYPE_VOID, SUB_VOID},
	}

	for _, test := range tests {
		if got := subMetaForMetatype(test.meta); got != test.want {
			t.Fatalf("subMetaForMetatype(%d) = %d, want %d", test.meta, got, test.want)
		}
	}
}

func TestDatatypeConstructorsAndMetadata(t *testing.T) {
	int4 := NewBase(4, TYPE_INT, "int4")
	if int4.Name() != "int4" || int4.DisplayName() != "int4" {
		t.Fatalf("base name/display mismatch: %q / %q", int4.Name(), int4.DisplayName())
	}
	if int4.Metatype() != TYPE_INT || int4.SubMeta() != SUB_INT_PLAIN {
		t.Fatalf("base meta/submeta mismatch: got %d/%d", int4.Metatype(), int4.SubMeta())
	}
	if int4.Size() != 4 || int4.AlignSize() != 4 {
		t.Fatalf("base size mismatch: size=%d alignSize=%d", int4.Size(), int4.AlignSize())
	}

	voidType := NewVoid()
	if !voidType.IsCoreType() || voidType.Name() != "void" || voidType.Size() != 0 {
		t.Fatalf("void metadata mismatch")
	}

	enumType := NewEnum(4, TYPE_ENUM_UINT, "color_t", map[uint64]string{1: "RED", 2: "GREEN"})
	if enumType.Metatype() != TYPE_UINT || enumType.SubMeta() != SUB_UINT_ENUM || !enumType.IsEnumType() {
		t.Fatalf("enum meta mismatch: got %d/%d", enumType.Metatype(), enumType.SubMeta())
	}
	if !enumType.HasNamedValue(1) || enumType.HasNamedValue(99) {
		t.Fatalf("enum named-value lookup mismatch")
	}

	arrayType := NewArray(3, int4)
	if arrayType.Count() != 3 || arrayType.Element() != int4 || arrayType.Size() != 12 {
		t.Fatalf("array metadata mismatch")
	}

	structType := NewStruct("pair_t", []TypeField{
		{Ident: 1, Offset: 0, Name: "left", Type: int4},
		{Ident: 2, Offset: 4, Name: "right", Type: int4},
	})
	if structType.Metatype() != TYPE_STRUCT || structType.SubMeta() != SUB_STRUCT {
		t.Fatalf("struct meta mismatch")
	}
	field, ok := structType.FieldAt(5)
	if !ok || field.Name != "right" {
		t.Fatalf("struct field lookup mismatch: %+v, %v", field, ok)
	}

	unionType := NewUnion("word_t", []TypeField{
		{Ident: 1, Offset: 0, Name: "asInt", Type: int4},
		{Ident: 2, Offset: 0, Name: "asEnum", Type: enumType},
	})
	if !unionType.NeedsResolution() || unionType.Size() != 4 {
		t.Fatalf("union metadata mismatch")
	}

	ptrToStruct := NewPointer(8, structType, 8)
	if ptrToStruct.Pointee() != structType || ptrToStruct.WordSize() != 8 {
		t.Fatalf("pointer metadata mismatch")
	}
	if ptrToStruct.SubMeta() != SUB_PTR_STRUCT {
		t.Fatalf("pointer submeta = %d, want %d", ptrToStruct.SubMeta(), SUB_PTR_STRUCT)
	}

	ptrToArray := NewPointer(8, arrayType, 8)
	if !ptrToArray.IsPointerToArray() {
		t.Fatalf("pointer-to-array flag not set")
	}

	codeType := NewCode("callable_t", int4, []Datatype{ptrToStruct, enumType}, true)
	if codeType.Metatype() != TYPE_CODE || codeType.SubMeta() != SUB_CODE {
		t.Fatalf("code meta mismatch")
	}
	if codeType.ReturnType() != int4 || !codeType.IsVariadic() {
		t.Fatalf("code signature mismatch")
	}
	if !reflect.DeepEqual(codeType.ParameterTypes(), []Datatype{ptrToStruct, enumType}) {
		t.Fatalf("code params mismatch")
	}
}

func TestCompositeBehaviorAndResolutionFlags(t *testing.T) {
	int4 := NewBase(4, TYPE_INT, "int4")

	oneField := NewStruct("wrapper_t", []TypeField{
		{Ident: 1, Offset: 0, Name: "value", Type: int4},
	})
	if !oneField.NeedsResolution() {
		t.Fatalf("single-field wrapper should need resolution")
	}

	incomplete := NewStruct("opaque_t", nil)
	if !incomplete.IsIncomplete() {
		t.Fatalf("empty struct should be incomplete")
	}

	arrayOne := NewArray(1, int4)
	if !arrayOne.NeedsResolution() {
		t.Fatalf("single-element array should need resolution")
	}

	unionType := NewUnion("alias_t", []TypeField{
		{Ident: 1, Offset: 0, Name: "raw", Type: int4},
		{Ident: 2, Offset: 0, Name: "signed", Type: int4},
	})
	if !unionType.NeedsResolution() {
		t.Fatalf("union should need resolution")
	}
}

func TestTypeFactoryInterning(t *testing.T) {
	factory := NewTypeFactory()

	intA := factory.GetBase(4, TYPE_INT, "int4")
	intB := factory.GetBase(4, TYPE_INT, "int4")
	if intA != intB {
		t.Fatalf("identical base types were not interned")
	}

	uInt := factory.GetBase(4, TYPE_UINT, "uint4")
	if intA == uInt {
		t.Fatalf("different primitive types should not alias")
	}

	ptrA := factory.GetPointer(8, intA, 8)
	ptrB := factory.GetPointer(8, intB, 8)
	if ptrA != ptrB {
		t.Fatalf("identical pointers were not interned")
	}

	arrayA := factory.GetArray(4, intA)
	arrayB := factory.GetArray(4, intB)
	if arrayA != arrayB {
		t.Fatalf("identical arrays were not interned")
	}

	structFields := []TypeField{
		{Ident: 1, Offset: 0, Name: "left", Type: intA},
		{Ident: 2, Offset: 4, Name: "right", Type: ptrA},
	}
	structA := factory.GetStruct("pair_t", structFields)
	structB := factory.GetStruct("pair_t", []TypeField{
		{Ident: 11, Offset: 0, Name: "left", Type: intB},
		{Ident: 22, Offset: 4, Name: "right", Type: ptrB},
	})
	if structA != structB {
		t.Fatalf("identical structs were not interned")
	}

	structC := factory.GetStruct("pair_t", []TypeField{
		{Ident: 1, Offset: 0, Name: "left", Type: intA},
		{Ident: 2, Offset: 4, Name: "different", Type: ptrA},
	})
	if structA == structC {
		t.Fatalf("different structs should not alias")
	}

	enumA := factory.GetEnum(4, TYPE_ENUM_UINT, "color_t", map[uint64]string{1: "RED", 2: "GREEN"})
	enumB := factory.GetEnum(4, TYPE_ENUM_UINT, "color_t", map[uint64]string{2: "GREEN", 1: "RED"})
	if enumA != enumB {
		t.Fatalf("identical enums were not interned")
	}

	enumC := factory.GetEnum(4, TYPE_ENUM_UINT, "color_t", map[uint64]string{1: "RED", 3: "BLUE"})
	if enumA == enumC {
		t.Fatalf("different enums should not alias")
	}

	codeA := factory.GetCode("callable_t", intA, []Datatype{ptrA, enumA}, true)
	codeB := factory.GetCode("callable_t", intB, []Datatype{ptrB, enumB}, true)
	if codeA != codeB {
		t.Fatalf("identical code types were not interned")
	}

	codeC := factory.GetCode("callable_t", intA, []Datatype{ptrA}, true)
	if codeA == codeC {
		t.Fatalf("different code signatures should not alias")
	}

	if got := factory.Intern(NewPointer(8, NewBase(4, TYPE_INT, "int4"), 8)); got != ptrA {
		t.Fatalf("Intern() did not canonicalize nested dependencies")
	}
}

func TestTypeOrder(t *testing.T) {
	int4 := NewBase(4, TYPE_INT, "int4")
	uint4 := NewBase(4, TYPE_UINT, "uint4")
	int8 := NewBase(8, TYPE_INT, "int8")
	unknown4 := NewBase(4, TYPE_UNKNOWN, "undefined4")

	// Same pointer orders 0.
	if got := TypeOrder(int4, int4); got != 0 {
		t.Fatalf("TypeOrder(int4,int4)=%d, want 0", got)
	}
	// int4 (SUB_INT_PLAIN=17) is more specific than unknown4 (SUB_UNKNOWN=21).
	if got := TypeOrder(int4, unknown4); got >= 0 {
		t.Fatalf("TypeOrder(int4,unknown4)=%d, want <0 (int4 wins)", got)
	}
	if got := TypeOrder(unknown4, int4); got <= 0 {
		t.Fatalf("TypeOrder(unknown4,int4)=%d, want >0", got)
	}
	// Same submeta: larger size wins (int8 more specific than int4).
	if got := TypeOrder(int4, int8); got <= 0 {
		t.Fatalf("TypeOrder(int4,int8)=%d, want >0 (int8 wins)", got)
	}
	if got := TypeOrder(int8, int4); got >= 0 {
		t.Fatalf("TypeOrder(int8,int4)=%d, want <0", got)
	}
	// uint4 (SUB_UINT_PLAIN=16) is more specific than int4 (SUB_INT_PLAIN=17).
	if got := TypeOrder(uint4, int4); got >= 0 {
		t.Fatalf("TypeOrder(uint4,int4)=%d, want <0 (uint4 wins)", got)
	}
}
