package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

type rawBlockSpec struct {
	ops []RawOp
}

type rawEdgeSpec struct {
	from  int
	to    int
	label uint32
}

type rawBuildEnv struct {
	reg    *address.Space
	cnst   *address.Space
	uniq   *address.Space
	fnAddr address.Address
}

type rawVarKey struct {
	spc    *address.Space
	offset uint64
	size   uint32
}

func newRawBuildEnv() rawBuildEnv {
	reg := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 4, WordSize: 1}
	cnst := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 4, WordSize: 1}
	uniq := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 3, AddrSize: 4, WordSize: 1}
	return rawBuildEnv{
		reg:    reg,
		cnst:   cnst,
		uniq:   uniq,
		fnAddr: address.Address{Space: reg, Offset: 0x401000},
	}
}

func TestPrintCExpressionPrecedence(t *testing.T) {
	t.Run("binary and boolean", func(t *testing.T) {
		env := newRawBuildEnv()
		fd := NewFuncdata("precedence", env.fnAddr, env.uniq, 0x1000, env.cnst)
		state := newPrintCState(NewPrintC(), fd)

		left := fd.SetInputVarnode(fd.NewVarnode(4, address.Address{Space: env.reg, Offset: 0x10}))
		right := fd.SetInputVarnode(fd.NewVarnode(4, address.Address{Space: env.reg, Offset: 0x14}))

		add := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(add, CPUI_INT_ADD)
		fd.OpSetInput(add, right, 0)
		fd.OpSetInput(add, fd.NewConstant(4, 3), 1)
		fd.NewVarnodeOut(4, address.Address{Space: env.uniq, Offset: 0x100}, add)
		fd.OpMarkAlive(add)

		mul := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(mul, CPUI_INT_MULT)
		fd.OpSetInput(mul, left, 0)
		fd.OpSetInput(mul, add.Output(), 1)
		fd.NewVarnodeOut(4, address.Address{Space: env.uniq, Offset: 0x104}, mul)
		fd.OpMarkAlive(mul)

		eq := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(eq, CPUI_INT_EQUAL)
		fd.OpSetInput(eq, left, 0)
		fd.OpSetInput(eq, fd.NewConstant(4, 0), 1)
		fd.NewVarnodeOut(1, address.Address{Space: env.uniq, Offset: 0x108}, eq)
		fd.OpMarkAlive(eq)

		ne := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(ne, CPUI_INT_NOTEQUAL)
		fd.OpSetInput(ne, right, 0)
		fd.OpSetInput(ne, fd.NewConstant(4, 1), 1)
		fd.NewVarnodeOut(1, address.Address{Space: env.uniq, Offset: 0x109}, ne)
		fd.OpMarkAlive(ne)

		orOp := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(orOp, CPUI_BOOL_OR)
		fd.OpSetInput(orOp, eq.Output(), 0)
		fd.OpSetInput(orOp, ne.Output(), 1)
		fd.NewVarnodeOut(1, address.Address{Space: env.uniq, Offset: 0x10a}, orOp)
		fd.OpMarkAlive(orOp)

		notOp := fd.NewOp(1, env.fnAddr)
		fd.OpSetOpcode(notOp, CPUI_BOOL_NEGATE)
		fd.OpSetInput(notOp, orOp.Output(), 0)
		fd.NewVarnodeOut(1, address.Address{Space: env.uniq, Offset: 0x10b}, notOp)
		fd.OpMarkAlive(notOp)

		state.collectSymbols()

		gotMul, err := state.renderOpExpr(mul, cPrecLowest)
		if err != nil {
			t.Fatalf("renderOpExpr(mul): %v", err)
		}
		if gotMul != "param_0 * (param_1 + 3)" {
			t.Fatalf("unexpected multiply expression: %q", gotMul)
		}

		gotBool, err := state.renderOpExpr(notOp, cPrecLowest)
		if err != nil {
			t.Fatalf("renderOpExpr(not): %v", err)
		}
		if gotBool != "!(param_0 == 0 || param_1 != 1)" {
			t.Fatalf("unexpected boolean expression: %q", gotBool)
		}
	})

	t.Run("cast style", func(t *testing.T) {
		env := newRawBuildEnv()
		fd := NewFuncdata("cast", env.fnAddr, env.uniq, 0x1000, env.cnst)
		state := newPrintCState(NewPrintC(), fd)
		intType := sharedTypeFactory.GetBase(4, TYPE_INT, "int")

		left := fd.SetInputVarnode(fd.NewVarnode(4, address.Address{Space: env.reg, Offset: 0x10}))
		right := fd.SetInputVarnode(fd.NewVarnode(4, address.Address{Space: env.reg, Offset: 0x14}))
		SetVarnodeType(left, intType)
		SetVarnodeType(right, intType)

		add := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(add, CPUI_INT_ADD)
		fd.OpSetInput(add, left, 0)
		fd.OpSetInput(add, right, 1)
		fd.NewVarnodeOut(4, address.Address{Space: env.uniq, Offset: 0x100}, add)
		SetVarnodeType(add.Output(), intType)
		fd.OpMarkAlive(add)

		cast := fd.NewOp(1, env.fnAddr)
		fd.OpSetOpcode(cast, CPUI_CAST)
		fd.OpSetInput(cast, add.Output(), 0)
		fd.NewVarnodeOut(4, address.Address{Space: env.uniq, Offset: 0x104}, cast)
		SetVarnodeType(cast.Output(), intType)
		fd.OpMarkAlive(cast)

		state.collectSymbols()

		got, err := state.renderOpExpr(cast, cPrecLowest)
		if err != nil {
			t.Fatalf("renderOpExpr(cast): %v", err)
		}
		if got != "(int)(param_0 + param_1)" {
			t.Fatalf("unexpected cast expression: %q", got)
		}
	})

	t.Run("call style", func(t *testing.T) {
		env := newRawBuildEnv()
		fd := NewFuncdata("call", env.fnAddr, env.uniq, 0x1000, env.cnst)
		state := newPrintCState(NewPrintC(), fd)
		intType := sharedTypeFactory.GetBase(4, TYPE_INT, "int")
		fnType := sharedTypeFactory.GetPointer(8, sharedTypeFactory.GetCode("handler_t", intType, []Datatype{intType}, false), 8)

		callee := fd.SetInputVarnode(fd.NewVarnode(8, address.Address{Space: env.reg, Offset: 0x10}))
		arg := fd.SetInputVarnode(fd.NewVarnode(4, address.Address{Space: env.reg, Offset: 0x14}))
		SetVarnodeType(callee, fnType)
		SetVarnodeType(arg, intType)

		add := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(add, CPUI_INT_ADD)
		fd.OpSetInput(add, arg, 0)
		fd.OpSetInput(add, fd.NewConstant(4, 3), 1)
		fd.NewVarnodeOut(4, address.Address{Space: env.uniq, Offset: 0x100}, add)
		SetVarnodeType(add.Output(), intType)
		fd.OpMarkAlive(add)

		call := fd.NewOp(2, env.fnAddr)
		fd.OpSetOpcode(call, CPUI_CALLIND)
		fd.OpSetInput(call, callee, 0)
		fd.OpSetInput(call, add.Output(), 1)
		fd.NewVarnodeOut(4, address.Address{Space: env.uniq, Offset: 0x104}, call)
		SetVarnodeType(call.Output(), intType)
		fd.OpMarkAlive(call)

		state.collectSymbols()

		got, err := state.renderOpExpr(call, cPrecLowest)
		if err != nil {
			t.Fatalf("renderOpExpr(call): %v", err)
		}
		if got != "(*param_0)(param_1 + 3)" {
			t.Fatalf("unexpected call expression: %q", got)
		}
	})
}

func TestPrintCDeclarationRendererAPI(t *testing.T) {
	env := newRawBuildEnv()
	fd := NewFuncdata("decls", env.fnAddr, env.uniq, 0x1000, env.cnst)
	intType := sharedTypeFactory.GetBase(4, TYPE_INT, "int")
	pairType := sharedTypeFactory.GetStruct("pair_t", []TypeField{{Offset: 0, Name: "left", Type: intType}})
	arrayType := sharedTypeFactory.GetArray(4, intType)
	ptrArray := sharedTypeFactory.GetPointer(8, arrayType, 8)
	funcType := sharedTypeFactory.GetCode("handler_t", intType, []Datatype{sharedTypeFactory.GetPointer(8, pairType, 8), intType}, true)
	funcPtr := sharedTypeFactory.GetPointer(8, funcType, 8)
	ptrArrayVar := fd.NewVarnode(8, address.Address{Space: env.reg, Offset: 0x20})
	SetVarnodeType(ptrArrayVar, ptrArray)

	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "decl pointer to array", got: CDeclString(ptrArray, "value"), want: "int (*value)[4]"},
		{name: "var decl pointer to array", got: CVarDeclString(ptrArrayVar, "value"), want: "int (*value)[4]"},
		{name: "decl array of pointers", got: CDeclString(sharedTypeFactory.GetArray(3, sharedTypeFactory.GetPointer(8, intType, 8)), "items"), want: "int *items[3]"},
		{name: "function signature", got: CFuncSignatureString("handler", funcType, []string{"ctx", "count"}), want: "int handler(struct pair_t *ctx, int count, ...)"},
		{name: "function pointer", got: CDeclString(funcPtr, "cb"), want: "int (*cb)(struct pair_t *, int, ...)"},
		{name: "type string", got: CTypeString(sharedTypeFactory.GetPointer(8, pairType, 8)), want: "struct pair_t *"},
		{name: "type definition", got: CTypeDefinitionString(pairType), want: "struct pair_t { int left; }"},
	}

	for _, tc := range cases {
		if tc.got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestPrintCEndToEndRawPcodeToStructuredC(t *testing.T) {
	env := newRawBuildEnv()
	fd := NewFuncdata("sample", env.fnAddr, env.uniq, 0x2000, env.cnst)

	blocks := []rawBlockSpec{
		{ops: []RawOp{
			{
				SeqNum: SeqNum{Address: env.fnAddr, Order: 0},
				OpCode: CPUI_INT_EQUAL,
				Output: &VarnodeData{Space: env.uniq, Offset: 0x100, Size: 1},
				Inputs: []VarnodeData{{Space: env.reg, Offset: 0x10, Size: 4}, {Space: env.cnst, Offset: 0, Size: 4}},
			},
			{
				SeqNum: SeqNum{Address: env.fnAddr, Order: 1},
				OpCode: CPUI_CBRANCH,
				Inputs: []VarnodeData{{Space: env.cnst, Offset: 1, Size: 4}, {Space: env.uniq, Offset: 0x100, Size: 1}},
			},
		}},
		{ops: []RawOp{{SeqNum: SeqNum{Address: env.fnAddr.Add(4), Order: 0}, OpCode: CPUI_RETURN, Inputs: []VarnodeData{{Space: env.cnst, Offset: 1, Size: 4}}}}},
		{ops: []RawOp{
			{
				SeqNum: SeqNum{Address: env.fnAddr.Add(8), Order: 0},
				OpCode: CPUI_INT_ADD,
				Output: &VarnodeData{Space: env.uniq, Offset: 0x104, Size: 4},
				Inputs: []VarnodeData{{Space: env.reg, Offset: 0x10, Size: 4}, {Space: env.cnst, Offset: 1, Size: 4}},
			},
			{
				SeqNum: SeqNum{Address: env.fnAddr.Add(8), Order: 1},
				OpCode: CPUI_BRANCH,
				Inputs: []VarnodeData{{Space: env.cnst, Offset: 2, Size: 4}},
			},
		}},
		{ops: []RawOp{{SeqNum: SeqNum{Address: env.fnAddr.Add(12), Order: 0}, OpCode: CPUI_RETURN, Inputs: []VarnodeData{{Space: env.uniq, Offset: 0x104, Size: 4}}}}},
	}
	edges := []rawEdgeSpec{{from: 0, to: 2}, {from: 0, to: 1}, {from: 2, to: 3}}
	graph := buildGraphFromRaw(t, fd, blocks, edges)

	heritage := NewHeritage(fd, []*address.Space{env.reg})
	heritage.Heritage(graph)

	pool := NewBatchAActionPool("batch-a", "analysis")
	if res := pool.Perform(fd); res < 0 {
		t.Fatalf("batch-a perform returned partial status %d", res)
	}

	fd.SetBasicBlocks(graph)
	if res := NewActionBlockStructure("analysis").Apply(fd); res != 0 {
		t.Fatalf("ActionBlockStructure.Apply returned %d", res)
	}
	if res := NewActionFinalStructure("analysis").Apply(fd); res != 0 {
		t.Fatalf("ActionFinalStructure.Apply returned %d", res)
	}

	got, err := NewPrintC().Emit(fd)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	// C++ parity: ruleBlockIfNoExit fires at i=0 (FalseOut=param_0+1 path),
	// negates condition (param_0==0 -> param_0!=0), and makes that the if-body.
	// param_0 lives in register space with no committed type -> TYPE_UNKNOWN -> "undefined4".
	// Return type: INT_ADD produces a TYPE_UINT unique varnode -> "unsigned int".
	// C++ parity: Ghidra emits "undefined4" for untyped 4-byte varnodes;
	// the return type is inferred from the RETURN's input (TYPE_UINT from INT_ADD).
	want := "unsigned int sample(undefined4 param_0) {\n    if (param_0 != 0) {\n        return param_0 + 1;\n    }\n    return 1;\n}\n"
	if got != want {
		t.Fatalf("unexpected emitted C:\n%s", got)
	}
}

func buildGraphFromRaw(t *testing.T, fd *Funcdata, blocks []rawBlockSpec, edges []rawEdgeSpec) *BlockGraph {
	t.Helper()
	graph := NewBlockGraph()
	created := make([]*BlockBasic, len(blocks))
	for i := range blocks {
		created[i] = graph.NewBlockBasicInGraph()
	}
	for _, edge := range edges {
		graph.AddEdge(&created[edge.from].FlowBlock, &created[edge.to].FlowBlock, edge.label)
	}

	defs := make(map[rawVarKey]*Varnode)

	for i, spec := range blocks {
		bb := created[i]
		for _, raw := range spec.ops {
			op := fd.NewOp(len(raw.Inputs), raw.SeqNum.Address)
			fd.OpSetOpcode(op, raw.OpCode)
			op.SetParent(bb)
			bb.AddOp(op)
			fd.OpMarkAlive(op)
			for slot, in := range raw.Inputs {
				vn := rawInputVarnode(fd, defs, in)
				fd.OpSetInput(op, vn, slot)
			}
			if raw.Output != nil {
				out := fd.NewVarnodeOut(int32(raw.Output.Size), raw.Output.Address(), op)
				defs[rawVarKey{spc: raw.Output.Space, offset: raw.Output.Offset, size: raw.Output.Size}] = out
			}
		}
	}

	graph.FindSpanningTree()
	graph.CalcForwardDominator()
	return graph
}

func rawInputVarnode(fd *Funcdata, defs map[rawVarKey]*Varnode, in VarnodeData) *Varnode {
	if in.Space.IsConstant() {
		return fd.NewConstant(int32(in.Size), in.Offset)
	}
	key := rawVarKey{spc: in.Space, offset: in.Offset, size: in.Size}
	if vn, ok := defs[key]; ok {
		return vn
	}
	return fd.NewVarnode(int32(in.Size), in.Address())
}

func TestE3FloatLiteralEmit(t *testing.T) {
	tests := []struct {
		name string
		bits uint64
		size uint32
		want string
	}{
		{"float_1.0", 0x3f800000, 4, "1f"},
		{"float_0.0", 0x00000000, 4, "0f"},
		{"float_neg1", 0xbf800000, 4, "-1f"},
		{"float_0.5", 0x3f000000, 4, "0.5f"},
		{"double_1.0", 0x3ff0000000000000, 8, "1"},
		{"double_0.0", 0x0000000000000000, 8, "0"},
		{"float_inf", 0x7f800000, 4, "INFINITY"},
		{"float_neg_inf", 0xff800000, 4, "-INFINITY"},
		{"float_nan", 0x7fc00000, 4, "NAN"},
		{"double_nan", 0x7ff8000000000000, 8, "NAN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderFloatLiteral(tt.bits, tt.size)
			if got != tt.want {
				t.Errorf("renderFloatLiteral(0x%x, %d) = %q, want %q", tt.bits, tt.size, got, tt.want)
			}
		})
	}
}
