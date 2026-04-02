package pcode

// TypeOp defines the behavioral properties of a p-code opcode.
// Each OpCode has exactly one TypeOp that determines flag defaults
// and display name. Full type propagation is Phase 4.
// C++ parity: typeop.hh TypeOp
type TypeOp interface {
	GetOpCode() OpCode
	GetFlags() uint32 // PcodeOp flags this opcode implies
	GetName() string  // display name ("+", "COPY", etc.)
	IsCommutative() bool
}

// typeOpBase is the default concrete TypeOp for all opcodes.
// C++ parity: typeop.cc TypeOp (base class fields)
type typeOpBase struct {
	opcode OpCode
	flags  uint32
	name   string
}

func (t *typeOpBase) GetOpCode() OpCode   { return t.opcode }
func (t *typeOpBase) GetFlags() uint32    { return t.flags }
func (t *typeOpBase) GetName() string     { return t.name }
func (t *typeOpBase) IsCommutative() bool { return t.flags&PcodeOpCommutative != 0 }

// RegisterTypeOps creates the canonical TypeOp instance for each OpCode.
// C++ parity: TypeOp::registerInstructions (typeop.cc)
func RegisterTypeOps() []TypeOp {
	inst := make([]TypeOp, CPUI_MAX+1)

	// Data movement
	inst[CPUI_COPY] = &typeOpBase{CPUI_COPY, PcodeOpUnary | PcodeOpNoCollapse, "COPY"}
	inst[CPUI_LOAD] = &typeOpBase{CPUI_LOAD, PcodeOpSpecial | PcodeOpNoCollapse, "LOAD"}
	inst[CPUI_STORE] = &typeOpBase{CPUI_STORE, PcodeOpSpecial | PcodeOpNoCollapse, "STORE"}

	// Control flow
	inst[CPUI_BRANCH] = &typeOpBase{CPUI_BRANCH, PcodeOpSpecial | PcodeOpBranch | PcodeOpCodeRef | PcodeOpNoCollapse, "BRANCH"}
	inst[CPUI_CBRANCH] = &typeOpBase{CPUI_CBRANCH, PcodeOpSpecial | PcodeOpBranch | PcodeOpCodeRef | PcodeOpNoCollapse, "CBRANCH"}
	inst[CPUI_BRANCHIND] = &typeOpBase{CPUI_BRANCHIND, PcodeOpSpecial | PcodeOpBranch | PcodeOpNoCollapse, "BRANCHIND"}
	inst[CPUI_CALL] = &typeOpBase{CPUI_CALL, PcodeOpSpecial | PcodeOpCall | PcodeOpHasCallSpec | PcodeOpCodeRef | PcodeOpNoCollapse, "CALL"}
	inst[CPUI_CALLIND] = &typeOpBase{CPUI_CALLIND, PcodeOpSpecial | PcodeOpCall | PcodeOpHasCallSpec | PcodeOpNoCollapse, "CALLIND"}
	inst[CPUI_CALLOTHER] = &typeOpBase{CPUI_CALLOTHER, PcodeOpSpecial | PcodeOpCall | PcodeOpNoCollapse, "CALLOTHER"}
	inst[CPUI_RETURN] = &typeOpBase{CPUI_RETURN, PcodeOpSpecial | PcodeOpReturns | PcodeOpNoCollapse | PcodeOpReturnCopy, "RETURN"}

	// SSA markers
	inst[CPUI_MULTIEQUAL] = &typeOpBase{CPUI_MULTIEQUAL, PcodeOpSpecial | PcodeOpMarker | PcodeOpNoCollapse, "MULTIEQUAL"}
	inst[CPUI_INDIRECT] = &typeOpBase{CPUI_INDIRECT, PcodeOpSpecial | PcodeOpMarker | PcodeOpNoCollapse, "INDIRECT"}

	// Integer comparison (binary, booloutput)
	inst[CPUI_INT_EQUAL] = &typeOpBase{CPUI_INT_EQUAL, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "=="}
	inst[CPUI_INT_NOTEQUAL] = &typeOpBase{CPUI_INT_NOTEQUAL, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "!="}
	inst[CPUI_INT_SLESS] = &typeOpBase{CPUI_INT_SLESS, PcodeOpBinary | PcodeOpBoolOutput, "<"}
	inst[CPUI_INT_SLESSEQUAL] = &typeOpBase{CPUI_INT_SLESSEQUAL, PcodeOpBinary | PcodeOpBoolOutput, "<="}
	inst[CPUI_INT_LESS] = &typeOpBase{CPUI_INT_LESS, PcodeOpBinary | PcodeOpBoolOutput, "<"}
	inst[CPUI_INT_LESSEQUAL] = &typeOpBase{CPUI_INT_LESSEQUAL, PcodeOpBinary | PcodeOpBoolOutput, "<="}

	// Extension/truncation
	inst[CPUI_INT_ZEXT] = &typeOpBase{CPUI_INT_ZEXT, PcodeOpUnary, "ZEXT"}
	inst[CPUI_INT_SEXT] = &typeOpBase{CPUI_INT_SEXT, PcodeOpUnary, "SEXT"}

	// Integer arithmetic
	inst[CPUI_INT_ADD] = &typeOpBase{CPUI_INT_ADD, PcodeOpBinary | PcodeOpCommutative, "+"}
	inst[CPUI_INT_SUB] = &typeOpBase{CPUI_INT_SUB, PcodeOpBinary, "-"}
	inst[CPUI_INT_CARRY] = &typeOpBase{CPUI_INT_CARRY, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "CARRY"}
	inst[CPUI_INT_SCARRY] = &typeOpBase{CPUI_INT_SCARRY, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "SCARRY"}
	inst[CPUI_INT_SBORROW] = &typeOpBase{CPUI_INT_SBORROW, PcodeOpBinary | PcodeOpBoolOutput, "SBORROW"}
	inst[CPUI_INT_2COMP] = &typeOpBase{CPUI_INT_2COMP, PcodeOpUnary, "-"}
	inst[CPUI_INT_NEGATE] = &typeOpBase{CPUI_INT_NEGATE, PcodeOpUnary, "~"}
	inst[CPUI_INT_XOR] = &typeOpBase{CPUI_INT_XOR, PcodeOpBinary | PcodeOpCommutative, "^"}
	inst[CPUI_INT_AND] = &typeOpBase{CPUI_INT_AND, PcodeOpBinary | PcodeOpCommutative, "&"}
	inst[CPUI_INT_OR] = &typeOpBase{CPUI_INT_OR, PcodeOpBinary | PcodeOpCommutative, "|"}
	inst[CPUI_INT_LEFT] = &typeOpBase{CPUI_INT_LEFT, PcodeOpBinary, "<<"}
	inst[CPUI_INT_RIGHT] = &typeOpBase{CPUI_INT_RIGHT, PcodeOpBinary, ">>"}
	inst[CPUI_INT_SRIGHT] = &typeOpBase{CPUI_INT_SRIGHT, PcodeOpBinary, ">>"}
	inst[CPUI_INT_MULT] = &typeOpBase{CPUI_INT_MULT, PcodeOpBinary | PcodeOpCommutative, "*"}
	inst[CPUI_INT_DIV] = &typeOpBase{CPUI_INT_DIV, PcodeOpBinary, "/"}
	inst[CPUI_INT_SDIV] = &typeOpBase{CPUI_INT_SDIV, PcodeOpBinary, "/"}
	inst[CPUI_INT_REM] = &typeOpBase{CPUI_INT_REM, PcodeOpBinary, "%"}
	inst[CPUI_INT_SREM] = &typeOpBase{CPUI_INT_SREM, PcodeOpBinary, "%"}

	// Boolean
	inst[CPUI_BOOL_NEGATE] = &typeOpBase{CPUI_BOOL_NEGATE, PcodeOpUnary | PcodeOpBoolOutput, "!"}
	inst[CPUI_BOOL_XOR] = &typeOpBase{CPUI_BOOL_XOR, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "^^"}
	inst[CPUI_BOOL_AND] = &typeOpBase{CPUI_BOOL_AND, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "&&"}
	inst[CPUI_BOOL_OR] = &typeOpBase{CPUI_BOOL_OR, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "||"}

	// Float ops
	inst[CPUI_FLOAT_EQUAL] = &typeOpBase{CPUI_FLOAT_EQUAL, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "=="}
	inst[CPUI_FLOAT_NOTEQUAL] = &typeOpBase{CPUI_FLOAT_NOTEQUAL, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "!="}
	inst[CPUI_FLOAT_LESS] = &typeOpBase{CPUI_FLOAT_LESS, PcodeOpBinary | PcodeOpBoolOutput, "<"}
	inst[CPUI_FLOAT_LESSEQUAL] = &typeOpBase{CPUI_FLOAT_LESSEQUAL, PcodeOpBinary | PcodeOpBoolOutput, "<="}
	inst[CPUI_FLOAT_NAN] = &typeOpBase{CPUI_FLOAT_NAN, PcodeOpUnary | PcodeOpBoolOutput, "NAN"}
	inst[CPUI_FLOAT_ADD] = &typeOpBase{CPUI_FLOAT_ADD, PcodeOpBinary | PcodeOpCommutative, "+"}
	inst[CPUI_FLOAT_DIV] = &typeOpBase{CPUI_FLOAT_DIV, PcodeOpBinary, "/"}
	inst[CPUI_FLOAT_MULT] = &typeOpBase{CPUI_FLOAT_MULT, PcodeOpBinary | PcodeOpCommutative, "*"}
	inst[CPUI_FLOAT_SUB] = &typeOpBase{CPUI_FLOAT_SUB, PcodeOpBinary, "-"}
	inst[CPUI_FLOAT_NEG] = &typeOpBase{CPUI_FLOAT_NEG, PcodeOpUnary, "-"}
	inst[CPUI_FLOAT_ABS] = &typeOpBase{CPUI_FLOAT_ABS, PcodeOpUnary, "ABS"}
	inst[CPUI_FLOAT_SQRT] = &typeOpBase{CPUI_FLOAT_SQRT, PcodeOpUnary, "SQRT"}
	inst[CPUI_FLOAT_INT2FLOAT] = &typeOpBase{CPUI_FLOAT_INT2FLOAT, PcodeOpUnary, "INT2FLOAT"}
	inst[CPUI_FLOAT_FLOAT2FLOAT] = &typeOpBase{CPUI_FLOAT_FLOAT2FLOAT, PcodeOpUnary, "FLOAT2FLOAT"}
	inst[CPUI_FLOAT_TRUNC] = &typeOpBase{CPUI_FLOAT_TRUNC, PcodeOpUnary, "TRUNC"}
	inst[CPUI_FLOAT_CEIL] = &typeOpBase{CPUI_FLOAT_CEIL, PcodeOpUnary, "CEIL"}
	inst[CPUI_FLOAT_FLOOR] = &typeOpBase{CPUI_FLOAT_FLOOR, PcodeOpUnary, "FLOOR"}
	inst[CPUI_FLOAT_ROUND] = &typeOpBase{CPUI_FLOAT_ROUND, PcodeOpUnary, "ROUND"}

	// Composite/pointer
	inst[CPUI_PIECE] = &typeOpBase{CPUI_PIECE, PcodeOpBinary, "CONCAT"}
	inst[CPUI_SUBPIECE] = &typeOpBase{CPUI_SUBPIECE, PcodeOpBinary, "SUB"}
	inst[CPUI_CAST] = &typeOpBase{CPUI_CAST, PcodeOpUnary | PcodeOpSpecial | PcodeOpNoCollapse, "CAST"}
	inst[CPUI_PTRADD] = &typeOpBase{CPUI_PTRADD, PcodeOpTernary | PcodeOpNoCollapse, "PTRADD"}
	inst[CPUI_PTRSUB] = &typeOpBase{CPUI_PTRSUB, PcodeOpBinary | PcodeOpNoCollapse, "PTRSUB"}
	inst[CPUI_SEGMENTOP] = &typeOpBase{CPUI_SEGMENTOP, PcodeOpSpecial | PcodeOpNoCollapse, "SEGMENTOP"}
	inst[CPUI_CPOOLREF] = &typeOpBase{CPUI_CPOOLREF, PcodeOpSpecial | PcodeOpNoCollapse, "CPOOLREF"}
	inst[CPUI_NEW] = &typeOpBase{CPUI_NEW, PcodeOpSpecial | PcodeOpCall | PcodeOpNoCollapse, "NEW"}

	// Bit manipulation
	inst[CPUI_INSERT] = &typeOpBase{CPUI_INSERT, PcodeOpTernary, "INSERT"}
	inst[CPUI_ZPULL] = &typeOpBase{CPUI_ZPULL, PcodeOpTernary, "ZPULL"}
	inst[CPUI_POPCOUNT] = &typeOpBase{CPUI_POPCOUNT, PcodeOpUnary, "POPCOUNT"}
	inst[CPUI_LZCOUNT] = &typeOpBase{CPUI_LZCOUNT, PcodeOpUnary, "LZCOUNT"}
	inst[CPUI_SPULL] = &typeOpBase{CPUI_SPULL, PcodeOpTernary, "SPULL"}

	return inst
}
