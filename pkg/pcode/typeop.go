package pcode

// TypeOp defines the behavioral properties of a p-code opcode.
// Each OpCode has exactly one TypeOp that determines flag defaults
// and display name.
// C++ parity: typeop.hh TypeOp
type TypeOp interface {
	GetOpCode() OpCode
	GetFlags() uint32 // PcodeOp flags this opcode implies
	GetName() string  // display name ("+", "COPY", etc.)
	IsCommutative() bool

	// PropagateType returns the type that should be applied to a target varnode
	// reached by following one type-edge through op.
	//
	// slot is the input slot index that carries inType (0-based), or -1 when
	// inType comes from the output varnode (reverse propagation).
	//
	// The return value is the inferred type for the other side of the edge:
	//   - slot >= 0: inType flows from input[slot] toward the output  -> return output type
	//   - slot == -1: inType flows from the output toward an input    -> return input type
	//
	// Returns nil when no type information can be derived.
	// C++ parity: typeop.hh TypeOp::propagateType (partial -- E5 subset)
	PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype
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

// PropagateType default: no type information derived.
func (t *typeOpBase) PropagateType(_ *PcodeOp, _ int, _ Datatype, _ *TypeFactory) Datatype {
	return nil
}

// ---------------------------------------------------------------------------
// Concrete per-opcode TypeOp structs with PropagateType implementations.
// Each embeds typeOpBase to inherit the non-propagation methods.
// C++ parity: typeop.cc TypeOpCopy, TypeOpLoad, TypeOpStore, etc. (partial)
// ---------------------------------------------------------------------------

// typeOpCopy / typeOpMultiequal: pass inType through unchanged.
type typeOpCopy struct{ typeOpBase }
type typeOpMultiequal struct{ typeOpBase }

func (t *typeOpCopy) PropagateType(_ *PcodeOp, _ int, inType Datatype, _ *TypeFactory) Datatype {
	return inType
}
func (t *typeOpMultiequal) PropagateType(_ *PcodeOp, _ int, inType Datatype, _ *TypeFactory) Datatype {
	return inType
}

// typeOpLoad:
//   slot=1  (addr input)  -> pointee type propagates to output
//   slot=-1 (from output) -> pointer-to-outType propagates to input[1]
type typeOpLoad struct{ typeOpBase }

func (t *typeOpLoad) PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	if slot == 1 {
		// input[1] is the address; if it carries a pointer, yield the pointee.
		if ptr, ok := inType.(*Pointer); ok {
			return ptr.Pointee()
		}
		return nil
	}
	if slot == -1 {
		// Reverse: output type known; propagate pointer-to-outType to input[1].
		if op == nil || op.Output() == nil {
			return nil
		}
		ptrSize := op.Input(1).Size()
		return tf.GetPointerTo(inType, ptrSize)
	}
	return nil
}

// typeOpStore:
//   slot=1 (addr)  -> pointee type propagates to input[2] (value)
//   slot=2 (value) -> pointer-to-valueType propagates to input[1] (addr)
type typeOpStore struct{ typeOpBase }

func (t *typeOpStore) PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	if slot == 1 {
		if ptr, ok := inType.(*Pointer); ok {
			return ptr.Pointee()
		}
		return nil
	}
	if slot == 2 {
		if op == nil || op.NumInput() < 2 || op.Input(1) == nil {
			return nil
		}
		ptrSize := op.Input(1).Size()
		return tf.GetPointerTo(inType, ptrSize)
	}
	return nil
}

// typeOpIntAdd: if inType is a pointer, propagate it to the output.
// typeOpIntAdd propagates pointer and signed-integer types.
// C++ parity: TypeOpIntAdd::propagateType (typeop.cc) --
//   pointer input -> pointer output (pointer arithmetic)
//   signed/int input -> signed/int output (preserves signedness)
type typeOpIntAdd struct{ typeOpBase }

func (t *typeOpIntAdd) PropagateType(_ *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	if slot >= 0 {
		// Forward: input -> output
		if _, ok := inType.(*Pointer); ok {
			return inType
		}
		// Propagate signed integer type to output (LP64: long/int).
		// C++ parity: TypeOpIntAdd propagates TYPE_INT through arithmetic.
		if base, ok := inType.(*Base); ok && base.Metatype() == TYPE_INT {
			return inType
		}
	}
	return nil
}

// typeOpPtradd / typeOpPtrsub: input[0] carries the pointer type;
// propagate it to the output (forward), or propagate output to input[0] (reverse).
type typeOpPtradd struct{ typeOpBase }
type typeOpPtrsub struct{ typeOpBase }

func ptraddPropagate(_ *PcodeOp, slot int, inType Datatype, _ *TypeFactory) Datatype {
	if slot == 0 {
		if _, ok := inType.(*Pointer); ok {
			return inType
		}
		return nil
	}
	if slot == -1 {
		// Reverse: output type flows back to input[0].
		if _, ok := inType.(*Pointer); ok {
			return inType
		}
		return nil
	}
	return nil
}

func (t *typeOpPtradd) PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	return ptraddPropagate(op, slot, inType, tf)
}
func (t *typeOpPtrsub) PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	return ptraddPropagate(op, slot, inType, tf)
}

// typeOpZext: zero-extension; propagate unsigned base type sized to target.
type typeOpZext struct{ typeOpBase }

func (t *typeOpZext) PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	if op == nil {
		return nil
	}
	if slot == 0 {
		// Forward: derive output type from output size.
		if op.Output() != nil {
			return tf.GetExactType(op.Output().Size(), TYPE_UINT)
		}
		return nil
	}
	if slot == -1 {
		// Reverse: derive input[0] type from input[0] size.
		if op.NumInput() > 0 && op.Input(0) != nil {
			return tf.GetExactType(op.Input(0).Size(), TYPE_UINT)
		}
		return nil
	}
	return nil
}

// typeOpSext: sign-extension; propagate signed base type sized to target.
type typeOpSext struct{ typeOpBase }

func (t *typeOpSext) PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	if op == nil {
		return nil
	}
	if slot == 0 {
		if op.Output() != nil {
			return tf.GetExactType(op.Output().Size(), TYPE_INT)
		}
		return nil
	}
	if slot == -1 {
		if op.NumInput() > 0 && op.Input(0) != nil {
			return tf.GetExactType(op.Input(0).Size(), TYPE_INT)
		}
		return nil
	}
	return nil
}

// typeOpIntMult: integer multiply propagates TYPE_INT bidirectionally.
// If either operand is TYPE_INT, the result is TYPE_INT; and if the output
// is TYPE_INT, both inputs are inferred as TYPE_INT.
// C++ parity: TypeOpIntMult::propagateType (typeop.cc) passes alttype through
// unchanged when alttype is TYPE_INT, enabling bidirectional signed inference.
type typeOpIntMult struct{ typeOpBase }

func (t *typeOpIntMult) PropagateType(_ *PcodeOp, slot int, inType Datatype, _ *TypeFactory) Datatype {
	if base, ok := inType.(*Base); ok && base.Metatype() == TYPE_INT {
		return inType // pass TYPE_INT through in both directions
	}
	return nil
}

// typeOpIntCmp: comparison ops always produce a 1-byte bool output.
// Forward: return bool. Reverse: no useful inference.
type typeOpIntCmp struct{ typeOpBase }

func (t *typeOpIntCmp) PropagateType(_ *PcodeOp, slot int, _ Datatype, tf *TypeFactory) Datatype {
	if slot >= 0 {
		return tf.GetBase(1, TYPE_BOOL, "bool")
	}
	return nil
}

// typeOpCast:
//   slot=0  (input) -> use output varnode size
//   slot=-1 (reverse from output) -> use input[0] size
type typeOpCast struct{ typeOpBase }

func (t *typeOpCast) PropagateType(op *PcodeOp, slot int, inType Datatype, tf *TypeFactory) Datatype {
	if op == nil {
		return nil
	}
	if slot == 0 {
		if op.Output() != nil && inType != nil {
			// Cast forward: keep metatype, resize to output size.
			return tf.GetExactType(op.Output().Size(), inType.Metatype())
		}
		return nil
	}
	if slot == -1 {
		if op.NumInput() > 0 && op.Input(0) != nil && inType != nil {
			return tf.GetExactType(op.Input(0).Size(), inType.Metatype())
		}
		return nil
	}
	return nil
}

// RegisterTypeOps creates the canonical TypeOp instance for each OpCode.
// C++ parity: TypeOp::registerInstructions (typeop.cc)
func RegisterTypeOps() []TypeOp {
	inst := make([]TypeOp, CPUI_MAX+1)

	// Data movement
	inst[CPUI_COPY] = &typeOpCopy{typeOpBase{CPUI_COPY, PcodeOpUnary | PcodeOpNoCollapse, "COPY"}}
	inst[CPUI_LOAD] = &typeOpLoad{typeOpBase{CPUI_LOAD, PcodeOpSpecial | PcodeOpNoCollapse, "LOAD"}}
	inst[CPUI_STORE] = &typeOpStore{typeOpBase{CPUI_STORE, PcodeOpSpecial | PcodeOpNoCollapse, "STORE"}}

	// Control flow
	inst[CPUI_BRANCH] = &typeOpBase{CPUI_BRANCH, PcodeOpSpecial | PcodeOpBranch | PcodeOpCodeRef | PcodeOpNoCollapse, "BRANCH"}
	inst[CPUI_CBRANCH] = &typeOpBase{CPUI_CBRANCH, PcodeOpSpecial | PcodeOpBranch | PcodeOpCodeRef | PcodeOpNoCollapse, "CBRANCH"}
	inst[CPUI_BRANCHIND] = &typeOpBase{CPUI_BRANCHIND, PcodeOpSpecial | PcodeOpBranch | PcodeOpNoCollapse, "BRANCHIND"}
	inst[CPUI_CALL] = &typeOpBase{CPUI_CALL, PcodeOpSpecial | PcodeOpCall | PcodeOpHasCallSpec | PcodeOpCodeRef | PcodeOpNoCollapse, "CALL"}
	inst[CPUI_CALLIND] = &typeOpBase{CPUI_CALLIND, PcodeOpSpecial | PcodeOpCall | PcodeOpHasCallSpec | PcodeOpNoCollapse, "CALLIND"}
	inst[CPUI_CALLOTHER] = &typeOpBase{CPUI_CALLOTHER, PcodeOpSpecial | PcodeOpCall | PcodeOpNoCollapse, "CALLOTHER"}
	inst[CPUI_RETURN] = &typeOpBase{CPUI_RETURN, PcodeOpSpecial | PcodeOpReturns | PcodeOpNoCollapse | PcodeOpReturnCopy, "RETURN"}

	// SSA markers
	inst[CPUI_MULTIEQUAL] = &typeOpMultiequal{typeOpBase{CPUI_MULTIEQUAL, PcodeOpSpecial | PcodeOpMarker | PcodeOpNoCollapse, "MULTIEQUAL"}}
	inst[CPUI_INDIRECT] = &typeOpBase{CPUI_INDIRECT, PcodeOpSpecial | PcodeOpMarker | PcodeOpNoCollapse, "INDIRECT"}

	// Integer comparison (binary, booloutput)
	inst[CPUI_INT_EQUAL] = &typeOpIntCmp{typeOpBase{CPUI_INT_EQUAL, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "=="}}
	inst[CPUI_INT_NOTEQUAL] = &typeOpIntCmp{typeOpBase{CPUI_INT_NOTEQUAL, PcodeOpBinary | PcodeOpBoolOutput | PcodeOpCommutative, "!="}}
	inst[CPUI_INT_SLESS] = &typeOpIntCmp{typeOpBase{CPUI_INT_SLESS, PcodeOpBinary | PcodeOpBoolOutput, "<"}}
	inst[CPUI_INT_SLESSEQUAL] = &typeOpIntCmp{typeOpBase{CPUI_INT_SLESSEQUAL, PcodeOpBinary | PcodeOpBoolOutput, "<="}}
	inst[CPUI_INT_LESS] = &typeOpIntCmp{typeOpBase{CPUI_INT_LESS, PcodeOpBinary | PcodeOpBoolOutput, "<"}}
	inst[CPUI_INT_LESSEQUAL] = &typeOpIntCmp{typeOpBase{CPUI_INT_LESSEQUAL, PcodeOpBinary | PcodeOpBoolOutput, "<="}}

	// Extension/truncation
	inst[CPUI_INT_ZEXT] = &typeOpZext{typeOpBase{CPUI_INT_ZEXT, PcodeOpUnary, "ZEXT"}}
	inst[CPUI_INT_SEXT] = &typeOpSext{typeOpBase{CPUI_INT_SEXT, PcodeOpUnary, "SEXT"}}

	// Integer arithmetic
	inst[CPUI_INT_ADD] = &typeOpIntAdd{typeOpBase{CPUI_INT_ADD, PcodeOpBinary | PcodeOpCommutative, "+"}}
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
	inst[CPUI_INT_MULT] = &typeOpIntMult{typeOpBase{CPUI_INT_MULT, PcodeOpBinary | PcodeOpCommutative, "*"}}
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
	inst[CPUI_CAST] = &typeOpCast{typeOpBase{CPUI_CAST, PcodeOpUnary | PcodeOpSpecial | PcodeOpNoCollapse, "CAST"}}
	inst[CPUI_PTRADD] = &typeOpPtradd{typeOpBase{CPUI_PTRADD, PcodeOpTernary | PcodeOpNoCollapse, "PTRADD"}}
	inst[CPUI_PTRSUB] = &typeOpPtrsub{typeOpBase{CPUI_PTRSUB, PcodeOpBinary | PcodeOpNoCollapse, "PTRSUB"}}
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

// C++ parity: typeop.cc TypeOpFloatInt2Float::preferredZextSize
func preferredZextSizeFloatInt2Float(inSize int) int {
	if inSize < 4 {
		return 4
	}
	if inSize < 8 {
		return 8
	}
	return inSize + 1
}
