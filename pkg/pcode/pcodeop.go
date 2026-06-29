package pcode

import (
	"fmt"
	"math/bits"
	"strings"

	"gosleigh/pkg/address"
)

// mostSigBitSet returns the index of the most significant set bit, or -1 if val
// is 0. C++ parity: globals mostsigbit_set.
func mostSigBitSet(val uint64) int { return bits.Len64(val) - 1 }

// getNZMaskLocal computes the non-zero mask of this op's output purely from its
// input Varnodes' current nzmasks (no transitive recomputation). cliploop drops
// MULTIEQUAL inputs arriving on loop back-edges so the initial DFS does not
// depend on not-yet-computed cyclic values.
//
// Sizes larger than 8 bytes fall back to the full mask (conservative); the C++
// extended-precision arithmetic is not ported (Gosleigh nzmask is a single
// uint64). This is safe: a wider mask never enables an unsound simplification.
//
// C++ parity: op.cc PcodeOp::getNZMaskLocal (lines 548-778).
func (op *PcodeOp) getNZMaskLocal(cliploop bool) uint64 {
	out := op.Output()
	if out == nil {
		return 0
	}
	size := out.Size()
	fullmask := maskForSize(size)
	wide := size > 8

	in := func(i int) uint64 {
		v := op.Input(i)
		if v == nil {
			return fullmask
		}
		return v.NZMask()
	}

	var resmask uint64
	switch op.Code() {
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_CARRY, CPUI_INT_SCARRY,
		CPUI_INT_SBORROW, CPUI_BOOL_NEGATE, CPUI_BOOL_XOR, CPUI_BOOL_AND,
		CPUI_BOOL_OR, CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS,
		CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN:
		resmask = 1
	case CPUI_COPY, CPUI_INT_ZEXT:
		resmask = in(0)
	case CPUI_INT_SEXT:
		iv := op.Input(0)
		if iv == nil {
			resmask = fullmask
		} else {
			resmask = uint64(signExtendToInt64(iv.NZMask(), iv.Size())) & fullmask
		}
	case CPUI_INT_XOR, CPUI_INT_OR:
		resmask = in(0)
		if resmask != fullmask {
			resmask |= in(1)
		}
	case CPUI_INT_AND:
		resmask = in(0)
		if resmask != 0 {
			resmask &= in(1)
		}
	case CPUI_INT_LEFT:
		s := op.Input(1)
		if s == nil || !s.IsConstant() || wide {
			resmask = fullmask
		} else {
			resmask = (in(0) << s.Offset()) & fullmask
		}
	case CPUI_INT_RIGHT:
		s := op.Input(1)
		if s == nil || !s.IsConstant() || wide {
			resmask = fullmask
		} else {
			resmask = in(0) >> s.Offset()
		}
	case CPUI_INT_SRIGHT:
		s := op.Input(1)
		if s == nil || !s.IsConstant() || wide {
			resmask = fullmask
		} else {
			sa := s.Offset()
			m := in(0)
			signBit := fullmask ^ (fullmask >> 1)
			if m&signBit == 0 {
				resmask = m >> sa
			} else {
				resmask = (m >> sa) | ((fullmask >> sa) ^ fullmask)
			}
		}
	case CPUI_INT_DIV:
		resmask = coveringMask(in(0))
		if s := op.Input(1); s != nil && s.IsConstant() {
			if sa := mostSigBitSet(in(1)); sa != -1 {
				resmask >>= uint(sa)
			}
		}
	case CPUI_INT_REM:
		resmask = coveringMask(in(1) - 1)
	case CPUI_POPCOUNT:
		resmask = coveringMask(uint64(bits.OnesCount64(in(0)))) & fullmask
	case CPUI_LZCOUNT:
		if iv := op.Input(0); iv != nil {
			resmask = coveringMask(uint64(iv.Size())*8) & fullmask
		} else {
			resmask = fullmask
		}
	case CPUI_SUBPIECE:
		resmask = in(0)
		sz1 := uint64(0)
		if s := op.Input(1); s != nil {
			sz1 = s.Offset()
		}
		iv := op.Input(0)
		if iv != nil && iv.Size() <= 8 {
			if sz1 < 8 {
				resmask >>= 8 * sz1
			} else {
				resmask = 0
			}
		} else {
			if sz1 < 8 {
				resmask >>= 8 * sz1
				if sz1 > 0 {
					resmask |= fullmask << (8 * (8 - sz1))
				}
			} else {
				resmask = fullmask
			}
		}
		resmask &= fullmask
	case CPUI_PIECE:
		lo := op.Input(1)
		var sa int32
		if lo != nil {
			sa = lo.Size()
		}
		hi := in(0)
		if sa < 8 {
			resmask = hi << (8 * uint(sa))
		} else {
			resmask = 0
		}
		resmask |= in(1)
	case CPUI_INT_MULT:
		if wide {
			resmask = fullmask
			break
		}
		val := in(0)
		other := in(1)
		sz1 := mostSigBitSet(val)
		sz2 := mostSigBitSet(other)
		if sz1 == -1 || sz2 == -1 {
			resmask = 0
			break
		}
		l1 := leastSigBitSet(val)
		l2 := leastSigBitSet(other)
		sa := l1 + l2
		if sa >= int(8*size) {
			resmask = 0
			break
		}
		sz1 = sz1 - l1 + 1
		sz2 = sz2 - l2 + 1
		total := sz1 + sz2
		if sz1 == 1 || sz2 == 1 {
			total--
		}
		resmask = fullmask
		if total < int(8*size) {
			resmask >>= uint(int(8*size) - total)
		}
		resmask = (resmask << uint(sa)) & fullmask
	case CPUI_INT_ADD:
		resmask = in(0)
		if resmask != fullmask {
			other := in(1)
			if other&resmask == 0 {
				resmask |= other
			} else {
				resmask |= other
				resmask |= resmask << 1 // possible carries
			}
			resmask &= fullmask
		}
	case CPUI_MULTIEQUAL:
		if op.NumInput() == 0 {
			resmask = fullmask
		} else {
			resmask = 0
			for i := 0; i < op.NumInput(); i++ {
				if cliploop && op.Parent() != nil && op.Parent().isLoopIn(i) {
					continue
				}
				resmask |= in(i)
			}
		}
	case CPUI_CALL, CPUI_CALLIND, CPUI_CPOOLREF:
		if op.HasFlag(PcodeOpCalculatedBool) {
			resmask = 1
		} else {
			resmask = fullmask
		}
	default:
		resmask = fullmask
	}
	return resmask
}

// PcodeOp primary flags -- uint32 bitmask.
// C++ parity: op.hh PcodeOp::Flags
const (
	PcodeOpStartBasic       uint32 = 0x1
	PcodeOpBranch           uint32 = 0x2
	PcodeOpCall             uint32 = 0x4
	PcodeOpReturns          uint32 = 0x8
	PcodeOpNoCollapse       uint32 = 0x10
	PcodeOpDead             uint32 = 0x20
	PcodeOpMarker           uint32 = 0x40
	PcodeOpBoolOutput       uint32 = 0x80
	PcodeOpBooleanFlip      uint32 = 0x100
	PcodeOpFallthruTrue     uint32 = 0x200
	PcodeOpIndirectSource   uint32 = 0x400
	PcodeOpCodeRef          uint32 = 0x800
	PcodeOpStartMark        uint32 = 0x1000
	PcodeOpMark             uint32 = 0x2000
	PcodeOpCommutative      uint32 = 0x4000
	PcodeOpUnary            uint32 = 0x8000
	PcodeOpBinary           uint32 = 0x10000
	PcodeOpSpecial          uint32 = 0x20000
	PcodeOpTernary          uint32 = 0x40000
	PcodeOpReturnCopy       uint32 = 0x80000
	PcodeOpNonPrinting      uint32 = 0x100000
	PcodeOpHalt             uint32 = 0x200000
	PcodeOpBadInstruction   uint32 = 0x400000
	PcodeOpUnimplemented    uint32 = 0x800000
	PcodeOpNoReturn         uint32 = 0x1000000
	PcodeOpMissing          uint32 = 0x2000000
	PcodeOpSpacebasePtr     uint32 = 0x4000000
	PcodeOpIndirectCreation uint32 = 0x8000000
	PcodeOpCalculatedBool   uint32 = 0x10000000
	PcodeOpHasCallSpec      uint32 = 0x20000000
	PcodeOpPtrFlow          uint32 = 0x40000000
	PcodeOpIndirectStore    uint32 = 0x80000000
)

// behavioralFlags is the mask of flags derived from TypeOp that SetOpcode
// must clear before re-applying. These are the opcode-intrinsic flags.
const behavioralFlags = PcodeOpBranch | PcodeOpCall | PcodeOpCodeRef |
	PcodeOpCommutative | PcodeOpReturns | PcodeOpNoCollapse |
	PcodeOpMarker | PcodeOpBoolOutput | PcodeOpUnary | PcodeOpBinary |
	PcodeOpTernary | PcodeOpSpecial | PcodeOpHasCallSpec | PcodeOpReturnCopy

// PcodeOp additional flags -- secondary bitmask.
// C++ parity: op.hh PcodeOp::AdditionalFlags
const (
	PcodeOpSpecialProp         uint32 = 0x1
	PcodeOpSpecialPrint        uint32 = 0x2
	PcodeOpModified            uint32 = 0x4
	PcodeOpWarning             uint32 = 0x8
	PcodeOpIncidentalCopy      uint32 = 0x10
	PcodeOpIsCpoolTransformed  uint32 = 0x20
	PcodeOpStopTypePropagation uint32 = 0x40
	PcodeOpHoldOutput          uint32 = 0x80
	PcodeOpConcatRoot          uint32 = 0x100
	PcodeOpNoIndirectCollapse  uint32 = 0x200
	PcodeOpStoreUnmapped       uint32 = 0x400
)

// PcodeOp is a single P-code operation node in the SSA IR graph.
// C++ parity: op.hh PcodeOp
type PcodeOp struct {
	opcode    TypeOp
	flags     uint32
	addlFlags uint32
	seq       SeqNum
	output    *Varnode
	inputs    []*Varnode
	parent    *BlockBasic
}

// NewPcodeOp creates a PcodeOp with the given number of input slots.
func NewPcodeOp(numInputs int, seq SeqNum) *PcodeOp {
	return &PcodeOp{
		seq:    seq,
		inputs: make([]*Varnode, numInputs),
	}
}

// Code returns the OpCode enum value for this op.
func (op *PcodeOp) Code() OpCode {
	if op.opcode == nil {
		return 0
	}
	return op.opcode.GetOpCode()
}

// GetOpcode returns the TypeOp behavioral dispatch.
func (op *PcodeOp) GetOpcode() TypeOp { return op.opcode }

// NumInput returns the number of input slots.
func (op *PcodeOp) NumInput() int { return len(op.inputs) }

// Output returns the output varnode (may be nil).
func (op *PcodeOp) Output() *Varnode { return op.output }

// Input returns the varnode at the given input slot.
func (op *PcodeOp) Input(slot int) *Varnode { return op.inputs[slot] }

// GetSlot finds which input slot holds the given varnode.
// Returns -1 if not found.
func (op *PcodeOp) GetSlot(vn *Varnode) int {
	for i, in := range op.inputs {
		if in == vn {
			return i
		}
	}
	return -1
}

// Seq returns the sequence number identifying this op.
func (op *PcodeOp) Seq() SeqNum { return op.seq }

// SetSeqNum sets the sequence number for this op.
func (op *PcodeOp) SetSeqNum(s SeqNum) { op.seq = s }

// Addr returns the machine address associated with this op.
func (op *PcodeOp) Addr() address.Address { return op.seq.Address }

// Parent returns the basic block containing this op.
func (op *PcodeOp) Parent() *BlockBasic { return op.parent }

// --- flag queries ---

func (op *PcodeOp) IsDead() bool             { return op.flags&PcodeOpDead != 0 }
func (op *PcodeOp) IsAssignment() bool       { return op.output != nil }
func (op *PcodeOp) IsCall() bool             { return op.flags&PcodeOpCall != 0 }
func (op *PcodeOp) IsMarker() bool           { return op.flags&PcodeOpMarker != 0 }
func (op *PcodeOp) IsBranch() bool           { return op.flags&PcodeOpBranch != 0 }
func (op *PcodeOp) IsBoolOutput() bool       { return op.flags&PcodeOpBoolOutput != 0 }
func (op *PcodeOp) IsCommutative() bool      { return op.flags&PcodeOpCommutative != 0 }
func (op *PcodeOp) IsIndirectCreation() bool { return op.flags&PcodeOpIndirectCreation != 0 }
func (op *PcodeOp) IsIndirectSource() bool   { return op.flags&PcodeOpIndirectSource != 0 }
func (op *PcodeOp) IsIndirectStore() bool    { return op.flags&PcodeOpIndirectStore != 0 }

// IsFlowBreak returns true if this op breaks sequential flow
// (branches, calls with noreturn, returns).
func (op *PcodeOp) IsFlowBreak() bool {
	return op.flags&(PcodeOpBranch|PcodeOpReturns) != 0
}

// EvalType returns the arity class flags (unary/binary/special/ternary).
func (op *PcodeOp) EvalType() uint32 {
	return op.flags & (PcodeOpUnary | PcodeOpBinary | PcodeOpSpecial | PcodeOpTernary)
}

// HaltType returns the halt-class flags.
func (op *PcodeOp) HaltType() uint32 {
	return op.flags & (PcodeOpHalt | PcodeOpBadInstruction | PcodeOpUnimplemented | PcodeOpNoReturn | PcodeOpMissing)
}

// --- flag mutation ---

func (op *PcodeOp) SetFlag(fl uint32)             { op.flags |= fl }
func (op *PcodeOp) ClearFlag(fl uint32)           { op.flags &^= fl }
func (op *PcodeOp) FlipFlag(fl uint32)            { op.flags ^= fl }
func (op *PcodeOp) HasFlag(fl uint32) bool        { return op.flags&fl != 0 }
func (op *PcodeOp) SetAdditionalFlag(fl uint32)   { op.addlFlags |= fl }
func (op *PcodeOp) ClearAdditionalFlag(fl uint32) { op.addlFlags &^= fl }

// SetOpcode assigns a new TypeOp, clearing all behavioral flags and
// re-applying those defined by the new TypeOp.
// C++ parity: PcodeOp::setOpcode
func (op *PcodeOp) SetOpcode(t TypeOp) {
	op.flags &^= behavioralFlags
	op.opcode = t
	if t != nil {
		op.flags |= t.GetFlags()
	}
}

// --- input/output mutation ---

func (op *PcodeOp) SetOutput(vn *Varnode)          { op.output = vn }
func (op *PcodeOp) SetInput(vn *Varnode, slot int) { op.inputs[slot] = vn }
func (op *PcodeOp) ClearInput(slot int)            { op.inputs[slot] = nil }

// SetNumInputs resizes the input slice, preserving existing entries.
func (op *PcodeOp) SetNumInputs(n int) {
	if n <= len(op.inputs) {
		op.inputs = op.inputs[:n]
		return
	}
	grown := make([]*Varnode, n)
	copy(grown, op.inputs)
	op.inputs = grown
}

// RemoveInput splices out the input at the given slot.
func (op *PcodeOp) RemoveInput(slot int) {
	op.inputs = append(op.inputs[:slot], op.inputs[slot+1:]...)
}

// InsertInput inserts a nil slot at the given position.
func (op *PcodeOp) InsertInput(slot int) {
	op.inputs = append(op.inputs, nil)
	copy(op.inputs[slot+1:], op.inputs[slot:])
	op.inputs[slot] = nil
}

func (op *PcodeOp) SetParent(p *BlockBasic) { op.parent = p }

// NextOp returns the next op in the basic block.
// Stub: requires BlockBasic iteration (WU4).
func (op *PcodeOp) NextOp() *PcodeOp { return nil }

// PreviousOp returns the previous op in the basic block.
// Stub: requires BlockBasic iteration (WU4).
func (op *PcodeOp) PreviousOp() *PcodeOp { return nil }

// String returns a debug representation of this op.
func (op *PcodeOp) String() string {
	var sb strings.Builder
	sb.WriteString(op.seq.Address.String())
	sb.WriteString(fmt.Sprintf(":%d ", op.seq.Order))
	if op.opcode != nil {
		sb.WriteString(op.opcode.GetName())
	} else {
		sb.WriteString("???")
	}
	if op.output != nil {
		sb.WriteString(" out")
	}
	sb.WriteString(fmt.Sprintf(" [%d inputs]", len(op.inputs)))
	if op.IsDead() {
		sb.WriteString(" (dead)")
	}
	return sb.String()
}
