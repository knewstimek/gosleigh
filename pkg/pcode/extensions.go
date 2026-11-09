package pcode

import "github.com/knewstimek/gosleigh/pkg/address"

// Extensions switches on core behavior beyond Ghidra. The zero value is the
// plain Ghidra port; every field is opt-in and listed in DIFFERENCES.md.
type Extensions struct {
	// NestedPieceTrials keeps parameter and return-value trials whose value
	// heritage joined from register parts in more than one level of PIECE.
	//
	// When an XMM register is written lane by lane (cvtdq2ps), as a scalar
	// with the upper lanes zeroed (movss from memory) and as a whole (movaps)
	// in one function, heritage joins it as PIECE(XMM0_Dd, PIECE(XMM0_Dc,
	// XMM0_Qa)) with SUBPIECEs between the levels. Ghidra then rejects the
	// XMM0_Qa trial in two places:
	//   - AncestorRealistic follows a PIECE only into a piece no larger than
	//     the trial, so the 12-byte low piece fails the path;
	//   - ancestorOpUse spends one of its 5 recursion levels on every PIECE
	//     and SUBPIECE and runs out before reaching the op that computed the
	//     value.
	// The float return is lost (the function prints as void and the code
	// computing the value is removed as dead), and so is a float argument in
	// XMM1..3 of a call to a function without a prototype.
	//
	// With this option AncestorRealistic follows a low piece that holds the
	// whole trial, and PIECE or same-register SUBPIECE steps do not use up
	// ancestorOpUse's recursion levels. Both are joins of one register's parts,
	// not data movement. Call arguments are first judged exactly as Ghidra
	// does; only a register trial Ghidra rejected is retested this way, and it
	// yields when Ghidra accepted another register of the same parameter slot
	// (a pointer in RDX beside a vector left in XMM1), so an argument Ghidra
	// recovers is never replaced.
	NestedPieceTrials bool

	// NarrowFloatReturns returns a 4-byte float as float when the output
	// slot is 8 bytes wide (x64 XMM0_Qa) and one path returns a float
	// parameter register unchanged; see isFloatReturn. Ghidra keeps all 8
	// bytes there, so the function returns ulonglong, every float result is
	// printed through (ulonglong)(uint) and the parameter becomes an integer.
	NarrowFloatReturns bool

	// NaNExactCompares keeps the negation of a float order comparison as
	// written, !(a < b), where Ghidra swaps it to b <= a (RuleBoolNegate
	// through get_booleanflip, and the printer's negated tokens). The two
	// differ when an operand is NaN, so minss and comiss/jnbe code printed
	// the NaN case taken the wrong way. It also keeps the NaN meaning of a
	// NaN test the decompiler drops (nanignore "compare"): Ghidra replaces
	// NaN || a < b by a < b and !NaN && !(a < b) by !(a < b), each with the
	// other value for NaN (comiss; ja prints its NaN case on the wrong
	// branch); the option rewrites the comparison to the NaN-free form with
	// the dropped test's value instead (!(b <= a), b <= a). To keep every NaN
	// test see decomp.Function.NaNIgnore (Ghidra's nanignore option).
	NaNExactCompares bool

	// BitCastSyntax prints a CAST between a float and an integer of the same
	// size as bit_cast<T>(x). Such a CAST reinterprets the bits (movd xmm0,
	// edx); a numeric conversion is a separate op (INT2FLOAT, TRUNC). Ghidra
	// prints both as (float)x, so (float)(x >> 9 | 0x3f800000) reads as a
	// conversion of the integer value.
	BitCastSyntax bool

	// FloatLoads keeps a narrow load of a float as a load. Ghidra widens a
	// load to the integer element its pointer points at and truncates it
	// (RuleExpandLoad: a natural integer truncation), so a float field read
	// through a longlong pointer prints as (int)p[0x3c8]. With the option a
	// load whose value is used as a float (by a float operation, or passed in
	// a float parameter slot) stays as it is.
	FloatLoads bool

	// CurrentSwitchLabels takes the case labels of a jump table from the
	// current model's normalized range when the flow-time model normalized a
	// different Varnode. Ghidra reverse-emulates the flow-time values through
	// the current path regardless, so a byte switch "lea eax,[rsi-0x80]"
	// printed case 0x100 for 0x80 (with "may not be properly labeled"). The
	// current range is used only when emulating it rebuilds the same address
	// table; see JumpTable.currentModelRelabels.
	CurrentSwitchLabels bool

	// AllocaReturnStores drops each call's return address store in a function
	// that moves its stack pointer by a register (alloca, "sub rsp, rax").
	// There Ghidra cannot place the store in the frame and prints one
	// "*(undefined8 *)((longlong)&local_10 + -param_1) = <return address>;" per call.
	// Other functions are not changed; see bridge.dropAllocaReturnStores.
	AllocaReturnStores bool
}

// isFloatOrder reports a float order comparison, whose negation is not the
// swapped comparison once NaN is possible.
func isFloatOrder(opc OpCode) bool {
	return opc == CPUI_FLOAT_LESS || opc == CPUI_FLOAT_LESSEQUAL
}

// SetCalleeReads installs a read-before-write hint source for callees (beyond
// Ghidra, see HostCalleeReads); nil (the default) is plain Ghidra.
func (fd *Funcdata) SetCalleeReads(r HostCalleeReads) { fd.calleeReads = r }

// SetExtensions selects the opt-in behavior beyond Ghidra for this function.
func (fd *Funcdata) SetExtensions(e Extensions) { fd.ext = e }

// Extensions returns the opt-in behavior beyond Ghidra for this function.
func (fd *Funcdata) Extensions() Extensions { return fd.ext }

// applyCalleeReturnHint locks the callee's return to the float the hint
// source reports, when the host does not lock it (beyond Ghidra, see
// HostCalleeReturn). The extrapop comes from the model, as for any host
// prototype without one. It runs in ActionDefaultParams, where the default
// model the storage is assigned from is set; at call-spec construction it may
// not be yet (assignCodeProtoStorage then fails and the hint was lost).
func (fc *FuncCallSpecs) applyCalleeReturnHint(fd *Funcdata) {
	if fc.entryAddress.Space == nil || (fc.hostProto != nil && fc.hostProto.OutputLocked) {
		return
	}
	base := &HostFunction{ExtraPop: ExtrapopUnknown}
	if fc.hostProto != nil {
		base = fc.hostProto
	}
	if assigned, good := fd.floatReturnProto(fc.entryAddress, base); good {
		fc.hostProto = assigned
		fc.returnHinted = true
	}
}

// floatReturnProto is base with its return locked to the float the hint
// source reports for the function at entry (beyond Ghidra, HostCalleeReturn),
// storage assigned from the model; false without a hint or a float return.
func (fd *Funcdata) floatReturnProto(entry address.Address, base *HostFunction) (*HostFunction, bool) {
	r, ok := fd.calleeReads.(HostCalleeReturn)
	if !ok {
		return nil, false
	}
	size := r.CalleeFloatReturn(entry)
	if size != 4 && size != 8 {
		return nil, false
	}
	name := "float"
	if size == 8 {
		name = "double"
	}
	hf := *base
	hf.OutputLocked = true
	hf.Output = &HostParam{Size: size, Type: ResolveHostType(&HostTypeDesc{Name: name, Meta: "float", Size: size})}
	return fd.assignCodeProtoStorage(&hf)
}

// keepsInputAtOutput reports that heritage should still try the call's
// output range as an input (beyond Ghidra): the output was locked by
// applyCalleeReturnHint and the callee reads that register before writing
// it ("float f(float)" both in XMM0). Heritage::guardCalls skips the exact
// output range; with Ghidra's Java side the whole prototype is committed and
// the input comes from it, but the hint locks only the return.
func (fc *FuncCallSpecs) keepsInputAtOutput(addr address.Address, size int32) bool {
	if !fc.returnHinted || addr.Space == nil {
		return false
	}
	lo, hi := addr.Offset, addr.Offset+uint64(size)
	for _, r := range fc.calleeReads {
		if r.Space == addr.Space.Name && r.Offset < hi && lo < r.Offset+uint64(r.Size) {
			return true
		}
	}
	return false
}
