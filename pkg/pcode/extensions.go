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

	// NoFloatAddresses keeps a float type from propagating into a value that
	// forms an address (a LOAD/STORE address, or the base of the addition
	// computing one). Ghidra ranks float above integer, so a stack slot first
	// holding `this` (homed RCX) and later reused as a double temporary types
	// `this` as double across the COPY into the slot, printing every field
	// access as bit_cast<longlong>(param_1) + off.
	NoFloatAddresses bool

	// SelfCancelNoUse stops a parameter trial's use check at x ^ x and
	// x - x: the result is a constant, not a use of x. `xor r9d, r9d` after
	// a call reads the R9 passed to it; when the zero then reaches a callee
	// with a locked prototype (Funcdata::checkCallDoubleUse), Ghidra drops
	// the R9 argument of the earlier call.
	SelfCancelNoUse bool

	// StaleStackArgBytes takes only the low bytes of a stack argument whose
	// slot is written partly right before the call (mov byte [rsp+0x30], 3)
	// while its high bytes come from an earlier, wider use of the slot.
	// Ghidra's ActionParamDouble splits such a PIECE only when both halves can
	// be parameters, which an x64 8-byte stack slot never allows, so the
	// argument prints as CONCAT71(in_stack_.., 3) or in_stack_.. & 0xff..00.
	StaleStackArgBytes bool

	// StaleStackArgs does not take an x64 stack slot as an argument when its
	// value reaches the call through another call (an INDIRECT): the
	// outgoing parameter area belongs to each callee, so a compiler writes
	// arguments after the previous call. Ghidra's onlyOpUse accepts a slot
	// written once in the prologue (MSVC's EH state, mov [rsp+0x20], -2)
	// whose only reads are calls, so once an earlier register argument is
	// found the call gains in_R8, in_R9 and the -2.
	StaleStackArgs bool

	// FoldedStackCopies keeps a copy of one stack variable into another
	// (b = a, with a filled in by a call such as GetEnumerator(&a)) live
	// after RulePropagateCopy folds it into a loop MULTIEQUAL. Ghidra's
	// ActionDirectWrite counts such a stack store as a direct write only
	// while the COPY exists; once folded, b's INDIRECTs at the calls taking
	// &b lose their address force, and when every path ends in a noreturn
	// call dead code removal drops the copy: MoveNext(&b) reads the zeroed b.
	FoldedStackCopies bool

	// FloatGrouping parenthesizes a float + or * whose right operand is the
	// same operation: float arithmetic is not associative, and PrintC prints
	// a * (b * c) as a * b * c, which C evaluates as (a * b) * c.
	FloatGrouping bool
}

// staleHighPiece reports a stack argument assembled as PIECE(high, low) where
// low is written between the previous call in the block (or the block start)
// and this call, and high is not: a compiler writes an argument whole right
// before its call, so the high bytes are left over from an earlier, wider use
// of the slot (often the previous call's argument).
func staleHighPiece(fd *Funcdata, call *PcodeOp, high, low *Varnode) bool {
	blk, at := call.Parent(), call.Seq().Order
	since, prev := uint64(0), false // order of the last call before this one in blk
	for i := 0; i < fd.NumCalls(); i++ {
		c := fd.GetCallSpecs(i)
		if c == nil || c.op == nil || c.op == call || c.op.Parent() != blk {
			continue
		}
		if o := c.op.Seq().Order; o < at && (!prev || o > since) {
			since, prev = o, true
		}
	}
	inWindow := func(op *PcodeOp) bool {
		o := op.Seq().Order
		return op.Parent() == blk && o < at && (!prev || o > since)
	}
	if !low.IsWritten() || low.Def() == nil || !inWindow(low.Def()) {
		return false
	}
	return !high.IsWritten() || high.Def() == nil || !inWindow(high.Def())
}

// formsAddress reports a Varnode used as a LOAD or STORE address, directly or
// through up to depth additions, pointer arithmetic or copies.
func formsAddress(vn *Varnode, depth int) bool {
	for _, op := range vn.descend {
		switch op.Code() {
		case CPUI_LOAD, CPUI_STORE:
			if op.NumInput() > 1 && op.Input(1) == vn {
				return true
			}
		case CPUI_INT_ADD, CPUI_PTRADD, CPUI_PTRSUB, CPUI_COPY:
			if depth > 0 && op.Output() != nil && formsAddress(op.Output(), depth-1) {
				return true
			}
		}
	}
	return false
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

// applyCalleePrototypeHint locks the callee's inputs to the list the hint
// source infers, when the host does not lock them (beyond Ghidra, see
// HostCalleePrototype). The host's return lock, if any, is kept; the extrapop
// comes from the default model when the host gives none.
func (fc *FuncCallSpecs) applyCalleePrototypeHint(fd *Funcdata) {
	// A host prototype with parameters, locked or not, carries their types
	// (a method's this pointer); the inferred list would replace them.
	if fc.entryAddress.Space == nil || (fc.hostProto != nil && (fc.hostProto.InputLocked || len(fc.hostProto.UnlockedParams) > 0)) {
		return
	}
	h, ok := fd.calleeReads.(HostCalleePrototype)
	if !ok {
		return
	}
	params, ok := h.CalleeInputs(fc.entryAddress)
	if !ok {
		return
	}
	hf := HostFunction{ExtraPop: ExtrapopUnknown}
	if fc.hostProto != nil {
		hf = *fc.hostProto
	}
	if hf.ExtraPop == ExtrapopUnknown {
		if m := fd.DefaultModel(); m != nil {
			hf.ExtraPop = m.GetExtraPop()
		}
	}
	hf.InputLocked = true
	hf.Params = params
	fc.hostProto = &hf
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
	// Only the return is assigned storage here; base's inputs, possibly locked
	// to inferred storage (applyCalleePrototypeHint), are kept as they are.
	out := HostFunction{ExtraPop: base.ExtraPop, Model: base.Model, OutputLocked: true,
		Output: &HostParam{Size: size, Type: ResolveHostType(&HostTypeDesc{Name: name, Meta: "float", Size: size})}}
	assigned, ok := fd.assignCodeProtoStorage(&out)
	if !ok {
		return nil, false
	}
	hf := *base
	hf.OutputLocked, hf.Output, hf.ExtraPop = true, assigned.Output, assigned.ExtraPop
	return &hf, true
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
