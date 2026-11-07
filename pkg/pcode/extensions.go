package pcode

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
}

// SetExtensions selects the opt-in behavior beyond Ghidra for this function.
func (fd *Funcdata) SetExtensions(e Extensions) { fd.ext = e }

// Extensions returns the opt-in behavior beyond Ghidra for this function.
func (fd *Funcdata) Extensions() Extensions { return fd.ext }
