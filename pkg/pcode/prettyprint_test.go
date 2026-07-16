package pcode

import "testing"

// emitAssign drives the emitter the way emitStatement does for an assignment:
// Token(lhs) Space "=" Space Token(rhs) ";" then newline. This mirrors the exact
// call sequence PrintC.emitStatement produces, so the test exercises the real
// integration surface rather than a synthetic token stream.
func emitAssign(e *PrettyEmitter, lhs, rhs string) string {
	e.Emit(lhs)
	e.Space()
	e.Emit("=")
	e.Space()
	e.Emit(rhs)
	e.Emit(";")
	e.Newline()
	return e.String()
}

func TestPrettyEmitterShortNoWrap(t *testing.T) {
	e := NewPrettyEmitter("", ppMaxLineSizeDefault)
	got := emitAssign(e, "local_14", "0")
	want := "local_14 = 0;\n"
	if got != want {
		t.Fatalf("short assignment wrapped or diverged:\n got %q\nwant %q", got, want)
	}
}

// TestPrettyEmitterAssignWrap reproduces the bump_scores store statement: the
// joined line is 105 chars (> 100), so Ghidra breaks after "=" with the right
// operand on the next line. C++ parity: EmitPrettyPrint over the assignment
// OpToken's two whitespace breaks (printc.cc assignment; prettyprint.cc scan).
func TestPrettyEmitterAssignWrap(t *testing.T) {
	lhs := "*(int *)(param_1 + 4 + (longlong)local_18 * 8)"
	rhs := "*(int *)(param_1 + 4 + (longlong)local_18 * 8) + param_3"
	e := NewPrettyEmitter("", ppMaxLineSizeDefault)
	got := emitAssign(e, lhs, rhs)
	// Break falls after "=", right operand starts a new line. Continuation indent
	// is discarded (goldens are stored un-indented); only the break position matters.
	want := "*(int *)(param_1 + 4 + (longlong)local_18 * 8) =\n" +
		"*(int *)(param_1 + 4 + (longlong)local_18 * 8) + param_3;\n"
	if got != want {
		t.Fatalf("assignment wrap mismatch:\n got %q\nwant %q", got, want)
	}
}

// TestPrettyEmitterNoTrailingSpace guards the space-before-newline case: a Space
// immediately followed by Newline must not leave a trailing space, matching
// TextEmitter's pending-space semantics.
func TestPrettyEmitterNoTrailingSpace(t *testing.T) {
	e := NewPrettyEmitter("", ppMaxLineSizeDefault)
	e.Emit("a")
	e.Space()
	e.Newline()
	e.Emit("b")
	e.Newline()
	got := e.String()
	want := "a\nb\n"
	if got != want {
		t.Fatalf("trailing space or divergence:\n got %q\nwant %q", got, want)
	}
}
