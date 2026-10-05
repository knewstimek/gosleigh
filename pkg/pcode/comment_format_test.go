package pcode

import (
	"strings"
	"testing"
)

// The expectations follow EmitPrettyPrint's rules: 100-column lines, the
// "   " fill on continuation lines, '\n' as a forced break, a trailing blank
// before a forced break kept, and the closing delimiter glued to the text.
func TestFormatLineComment(t *testing.T) {
	short := formatLineComment("WARNING: Removing unreachable block (ram,0x00401000)", 0)
	if len(short) != 1 || short[0] != "/* WARNING: Removing unreachable block (ram,0x00401000) */" {
		t.Fatalf("short comment: %q", short)
	}

	word := strings.Repeat("x", 30)
	long := formatLineComment("Head line\n "+strings.Repeat(word+" ", 5)+"\n\nTail", 0)
	want := []string{
		"/* Head line",
		"    " + strings.Join([]string{word, word, word}, " "),
		"   " + word + " " + word + " ",
		"   ",
		"   Tail */",
	}
	if strings.Join(long, "|") != strings.Join(want, "|") {
		t.Fatalf("long comment:\n got %q\nwant %q", long, want)
	}
}
