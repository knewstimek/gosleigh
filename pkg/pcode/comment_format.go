package pcode

import "strings"

// Comment layout constants of the C printer.
// C++ parity: EmitPrettyPrint maxlinesize (100); PrintC::setCStyleComments
// ("/* ", " */", fill = spaces the width of the start delimiter).
const (
	commentLineSize = 100
	commentStart    = "/* "
	commentEnd      = " */"
)

// formatLineComment lays out a comment the way PrintLanguage::emitLineComment
// feeds it through EmitPrettyPrint: words are tokens, runs of blanks are
// breakable spaces, '\n' forces a line, a continuation line starts with the
// comment fill, and a break is skipped when it would gain fewer than 10
// columns. indent is the column the comment starts at. Returns the lines
// without the leading indentation of the first line.
// C++ parity: printlanguage.cc emitLineComment, prettyprint.cc
// EmitPrettyPrint::print (tokenbreak / tokenstring) + overflow, checkstring.
func formatLineComment(text string, indent int) []string {
	fill := strings.Repeat(" ", len(commentStart))
	type tok struct {
		brk    bool // breakable spaces (or forced line when line is set)
		line   bool
		spaces int
		str    string
	}
	var toks []tok
	needbreak := false
	addStr := func(s string) {
		if needbreak { // checkstring: adjacent strings get a zero-width break
			toks = append(toks, tok{brk: true})
		}
		toks = append(toks, tok{str: s})
		needbreak = true
	}
	addBreak := func(t tok) {
		if !needbreak { // checkbreak: a break needs content before it
			toks = append(toks, tok{str: ""})
		}
		toks = append(toks, t)
		needbreak = false
	}
	addStr(commentStart)
	for pos := 0; pos < len(text); {
		c := text[pos]
		switch {
		case c == ' ' || c == '\t':
			n := 0
			for pos < len(text) && (text[pos] == ' ' || text[pos] == '\t') {
				n++
				pos++
			}
			addBreak(tok{brk: true, spaces: n})
		case c == '\n':
			addBreak(tok{brk: true, line: true})
			pos++
		case c == '\r':
			pos++
		default:
			start := pos
			for pos < len(text) && !isCommentSpace(text[pos]) {
				pos++
			}
			addStr(text[start:pos])
		}
	}
	addStr(commentEnd)

	// The size of a break is its spaces plus the string that follows it.
	size := func(i int) int {
		n := toks[i].spaces
		if i+1 < len(toks) && !toks[i+1].brk {
			n += len(toks[i+1].str)
		}
		return n
	}
	var lines []string
	var cur strings.Builder
	group := commentLineSize - indent // indentstack.back() for the comment group
	remain := group
	newline := func() {
		lines = append(lines, cur.String())
		cur.Reset()
		cur.WriteString(strings.Repeat(" ", commentLineSize-remain))
		cur.WriteString(fill)
		remain -= len(fill)
	}
	for i, t := range toks {
		switch {
		case t.brk && t.line: // tagLine(): a relative break that always fires
			remain = group
			newline()
		case t.brk:
			if size(i) > remain {
				if t.spaces <= remain && group-remain < 10 {
					cur.WriteString(strings.Repeat(" ", t.spaces))
					remain -= t.spaces
					continue
				}
				remain = group
				newline()
			} else {
				cur.WriteString(strings.Repeat(" ", t.spaces))
				remain -= t.spaces
			}
		default:
			if len(t.str) > remain && group != remain && group != remain+len(fill) {
				remain = group // overflow()
				newline()
			}
			cur.WriteString(t.str)
			remain -= len(t.str)
		}
	}
	return append(lines, cur.String())
}

func isCommentSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
