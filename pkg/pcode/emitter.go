package pcode

import "strings"

// TokenEmitter is the low-level sink used by language printers.
// It centralizes deterministic whitespace, indentation, and newline handling.
type TokenEmitter interface {
	Emit(text string)
	Space()
	Newline()
	Indent()
	Dedent()
	Reset()
	String() string
}

// TextEmitter renders tokens into a string builder with stable formatting.
type TextEmitter struct {
	builder      strings.Builder
	indentUnit   string
	indentLevel  int
	lineStart    bool
	pendingSpace bool
}

func NewTextEmitter() *TextEmitter {
	return NewTextEmitterWithIndent("    ")
}

func NewTextEmitterWithIndent(indent string) *TextEmitter {
	return &TextEmitter{
		indentUnit: indent,
		lineStart:  true,
	}
}

func (e *TextEmitter) Emit(text string) {
	if text == "" {
		return
	}
	parts := strings.Split(text, "\n")
	for i, part := range parts {
		if i > 0 {
			e.Newline()
		}
		if part == "" {
			continue
		}
		e.ensureLinePrefix()
		if e.pendingSpace {
			e.builder.WriteByte(' ')
			e.pendingSpace = false
		}
		e.builder.WriteString(part)
	}
}

func (e *TextEmitter) Space() {
	if e.lineStart {
		return
	}
	e.pendingSpace = true
}

func (e *TextEmitter) Newline() {
	e.pendingSpace = false
	e.builder.WriteByte('\n')
	e.lineStart = true
}

func (e *TextEmitter) Indent() {
	e.indentLevel++
}

func (e *TextEmitter) Dedent() {
	if e.indentLevel > 0 {
		e.indentLevel--
	}
}

func (e *TextEmitter) Reset() {
	e.builder.Reset()
	e.indentLevel = 0
	e.lineStart = true
	e.pendingSpace = false
}

func (e *TextEmitter) String() string {
	return e.builder.String()
}

func (e *TextEmitter) ensureLinePrefix() {
	if !e.lineStart {
		return
	}
	for i := 0; i < e.indentLevel; i++ {
		e.builder.WriteString(e.indentUnit)
	}
	e.lineStart = false
}
