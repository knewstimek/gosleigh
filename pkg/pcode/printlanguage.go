package pcode

import "strings"

// ExprPrecedence uses larger numbers for tighter binding.
type ExprPrecedence int

const (
	ExprPrecLowest ExprPrecedence = iota
	ExprPrecAssign
	ExprPrecConditional
	ExprPrecLogicalOr
	ExprPrecLogicalAnd
	ExprPrecBitOr
	ExprPrecBitXor
	ExprPrecBitAnd
	ExprPrecEquality
	ExprPrecRelational
	ExprPrecShift
	ExprPrecAdd
	ExprPrecMultiply
	ExprPrecCast
	ExprPrecUnary
	ExprPrecPostfix
	ExprPrecPrimary
)

type ExprAssociativity uint8

const (
	ExprAssocNone ExprAssociativity = iota
	ExprAssocLeft
	ExprAssocRight
)

type ExprPosition uint8

const (
	ExprPosNone ExprPosition = iota
	ExprPosLeft
	ExprPosRight
)

// ExprFragment is a rendered expression plus the precedence it binds at.
type ExprFragment struct {
	Text       string
	Precedence ExprPrecedence
}

// PrintLanguage owns shared token and expression helpers used by concrete printers.
type PrintLanguage struct {
	emitter TokenEmitter
}

func NewPrintLanguage(emitter TokenEmitter) *PrintLanguage {
	if emitter == nil {
		emitter = NewTextEmitter()
	}
	return &PrintLanguage{emitter: emitter}
}

func (pl *PrintLanguage) Emitter() TokenEmitter {
	return pl.emitter
}

func (pl *PrintLanguage) Reset() {
	pl.emitter.Reset()
}

func (pl *PrintLanguage) String() string {
	return pl.emitter.String()
}

func (pl *PrintLanguage) Token(text string) {
	pl.emitter.Emit(text)
}

func (pl *PrintLanguage) Tokens(tokens ...string) {
	for _, token := range tokens {
		pl.Token(token)
	}
}

func (pl *PrintLanguage) Word(word string) {
	pl.Token(word)
}

func (pl *PrintLanguage) Words(words ...string) {
	for i, word := range words {
		if i > 0 {
			pl.Space()
		}
		pl.Word(word)
	}
}

func (pl *PrintLanguage) Space() {
	pl.emitter.Space()
}

func (pl *PrintLanguage) Newline() {
	pl.emitter.Newline()
}

func (pl *PrintLanguage) BlankLine() {
	pl.Newline()
	pl.Newline()
}

func (pl *PrintLanguage) Indent() {
	pl.emitter.Indent()
}

func (pl *PrintLanguage) Dedent() {
	pl.emitter.Dedent()
}

func (pl *PrintLanguage) Line(fn func()) {
	if fn != nil {
		fn()
	}
	pl.Newline()
}

func (pl *PrintLanguage) Statement(fn func()) {
	pl.Line(func() {
		if fn != nil {
			fn()
		}
		pl.Token(";")
	})
}

func (pl *PrintLanguage) OpenBlock() {
	pl.Token("{")
	pl.Newline()
	pl.Indent()
}

func (pl *PrintLanguage) CloseBlock() {
	pl.Dedent()
	pl.Token("}")
	pl.Newline()
}

func (pl *PrintLanguage) OpenBlockAfter(prefix func()) {
	if prefix != nil {
		prefix()
		pl.Space()
	}
	pl.OpenBlock()
}

func (pl *PrintLanguage) CloseBlockWithSuffix(suffix func()) {
	pl.Dedent()
	pl.Token("}")
	if suffix != nil {
		pl.Space()
		suffix()
	}
	pl.Newline()
}

func (pl *PrintLanguage) Label(name string) {
	pl.Token(name)
	pl.Token(":")
	pl.Newline()
}

func (pl *PrintLanguage) Expr(text string, precedence ExprPrecedence) ExprFragment {
	return ExprFragment{Text: text, Precedence: precedence}
}

func (pl *PrintLanguage) Atom(text string) ExprFragment {
	return pl.Expr(text, ExprPrecPrimary)
}

func (pl *PrintLanguage) GroupExpr(expr ExprFragment) ExprFragment {
	return ExprFragment{Text: "(" + expr.Text + ")", Precedence: ExprPrecPrimary}
}

func (pl *PrintLanguage) ExprString(expr ExprFragment, parent ExprPrecedence, pos ExprPosition, assoc ExprAssociativity) string {
	if expr.Text == "" {
		return ""
	}
	if !needsExprParens(expr.Precedence, parent, pos, assoc) {
		return expr.Text
	}
	return "(" + expr.Text + ")"
}

func (pl *PrintLanguage) EmitExpr(expr ExprFragment) {
	pl.Token(expr.Text)
}

func (pl *PrintLanguage) EmitChildExpr(expr ExprFragment, parent ExprPrecedence, pos ExprPosition, assoc ExprAssociativity) {
	pl.Token(pl.ExprString(expr, parent, pos, assoc))
}

func (pl *PrintLanguage) UnaryExpr(op string, precedence ExprPrecedence, expr ExprFragment) ExprFragment {
	return ExprFragment{
		Text:       op + pl.ExprString(expr, precedence, ExprPosRight, ExprAssocRight),
		Precedence: precedence,
	}
}

func (pl *PrintLanguage) BinaryExpr(left ExprFragment, op string, right ExprFragment, precedence ExprPrecedence, assoc ExprAssociativity) ExprFragment {
	var builder strings.Builder
	builder.WriteString(pl.ExprString(left, precedence, ExprPosLeft, assoc))
	builder.WriteByte(' ')
	builder.WriteString(op)
	builder.WriteByte(' ')
	builder.WriteString(pl.ExprString(right, precedence, ExprPosRight, assoc))
	return ExprFragment{Text: builder.String(), Precedence: precedence}
}

func (pl *PrintLanguage) PostfixExpr(expr ExprFragment, suffix string) ExprFragment {
	return ExprFragment{
		Text:       pl.ExprString(expr, ExprPrecPostfix, ExprPosLeft, ExprAssocLeft) + suffix,
		Precedence: ExprPrecPostfix,
	}
}

func (pl *PrintLanguage) CallExpr(callee ExprFragment, args ...ExprFragment) ExprFragment {
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = arg.Text
	}
	return ExprFragment{
		Text:       pl.ExprString(callee, ExprPrecPostfix, ExprPosLeft, ExprAssocLeft) + "(" + strings.Join(parts, ", ") + ")",
		Precedence: ExprPrecPostfix,
	}
}

func (pl *PrintLanguage) CastExpr(typeName string, expr ExprFragment) ExprFragment {
	return ExprFragment{
		Text:       "(" + typeName + ")" + pl.ExprString(expr, ExprPrecCast, ExprPosRight, ExprAssocRight),
		Precedence: ExprPrecCast,
	}
}

func needsExprParens(child ExprPrecedence, parent ExprPrecedence, pos ExprPosition, assoc ExprAssociativity) bool {
	if parent == ExprPrecLowest || child == ExprPrecPrimary {
		return false
	}
	if child < parent {
		return true
	}
	if child > parent {
		return false
	}
	switch assoc {
	case ExprAssocLeft:
		return pos == ExprPosRight
	case ExprAssocRight:
		return pos == ExprPosLeft
	default:
		return pos != ExprPosNone
	}
}
