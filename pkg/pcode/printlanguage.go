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
	ExprPrecUnary
	ExprPrecPostfix
	ExprPrecPrimary
)

// ExprPrecCast aliases ExprPrecUnary: a C cast binds at the same precedence as the
// unary prefix operators (* & ! ~ prefix +/-), so e.g. *(int *)x needs no
// parentheses around the cast. C++ parity: PrintC::dereference and PrintC::typecast
// OpTokens both use precedence 62 (printc.cc:34-35); PrintLanguage::parentheses
// (printlanguage.cc) returns false for a presurround (cast) operand under a
// unary_prefix parent at equal precedence.
const ExprPrecCast = ExprPrecUnary

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
// op records the binary operator token that produced the fragment (empty for
// non-binary fragments); it lets the parenthesization rule distinguish two
// same-precedence operators (e.g. + vs -) the way Ghidra's OpToken identity
// comparison does. C++ parity: PrintLanguage::parentheses (printlanguage.cc:281).
type ExprFragment struct {
	Text       string
	Precedence ExprPrecedence
	op         string
	// left/right are the unparenthesized child fragments of a binary fragment,
	// with leftParen/rightParen recording whether binaryChildString wrapped them.
	// Retaining the children keeps the whole expression tree available at emit
	// time, so EmitFragment can reproduce Ghidra's per-operator token stream
	// (a group per operator node, spaces(spacing,bump) on both sides of the
	// operator, openParen/closeParen groups for parenthesized operands) instead
	// of handing the pretty-printer one opaque content token. C++ parity: the
	// RPN stack in PrintLanguage::pushOp/pushAtom never flattens a subtree.
	left       *ExprFragment
	right      *ExprFragment
	leftParen  bool
	rightParen bool
}

// associativeBinaryOps are the binary operators Ghidra marks associative in its
// OpToken table (printc.cc): two adjacent uses at equal precedence do NOT require
// parentheses. All other equal-precedence adjacencies are parenthesized.
var associativeBinaryOps = map[string]bool{"*": true, "+": true, "&": true, "^": true, "|": true}

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

// GroupEmitter is the optional part of the emitter contract that carries
// expression structure: printing groups, parenthesis groups, and operator break
// points. Only the pretty-printing emitter implements it; a plain TextEmitter
// does not, in which case EmitFragment falls back to a single flat token (the
// rendered characters are identical either way, only break opportunities are
// lost). C++ parity: the Emit base class declares openGroup/closeGroup/
// openParen/closeParen/spaces, and EmitNoMarkup ignores the grouping ones.
type GroupEmitter interface {
	OpenGroup() int
	CloseGroup(id int)
	OpenParen(paren string) int
	CloseParen(paren string, id int)
	Spaces(num, bump int)
}

// binaryOpBump is OpToken::bump for the binary operators PrintC builds through
// BinaryExpr. Every one of them is spacing=1/bump=0 in printc.cc:36-57; only the
// assignment family carries bump=5, and assignments are emitted by the statement
// printer (EmitAssignFragment) rather than through BinaryExpr.
const binaryOpBump = 0

// binaryOpSpacing is OpToken::spacing for those same operators (printc.cc:36-57).
const binaryOpSpacing = 1

// assignOpBump is OpToken::bump for PrintC::assignment (printc.cc:56).
const assignOpBump = 5

// EmitFragment emits an expression as the nested token stream Ghidra produces,
// so the Oppen pretty-printer can break at any operator boundary rather than
// only between statement-level tokens. Each binary node becomes
// openGroup / left / spaces(spacing,bump) / op / spaces(spacing,bump) / right /
// closeGroup, and a parenthesized operand becomes an openParen/closeParen group,
// mirroring PrintLanguage::pushOp + emitOp + pushAtom (printlanguage.cc:129-187,
// 329-338). Nodes Gosleigh still renders as flat strings (unary, cast, call,
// subscript, ...) are emitted as single content tokens; they contribute no break
// point, exactly as they would if their internal spaces() calls were absent.
func (pl *PrintLanguage) EmitFragment(expr ExprFragment) {
	ge, ok := pl.emitter.(GroupEmitter)
	if !ok {
		pl.Token(expr.Text)
		return
	}
	pl.emitFragmentTree(ge, expr)
}

// EmitAssignFragment emits "lhs = rhs" with the assignment operator's own break
// points and bump, then the rhs as a structured sub-expression. C++ parity:
// PrintC::opCopy etc. push PrintC::assignment (spacing 1, bump 5) and let
// emitOp place spaces(1,5) on both sides of "=" (printc.cc:56,
// printlanguage.cc:333-338).
func (pl *PrintLanguage) EmitAssignFragment(lhs string, rhs ExprFragment) {
	ge, ok := pl.emitter.(GroupEmitter)
	if !ok {
		pl.Token(lhs)
		pl.Space()
		pl.Token("=")
		pl.Space()
		pl.Token(rhs.Text)
		return
	}
	id := ge.OpenGroup()
	pl.Token(lhs)
	ge.Spaces(binaryOpSpacing, assignOpBump)
	pl.Token("=")
	ge.Spaces(binaryOpSpacing, assignOpBump)
	pl.emitFragmentTree(ge, rhs)
	ge.CloseGroup(id)
}

func (pl *PrintLanguage) emitFragmentTree(ge GroupEmitter, expr ExprFragment) {
	if expr.op == "" || expr.left == nil || expr.right == nil {
		pl.Token(expr.Text)
		return
	}
	id := ge.OpenGroup()
	pl.emitFragmentOperand(ge, *expr.left, expr.leftParen)
	ge.Spaces(binaryOpSpacing, binaryOpBump)
	pl.Token(expr.op)
	ge.Spaces(binaryOpSpacing, binaryOpBump)
	pl.emitFragmentOperand(ge, *expr.right, expr.rightParen)
	ge.CloseGroup(id)
}

func (pl *PrintLanguage) emitFragmentOperand(ge GroupEmitter, child ExprFragment, paren bool) {
	if !paren {
		pl.emitFragmentTree(ge, child)
		return
	}
	id := ge.OpenParen("(")
	pl.emitFragmentTree(ge, child)
	ge.CloseParen(")", id)
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
	leftStr, leftParen := pl.binaryChild(left, op, precedence)
	rightStr, rightParen := pl.binaryChild(right, op, precedence)
	leftChild, rightChild := left, right
	return ExprFragment{
		Text:       leftStr + " " + op + " " + rightStr,
		Precedence: precedence,
		op:         op,
		left:       &leftChild,
		right:      &rightChild,
		leftParen:  leftParen,
		rightParen: rightParen,
	}
}

// binaryChildString parenthesizes a binary operand following Ghidra's rule
// (PrintLanguage::parentheses, printlanguage.cc:278-287): a child binding looser
// than the parent is parenthesized; a child binding tighter is not; at equal
// precedence the child is parenthesized UNLESS it is the same associative operator
// as the parent. This differs from textbook C left/right associativity: Ghidra
// parenthesizes e.g. (a + b) - c and (a - b) - c because '-' is non-associative
// and '+' != '-'.
func (pl *PrintLanguage) binaryChildString(child ExprFragment, parentOp string, parentPrec ExprPrecedence) string {
	s, _ := pl.binaryChild(child, parentOp, parentPrec)
	return s
}

// binaryChild is binaryChildString plus the parenthesization decision itself,
// which EmitFragment needs in order to emit an openParen/closeParen group
// instead of literal "(" / ")" characters inside a flat token.
func (pl *PrintLanguage) binaryChild(child ExprFragment, parentOp string, parentPrec ExprPrecedence) (string, bool) {
	if child.Text == "" {
		return "", false
	}
	paren := false
	switch {
	case child.Precedence == ExprPrecPrimary || parentPrec == ExprPrecLowest:
		paren = false
	case child.Precedence < parentPrec:
		paren = true
	case child.Precedence > parentPrec:
		paren = false
	default:
		paren = !(child.op == parentOp && associativeBinaryOps[parentOp])
	}
	if paren {
		return "(" + child.Text + ")", true
	}
	return child.Text, false
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

// mostNaturalBase returns 16 (hex) or 10 (decimal) as the more natural radix for
// displaying val, counting runs of 0/9 decimal digits vs runs of 0/f hex digits.
// C++ parity: PrintLanguage::mostNaturalBase (printlanguage.cc:735).
func mostNaturalBase(val uint64) int {
	countdec := 0 // Count trailing run of 0's or 9's (decimal)
	tmp := val
	if tmp == 0 {
		return 10
	}
	setdig := int(tmp % 10)
	if setdig == 0 || setdig == 9 {
		countdec++
		tmp /= 10
		for tmp != 0 {
			dig := int(tmp % 10)
			if dig == setdig {
				countdec++
			} else {
				break
			}
			tmp /= 10
		}
	}
	switch countdec {
	case 0:
		return 16
	case 1:
		if tmp > 1 || setdig == 9 {
			return 16
		}
	case 2:
		if tmp > 10 {
			return 16
		}
	case 3, 4:
		if tmp > 100 {
			return 16
		}
	default:
		if tmp > 1000 {
			return 16
		}
	}

	counthex := 0 // Count trailing run of 0's or f's (hex)
	tmp = val
	setdig = int(tmp & 0xf)
	if setdig == 0 || setdig == 0xf {
		counthex++
		tmp >>= 4
		for tmp != 0 {
			dig := int(tmp & 0xf)
			if dig == setdig {
				counthex++
			} else {
				break
			}
			tmp >>= 4
		}
	}

	if countdec > counthex {
		return 10
	}
	return 16
}
