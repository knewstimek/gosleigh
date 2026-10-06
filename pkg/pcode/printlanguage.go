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
	// node carries the operator structure of a non-binary fragment (call,
	// cast, unary prefix, scope, comma) for EmitFragment; nil for atoms and
	// for fragments only known as flat text.
	node *fragNode
	// member is the member-access token ("." or "->") when the fragment
	// is a member access.
	member string
	// hidden marks an operand printed through a hidden operator token (an
	// implied extension): at equal precedence it is parenthesized even under
	// the same associative operator. C++ parity: PrintLanguage::parentheses,
	// OpToken::hiddenfunction case.
	hidden bool
}

// fragKind is OpToken::tokentype for the structured fragment forms.
type fragKind int

const (
	fragBinary       fragKind = iota // child0 spaces op spaces child1
	fragUnaryPrefix                  // op spaces child0
	fragPostSurround                 // child0 spaces open spaces child1 close
	fragPreSurround                  // open child0 close spaces child1
	fragSpace                        // child0 spaces child1
	fragComma                        // child0 "," spaces child1 (comma_separate)
	fragParen                        // "(" child0 ")" as a parenthesis group
	fragCondJoin                     // child0 spaces op spaces child1, no group (emitBlockCondition)
	fragStatement                    // child0 inside a statement delimiter (begin/endStatement)
)

// fragNode mirrors one ReversePolish entry: an OpToken with its operands.
// parens[i] records whether operand i is wrapped in an openParen group.
// C++ parity: printlanguage.cc PrintLanguage::emitOp / pushOp.
type fragNode struct {
	kind           fragKind
	print1, print2 string
	spacing, bump  int
	kids           []ExprFragment
	parens         []bool
}

// associativeBinaryOps are the binary operators Ghidra marks associative in its
// OpToken table (printc.cc): two adjacent uses at equal precedence do NOT require
// parentheses. All other equal-precedence adjacencies are parenthesized.
var associativeBinaryOps = map[string]bool{"*": true, "+": true, "&": true, "^": true, "|": true}

// PrintLanguage owns shared token and expression helpers used by concrete printers.
type PrintLanguage struct {
	emitter TokenEmitter
	// noCommaSpace prints call arguments as "a,b" (Ghidra format).
	// C++ parity: printc.cc PrintC::comma has spacing 0.
	noCommaSpace bool
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

// StatementGroup emits fn inside a statement delimiter group, so a line
// break prefers the space in front of it. C++ parity: Emit::beginStatement /
// endStatement.
func (pl *PrintLanguage) StatementGroup(fn func()) {
	ge, ok := pl.emitter.(GroupEmitter)
	if !ok {
		fn()
		return
	}
	id := ge.OpenGroup()
	fn()
	ge.CloseGroup(id)
}

func (pl *PrintLanguage) OpenBlock() {
	// The indent opens before the line break so the first statement's width
	// is measured at the block's indent. C++ parity: PrintC emits
	// startIndent then tagLine before each statement.
	pl.Token("{")
	pl.Indent()
	pl.Newline()
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
	return ExprFragment{Text: "(" + expr.Text + ")", Precedence: ExprPrecPrimary, node: &fragNode{
		kind: fragParen, kids: []ExprFragment{expr}, parens: []bool{true}}}
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

// EmitAssignFragments is EmitAssignFragment with a structured left side.
// C++ parity: PrintC::opStore (assignment over the dereference expression).
func (pl *PrintLanguage) EmitAssignFragments(lhs, rhs ExprFragment) {
	ge, ok := pl.emitter.(GroupEmitter)
	if !ok {
		pl.EmitAssignFragment(pl.ExprString(lhs, cPrecAssign, ExprPosNone, ExprAssocNone), rhs)
		return
	}
	id := ge.OpenGroup()
	pl.emitFragmentOperand(ge, lhs, needsExprParens(lhs.Precedence, cPrecAssign, ExprPosLeft, ExprAssocRight))
	ge.Spaces(binaryOpSpacing, assignOpBump)
	pl.Token("=")
	ge.Spaces(binaryOpSpacing, assignOpBump)
	pl.emitFragmentTree(ge, rhs)
	ge.CloseGroup(id)
}

func (pl *PrintLanguage) emitFragmentTree(ge GroupEmitter, expr ExprFragment) {
	pl.emitFragmentTreeIn(ge, expr, true)
}

// emitFragmentTreeIn emits expr; ownGroup is false when the caller's paren
// already is the operator's printing group. C++ parity: PrintLanguage::pushOp
// opens either openParen or openGroup for an operator, never both.
func (pl *PrintLanguage) emitFragmentTreeIn(ge GroupEmitter, expr ExprFragment, ownGroup bool) {
	if n := expr.node; n != nil {
		if n.kind == fragParen {
			// Structural parentheses (emitBlockCondition's openParen) are the
			// group themselves.
			id := ge.OpenParen("(")
			pl.emitFragmentTree(ge, n.kids[0])
			ge.CloseParen(")", id)
			return
		}
		if n.kind == fragCondJoin {
			// A structured &&/|| between condition blocks is emitted without an
			// operator group. C++ parity: PrintC::emitBlockCondition (emitOp on
			// a ReversePolish that was never pushed).
			pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
			ge.Spaces(n.spacing, n.bump)
			pl.Token(n.print1)
			ge.Spaces(n.spacing, n.bump)
			pl.emitFragmentOperand(ge, n.kids[1], n.parens[1])
			return
		}
		if n.kind == fragComma {
			// The comma separating comma_separate statements is plain output,
			// not an operator: no printing group of its own.
			// C++ parity: PrintC::emitBlockBasic (print(COMMA); spaces(1)).
			pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
			pl.Token(n.print1)
			ge.Spaces(n.spacing, n.bump)
			pl.emitFragmentOperand(ge, n.kids[1], n.parens[1])
			return
		}
		pl.emitFragmentNode(ge, n, ownGroup)
		return
	}
	if expr.op == "" || expr.left == nil || expr.right == nil {
		pl.Token(expr.Text)
		return
	}
	id := -1
	if ownGroup {
		id = ge.OpenGroup()
	}
	pl.emitFragmentOperand(ge, *expr.left, expr.leftParen)
	ge.Spaces(binaryOpSpacing, binaryOpBump)
	pl.Token(expr.op)
	ge.Spaces(binaryOpSpacing, binaryOpBump)
	pl.emitFragmentOperand(ge, *expr.right, expr.rightParen)
	if ownGroup {
		ge.CloseGroup(id)
	}
}

func (pl *PrintLanguage) emitFragmentOperand(ge GroupEmitter, child ExprFragment, paren bool) {
	if !paren {
		pl.emitFragmentTree(ge, child)
		return
	}
	id := ge.OpenParen("(")
	pl.emitFragmentTreeIn(ge, child, false) // the paren is the operator's group
	ge.CloseParen(")", id)
}

// emitFragmentNode replays one operator node as Ghidra's emitOp sequence
// inside its own printing group. C++ parity: PrintLanguage::emitOp.
func (pl *PrintLanguage) emitFragmentNode(ge GroupEmitter, n *fragNode, ownGroup bool) {
	id := -1
	if ownGroup {
		id = ge.OpenGroup()
	}
	switch n.kind {
	case fragBinary:
		pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
		ge.Spaces(n.spacing, n.bump)
		pl.Token(n.print1)
		ge.Spaces(n.spacing, n.bump)
		pl.emitFragmentOperand(ge, n.kids[1], n.parens[1])
	case fragUnaryPrefix:
		pl.Token(n.print1)
		ge.Spaces(n.spacing, n.bump)
		pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
	case fragPostSurround:
		pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
		ge.Spaces(n.spacing, n.bump)
		pid := ge.OpenParen(n.print1)
		ge.Spaces(0, n.bump)
		pl.emitFragmentOperand(ge, n.kids[1], n.parens[1])
		ge.CloseParen(n.print2, pid)
	case fragPreSurround:
		pid := ge.OpenParen(n.print1)
		pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
		ge.CloseParen(n.print2, pid)
		ge.Spaces(n.spacing, n.bump)
		pl.emitFragmentOperand(ge, n.kids[1], n.parens[1])
	case fragSpace:
		pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
		ge.Spaces(n.spacing, n.bump)
		pl.emitFragmentOperand(ge, n.kids[1], n.parens[1])
	case fragStatement:
		pl.emitFragmentTree(ge, n.kids[0])
	case fragParen:
		pl.emitFragmentOperand(ge, n.kids[0], true)
	case fragComma:
		pl.emitFragmentOperand(ge, n.kids[0], n.parens[0])
		pl.Token(n.print1)
		ge.Spaces(n.spacing, n.bump)
		pl.emitFragmentOperand(ge, n.kids[1], n.parens[1])
	}
	if ownGroup {
		ge.CloseGroup(id)
	}
}

// parenText wraps text in parentheses when paren is set.
func parenText(text string, paren bool) string {
	if paren {
		return "(" + text + ")"
	}
	return text
}

// scopedNameExpr splits a namespace-qualified name at its top-level "::"
// into left-nested scope operators (template and call-operator brackets stay
// whole, e.g. A<T>::operator()<U>).
// C++ parity: PrintC::pushSymbolScope with PrintC::scope (spacing 0).
func scopedNameExpr(name string) ExprFragment {
	depth := 0
	cut := -1
	for i := 0; i+1 < len(name); i++ {
		switch name[i] {
		case '<', '(':
			depth++
		case '>', ')':
			depth--
		case ':':
			if depth == 0 && name[i+1] == ':' {
				cut = i
				i++
			}
		}
	}
	// Only the base name is a function-name token; the scope names are syntax
	// and stay raw. Java parity: PrettyPrinter cleans ClangFuncNameToken.
	if cut <= 0 || cut+2 >= len(name) {
		return ExprFragment{Text: cppDisplayName(name), Precedence: ExprPrecPrimary}
	}
	left := scopedNameExprScope(name[:cut])
	right := ExprFragment{Text: cppDisplayName(name[cut+2:]), Precedence: ExprPrecPrimary}
	return ExprFragment{Text: left.Text + "::" + right.Text, Precedence: ExprPrecPrimary, node: &fragNode{
		kind: fragBinary, print1: "::", kids: []ExprFragment{left, right}, parens: []bool{false, false}}}
}

// scopedNameExprScope is scopedNameExpr for the scope part of a name, whose
// tokens are printed raw.
func scopedNameExprScope(name string) ExprFragment {
	depth := 0
	cut := -1
	for i := 0; i+1 < len(name); i++ {
		switch name[i] {
		case '<', '(':
			depth++
		case '>', ')':
			depth--
		case ':':
			if depth == 0 && name[i+1] == ':' {
				cut = i
				i++
			}
		}
	}
	if cut <= 0 || cut+2 >= len(name) {
		return ExprFragment{Text: name, Precedence: ExprPrecPrimary}
	}
	left := scopedNameExprScope(name[:cut])
	right := ExprFragment{Text: name[cut+2:], Precedence: ExprPrecPrimary}
	return ExprFragment{Text: name, Precedence: ExprPrecPrimary, node: &fragNode{
		kind: fragBinary, print1: "::", kids: []ExprFragment{left, right}, parens: []bool{false, false}}}
}

func (pl *PrintLanguage) EmitChildExpr(expr ExprFragment, parent ExprPrecedence, pos ExprPosition, assoc ExprAssociativity) {
	pl.Token(pl.ExprString(expr, parent, pos, assoc))
}

func (pl *PrintLanguage) UnaryExpr(op string, precedence ExprPrecedence, expr ExprFragment) ExprFragment {
	paren := expr.Text != "" && needsExprParens(expr.Precedence, precedence, ExprPosRight, ExprAssocRight)
	return ExprFragment{
		Text:       op + parenText(expr.Text, paren),
		Precedence: precedence,
		node: &fragNode{kind: fragUnaryPrefix, print1: op,
			kids: []ExprFragment{expr}, parens: []bool{paren}},
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
		paren = child.hidden || !(child.op == parentOp && associativeBinaryOps[parentOp])
	}
	if paren {
		return "(" + child.Text + ")", true
	}
	return child.Text, false
}

// CondJoinExpr is a BinaryExpr between structured condition blocks, emitted
// without an operator group (see fragCondJoin).
func (pl *PrintLanguage) CondJoinExpr(left ExprFragment, op string, right ExprFragment, precedence ExprPrecedence, assoc ExprAssociativity) ExprFragment {
	f := pl.BinaryExpr(left, op, right, precedence, assoc)
	f.node = &fragNode{kind: fragCondJoin, print1: op, spacing: binaryOpSpacing, bump: binaryOpBump,
		kids: []ExprFragment{*f.left, *f.right}, parens: []bool{f.leftParen, f.rightParen}}
	return f
}

// AssignExpr is "lhs = rhs" with the assignment token's break points.
// C++ parity: PrintC::assignment (spacing 1, bump 5).
func (pl *PrintLanguage) AssignExpr(lhs string, rhs ExprFragment) ExprFragment {

	l := ExprFragment{Text: lhs, Precedence: ExprPrecPrimary}
	return ExprFragment{Text: lhs + " = " + rhs.Text, Precedence: ExprPrecAssign, node: &fragNode{
		kind: fragBinary, print1: "=", spacing: binaryOpSpacing, bump: assignOpBump,
		kids: []ExprFragment{l, rhs}, parens: []bool{false, false}}}
}

// StatementExpr wraps one statement printed inside an expression (comma
// mode) in its own group. C++ parity: PrintC::emitStatement beginStatement.
func (pl *PrintLanguage) StatementExpr(stmt ExprFragment) ExprFragment {
	return ExprFragment{Text: stmt.Text, Precedence: stmt.Precedence, node: &fragNode{
		kind: fragStatement, kids: []ExprFragment{stmt}, parens: []bool{false}}}
}

// CommaExpr joins two statements printed under comma_separate: the first, a
// comma, then a breakable space. C++ parity: PrintC::emitBlockBasic
// (comma_separate: print(COMMA); spaces(1)).
func (pl *PrintLanguage) CommaExpr(a, b ExprFragment) ExprFragment {
	return ExprFragment{Text: a.Text + ", " + b.Text, Precedence: ExprPrecLowest, node: &fragNode{
		kind: fragComma, print1: ",", spacing: 1,
		kids: []ExprFragment{a, b}, parens: []bool{false, false}}}
}

func (pl *PrintLanguage) PostfixExpr(expr ExprFragment, suffix string) ExprFragment {
	return ExprFragment{
		Text:       pl.ExprString(expr, ExprPrecPostfix, ExprPosLeft, ExprAssocLeft) + suffix,
		Precedence: ExprPrecPostfix,
	}
}

// MemberExpr builds base.name or base->name. The two tokens share one
// precedence but only chain without parentheses with themselves:
// this->a->b, s.a.b, but (this->a).b and (s.a)->b.
// C++ parity: PrintLanguage::parentheses for the binary object_member /
// pointer_member tokens (associative only when topToken == op2).
func (pl *PrintLanguage) MemberExpr(base ExprFragment, op, name string) ExprFragment {
	var paren bool
	if base.member != "" {
		paren = base.member != op
	} else {
		paren = base.Text != "" && needsExprParens(base.Precedence, ExprPrecPostfix, ExprPosLeft, ExprAssocLeft)
	}
	if paren {
		return ExprFragment{Text: "(" + pl.ExprString(base, ExprPrecLowest, ExprPosNone, ExprAssocNone) + ")" + op + name, Precedence: ExprPrecPostfix, member: op}
	}
	return ExprFragment{Text: pl.ExprString(base, ExprPrecPostfix, ExprPosLeft, ExprAssocLeft) + op + name, Precedence: ExprPrecPostfix, member: op}
}

func (pl *PrintLanguage) argSep() string {
	if pl.noCommaSpace {
		return ","
	}
	return ", "
}

// CallExpr builds name(args): a function_call postsurround (spacing 0,
// bump 10) over the callee and a left-nested comma chain (spacing 0).
// C++ parity: PrintC::opCall / opFunc pushing function_call and comma.
func (pl *PrintLanguage) CallExpr(callee ExprFragment, args ...ExprFragment) ExprFragment {
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = arg.Text
	}
	calleeParen := callee.Text != "" && needsExprParens(callee.Precedence, ExprPrecPostfix, ExprPosLeft, ExprAssocLeft)
	frag := ExprFragment{
		Text:       parenText(callee.Text, calleeParen) + "(" + strings.Join(parts, pl.argSep()) + ")",
		Precedence: ExprPrecPostfix,
	}
	if pl.noCommaSpace {
		if callee.node == nil && callee.op == "" && !calleeParen {
			callee = scopedNameExpr(callee.Text)
		}
		list := ExprFragment{Text: "", Precedence: ExprPrecPrimary}
		for i, arg := range args {
			if i == 0 {
				list = arg
				continue
			}
			list = ExprFragment{Text: list.Text + "," + arg.Text, Precedence: ExprPrecLowest, node: &fragNode{
				kind: fragBinary, print1: ",", kids: []ExprFragment{list, arg}, parens: []bool{false, false}}}
		}
		frag.node = &fragNode{kind: fragPostSurround, print1: "(", print2: ")", bump: 10,
			kids: []ExprFragment{callee, list}, parens: []bool{calleeParen, false}}
	}
	return frag
}

// CastExpr builds (type)expr: a typecast presurround over the type
// expression and the operand. C++ parity: PrintC::opTypeCast.
func (pl *PrintLanguage) CastExpr(typeName string, expr ExprFragment) ExprFragment {
	paren := expr.Text != "" && needsExprParens(expr.Precedence, ExprPrecCast, ExprPosRight, ExprAssocRight)
	return ExprFragment{
		Text:       "(" + typeName + ")" + parenText(expr.Text, paren),
		Precedence: ExprPrecCast,
		node: &fragNode{kind: fragPreSurround, print1: "(", print2: ")",
			kids: []ExprFragment{declExpr(typeName, ""), expr}, parens: []bool{false, paren}},
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

// splitScopePath splits a qualified name at its top-level "::" separators
// (template and call-operator brackets stay whole).
func splitScopePath(name string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i+1 < len(name); i++ {
		switch name[i] {
		case '<', '(':
			depth++
		case '>', ')':
			depth--
		case ':':
			if depth == 0 && name[i+1] == ':' {
				parts = append(parts, name[start:i])
				start = i + 2
				i++
			}
		}
	}
	return append(parts, name[start:])
}

// minimalScopedName qualifies a symbol name only as far as needed to resolve
// it from the current function's scope: a callee in the caller's own class
// prints bare. The scope path of each name is its qualification; the global
// scope is the root of both.
// C++ parity: PrintC::pushSymbolScope (MINIMAL_NAMESPACES) ->
// Symbol::getResolutionDepth + Scope::findDistinguishingScope.
// TODO known mismatch: Scope::isNameUsed needs every name the host knows in
// the intermediate scopes; it is taken as false.
func (s *printCState) minimalScopedName(qualified string) string {
	parts := splitScopePath(qualified)
	symScope := parts[:len(parts)-1] // Path of the symbol's scope (global excluded)
	var useScope []string
	if s.fd != nil {
		fn := s.fd.DisplayName()
		if fn == "" {
			fn = s.fd.Name()
		}
		if up := splitScopePath(fn); len(up) > 1 {
			useScope = up[:len(up)-1]
		}
	}
	depth := resolutionDepth(symScope, useScope)
	if depth == 0 {
		return parts[len(parts)-1]
	}
	if depth > len(symScope) { // Up to the global scope, whose display name is empty
		return "::" + strings.Join(parts, "::")
	}
	return strings.Join(parts[len(parts)-1-depth:], "::")
}

// resolutionDepth is the number of scope names needed to reach a symbol in
// scope sym from scope use (paths from the global scope, global excluded).
// C++ parity: Symbol::getResolutionDepth with isNameUsed false.
func resolutionDepth(sym, use []string) int {
	same := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	if same(sym, use) {
		return 0 // Symbol is in the scope where it is used
	}
	// findDistinguishingScope: the first scope on sym's path not shared
	// with use's path, or none when sym's scope is an ancestor of use.
	min := len(sym)
	if len(use) < min {
		min = len(use)
	}
	dist := -1 // Index into sym of the distinguishing scope
	for i := 0; i < min; i++ {
		if sym[i] != use[i] {
			dist = i
			break
		}
	}
	if dist < 0 {
		if min < len(sym) {
			dist = min // sym's path matches use's but is longer
		} else if min < len(use) {
			return 0 // sym's scope is an ancestor of use
		} else {
			dist = len(sym) - 1 // Identical paths: unreachable after same()
		}
	}
	// Print every scope from sym's own up to and including the
	// distinguishing scope.
	return len(sym) - dist
}

// symbolNameExpr builds a global symbol reference: its scope names as raw
// tokens joined by the scope operator and the (already display-cleaned) base
// name, so the printer can break the line between scopes.
// C++ parity: PrintC::pushSymbolScope + pushSymbol.
func symbolNameExpr(scoped, base string) ExprFragment {
	parts := splitScopePath(scoped)
	if len(parts) < 2 {
		return ExprFragment{Text: base, Precedence: ExprPrecPrimary}
	}
	left := scopedNameExprScope(strings.Join(parts[:len(parts)-1], "::"))
	if parts[0] == "" { // Global scope (empty display name)
		left = ExprFragment{Text: "", Precedence: ExprPrecPrimary}
	}
	right := ExprFragment{Text: base, Precedence: ExprPrecPrimary}
	return ExprFragment{Text: left.Text + "::" + base, Precedence: ExprPrecPrimary, node: &fragNode{
		kind: fragBinary, print1: "::", kids: []ExprFragment{left, right}, parens: []bool{false, false}}}
}
