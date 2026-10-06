// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import "strings"

// sigLayout is a rendered function signature split into the pieces
// PrintC::emitFunctionDeclaration emits as separate tokens: the return type,
// the calling-convention model, the name, and one declaration per parameter.
type sigLayout struct {
	ret    string
	model  string
	name   string
	params []string
	names  []string
}

// newSigLayout derives the layout from the flat signature and accepts it only
// when re-joining the pieces reproduces the signature exactly, so the
// structured emission can never change the printed characters.
func newSigLayout(decls *CDeclRenderer, sig, name, modelPrefix string, types []Datatype, names []string) *sigLayout {
	l := &sigLayout{name: name, model: strings.TrimSuffix(modelPrefix, " ")}
	if len(types) == 0 {
		l.params = []string{"void"}
		l.names = []string{""}
	} else {
		for i, dt := range types {
			l.params = append(l.params, decls.Declaration(dt, names[i]))
			l.names = append(l.names, names[i])
		}
	}
	tail := name + "(" + strings.Join(l.params, ",") + ")"
	if !strings.HasSuffix(sig, tail) {
		return nil
	}
	prefix := sig[:len(sig)-len(tail)]
	if l.model != "" {
		if !strings.HasSuffix(prefix, l.model+" ") {
			return nil
		}
		prefix = strings.TrimSuffix(prefix, l.model+" ")
	}
	if !strings.HasSuffix(prefix, " ") {
		return nil
	}
	l.ret = strings.TrimSuffix(prefix, " ")
	return l
}

// emitSignature emits the declaration with Ghidra's break points: spaces(1)
// after the return type and model, then a group holding the name and the
// function_call parenthesis around the parameter declarations.
// C++ parity: printc.cc PrintC::emitFunctionDeclaration / emitPrototypeInputs.
func (s *printCState) emitSignature(sig string) {
	ge, ok := s.emitter.(GroupEmitter)
	l := s.sigLayout
	if !ok || l == nil {
		s.lang.Token(sig)
		return
	}
	s.lang.EmitFragment(declExpr(l.ret, ""))
	ge.Spaces(1, 0)
	if l.model != "" {
		s.lang.Token(l.model)
		ge.Spaces(1, 0)
	}
	id1 := ge.OpenGroup()
	s.lang.EmitFragment(scopedNameExpr(l.name))
	ge.Spaces(0, 10)
	id2 := ge.OpenParen("(")
	ge.Spaces(0, 10)
	for i, p := range l.params {
		if i > 0 {
			s.lang.Token(",")
		}
		s.lang.EmitFragment(declExpr(strings.TrimSuffix(p, l.names[i]), l.names[i]))
	}
	ge.CloseParen(")", id2)
	ge.CloseGroup(id1)
}

// declExpr builds the type_expr_space / ptr_expr structure of a simple
// "base **ident" declaration; other shapes stay one flat token.
// C++ parity: PrintC::pushTypeStart / pushSymbol / pushTypeEnd.
func declExpr(typeText, ident string) ExprFragment {
	flat := ExprFragment{Text: typeText + ident, Precedence: ExprPrecPrimary}
	stars := len(typeText) - len(strings.TrimRight(typeText, "*"))
	base := typeText[:len(typeText)-stars]
	if stars == 0 && ident == "" && !strings.ContainsAny(base, "()[]") {
		// A bare type name: type_expr_nospace over the type and a blank
		// identifier, which is its own printing group.
		// C++ parity: PrintC::pushType -> pushTypeStart(ct,true).
		return ExprFragment{Text: flat.Text, Precedence: ExprPrecPrimary, node: &fragNode{
			kind: fragSpace, spacing: 0,
			kids:   []ExprFragment{{Text: base, Precedence: ExprPrecPrimary}, blankExpr},
			parens: []bool{false, false}}}
	}
	if !strings.HasSuffix(base, " ") || strings.ContainsAny(base, "()[]") {
		return flat
	}
	base = base[:len(base)-1]
	inner := ExprFragment{Text: ident, Precedence: ExprPrecPrimary}
	for i := 0; i < stars; i++ {
		inner = ExprFragment{Text: "*" + inner.Text, Precedence: ExprPrecPrimary, node: &fragNode{
			kind: fragUnaryPrefix, print1: "*", kids: []ExprFragment{inner}, parens: []bool{false}}}
	}
	return ExprFragment{Text: flat.Text, Precedence: ExprPrecPrimary, node: &fragNode{
		kind: fragSpace, spacing: 1,
		kids:   []ExprFragment{{Text: base, Precedence: ExprPrecPrimary}, inner},
		parens: []bool{false, false}}}
}
