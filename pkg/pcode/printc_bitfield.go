// Copyright 2026 The Gosleigh Authors
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

// checkBitFieldMember reports that a bitfield read or written through the
// LOAD/STORE pointer vn prints with member syntax ('.') rather than pointer
// syntax ('->'): a PTRSUB to the bitfield's byte range is skipped, then
// the array/member check of checkArrayDeref applies.
// C++ parity: PrintC::checkBitFieldMember.
func checkBitFieldMember(vn *Varnode, field *TypeBitField) bool {
	if field.Bits.ByteOffset != 0 { // a PTRSUB should be present
		if !vn.IsWritten() || vn.Def().Code() != CPUI_PTRSUB {
			return false
		}
		vn = vn.Def().Input(0)
	}
	return checkArrayDeref(vn)
}

// renderBitFieldAccess is base.field or base->field for a bitfield reached
// through the pointer structPtr (ptrVn being the LOAD/STORE pointer).
// C++ parity: the object_member / pointer_member pushes of
// emitBitFieldStore and opZpullOp (print_store_value / print_load_value).
func (s *printCState) renderBitFieldAccess(ptrVn, structPtr *Varnode, field *TypeBitField) (ExprFragment, error) {
	if checkBitFieldMember(ptrVn, field) {
		frag, ok, err := s.renderDerefValue(structPtr)
		if err != nil {
			return ExprFragment{}, err
		}
		if ok {
			return s.lang.MemberExpr(frag, ".", field.Name), nil
		}
	}
	frag, err := s.renderVarnodeExpr(structPtr)
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.MemberExpr(frag, "->", field.Name), nil
}

// readSymbolName is a variable's name as read by op, through its symbol's
// type when it is only part of a symbol.
// C++ parity: PrintC::pushSymbolDetail (isRead).
func (s *printCState) readSymbolName(vn *Varnode, op *PcodeOp, slot int) string {
	if e := s.fd.globalEntryOf(vn); e != nil {
		name, _ := s.globalVarnodeName(vn, e, nil, op, slot)
		return name
	}
	name, _ := s.localPieceName(vn, s.nameOf(vn), nil, op, slot)
	return name
}

// renderPull prints a ZPULL or SPULL as the bitfield it extracts.
// C++ parity: PrintC::opZpullOp / opSpullOp.
func (s *printCState) renderPull(op *PcodeOp) (ExprFragment, error) {
	expr := newPullExpression(op)
	if !expr.isValid() {
		name := "ZPULL"
		if op.Code() == CPUI_SPULL {
			name = "SPULL"
		}
		return s.renderPseudoCall(name, op, 0) // no other way to print it
	}
	if expr.loadOp != nil {
		return s.renderBitFieldAccess(expr.loadOp.Input(1), expr.structPtr, expr.bitfield)
	}
	base := s.globalNameExpr(op.Input(0), s.readSymbolName(op.Input(0), op, 0))
	return s.lang.MemberExpr(base, ".", expr.bitfield.Name), nil
}

// emitBitFieldStore prints a STORE of an INSERT as an assignment to the
// bitfield: ptr->field = value. It reports false when the STORE does not
// match, to print normally.
// C++ parity: PrintC::emitBitFieldStore.
func (s *printCState) emitBitFieldStore(op *PcodeOp) (bool, error) {
	expr := newInsertStoreExpression(op)
	if !expr.isValid() {
		return false, nil
	}
	lhs, err := s.renderBitFieldAccess(op.Input(1), expr.structPtr, expr.bitfield)
	if err != nil {
		return true, err
	}
	s.opStack = append(s.opStack, expr.insertOp) // the INSERT reads the value
	rhs, err := s.renderVarnodeExpr(expr.insertOp.Input(1))
	s.opStack = s.opStack[:len(s.opStack)-1]
	if err != nil {
		return true, err
	}
	s.emitBitFieldAssign(lhs, rhs)
	return true, nil
}

// emitBitFieldExpression prints an INSERT into a mapped variable as an
// assignment to the bitfield: var.field = value. It reports false when
// the INSERT does not match, to print functionally.
// C++ parity: PrintC::emitBitFieldExpression.
func (s *printCState) emitBitFieldExpression(op *PcodeOp) (bool, error) {
	expr := newInsertExpression(op)
	if !expr.isValid() {
		return false, nil
	}
	out := op.Output()
	be := out.Space() != nil && out.Space().BigEndian
	symName := expr.symbol.Name()
	if symName == "" {
		symName = s.nameOf(out)
	}
	path, _ := partialSymbolName(symName, expr.symbol.Type(), expr.offsetToBitStruct, expr.theStruct.Size(), nil, be, op, -1)
	lhs := s.lang.MemberExpr(s.globalNameExpr(out, path), ".", expr.bitfield.Name)
	rhs, err := s.renderVarnodeExpr(op.Input(1))
	if err != nil {
		return true, err
	}
	s.emitBitFieldAssign(lhs, rhs)
	return true, nil
}

func (s *printCState) emitBitFieldAssign(lhs, rhs ExprFragment) {
	rendered := s.lang.ExprString(rhs, cPrecAssign, ExprPosNone, ExprAssocNone)
	s.lang.Statement(func() {
		if rendered != rhs.Text {
			s.emitAssign(s.lang.ExprString(lhs, cPrecAssign, ExprPosNone, ExprAssocNone), rhs, rendered)
			return
		}
		s.lang.EmitAssignFragments(lhs, rhs)
	})
}
