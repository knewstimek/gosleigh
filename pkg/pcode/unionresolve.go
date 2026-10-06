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

// Resolution of data-types that read differently per use: a union, a
// structure (or 1-element array) whose single component fills it, or a
// pointer to a union. Each read (slot >= 0) or write (slot -1) of a Varnode
// with such a type resolves either to the type itself or to one of its
// components; the choice is cached per edge on the Funcdata.
//
// C++ parity: unionresolve.hh/cc (ResolvedUnion, ResolveEdge), funcdata.cc
// (getUnionField, setUnionField, forceFacingType, inheritResolution) and the
// resolveInFlow/findResolve/findCompatibleResolve methods of type.cc.
// Known mismatch: ScoreUnionFields (scoring the fields of a real union) is
// not ported; a union or a pointer to a union resolves to itself unless a
// resolution was set explicitly.

// ResolvedUnion is a data-type resolved from a parent that needs
// resolution: one of its components (fieldNum >= 0) or the parent itself.
// C++ parity: class ResolvedUnion.
type ResolvedUnion struct {
	resolve  Datatype // The resolved data-type
	baseType Datatype // Union or structure being resolved
	fieldNum int      // Index of the referenced field, or -1
	lock     bool     // A locked resolution cannot be overridden
}

// newResolvedSelf resolves parent to itself.
// C++ parity: ResolvedUnion::ResolvedUnion(Datatype *parent).
func newResolvedSelf(parent Datatype) ResolvedUnion {
	base := parent
	if p, ok := parent.(*Pointer); ok {
		base = p.Pointee()
	}
	return ResolvedUnion{resolve: parent, baseType: base, fieldNum: -1}
}

// newResolvedField resolves parent to its component fldNum (to a pointer to
// it when parent is a pointer), or to itself for fldNum < 0.
// C++ parity: ResolvedUnion::ResolvedUnion(Datatype *,int4,TypeFactory &).
func newResolvedField(parent Datatype, fldNum int, tf *TypeFactory) ResolvedUnion {
	res := ResolvedUnion{baseType: parent, fieldNum: fldNum}
	if fldNum < 0 {
		res.resolve = parent
		return res
	}
	if p, ok := parent.(*Pointer); ok {
		res.resolve = tf.GetPointer(parent.Size(), datatypeDepend(p.Pointee(), fldNum), p.WordSize())
	} else {
		res.resolve = datatypeDepend(parent, fldNum)
	}
	return res
}

// Datatype returns the resolved data-type.
func (r *ResolvedUnion) Datatype() Datatype { return r.resolve }

// FieldNum returns the index of the resolved field or -1.
func (r *ResolvedUnion) FieldNum() int { return r.fieldNum }

// datatypeDepend is the component fldNum of a composite data-type.
// C++ parity: Datatype::getDepend.
func datatypeDepend(dt Datatype, fldNum int) Datatype {
	switch t := dt.(type) {
	case *Struct:
		if f := t.fields; fldNum >= 0 && fldNum < len(f) {
			return f[fldNum].Type
		}
	case *Union:
		if f := t.fields; fldNum >= 0 && fldNum < len(f) {
			return f[fldNum].Type
		}
	case *Array:
		return t.Element()
	case *Pointer:
		return t.Pointee()
	}
	return nil
}

// resolveEdge keys a resolution: the base data-type (a pointer collapses to
// what it points to), the op, and the slot with the pointer-ness encoded.
// C++ parity: class ResolveEdge (the op is keyed by identity, not time).
type resolveEdge struct {
	base     Datatype
	op       *PcodeOp
	encoding int
}

func newResolveEdge(parent Datatype, op *PcodeOp, slot int) resolveEdge {
	e := resolveEdge{base: parent, op: op, encoding: slot}
	if p, ok := parent.(*Pointer); ok {
		e.base = p.Pointee() // Strip pointer
		e.encoding += 0x1000 // Encode the fact that a pointer is getting accessed
	}
	return e
}

// getUnionField returns the resolution recorded for the edge, or nil.
// C++ parity: Funcdata::getUnionField.
func (fd *Funcdata) getUnionField(parent Datatype, op *PcodeOp, slot int) *ResolvedUnion {
	if fd == nil || fd.unionMap == nil {
		return nil
	}
	return fd.unionMap[newResolveEdge(parent, op, slot)]
}

// setUnionField records a resolution for the edge unless a locked one is
// there; a MULTIEQUAL copies it to every input slot holding the same Varnode.
// C++ parity: Funcdata::setUnionField.
func (fd *Funcdata) setUnionField(parent Datatype, op *PcodeOp, slot int, resolve ResolvedUnion) bool {
	if fd.unionMap == nil {
		fd.unionMap = make(map[resolveEdge]*ResolvedUnion)
	}
	edge := newResolveEdge(parent, op, slot)
	if cur, ok := fd.unionMap[edge]; ok {
		if cur.lock {
			return false
		}
		*cur = resolve
	} else {
		r := resolve
		fd.unionMap[edge] = &r
	}
	if op.Code() == CPUI_MULTIEQUAL && slot >= 0 {
		// Data-type propagation doesn't happen between MULTIEQUAL input slots
		// holding the same Varnode, so copy the resolution to them
		vn := op.Input(slot)
		for i := 0; i < op.NumInput(); i++ {
			if i == slot || op.Input(i) != vn {
				continue
			}
			dup := newResolveEdge(parent, op, i)
			if cur, ok := fd.unionMap[dup]; ok {
				if !cur.lock {
					*cur = resolve
				}
			} else {
				r := resolve
				fd.unionMap[dup] = &r
			}
		}
	}
	return true
}

// forceFacingType sets the resolution of the edge to the given field.
// C++ parity: Funcdata::forceFacingType.
func (fd *Funcdata) forceFacingType(parent Datatype, fieldNum int, op *PcodeOp, slot int) {
	fd.setUnionField(parent, op, slot, newResolvedField(parent, fieldNum, sharedTypeFactory))
}

// inheritResolution copies the resolution of oldOp/oldSlot to op/slot and
// returns its field number (-1 when there is none to copy).
// C++ parity: Funcdata::inheritResolution.
func (fd *Funcdata) inheritResolution(parent Datatype, op *PcodeOp, slot int, oldOp *PcodeOp, oldSlot int) int {
	if fd == nil || fd.unionMap == nil {
		return -1
	}
	cur, ok := fd.unionMap[newResolveEdge(parent, oldOp, oldSlot)]
	if !ok {
		return -1
	}
	fd.setUnionField(parent, op, slot, *cur)
	return cur.fieldNum
}

// opFuncdata is the function an op belongs to.
func opFuncdata(op *PcodeOp) *Funcdata {
	if op == nil || op.Parent() == nil {
		return nil
	}
	return op.Parent().GetFuncdata()
}

// resolveInFlow resolves dt for the read (slot >= 0) or write (slot -1) by
// op, computing and caching the answer when none is recorded.
// C++ parity: Datatype::resolveInFlow and its TypeStruct, TypeArray and
// TypePointer overrides.
func resolveInFlow(dt Datatype, op *PcodeOp, slot int) Datatype {
	fd := opFuncdata(op)
	if fd == nil || dt == nil || !dt.NeedsResolution() {
		return dt
	}
	switch dt.(type) {
	case *Struct, *Array:
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
		compFill := newResolvedField(dt, scoreSingleComponent(dt, op, slot), sharedTypeFactory)
		fd.setUnionField(dt, op, slot, compFill)
		return compFill.resolve
	case *Pointer, *Union:
		// Known mismatch: ScoreUnionFields is not ported.
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
	}
	return dt
}

// findResolve is the cached resolution of dt for the read or write by op; a
// single-component type not yet resolved refers to its component.
// C++ parity: Datatype::findResolve and its overrides.
func findResolve(dt Datatype, op *PcodeOp, slot int) Datatype {
	fd := opFuncdata(op)
	if dt == nil || !dt.NeedsResolution() {
		return dt
	}
	switch t := dt.(type) {
	case *Struct:
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
		if len(t.fields) > 0 {
			return t.fields[0].Type // If not calculated before, assume referring to field
		}
	case *Array:
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
		return t.Element() // If not calculated before, assume referring to the element
	case *Pointer, *Union:
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
	}
	return dt
}

// findCompatibleResolve is the index of the form of dt matching ct, or -1.
// C++ parity: Datatype::findCompatibleResolve and its overrides.
func findCompatibleResolve(dt, ct Datatype) int {
	var comp Datatype
	switch t := dt.(type) {
	case *Struct:
		if len(t.fields) == 0 {
			return -1
		}
		comp = t.fields[0].Type
	case *Array:
		comp = t.Element()
	case *Union:
		for i, f := range t.fields {
			if f.Type == ct {
				return i
			}
		}
		return -1
	default:
		return -1
	}
	if ct.NeedsResolution() && !comp.NeedsResolution() {
		if findCompatibleResolve(ct, comp) >= 0 {
			return 0
		}
	}
	if comp == ct {
		return 0
	}
	return -1
}

// scoreSingleComponent decides whether a use of a type with one filling
// component names the whole type (-1) or the component (0).
// C++ parity: TypeStruct::scoreSingleComponent.
func scoreSingleComponent(parent Datatype, op *PcodeOp, slot int) int {
	switch {
	case op.Code() == CPUI_COPY || op.Code() == CPUI_INDIRECT:
		vn := op.Input(0)
		if slot == 0 {
			vn = op.Output()
		}
		if vn != nil && vn.IsTypeLock() && vn.Type() == parent {
			return -1 // COPY of the structure directly, use whole structure
		}
	case (op.Code() == CPUI_LOAD && slot == -1) || (op.Code() == CPUI_STORE && slot == 2):
		if vn := op.Input(1); vn != nil && vn.IsTypeLock() {
			if p, ok := vn.TypeReadFacing(op).(*Pointer); ok && p.Pointee() == parent {
				return -1 // LOAD or STORE of the structure directly
			}
		}
	case op.IsCall():
		fd := opFuncdata(op)
		if fd == nil {
			break
		}
		if fc := fd.callSpecsForOp(op); fc != nil {
			var pt Datatype
			if slot >= 1 && fc.IsInputLocked() {
				if p, ok := fc.LockedParam(slot - 1); ok {
					pt = p.Type
				}
			} else if slot < 0 && fc.IsOutputLocked() && fc.lockedOut != nil {
				pt = fc.lockedOut.Type
			}
			if pt != nil && pt == parent {
				return -1 // The signature refers to the parent directly
			}
		}
	}
	return 0 // In all other cases resolve to the component
}
