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
	if p, ok := parent.(*PartialUnion); ok {
		parent = p.container
	}
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
	} else if p, ok := parent.(*PartialUnion); ok {
		e.base = p.container
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
	switch t := dt.(type) {
	case *Struct, *Array:
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
		compFill := newResolvedField(dt, scoreSingleComponent(dt, op, slot), sharedTypeFactory)
		fd.setUnionField(dt, op, slot, compFill)
		return compFill.resolve
	case *Union:
		// C++ parity: TypeUnion::resolveInFlow.
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
		res := scoreUnionField(sharedTypeFactory, dt, op, slot)
		fd.setUnionField(dt, op, slot, res)
		return res.resolve
	case *PartialUnion:
		// C++ parity: TypePartialUnion::resolveInFlow.
		var cur Datatype = t.container
		off := t.offset
		for cur != nil && cur.Size() > t.Size() {
			if u, ok := cur.(*Union); ok {
				idx, newoff := resolveTruncation(u, off, op, slot)
				if idx < 0 {
					cur = nil
				} else {
					cur, off = u.fields[idx].Type, newoff
				}
			} else {
				cur, off = datatypeSubType(cur, off)
			}
		}
		if cur != nil && cur.Size() == t.Size() {
			return cur
		}
		return t.stripped
	case *Pointer:
		// C++ parity: TypePointer::resolveInFlow (only a pointer to a union).
		if dt.(*Pointer).Pointee().Metatype() != TYPE_UNION {
			return dt
		}
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
		res := scoreUnionField(sharedTypeFactory, dt, op, slot)
		fd.setUnionField(dt, op, slot, res)
		return res.resolve
	}
	return dt
}

// resolveTruncation picks the union field a truncation to offset reads,
// scoring it when no answer is cached; it returns the field index (or -1)
// and the offset left within the field.
// C++ parity: TypeUnion::resolveTruncation.
func resolveTruncation(u *Union, offset int64, op *PcodeOp, slot int) (int, int64) {
	fd := opFuncdata(op)
	if fd == nil {
		return -1, offset
	}
	if res := fd.getUnionField(u, op, slot); res != nil {
		if res.fieldNum >= 0 {
			return res.fieldNum, offset - int64(u.fields[res.fieldNum].Offset)
		}
		return -1, offset
	}
	var res ResolvedUnion
	if op.Code() == CPUI_SUBPIECE && slot == 1 { // The slot is artificial in this case
		res = scoreUnionSubpiece(sharedTypeFactory, u, offset, op)
		fd.setUnionField(u, op, slot, res)
		if res.fieldNum >= 0 {
			return res.fieldNum, 0
		}
		return -1, offset
	}
	res = scoreUnionTruncation(sharedTypeFactory, u, offset, op, slot)
	fd.setUnionField(u, op, slot, res)
	if res.fieldNum >= 0 {
		return res.fieldNum, offset - int64(u.fields[res.fieldNum].Offset)
	}
	return -1, offset
}

// datatypeResolveTruncation is the type of the field of a union or partial
// union a truncation at offset reads, and the offset left within it, or nil.
// C++ parity: TypeUnion/TypePartialUnion::resolveTruncation.
func datatypeResolveTruncation(dt Datatype, offset int64, op *PcodeOp, slot int) (Datatype, int64) {
	var u *Union
	switch t := dt.(type) {
	case *Union:
		u = t
	case *PartialUnion:
		u, offset = t.container, offset+t.offset
	default:
		return nil, offset
	}
	idx, newoff := resolveTruncation(u, offset, op, slot)
	if idx < 0 {
		return nil, newoff
	}
	return u.fields[idx].Type, newoff
}

// unionFindTruncation is the cached field of a union a truncation of sz
// bytes at offset reads, or -1; no new scoring is done.
// C++ parity: TypeUnion::findTruncation.
func unionFindTruncation(u *Union, offset int64, sz int32, op *PcodeOp, slot int) (int, int64) {
	fd := opFuncdata(op)
	res := fd.getUnionField(u, op, slot)
	if res != nil && res.fieldNum >= 0 {
		f := u.fields[res.fieldNum]
		newoff := offset - int64(f.Offset)
		if newoff+int64(sz) > int64(f.Type.Size()) {
			return -1, offset // Truncation spans more than one field
		}
		return res.fieldNum, newoff
	}
	return -1, offset
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
	case *Union:
		if res := fd.getUnionField(dt, op, slot); res != nil {
			return res.resolve
		}
	case *PartialUnion:
		// C++ parity: TypePartialUnion::findResolve. As in C++, the offset is
		// not moved past a resolved union level.
		var cur Datatype = t.container
		off := t.offset
		for cur != nil && cur.Size() > t.Size() {
			if cur.Metatype() == TYPE_UNION {
				if nt := findResolve(cur, op, slot); nt != cur {
					cur = nt
				} else {
					cur = nil
				}
			} else {
				cur, off = datatypeSubType(cur, off)
			}
		}
		if cur != nil && cur.Size() == t.Size() {
			return cur
		}
		return t.stripped
	case *Pointer:
		if t.Pointee().Metatype() == TYPE_UNION {
			if res := fd.getUnionField(dt, op, slot); res != nil {
				return res.resolve
			}
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
	case *PartialUnion: // C++ parity: TypePartialUnion::findCompatibleResolve
		return findCompatibleResolve(t.container, ct)
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
