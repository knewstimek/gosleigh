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

import (
	"sort"
	"sync/atomic"
)

// HighVariable is a high-level variable that may be backed by one or more
// low-level Varnodes (SSA values). It carries a human-readable name for
// output in the decompiler.
//
// C++ parity: varnode.hh HighVariable (partial)
type HighVariable struct {
	serial uint64 // creation order (see highSerial)
	// irregularInput marks an input named as a non-parameter (in_<reg> or
	// its stack name), which printc declares as a local.
	irregularInput bool

	// mergeClasses counts speculatively merged groups (0 means 1).
	// C++ parity: HighVariable::numMergeClasses.
	mergeClasses int
	name         string
	instances    []*Varnode
	datatype     Datatype // type annotation; nil means unknown

	// cover is the union of live ranges of all member Varnodes.
	// nil means the cover has not been computed yet (dirty).
	// C++ parity: HighVariable::internalCover
	cover *Cover

	// piece places the variable in a group of overlapping variables.
	// C++ parity: HighVariable::piece.
	piece *variablePiece

	// dynamicSym marks a variable whose storage and use point were already
	// claimed by another variable's symbol, so it gets a dynamic symbol
	// (declared after the mapped ones). C++ parity: Funcdata::handleSymbolConflict.
	dynamicSym bool

	// finalType, once set, is the variable's data-type regardless of its
	// members. C++ parity: HighVariable::type with the type_finalized flag.
	finalType Datatype

	// linkedRep is the name representative when ActionNameVars linked the
	// variable to its symbol; the symbol's storage and use point come from it.
	// C++ parity: Funcdata::linkSymbol (addSymbol at the representative).
	linkedRep *Varnode
}

// GetSymbol returns the Symbol this high variable maps to, or nil. It walks the
// member Varnodes and returns the Symbol of the first one carrying a
// SymbolEntry -- mirroring HighVariable::updateSymbol, which stops at the first
// instance with a mapentry. The resolution is recomputed on each call rather
// than cached with a dirty flag; the result is identical because it depends
// only on the current instance/entry population.
// C++ parity: HighVariable::getSymbol / updateSymbol (variable.cc:418)
func (hv *HighVariable) GetSymbol() *Symbol {
	if hv == nil {
		return nil
	}
	for _, vn := range hv.instances {
		if vn == nil {
			continue
		}
		if e := vn.GetSymbolEntry(); e != nil {
			return e.Symbol()
		}
	}
	return nil
}

// GetSymbolOffset returns the byte offset into the mapped Symbol that this high
// variable represents, or -1 when it maps the whole Symbol (or no Symbol). The
// offset is derived from the same instance GetSymbol selects.
// C++ parity: HighVariable::getSymbolOffset (with setSymbol offset rules)
func (hv *HighVariable) GetSymbolOffset() int32 {
	if hv == nil {
		return -1
	}
	for _, vn := range hv.instances {
		if vn == nil {
			continue
		}
		if e := vn.GetSymbolEntry(); e != nil {
			return symbolOffsetFor(vn, e)
		}
	}
	return -1
}

// symbolOffsetFor computes the symbol offset a member Varnode contributes for a
// given SymbolEntry, following HighVariable::setSymbol. VariablePiece groups are
// not modeled, so the proto-partial branch is omitted; the remaining branches
// (dynamic, equate, whole-storage match, and the byte-distance fallback) are
// ported verbatim.
// C++ parity: HighVariable::setSymbol (variable.cc:245)
func symbolOffsetFor(vn *Varnode, entry *SymbolEntry) int32 {
	sym := entry.Symbol()
	switch {
	case entry.IsDynamic():
		return -1
	case sym != nil && sym.Category() == SymbolEquate:
		return -1
	case sym != nil && sym.Type() != nil &&
		sym.Type().Size() == vn.Size() && entry.Addr() == vn.Addr():
		// A matching whole-storage entry.
		return -1
	default:
		// Byte distance of the Varnode within the Symbol storage plus the entry
		// offset. C++ uses Address::overlapJoin; for non-join spaces this reduces
		// to the plain byte distance, which is the only case Gosleigh produces.
		var dist int32
		if sym != nil && entry.Addr().Space == vn.Addr().Space {
			dist = int32(vn.Addr().Offset - entry.Addr().Offset)
		}
		return dist + entry.Offset()
	}
}

// NewHighVariable creates a HighVariable with the given name and zero instances.
// C++ parity: HighVariable::HighVariable
func NewHighVariable(name string) *HighVariable {
	return &HighVariable{name: name, serial: highSerial.Add(1)}
}

// highSerial numbers HighVariables in creation order. C++ walks
// map<HighVariable *,...> containers in pointer order, which follows
// allocation order; the serial stands in for that order.
var highSerial atomic.Uint64

// Name returns the display name of this variable.
func (hv *HighVariable) Name() string {
	if hv == nil {
		return ""
	}
	return hv.name
}

// SetName sets the display name.
func (hv *HighVariable) SetName(name string) {
	if hv == nil {
		return
	}
	hv.name = name
}

// AddInstance associates a Varnode with this high variable and sets the
// back-pointer on the varnode.
// C++ parity: HighVariable::merge / Varnode::setHigh
func (hv *HighVariable) AddInstance(vn *Varnode) {
	if hv == nil || vn == nil {
		return
	}
	if vn.high == hv {
		for _, w := range hv.instances {
			if w == vn {
				return // already an instance
			}
		}
	}
	// Keep the instances in address order (after any equal address), the
	// order HighVariable::mergeInternal maintains with compareJustLoc.
	at := sort.Search(len(hv.instances), func(i int) bool { return vn.Addr().Less(hv.instances[i].Addr()) })
	hv.instances = append(hv.instances, nil)
	copy(hv.instances[at+1:], hv.instances[at:])
	hv.instances[at] = vn
	vn.SetHigh(hv)
}

// NumInstances returns the number of associated low-level varnodes.
func (hv *HighVariable) NumInstances() int {
	if hv == nil {
		return 0
	}
	return len(hv.instances)
}

// GetInstance returns the i-th associated varnode, or nil if out of range.
func (hv *HighVariable) GetInstance(i int) *Varnode {
	if hv == nil || i < 0 || i >= len(hv.instances) {
		return nil
	}
	return hv.instances[i]
}

// Instances returns all associated low-level varnodes.
func (hv *HighVariable) Instances() []*Varnode {
	if hv == nil {
		return nil
	}
	return hv.instances
}

// IsAddrTied returns true if any instance Varnode has the address-tied flag.
// An addr-tied HighVariable is bound to a specific storage address (stack
// slot or global), and must not be merged with a differently-addressed
// addr-tied HighVariable.
// C++ parity: HighVariable::isAddrTied (variable.cc)
func (hv *HighVariable) IsAddrTied() bool {
	if hv == nil {
		return false
	}
	for _, vn := range hv.instances {
		if vn != nil && vn.IsAddrTied() {
			return true
		}
	}
	return false
}

// TiedVarnode returns the first addr-tied instance (or nil if none).
// C++ parity: HighVariable::getTiedVarnode().
func (hv *HighVariable) TiedVarnode() *Varnode {
	if hv == nil {
		return nil
	}
	for _, vn := range hv.instances {
		if vn != nil && vn.IsAddrTied() {
			return vn
		}
	}
	return nil
}

// IsInput returns true if any instance Varnode is a function input.
// C++ parity: HighVariable::isInput (variable.cc)
func (hv *HighVariable) IsInput() bool {
	if hv == nil {
		return false
	}
	for _, vn := range hv.instances {
		if vn != nil && vn.IsInput() {
			return true
		}
	}
	return false
}

// IsTypeLock returns true if any instance Varnode has the typelock flag set.
// C++ parity: HighVariable::isTypeLock (variable.hh:222)
func (hv *HighVariable) IsTypeLock() bool {
	if hv == nil {
		return false
	}
	for _, vn := range hv.instances {
		if vn != nil && vn.IsTypeLock() {
			return true
		}
	}
	return false
}

// IsNameLock returns true if any instance Varnode has the namelock flag set.
// C++ parity: HighVariable::isNameLock (variable.hh) via updateFlags, which ORs
// the namelock property across all instance Varnodes.
func (hv *HighVariable) IsNameLock() bool {
	if hv == nil {
		return false
	}
	for _, vn := range hv.instances {
		if vn != nil && vn.IsNameLock() {
			return true
		}
	}
	return false
}

// IsPersist returns true if any instance Varnode has the persist flag.
// C++ parity: HighVariable::isPersist (variable.cc)
func (hv *HighVariable) IsPersist() bool {
	if hv == nil {
		return false
	}
	for _, vn := range hv.instances {
		if vn != nil && vn.IsPersist() {
			return true
		}
	}
	return false
}

// PhysicalRep returns the first non-unique, non-constant instance Varnode
// (i.e., the representative backed by physical storage: register or stack).
// Returns nil if the HV only has unique-space intermediates.
//
// Two HVs that both have PhysicalRep() at different (Space, Offset) addresses
// represent distinct physical variables and must not be merged.
// C++ parity: indirect equivalent of HighVariable::getTiedVarnode() extended
// to register-space varnodes, which Ghidra handles via Cover intersection.
func (hv *HighVariable) PhysicalRep() *Varnode {
	if hv == nil {
		return nil
	}
	for _, vn := range hv.instances {
		if vn == nil {
			continue
		}
		if vn.IsConstant() {
			continue
		}
		sp := vn.Space()
		if sp == nil || sp.IsUnique() {
			continue
		}
		return vn
	}
	return nil
}

// Type returns the data-type of the high variable: that of its most locked,
// most specific member. The stored annotation is only a fallback for a high
// whose members carry no type yet. Recomputed on each call instead of cached
// with a dirty flag, so member type changes are always seen.
// C++ parity: HighVariable::getType -> updateType / getTypeRepresentative.
func (hv *HighVariable) Type() Datatype {
	if hv == nil {
		return nil
	}
	if hv.finalType != nil {
		return hv.finalType
	}
	var rep *Varnode
	for _, vn := range hv.instances {
		if vn == nil || vn.Type() == nil {
			continue
		}
		// A free Varnode without readers is one C++ clearDeadVarnodes would
		// have destroyed (removing it from its high); one created since the
		// last ClearDeadVarnodes must not vote here.
		if vn.IsFree() && vn.HasNoDescend() {
			continue
		}
		switch {
		case rep == nil:
			rep = vn
		case rep.IsTypeLock() != vn.IsTypeLock():
			if vn.IsTypeLock() {
				rep = vn
			}
		case typeOrderBool(vn.Type(), rep.Type()) < 0:
			rep = vn
		}
	}
	if rep == nil {
		return hv.datatype
	}
	return hv.stripType(rep.Type())
}

// stripType drops the partial or relative form of a variable's data-type,
// except a piece of a structure or union backed by a bigger symbol, and a
// partial enumeration on a lone constant.
// C++ parity: HighVariable::stripType.
func (hv *HighVariable) stripType(tp Datatype) Datatype {
	keepPartial := func() bool {
		if sym := hv.GetSymbol(); sym != nil && sym.Type() != nil && hv.GetSymbolOffset() != -1 {
			m := sym.Type().Metatype()
			return m == TYPE_STRUCT || m == TYPE_UNION // A bigger backing symbol
		}
		// A global variable's symbol is kept by the global scope.
		if fd := hv.funcdata(); fd != nil {
			for _, vn := range hv.instances {
				e := fd.globalEntryOf(vn)
				if e == nil || e.Symbol() == nil || e.Symbol().Type() == nil {
					continue
				}
				st := e.Symbol().Type()
				if vn.Space() == e.Addr().Space && vn.Offset() == e.Addr().Offset && vn.Size() == st.Size() {
					return false // The whole symbol (symbol offset -1)
				}
				m := st.Metatype()
				return m == TYPE_STRUCT || m == TYPE_UNION
			}
		}
		return false
	}
	switch t := tp.(type) {
	case *Enum:
		if t.parent != nil {
			if len(hv.instances) == 1 && hv.instances[0].IsConstant() {
				return t // Only preserve a partial enum on a constant
			}
			return t.stripped
		}
	case *PartialStruct:
		if keepPartial() {
			return t
		}
		return t.stripped
	case *PartialUnion:
		if keepPartial() {
			return t
		}
		return t.stripped
	case *Pointer:
		if t.relStripped != nil {
			return t.relStripped
		}
	}
	return tp
}

// SetType sets the type annotation for this high variable.
// C++ parity: HighVariable::setType (partial)
func (hv *HighVariable) SetType(dt Datatype) {
	if hv == nil {
		return
	}
	hv.datatype = dt
}

// rebuildCover recomputes the union Cover from all member Varnodes.
// Must be called before any Cover-based intersection test.
// C++ parity: HighVariable::updateInternalCover
func (hv *HighVariable) rebuildCover() {
	if hv == nil {
		return
	}
	c := &Cover{}
	for _, vn := range hv.instances {
		vnCover := &Cover{}
		vnCover.Rebuild(vn)
		c.Merge(vnCover)
	}
	hv.cover = c
}

// getCover returns the current Cover, rebuilding it if nil (dirty).
// C++ parity: HighVariable::getCover / updateInternalCover
func (hv *HighVariable) getCover() *Cover {
	if hv == nil {
		return nil
	}
	internal := hv.internalCover()
	if hv.piece == nil {
		return internal
	}
	// A piece of a group answers with its extended cover: its own plus that
	// of every piece overlapping it. C++ parity: HighVariable::getCover ->
	// VariablePiece::updateCover (recomputed here rather than cached).
	ext := &Cover{}
	ext.Merge(internal)
	for _, other := range hv.piece.intersections() {
		if c := other.high.internalCover(); c != nil {
			ext.Merge(c)
		}
	}
	return ext
}

// internalCover is the union of the instance covers.
// C++ parity: HighVariable::internalCover / updateInternalCover.
func (hv *HighVariable) internalCover() *Cover {
	if hv.cover == nil {
		hv.rebuildCover()
	}
	return hv.cover
}

// MarkCoverDirty invalidates the cached Cover so it is rebuilt on next access.
// C++ parity: HighVariable::coverDirty
func (hv *HighVariable) MarkCoverDirty() {
	if hv != nil {
		hv.cover = nil
	}
}

func (hv *HighVariable) SetExplicit() {
	if hv == nil {
		return
	}
	for _, vn := range hv.instances {
		if vn != nil {
			vn.SetExplicit()
		}
	}
}

func (hv *HighVariable) ClearImplied() {
	if hv == nil {
		return
	}
	for _, vn := range hv.instances {
		if vn != nil {
			vn.ClearImplied()
		}
	}
}

// isExtraOut reports whether the variable holds an extra call output: an
// INDIRECT creation that is not address tied.
// C++ parity: HighVariable::isExtraOut.
func (hv *HighVariable) isExtraOut() bool {
	var fl uint32
	for _, vn := range hv.instances {
		fl |= vn.flags & (VarnodeIndirectCreation | VarnodeAddrTied)
	}
	return fl == VarnodeIndirectCreation
}

// numMergeClasses is the number of speculatively merged groups.
// C++ parity: HighVariable::getNumMergeClasses.
func (hv *HighVariable) numMergeClasses() int {
	if hv.mergeClasses == 0 {
		return 1
	}
	return hv.mergeClasses
}

// finalizeDatatype fixes the variable's data-type to its symbol's (piece of)
// data-type. C++ parity: HighVariable::finalizeDatatype.
// off is the variable's byte offset within the symbol.
func (hv *HighVariable) finalizeDatatype(tf *TypeFactory, sym *Symbol, off int64) {
	if sym == nil || sym.Type() == nil || len(hv.instances) == 0 {
		return
	}
	tp := tf.exactPiece(sym.Type(), off, hv.instances[0].Size())
	if tp == nil || tp.Metatype() == TYPE_UNKNOWN {
		return
	}
	hv.finalType = hv.stripType(tp)
}

// funcdata is the function holding the variable, found through an op of one
// of its instances.
func (hv *HighVariable) funcdata() *Funcdata {
	for _, vn := range hv.instances {
		if op := vn.Def(); op != nil {
			if fd := opFuncdata(op); fd != nil {
				return fd
			}
		}
		for _, op := range vn.DescendIter() {
			if fd := opFuncdata(op); fd != nil {
				return fd
			}
		}
	}
	return nil
}
