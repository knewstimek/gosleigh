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

// HighVariable is a high-level variable that may be backed by one or more
// low-level Varnodes (SSA values). It carries a human-readable name for
// output in the decompiler.
//
// C++ parity: varnode.hh HighVariable (partial)
type HighVariable struct {
	name      string
	instances []*Varnode
	datatype  Datatype // type annotation; nil means unknown

	// cover is the union of live ranges of all member Varnodes.
	// nil means the cover has not been computed yet (dirty).
	// C++ parity: HighVariable::internalCover
	cover *Cover
}

// NewHighVariable creates a HighVariable with the given name and zero instances.
// C++ parity: HighVariable::HighVariable
func NewHighVariable(name string) *HighVariable {
	return &HighVariable{name: name}
}

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
	hv.instances = append(hv.instances, vn)
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

// Type returns the type annotation for this high variable, or nil if unset.
func (hv *HighVariable) Type() Datatype {
	if hv == nil {
		return nil
	}
	return hv.datatype
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
