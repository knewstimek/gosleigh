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

	"gosleigh/pkg/address"
)

// paramEntry mirrors the small subset of Ghidra ParamEntry state needed for ParamTrial ordering.
// C++ parity: fspec.hh ParamEntry (partial)
type paramEntry struct {
	group        int32
	exclusion    bool
	reverseStack bool
}

// ParamTrial is a placeholder for a potential parameter location.
// C++ parity: fspec.hh ParamTrial
type ParamTrial struct {
	flags         uint32
	addr          address.Address
	size          int32
	slot          int32
	entry         *paramEntry
	offset        int32
	fixedPosition int32
}

const (
	paramTrialChecked           uint32 = 1
	paramTrialUsed              uint32 = 2
	paramTrialDefNoUse          uint32 = 4
	paramTrialActive            uint32 = 8
	paramTrialUnref             uint32 = 0x10
	paramTrialKilledByCall      uint32 = 0x20
	paramTrialRemFormed         uint32 = 0x40
	paramTrialIndCreateFormed   uint32 = 0x80
	paramTrialCondExeEffect     uint32 = 0x100
	paramTrialAncestorRealistic uint32 = 0x200
	paramTrialAncestorSolid     uint32 = 0x400
)

// NewParamTrial constructs a trial from its address, size, and slot.
// C++ parity: ParamTrial::ParamTrial
func NewParamTrial(addr address.Address, size, slot int32) ParamTrial {
	return ParamTrial{addr: addr, size: size, slot: slot, offset: -1, fixedPosition: -1}
}

// GetAddress returns the trial address.
// C++ parity: ParamTrial::getAddress
func (p *ParamTrial) GetAddress() address.Address {
	if p == nil {
		return address.Address{}
	}
	return p.addr
}

// GetSize returns the trial size.
// C++ parity: ParamTrial::getSize
func (p *ParamTrial) GetSize() int32 {
	if p == nil {
		return 0
	}
	return p.size
}

// GetSlot returns the assigned slot.
// C++ parity: ParamTrial::getSlot
func (p *ParamTrial) GetSlot() int32 {
	if p == nil {
		return -1
	}
	return p.slot
}

// SetSlot updates the assigned slot.
// C++ parity: ParamTrial::setSlot
func (p *ParamTrial) SetSlot(val int32) {
	if p == nil {
		return
	}
	p.slot = val
}

// GetEntry returns the prototype entry matched to this trial.
// C++ parity: ParamTrial::getEntry
func (p *ParamTrial) GetEntry() *paramEntry {
	if p == nil {
		return nil
	}
	return p.entry
}

// GetOffset returns the offset into the matched entry.
// C++ parity: ParamTrial::getOffset
func (p *ParamTrial) GetOffset() int32 {
	if p == nil {
		return -1
	}
	return p.offset
}

// SetEntry records the matched entry and its offset.
// C++ parity: ParamTrial::setEntry
func (p *ParamTrial) SetEntry(ent *paramEntry, off int32) {
	if p == nil {
		return
	}
	p.entry = ent
	p.offset = off
}

// SetFixedPosition updates the fixed-position sort key.
// C++ parity: ParamTrial::setFixedPosition
func (p *ParamTrial) SetFixedPosition(pos int32) {
	if p == nil {
		return
	}
	p.fixedPosition = pos
}

// MarkUsed marks the trial as a formal parameter.
// C++ parity: ParamTrial::markUsed
func (p *ParamTrial) MarkUsed() {
	if p == nil {
		return
	}
	p.flags |= paramTrialUsed
}

// MarkActive marks the trial as actively used in data-flow.
// C++ parity: ParamTrial::markActive
func (p *ParamTrial) MarkActive() {
	if p == nil {
		return
	}
	p.flags |= paramTrialActive | paramTrialChecked
}

// MarkNotActive marks the trial as not actively used.
// C++ parity: ParamTrial::markInactive
func (p *ParamTrial) MarkNotActive() {
	if p == nil {
		return
	}
	p.flags &^= paramTrialActive
	p.flags |= paramTrialChecked
}

// MarkInactive is an alias for MarkNotActive.
// C++ parity: ParamTrial::markInactive
func (p *ParamTrial) MarkInactive() { p.MarkNotActive() }

// MarkNoUse marks the trial as definitely not a parameter.
// C++ parity: ParamTrial::markNoUse
func (p *ParamTrial) MarkNoUse() {
	if p == nil {
		return
	}
	p.flags &^= (paramTrialActive | paramTrialUsed)
	p.flags |= paramTrialChecked | paramTrialDefNoUse
}

// MarkUnref marks the trial as having no varnode representative.
// C++ parity: ParamTrial::markUnref
func (p *ParamTrial) MarkUnref() {
	if p == nil {
		return
	}
	p.flags |= paramTrialUnref | paramTrialChecked
	p.slot = -1
}

// MarkKilledByCall marks the trial as killed by a call.
// C++ parity: ParamTrial::markKilledByCall
func (p *ParamTrial) MarkKilledByCall() {
	if p == nil {
		return
	}
	p.flags |= paramTrialKilledByCall
}

// IsChecked reports whether the trial has been checked.
// C++ parity: ParamTrial::isChecked
func (p *ParamTrial) IsChecked() bool {
	return p != nil && p.flags&paramTrialChecked != 0
}

// IsActive reports whether the trial is actively used in data-flow.
// C++ parity: ParamTrial::isActive
func (p *ParamTrial) IsActive() bool {
	return p != nil && p.flags&paramTrialActive != 0
}

// IsDefinitelyNotUsed reports whether the trial is definitely not used.
// C++ parity: ParamTrial::isDefinitelyNotUsed
func (p *ParamTrial) IsDefinitelyNotUsed() bool {
	return p != nil && p.flags&paramTrialDefNoUse != 0
}

// IsUsed reports whether the trial is a formal parameter.
// C++ parity: ParamTrial::isUsed
func (p *ParamTrial) IsUsed() bool {
	return p != nil && p.flags&paramTrialUsed != 0
}

// IsUnref reports whether the trial has no representative varnode.
// C++ parity: ParamTrial::isUnref
func (p *ParamTrial) IsUnref() bool {
	return p != nil && p.flags&paramTrialUnref != 0
}

// IsKilledByCall reports whether the storage is likely killed by a call.
// C++ parity: ParamTrial::isKilledByCall
func (p *ParamTrial) IsKilledByCall() bool {
	return p != nil && p.flags&paramTrialKilledByCall != 0
}

// SetRemFormed marks the trial as formed by a remainder operation.
// C++ parity: ParamTrial::setRemFormed
func (p *ParamTrial) SetRemFormed() {
	if p == nil {
		return
	}
	p.flags |= paramTrialRemFormed
}

// IsRemFormed reports whether the trial came from a remainder operation.
// C++ parity: ParamTrial::isRemFormed
func (p *ParamTrial) IsRemFormed() bool {
	return p != nil && p.flags&paramTrialRemFormed != 0
}

// SetIndCreateFormed marks the trial as formed by indirect creation.
// C++ parity: ParamTrial::setIndCreateFormed
func (p *ParamTrial) SetIndCreateFormed() {
	if p == nil {
		return
	}
	p.flags |= paramTrialIndCreateFormed
}

// IsIndCreateFormed reports whether the trial came from indirect creation.
// C++ parity: ParamTrial::isIndCreateFormed
func (p *ParamTrial) IsIndCreateFormed() bool {
	return p != nil && p.flags&paramTrialIndCreateFormed != 0
}

// SetCondExeEffect marks the trial as potentially affected by conditional execution.
// C++ parity: ParamTrial::setCondExeEffect
func (p *ParamTrial) SetCondExeEffect() {
	if p == nil {
		return
	}
	p.flags |= paramTrialCondExeEffect
}

// HasCondExeEffect reports whether the trial may be affected by conditional execution.
// C++ parity: ParamTrial::hasCondExeEffect
func (p *ParamTrial) HasCondExeEffect() bool {
	return p != nil && p.flags&paramTrialCondExeEffect != 0
}

// SetAncestorRealistic marks the trial as having a realistic ancestor.
// C++ parity: ParamTrial::setAncestorRealistic
func (p *ParamTrial) SetAncestorRealistic() {
	if p == nil {
		return
	}
	p.flags |= paramTrialAncestorRealistic
}

// HasAncestorRealistic reports whether the trial has a realistic ancestor.
// C++ parity: ParamTrial::hasAncestorRealistic
func (p *ParamTrial) HasAncestorRealistic() bool {
	return p != nil && p.flags&paramTrialAncestorRealistic != 0
}

// SetAncestorSolid marks the trial as showing solid movement into a Varnode.
// C++ parity: ParamTrial::setAncestorSolid
func (p *ParamTrial) SetAncestorSolid() {
	if p == nil {
		return
	}
	p.flags |= paramTrialAncestorSolid
}

// HasAncestorSolid reports whether the trial shows solid movement into a Varnode.
// C++ parity: ParamTrial::hasAncestorSolid
func (p *ParamTrial) HasAncestorSolid() bool {
	return p != nil && p.flags&paramTrialAncestorSolid != 0
}

// SplitHi creates a trial for the first sz bytes.
// C++ parity: ParamTrial::splitHi
func (p ParamTrial) SplitHi(sz int32) ParamTrial {
	res := NewParamTrial(p.addr, sz, p.slot)
	res.flags = p.flags
	return res
}

// SplitLo creates a trial for the last sz bytes.
// C++ parity: ParamTrial::splitLo
func (p ParamTrial) SplitLo(sz int32) ParamTrial {
	newAddr := p.addr.Add(uint64(p.size - sz))
	res := NewParamTrial(newAddr, sz, p.slot+1)
	res.flags = p.flags
	return res
}

// TestShrink reports whether the trial can be shrunk to the new range.
// C++ parity: ParamTrial::testShrink
func (p ParamTrial) TestShrink(newAddr address.Address, sz int32) bool {
	testAddr := p.addr
	if p.addr.Space != nil && p.addr.Space.BigEndian {
		testAddr = p.addr.Add(uint64(p.size - sz))
	}
	if testAddr != newAddr {
		return false
	}
	return p.entry == nil
}

// Less orders trials in formal-parameter order.
// C++ parity: ParamTrial::operator<
func (p ParamTrial) Less(b ParamTrial) bool {
	if p.entry == nil && b.entry == nil {
		if p.slot != b.slot {
			return p.slot < b.slot
		}
		if p.addr != b.addr {
			return p.addr.Less(b.addr)
		}
		if p.size != b.size {
			return p.size < b.size
		}
		return false
	}
	if p.entry == nil {
		return false
	}
	if b.entry == nil {
		return true
	}
	if p.entry.group != b.entry.group {
		return p.entry.group < b.entry.group
	}
	if p.entry != b.entry {
		return false
	}
	if p.entry.exclusion {
		return p.offset < b.offset
	}
	if p.addr != b.addr {
		if p.entry.reverseStack {
			return b.addr.Less(p.addr)
		}
		return p.addr.Less(b.addr)
	}
	return p.size < b.size
}

// FixedPositionCompare sorts by fixed position and then by Less.
// C++ parity: ParamTrial::fixedPositionCompare
func FixedPositionCompare(a, b ParamTrial) bool {
	if a.fixedPosition == -1 && b.fixedPosition == -1 {
		return a.Less(b)
	}
	if a.fixedPosition == -1 {
		return false
	}
	if b.fixedPosition == -1 {
		return true
	}
	return a.fixedPosition < b.fixedPosition
}

// ParamActive is the container for parameter trials under analysis.
// C++ parity: fspec.hh ParamActive
type ParamActive struct {
	trial            []ParamTrial
	slotbase         int32
	stackplaceholder int32
	numpasses        int32
	maxpass          int32
	isfullychecked   bool
	needsfinalcheck  bool
	recoversubcall   bool
	joinReverse      bool
}

// NewParamActive constructs an empty active-trial container.
// C++ parity: ParamActive::ParamActive
func NewParamActive(recoversub bool) *ParamActive {
	return &ParamActive{
		slotbase:         1,
		stackplaceholder: -1,
		maxpass:          0,
		recoversubcall:   recoversub,
	}
}

// Clear resets the container to an empty state.
// C++ parity: ParamActive::clear
func (p *ParamActive) Clear() {
	if p == nil {
		return
	}
	p.trial = nil
	p.slotbase = 1
	p.stackplaceholder = -1
	p.numpasses = 0
	p.isfullychecked = false
	p.joinReverse = false
}

// RegisterTrial adds a new trial to the container.
// C++ parity: ParamActive::registerTrial
func (p *ParamActive) RegisterTrial(addr address.Address, sz int32) {
	if p == nil {
		return
	}
	tr := NewParamTrial(addr, sz, p.slotbase)
	if addr.Space != nil && addr.Space.Kind != address.SpaceKindStack {
		tr.MarkKilledByCall()
	}
	p.trial = append(p.trial, tr)
	p.slotbase++
}

// NumTrials returns the number of tracked trials.
// C++ parity: ParamActive::getNumTrials
func (p *ParamActive) NumTrials() int {
	if p == nil {
		return 0
	}
	return len(p.trial)
}

// Trial returns the i-th trial.
// C++ parity: ParamActive::getTrial
func (p *ParamActive) Trial(i int) *ParamTrial {
	if p == nil || i < 0 || i >= len(p.trial) {
		return nil
	}
	return &p.trial[i]
}

// TrialForInputVarnode returns the trial mapped to the given input slot.
// C++ parity: ParamActive::getTrialForInputVarnode
func (p *ParamActive) TrialForInputVarnode(slot int) *ParamTrial {
	if p == nil {
		return nil
	}
	target := int32(slot + 1)
	for i := range p.trial {
		if p.trial[i].slot == target {
			return &p.trial[i]
		}
	}
	return nil
}

// WhichTrial finds the first overlapping trial index.
// C++ parity: ParamActive::whichTrial
func (p *ParamActive) WhichTrial(addr address.Address, sz int32) int {
	if p == nil {
		return -1
	}
	for i := range p.trial {
		cur := p.trial[i]
		if cur.addr.Space != addr.Space || cur.addr.Space == nil || cur.addr.Space.IsConstant() {
			continue
		}
		if overlaps(addr, sz, cur.addr, cur.size) {
			return i
		}
	}
	return -1
}

// NeedsFinalCheck reports whether a final pass is required.
// C++ parity: ParamActive::needsFinalCheck
func (p *ParamActive) NeedsFinalCheck() bool {
	return p != nil && p.needsfinalcheck
}

// MarkNeedsFinalCheck requests a final pass.
// C++ parity: ParamActive::markNeedsFinalCheck
func (p *ParamActive) MarkNeedsFinalCheck() {
	if p == nil {
		return
	}
	p.needsfinalcheck = true
}

// IsJoinReverse reports whether parameters should be joined in reverse order.
// C++ parity: ParamActive::isJoinReverse
func (p *ParamActive) IsJoinReverse() bool {
	return p != nil && p.joinReverse
}

// SetJoinReverse marks that parameters should be joined in reverse order.
// C++ parity: ParamActive::setJoinReverse
func (p *ParamActive) SetJoinReverse() {
	if p == nil {
		return
	}
	p.joinReverse = true
}

// IsRecoverSubcall reports whether this tracks a sub-function recovery.
// C++ parity: ParamActive::isRecoverSubcall
func (p *ParamActive) IsRecoverSubcall() bool {
	return p != nil && p.recoversubcall
}

// IsFullyChecked reports whether all trials have been checked.
// C++ parity: ParamActive::isFullyChecked
func (p *ParamActive) IsFullyChecked() bool {
	return p != nil && p.isfullychecked
}

// MarkFullyChecked marks the container as complete.
// C++ parity: ParamActive::markFullyChecked
func (p *ParamActive) MarkFullyChecked() {
	if p == nil {
		return
	}
	p.isfullychecked = true
}

// SetPlaceholderSlot reserves a placeholder stack slot.
// C++ parity: ParamActive::setPlaceholderSlot
func (p *ParamActive) SetPlaceholderSlot() {
	if p == nil {
		return
	}
	p.stackplaceholder = p.slotbase
	p.slotbase++
}

// FreePlaceholderSlot releases the placeholder slot.
// C++ parity: ParamActive::freePlaceholderSlot
func (p *ParamActive) FreePlaceholderSlot() {
	if p == nil {
		return
	}
	for i := range p.trial {
		if p.trial[i].slot > p.stackplaceholder {
			p.trial[i].slot--
		}
	}
	p.stackplaceholder = -2
	p.slotbase--
	p.maxpass = 0
}

// NumPasses returns the number of analysis passes.
// C++ parity: ParamActive::getNumPasses
func (p *ParamActive) NumPasses() int32 {
	if p == nil {
		return 0
	}
	return p.numpasses
}

// MaxPass returns the pass limit.
// C++ parity: ParamActive::getMaxPass
func (p *ParamActive) MaxPass() int32 {
	if p == nil {
		return 0
	}
	return p.maxpass
}

// SetMaxPass updates the pass limit.
// C++ parity: ParamActive::setMaxPass
func (p *ParamActive) SetMaxPass(val int32) {
	if p == nil {
		return
	}
	p.maxpass = val
}

// FinishPass records the completion of an analysis pass.
// C++ parity: ParamActive::finishPass
func (p *ParamActive) FinishPass() {
	if p == nil {
		return
	}
	p.numpasses++
}

// SortTrials orders the trials in formal-parameter order.
// C++ parity: ParamActive::sortTrials
func (p *ParamActive) SortTrials() {
	if p == nil {
		return
	}
	sort.SliceStable(p.trial, func(i, j int) bool {
		return p.trial[i].Less(p.trial[j])
	})
}

// SortFixedPosition orders trials by fixed position and then by Less.
// C++ parity: ParamActive::sortFixedPosition
func (p *ParamActive) SortFixedPosition() {
	if p == nil {
		return
	}
	sort.SliceStable(p.trial, func(i, j int) bool {
		return FixedPositionCompare(p.trial[i], p.trial[j])
	})
}

// DeleteUnusedTrials removes trials that are not marked as used.
// C++ parity: ParamActive::deleteUnusedTrials
func (p *ParamActive) DeleteUnusedTrials() {
	if p == nil {
		return
	}
	newTrials := make([]ParamTrial, 0, len(p.trial))
	slot := int32(1)
	for i := range p.trial {
		cur := p.trial[i]
		if !cur.IsUsed() {
			continue
		}
		cur.slot = slot
		slot++
		newTrials = append(newTrials, cur)
	}
	p.trial = newTrials
}

// SplitTrial splits the given trial into two at the requested size.
// C++ parity: ParamActive::splitTrial
func (p *ParamActive) SplitTrial(i int, sz int32) {
	if p == nil || i < 0 || i >= len(p.trial) {
		return
	}
	if p.stackplaceholder >= 0 {
		return
	}
	slot := p.trial[i].slot
	newTrials := make([]ParamTrial, 0, len(p.trial)+1)
	for j := 0; j < i; j++ {
		cur := p.trial[j]
		if cur.slot > slot {
			cur.slot++
		}
		newTrials = append(newTrials, cur)
	}
	newTrials = append(newTrials, p.trial[i].SplitHi(sz))
	newTrials = append(newTrials, p.trial[i].SplitLo(p.trial[i].size-sz))
	for j := i + 1; j < len(p.trial); j++ {
		cur := p.trial[j]
		if cur.slot > slot {
			cur.slot++
		}
		newTrials = append(newTrials, cur)
	}
	p.slotbase++
	p.trial = newTrials
}

// JoinTrial joins the trial at the given slot with the next slot.
// C++ parity: ParamActive::joinTrial
func (p *ParamActive) JoinTrial(slot int32, addr address.Address, sz int32) {
	if p == nil {
		return
	}
	if p.stackplaceholder >= 0 {
		return
	}
	newTrials := make([]ParamTrial, 0, len(p.trial))
	var sizecheck int32
	for i := range p.trial {
		cur := p.trial[i]
		switch cur.slot {
		case slot:
			sizecheck += cur.size
			joined := NewParamTrial(addr, sz, slot)
			joined.MarkUsed()
			joined.MarkActive()
			newTrials = append(newTrials, joined)
		case slot + 1:
			sizecheck += cur.size
		default:
			if cur.slot > slot {
				cur.slot--
			}
			newTrials = append(newTrials, cur)
		}
	}
	if sizecheck != sz {
		return
	}
	p.slotbase--
	p.trial = newTrials
}

// NumUsed returns the number of leading used trials.
// C++ parity: ParamActive::getNumUsed
func (p *ParamActive) NumUsed() int {
	if p == nil {
		return 0
	}
	count := 0
	for count < len(p.trial) {
		if !p.trial[count].IsUsed() {
			break
		}
		count++
	}
	return count
}

// ApplyActiveParamModel rebuilds the function's local scope from active parameter trials.
// C++ parity: ActionActiveParam::apply (Go-local helper)
func ApplyActiveParamModel(fd *Funcdata) bool {
	if fd == nil {
		return false
	}
	fp := fd.GetFuncProto()
	if fp == nil || fp.Model() == nil {
		return false
	}
	model := fp.Model()
	active := NewParamActive(false)

	all := fd.GetVarnodeBank().AllVarnodes()
	activeParamKeys := make(map[trialKey]struct{})
	filtered := make([]*Varnode, 0, len(all))

	for _, vn := range all {
		if vn == nil || vn.Space() == nil {
			continue
		}
		if isParamLocation(vn, model) {
			active.RegisterTrial(vn.Addr(), vn.Size())
			cur := active.Trial(active.NumTrials() - 1)
			if vn.IsInput() || vn.NumDescend() > 0 {
				cur.MarkUsed()
				cur.MarkActive()
				activeParamKeys[newTrialKey(vn)] = struct{}{}
			}
		}
		if isLocalLocation(vn, model) {
			filtered = append(filtered, vn)
		}
	}

	active.SortTrials()
	active.DeleteUnusedTrials()
	if active.NumUsed() == 0 {
		return false
	}
	for _, vn := range all {
		if vn == nil {
			continue
		}
		if isLocalLocation(vn, model) {
			continue
		}
		if _, ok := activeParamKeys[newTrialKey(vn)]; ok {
			filtered = append(filtered, vn)
		}
	}

	fp.SetInputLocked(true)
	sl := NewScopeLocal(model)
	fd.SetScopeLocal(sl)
	sl.BuildFromVarnodes(filtered, fp)
	return true
}

// ApplyActiveReturnModel wires the active return register and prunes dead return uses.
// C++ parity: ActionActiveReturn::apply (Go-local helper)
func ApplyActiveReturnModel(fd *Funcdata) bool {
	if fd == nil {
		return false
	}
	fp := fd.GetFuncProto()
	if fp == nil || fp.Model() == nil {
		return false
	}
	model := fp.Model()
	if model.ReturnRegSpaceIndex < 0 || model.ReturnRegSize == 0 {
		return false
	}

	active := NewParamActive(false)
	foundActive := false
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		if int(vn.Space().Index) != model.ReturnRegSpaceIndex || vn.Offset() != model.ReturnRegOffset || vn.Size() != model.ReturnRegSize {
			continue
		}
		active.RegisterTrial(vn.Addr(), vn.Size())
		cur := active.Trial(active.NumTrials() - 1)
		if vn.IsWritten() {
			for _, op := range fd.GetPcodeOpBank().AllOps() {
				if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
					continue
				}
				if ancestorOpUseReturn(vn, op, 1, 5, make(map[*PcodeOp]bool)) {
					cur.MarkUsed()
					cur.MarkActive()
					foundActive = true
					break
				}
			}
		}
	}

	if !foundActive {
		fp.SetOutputLock(false)
		applyReturnRecovery(fd)
		return false
	}

	fp.SetOutputLock(true)
	anchorReturnReg(fd, model)
	applyReturnRecovery(fd)
	return true
}

type trialKey struct {
	space *address.Space
	off   uint64
	size  int32
}

func newTrialKey(vn *Varnode) trialKey {
	if vn == nil || vn.Space() == nil {
		return trialKey{}
	}
	return trialKey{space: vn.Space(), off: vn.Offset(), size: vn.Size()}
}

func isParamLocation(vn *Varnode, model *ProtoModel) bool {
	if vn == nil || vn.Space() == nil || model == nil {
		return false
	}
	if model.StackSpace != nil && vn.Space() == model.StackSpace {
		return model.IsParamOffset(vn.Offset())
	}
	if len(model.RegParamOffsets) > 0 {
		if vn.Space().Name != "register" {
			return false
		}
		_, ok := model.RegParamOffsets[vn.Offset()]
		return ok
	}
	return false
}

func isLocalLocation(vn *Varnode, model *ProtoModel) bool {
	if vn == nil || vn.Space() == nil || model == nil {
		return false
	}
	if model.StackSpace != nil && vn.Space() == model.StackSpace {
		return model.IsLocalOffset(vn.Offset())
	}
	return false
}

func overlaps(aAddr address.Address, aSize int32, bAddr address.Address, bSize int32) bool {
	if aAddr.Space != bAddr.Space || aAddr.Space == nil || aAddr.Space.IsConstant() {
		return false
	}
	aStart := aAddr.Offset
	bStart := bAddr.Offset
	if aStart < bStart {
		return aStart+uint64(aSize) > bStart
	}
	return bStart+uint64(bSize) > aStart
}
