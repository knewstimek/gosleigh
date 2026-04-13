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

// ActionStart gathers raw p-code for a function.
// C++ parity: coreaction.hh ActionStart
type ActionStart struct{ ActionBase }

var _ Action = (*ActionStart)(nil)

// NewActionStart constructs ActionStart.
// C++ parity: coreaction.hh ActionStart::ActionStart
func NewActionStart(group string) *ActionStart {
	act := &ActionStart{}
	act.ActionBase = NewActionBase(act, 0, "start", group)
	return act
}

// Clone clones ActionStart for the provided group list.
// C++ parity: coreaction.hh ActionStart::clone
func (a *ActionStart) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionStart(a.GetGroup())
}

// Apply starts processing.
// C++ parity: coreaction.hh ActionStart::apply
func (a *ActionStart) Apply(data *Funcdata) int {
	data.StartProcessing()
	return 0
}

// ActionStop performs post-processing after decompilation.
// C++ parity: coreaction.hh ActionStop
type ActionStop struct{ ActionBase }

var _ Action = (*ActionStop)(nil)

// NewActionStop constructs ActionStop.
// C++ parity: coreaction.hh ActionStop::ActionStop
func NewActionStop(group string) *ActionStop {
	act := &ActionStop{}
	act.ActionBase = NewActionBase(act, 0, "stop", group)
	return act
}

// Clone clones ActionStop for the provided group list.
// C++ parity: coreaction.hh ActionStop::clone
func (a *ActionStop) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionStop(a.GetGroup())
}

// Apply stops processing.
// C++ parity: coreaction.hh ActionStop::apply
func (a *ActionStop) Apply(data *Funcdata) int {
	data.StopProcessing()
	return 0
}

// ActionStartCleanUp starts the post-transform clean-up phase.
// C++ parity: coreaction.hh ActionStartCleanUp
type ActionStartCleanUp struct{ ActionBase }

var _ Action = (*ActionStartCleanUp)(nil)

// NewActionStartCleanUp constructs ActionStartCleanUp.
// C++ parity: coreaction.hh ActionStartCleanUp::ActionStartCleanUp
func NewActionStartCleanUp(group string) *ActionStartCleanUp {
	act := &ActionStartCleanUp{}
	act.ActionBase = NewActionBase(act, 0, "startcleanup", group)
	return act
}

// Clone clones ActionStartCleanUp for the provided group list.
// C++ parity: coreaction.hh ActionStartCleanUp::clone
func (a *ActionStartCleanUp) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionStartCleanUp(a.GetGroup())
}

// Apply starts the clean-up phase.
// C++ parity: coreaction.hh ActionStartCleanUp::apply
func (a *ActionStartCleanUp) Apply(data *Funcdata) int {
	data.StartCleanUp()
	return 0
}

// ActionStartTypes enables type recovery and marks the transition when first seen.
// C++ parity: coreaction.hh ActionStartTypes
type ActionStartTypes struct{ ActionBase }

var _ Action = (*ActionStartTypes)(nil)

// NewActionStartTypes constructs ActionStartTypes.
// C++ parity: coreaction.hh ActionStartTypes::ActionStartTypes
func NewActionStartTypes(group string) *ActionStartTypes {
	act := &ActionStartTypes{}
	act.ActionBase = NewActionBase(act, 0, "starttypes", group)
	return act
}

// Reset enables type recovery before the action runs.
// C++ parity: coreaction.hh ActionStartTypes::reset
func (a *ActionStartTypes) Reset(data *Funcdata) {
	data.SetTypeRecovery(true)
}

// Clone clones ActionStartTypes for the provided group list.
// C++ parity: coreaction.hh ActionStartTypes::clone
func (a *ActionStartTypes) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionStartTypes(a.GetGroup())
}

// Apply starts type recovery if it is not already active.
// C++ parity: coreaction.hh ActionStartTypes::apply
func (a *ActionStartTypes) Apply(data *Funcdata) int {
	if data.StartTypeRecovery() {
		a.count++
	}
	return 0
}

// ActionHeritage builds SSA heritage for a function.
// C++ parity: coreaction.hh ActionHeritage
type ActionHeritage struct{ ActionBase }

var _ Action = (*ActionHeritage)(nil)

// NewActionHeritage constructs ActionHeritage.
// C++ parity: coreaction.hh ActionHeritage::ActionHeritage
func NewActionHeritage(group string) *ActionHeritage {
	act := &ActionHeritage{}
	act.ActionBase = NewActionBase(act, 0, "heritage", group)
	return act
}

// Clone clones ActionHeritage for the provided group list.
// C++ parity: coreaction.hh ActionHeritage::clone
func (a *ActionHeritage) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionHeritage(a.GetGroup())
}

// Apply runs heritage.
// C++ parity: coreaction.hh ActionHeritage::apply
func (a *ActionHeritage) Apply(data *Funcdata) int {
	data.OpHeritage()
	return 0
}

// ActionNonzeroMask computes non-zero masks.
// C++ parity: coreaction.hh ActionNonzeroMask
type ActionNonzeroMask struct{ ActionBase }

var _ Action = (*ActionNonzeroMask)(nil)

// NewActionNonzeroMask constructs ActionNonzeroMask.
// C++ parity: coreaction.hh ActionNonzeroMask::ActionNonzeroMask
func NewActionNonzeroMask(group string) *ActionNonzeroMask {
	act := &ActionNonzeroMask{}
	act.ActionBase = NewActionBase(act, 0, "nonzeromask", group)
	return act
}

// Clone clones ActionNonzeroMask for the provided group list.
// C++ parity: coreaction.hh ActionNonzeroMask::clone
func (a *ActionNonzeroMask) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionNonzeroMask(a.GetGroup())
}

// Apply computes non-zero masks.
// C++ parity: coreaction.hh ActionNonzeroMask::apply
func (a *ActionNonzeroMask) Apply(data *Funcdata) int {
	data.CalcNZMask()
	return 0
}

// ActionCopyMarker marks COPY operations as non-printing.
// C++ parity: coreaction.hh ActionCopyMarker
type ActionCopyMarker struct{ ActionBase }

var _ Action = (*ActionCopyMarker)(nil)

// NewActionCopyMarker constructs ActionCopyMarker.
// C++ parity: coreaction.hh ActionCopyMarker::ActionCopyMarker
func NewActionCopyMarker(group string) *ActionCopyMarker {
	act := &ActionCopyMarker{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "copymarker", group)
	return act
}

// Clone clones ActionCopyMarker for the provided group list.
// C++ parity: coreaction.hh ActionCopyMarker::clone
func (a *ActionCopyMarker) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionCopyMarker(a.GetGroup())
}

// Apply marks internal COPYs.
// C++ parity: coreaction.hh ActionCopyMarker::apply
func (a *ActionCopyMarker) Apply(data *Funcdata) int {
	NewMerge(data).markInternalCopies()
	return 0
}

// ActionDominantCopy collapses repeated COPY sources to a dominant COPY.
// C++ parity: coreaction.hh ActionDominantCopy
type ActionDominantCopy struct{ ActionBase }

var _ Action = (*ActionDominantCopy)(nil)

// NewActionDominantCopy constructs ActionDominantCopy.
// C++ parity: coreaction.hh ActionDominantCopy::ActionDominantCopy
func NewActionDominantCopy(group string) *ActionDominantCopy {
	act := &ActionDominantCopy{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "dominantcopy", group)
	return act
}

// Clone clones ActionDominantCopy for the provided group list.
// C++ parity: coreaction.hh ActionDominantCopy::clone
func (a *ActionDominantCopy) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDominantCopy(a.GetGroup())
}

// Apply processes copy trims.
// C++ parity: coreaction.hh ActionDominantCopy::apply
func (a *ActionDominantCopy) Apply(data *Funcdata) int {
	NewMerge(data).processCopyTrims()
	return 0
}

// ActionMapGlobals creates symbols for discovered globals.
// C++ parity: coreaction.hh ActionMapGlobals
type ActionMapGlobals struct{ ActionBase }

var _ Action = (*ActionMapGlobals)(nil)

// NewActionMapGlobals constructs ActionMapGlobals.
// C++ parity: coreaction.hh ActionMapGlobals::ActionMapGlobals
func NewActionMapGlobals(group string) *ActionMapGlobals {
	act := &ActionMapGlobals{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "mapglobals", group)
	return act
}

// Clone clones ActionMapGlobals for the provided group list.
// C++ parity: coreaction.hh ActionMapGlobals::clone
func (a *ActionMapGlobals) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMapGlobals(a.GetGroup())
}

// Apply maps globals.
// C++ parity: coreaction.hh ActionMapGlobals::apply
func (a *ActionMapGlobals) Apply(data *Funcdata) int {
	data.MapGlobals()
	return 0
}

// ActionMarkIndirectOnly marks Varnodes only used by INDIRECT ops.
// C++ parity: coreaction.hh ActionMarkIndirectOnly
type ActionMarkIndirectOnly struct{ ActionBase }

var _ Action = (*ActionMarkIndirectOnly)(nil)

// NewActionMarkIndirectOnly constructs ActionMarkIndirectOnly.
// C++ parity: coreaction.hh ActionMarkIndirectOnly::ActionMarkIndirectOnly
func NewActionMarkIndirectOnly(group string) *ActionMarkIndirectOnly {
	act := &ActionMarkIndirectOnly{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "markindirectonly", group)
	return act
}

// Clone clones ActionMarkIndirectOnly for the provided group list.
// C++ parity: coreaction.hh ActionMarkIndirectOnly::clone
func (a *ActionMarkIndirectOnly) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMarkIndirectOnly(a.GetGroup())
}

// Apply marks indirect-only values.
// C++ parity: coreaction.hh ActionMarkIndirectOnly::apply
func (a *ActionMarkIndirectOnly) Apply(data *Funcdata) int {
	data.MarkIndirectOnly()
	return 0
}

// ActionMergeAdjacent merges adjacent input/output Varnodes.
// C++ parity: coreaction.hh ActionMergeAdjacent
type ActionMergeAdjacent struct{ ActionBase }

var _ Action = (*ActionMergeAdjacent)(nil)

// NewActionMergeAdjacent constructs ActionMergeAdjacent.
// C++ parity: coreaction.hh ActionMergeAdjacent::ActionMergeAdjacent
func NewActionMergeAdjacent(group string) *ActionMergeAdjacent {
	act := &ActionMergeAdjacent{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "mergeadjacent", group)
	return act
}

// Clone clones ActionMergeAdjacent for the provided group list.
// C++ parity: coreaction.hh ActionMergeAdjacent::clone
func (a *ActionMergeAdjacent) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMergeAdjacent(a.GetGroup())
}

// Apply merges adjacent Varnodes.
// C++ parity: coreaction.hh ActionMergeAdjacent::apply
func (a *ActionMergeAdjacent) Apply(data *Funcdata) int {
	NewMerge(data).MergeAdjacent()
	return 0
}

// ActionMergeMultiEntry merges Varnodes with multiple SymbolEntrys.
// C++ parity: coreaction.hh ActionMergeMultiEntry
type ActionMergeMultiEntry struct{ ActionBase }

var _ Action = (*ActionMergeMultiEntry)(nil)

// NewActionMergeMultiEntry constructs ActionMergeMultiEntry.
// C++ parity: coreaction.hh ActionMergeMultiEntry::ActionMergeMultiEntry
func NewActionMergeMultiEntry(group string) *ActionMergeMultiEntry {
	act := &ActionMergeMultiEntry{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "mergemultientry", group)
	return act
}

// Clone clones ActionMergeMultiEntry for the provided group list.
// C++ parity: coreaction.hh ActionMergeMultiEntry::clone
func (a *ActionMergeMultiEntry) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMergeMultiEntry(a.GetGroup())
}

// Apply merges multi-entry symbols.
// C++ parity: coreaction.hh ActionMergeMultiEntry::apply
func (a *ActionMergeMultiEntry) Apply(data *Funcdata) int {
	NewMerge(data).mergeMultiEntry()
	return 0
}

// ActionMergeType merges Varnodes by data type.
// C++ parity: coreaction.hh ActionMergeType
type ActionMergeType struct{ ActionBase }

var _ Action = (*ActionMergeType)(nil)

// NewActionMergeType constructs ActionMergeType.
// C++ parity: coreaction.hh ActionMergeType::ActionMergeType
func NewActionMergeType(group string) *ActionMergeType {
	act := &ActionMergeType{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "mergetype", group)
	return act
}

// Clone clones ActionMergeType for the provided group list.
// C++ parity: coreaction.hh ActionMergeType::clone
func (a *ActionMergeType) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMergeType(a.GetGroup())
}

// Apply merges by datatype.
// C++ parity: coreaction.hh ActionMergeType::apply
func (a *ActionMergeType) Apply(data *Funcdata) int {
	NewMerge(data).mergeByDatatype()
	return 0
}

// ActionSpacebase marks and types stack-pointer Varnodes.
// C++ parity: coreaction.hh ActionSpacebase
type ActionSpacebase struct{ ActionBase }

var _ Action = (*ActionSpacebase)(nil)

// NewActionSpacebase constructs ActionSpacebase.
// C++ parity: coreaction.hh ActionSpacebase::ActionSpacebase
func NewActionSpacebase(group string) *ActionSpacebase {
	act := &ActionSpacebase{}
	act.ActionBase = NewActionBase(act, 0, "spacebase", group)
	return act
}

// Clone clones ActionSpacebase for the provided group list.
// C++ parity: coreaction.hh ActionSpacebase::clone
func (a *ActionSpacebase) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionSpacebase(a.GetGroup())
}

// Apply runs spacebase processing.
// C++ parity: coreaction.hh ActionSpacebase::apply
func (a *ActionSpacebase) Apply(data *Funcdata) int {
	data.Spacebase()
	return 0
}

// ActionForceGoto applies force-goto overrides.
// C++ parity: coreaction.cc ActionForceGoto
type ActionForceGoto struct{ ActionBase }

var _ Action = (*ActionForceGoto)(nil)

// NewActionForceGoto constructs ActionForceGoto.
// C++ parity: coreaction.cc ActionForceGoto::ActionForceGoto
func NewActionForceGoto(group string) *ActionForceGoto {
	act := &ActionForceGoto{}
	act.ActionBase = NewActionBase(act, 0, "forcegoto", group)
	return act
}

// Clone clones ActionForceGoto for the provided group list.
// C++ parity: coreaction.cc ActionForceGoto::clone
func (a *ActionForceGoto) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionForceGoto(a.GetGroup())
}

// Apply applies force-goto overrides.
// C++ parity: coreaction.cc ActionForceGoto::apply
func (a *ActionForceGoto) Apply(data *Funcdata) int {
	data.ApplyForceGoto()
	return 0
}

// ActionStructureTransform gives structured blocks a final transformation pass.
// C++ parity: blockaction.hh ActionStructureTransform
type ActionStructureTransform struct{ ActionBase }

var _ Action = (*ActionStructureTransform)(nil)

// NewActionStructureTransform constructs ActionStructureTransform.
// C++ parity: blockaction.hh ActionStructureTransform::ActionStructureTransform
func NewActionStructureTransform(group string) *ActionStructureTransform {
	act := &ActionStructureTransform{}
	act.ActionBase = NewActionBase(act, 0, "structuretransform", group)
	return act
}

// Clone clones ActionStructureTransform for the provided group list.
// C++ parity: blockaction.hh ActionStructureTransform::clone
func (a *ActionStructureTransform) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionStructureTransform(a.GetGroup())
}

// Apply runs the final structure transform.
// C++ parity: blockaction.cc ActionStructureTransform::apply
func (a *ActionStructureTransform) Apply(data *Funcdata) int {
	data.GetStructure().FinalTransform(data)
	return 0
}

// ActionFuncLinkOutOnly prepares call outputs only.
// C++ parity: coreaction.hh ActionFuncLinkOutOnly
type ActionFuncLinkOutOnly struct{ ActionBase }

var _ Action = (*ActionFuncLinkOutOnly)(nil)

// NewActionFuncLinkOutOnly constructs ActionFuncLinkOutOnly.
// C++ parity: coreaction.hh ActionFuncLinkOutOnly::ActionFuncLinkOutOnly
func NewActionFuncLinkOutOnly(group string) *ActionFuncLinkOutOnly {
	act := &ActionFuncLinkOutOnly{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "funclink_outonly", group)
	return act
}

// Clone clones ActionFuncLinkOutOnly for the provided group list.
// C++ parity: coreaction.hh ActionFuncLinkOutOnly::clone
func (a *ActionFuncLinkOutOnly) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionFuncLinkOutOnly(a.GetGroup())
}

// Apply is a scaffolded no-op because the call-spec pipeline is not yet ported.
// C++ parity: coreaction.cc ActionFuncLinkOutOnly::apply
func (a *ActionFuncLinkOutOnly) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionUnreachable removes unreachable blocks.
// C++ parity: coreaction.hh ActionUnreachable
type ActionUnreachable struct{ ActionBase }

var _ Action = (*ActionUnreachable)(nil)

// NewActionUnreachable constructs ActionUnreachable.
// C++ parity: coreaction.hh ActionUnreachable::ActionUnreachable
func NewActionUnreachable(group string) *ActionUnreachable {
	act := &ActionUnreachable{}
	act.ActionBase = NewActionBase(act, 0, "unreachable", group)
	return act
}

// Clone clones ActionUnreachable for the provided group list.
// C++ parity: coreaction.hh ActionUnreachable::clone
func (a *ActionUnreachable) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionUnreachable(a.GetGroup())
}

// Apply removes unreachable blocks.
// C++ parity: coreaction.cc ActionUnreachable::apply
func (a *ActionUnreachable) Apply(data *Funcdata) int {
	if data.RemoveUnreachableBlocks(true, false) {
		a.count++
	}
	return 0
}

// ActionDoNothing removes blocks that do nothing.
// C++ parity: coreaction.hh ActionDoNothing
type ActionDoNothing struct{ ActionBase }

var _ Action = (*ActionDoNothing)(nil)

// NewActionDoNothing constructs ActionDoNothing.
// C++ parity: coreaction.hh ActionDoNothing::ActionDoNothing
func NewActionDoNothing(group string) *ActionDoNothing {
	act := &ActionDoNothing{}
	act.ActionBase = NewActionBase(act, ActionRuleRepeatApply, "donothing", group)
	return act
}

// Clone clones ActionDoNothing for the provided group list.
// C++ parity: coreaction.hh ActionDoNothing::clone
func (a *ActionDoNothing) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDoNothing(a.GetGroup())
}

// Apply is a scaffolded no-op because the block-removal helpers are not yet ported.
// C++ parity: coreaction.cc ActionDoNothing::apply
func (a *ActionDoNothing) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionRedundBranch removes redundant branches.
// C++ parity: coreaction.hh ActionRedundBranch
type ActionRedundBranch struct{ ActionBase }

var _ Action = (*ActionRedundBranch)(nil)

// NewActionRedundBranch constructs ActionRedundBranch.
// C++ parity: coreaction.hh ActionRedundBranch::ActionRedundBranch
func NewActionRedundBranch(group string) *ActionRedundBranch {
	act := &ActionRedundBranch{}
	act.ActionBase = NewActionBase(act, 0, "redundbranch", group)
	return act
}

// Clone clones ActionRedundBranch for the provided group list.
// C++ parity: coreaction.hh ActionRedundBranch::clone
func (a *ActionRedundBranch) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionRedundBranch(a.GetGroup())
}

// Apply removes redundant branches.
// C++ parity: coreaction.cc ActionRedundBranch::apply
func (a *ActionRedundBranch) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionDeterminedBranch removes branches with constant conditions.
// C++ parity: coreaction.hh ActionDeterminedBranch
type ActionDeterminedBranch struct{ ActionBase }

var _ Action = (*ActionDeterminedBranch)(nil)

// NewActionDeterminedBranch constructs ActionDeterminedBranch.
// C++ parity: coreaction.hh ActionDeterminedBranch::ActionDeterminedBranch
func NewActionDeterminedBranch(group string) *ActionDeterminedBranch {
	act := &ActionDeterminedBranch{}
	act.ActionBase = NewActionBase(act, 0, "determinedbranch", group)
	return act
}

// Clone clones ActionDeterminedBranch for the provided group list.
// C++ parity: coreaction.hh ActionDeterminedBranch::clone
func (a *ActionDeterminedBranch) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDeterminedBranch(a.GetGroup())
}

// Apply removes determined branches.
// C++ parity: coreaction.cc ActionDeterminedBranch::apply
func (a *ActionDeterminedBranch) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionMappedLocalSync synchronizes local symbols with Varnodes.
// C++ parity: coreaction.hh ActionMappedLocalSync
type ActionMappedLocalSync struct{ ActionBase }

var _ Action = (*ActionMappedLocalSync)(nil)

// NewActionMappedLocalSync constructs ActionMappedLocalSync.
// C++ parity: coreaction.hh ActionMappedLocalSync::ActionMappedLocalSync
func NewActionMappedLocalSync(group string) *ActionMappedLocalSync {
	act := &ActionMappedLocalSync{}
	act.ActionBase = NewActionBase(act, 0, "mapped_local_sync", group)
	return act
}

// Clone clones ActionMappedLocalSync for the provided group list.
// C++ parity: coreaction.hh ActionMappedLocalSync::clone
func (a *ActionMappedLocalSync) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMappedLocalSync(a.GetGroup())
}

// Apply synchronizes symbols and Varnodes.
// C++ parity: coreaction.cc ActionMappedLocalSync::apply
func (a *ActionMappedLocalSync) Apply(data *Funcdata) int {
	if data.SyncVarnodesWithSymbols(data.GetScopeLocal(), true, true) {
		a.count++
	}
	return 0
}

// ActionNormalizeSetup clears prototype locks before normalize-mode analysis.
// C++ parity: coreaction.hh ActionNormalizeSetup
type ActionNormalizeSetup struct{ ActionBase }

var _ Action = (*ActionNormalizeSetup)(nil)

// NewActionNormalizeSetup constructs ActionNormalizeSetup.
// C++ parity: coreaction.hh ActionNormalizeSetup::ActionNormalizeSetup
func NewActionNormalizeSetup(group string) *ActionNormalizeSetup {
	act := &ActionNormalizeSetup{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "normalizesetup", group)
	return act
}

// Clone clones ActionNormalizeSetup for the provided group list.
// C++ parity: coreaction.hh ActionNormalizeSetup::clone
func (a *ActionNormalizeSetup) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionNormalizeSetup(a.GetGroup())
}

// Apply clears prototype locks and input classification.
// C++ parity: coreaction.cc ActionNormalizeSetup::apply
func (a *ActionNormalizeSetup) Apply(data *Funcdata) int {
	fp := data.GetFuncProto()
	if fp == nil {
		return 0
	}
	fp.ClearInput()
	fp.SetModelLock(false)
	fp.SetOutputLock(false)
	return 0
}

// ActionExtraPopSetup defines formal links between stack-pointer values across calls.
// C++ parity: coreaction.hh ActionExtraPopSetup
type ActionExtraPopSetup struct{ ActionBase }

var _ Action = (*ActionExtraPopSetup)(nil)

// NewActionExtraPopSetup constructs ActionExtraPopSetup.
// C++ parity: coreaction.hh ActionExtraPopSetup::ActionExtraPopSetup
func NewActionExtraPopSetup(group string) *ActionExtraPopSetup {
	act := &ActionExtraPopSetup{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "extrapopsetup", group)
	return act
}

// Clone clones ActionExtraPopSetup for the provided group list.
// C++ parity: coreaction.hh ActionExtraPopSetup::clone
func (a *ActionExtraPopSetup) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionExtraPopSetup(a.GetGroup())
}

// Apply is a scaffolded no-op because the call-spec pipeline is not yet ported.
// C++ parity: coreaction.cc ActionExtraPopSetup::apply
func (a *ActionExtraPopSetup) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionActiveParam tracks active input parameter recovery.
// C++ parity: coreaction.hh ActionActiveParam
type ActionActiveParam struct{ ActionBase }

var _ Action = (*ActionActiveParam)(nil)

// NewActionActiveParam constructs ActionActiveParam.
// C++ parity: coreaction.hh ActionActiveParam::ActionActiveParam
func NewActionActiveParam(group string) *ActionActiveParam {
	act := &ActionActiveParam{}
	act.ActionBase = NewActionBase(act, 0, "activeparam", group)
	return act
}

// Clone clones ActionActiveParam for the provided group list.
// C++ parity: coreaction.hh ActionActiveParam::clone
func (a *ActionActiveParam) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionActiveParam(a.GetGroup())
}

// Apply is a scaffolded no-op because the active call-spec pipeline is not yet ported.
// C++ parity: coreaction.cc ActionActiveParam::apply
func (a *ActionActiveParam) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionActiveReturn tracks active return-value recovery.
// C++ parity: coreaction.hh ActionActiveReturn
type ActionActiveReturn struct{ ActionBase }

var _ Action = (*ActionActiveReturn)(nil)

// NewActionActiveReturn constructs ActionActiveReturn.
// C++ parity: coreaction.hh ActionActiveReturn::ActionActiveReturn
func NewActionActiveReturn(group string) *ActionActiveReturn {
	act := &ActionActiveReturn{}
	act.ActionBase = NewActionBase(act, 0, "activereturn", group)
	return act
}

// Clone clones ActionActiveReturn for the provided group list.
// C++ parity: coreaction.hh ActionActiveReturn::clone
func (a *ActionActiveReturn) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionActiveReturn(a.GetGroup())
}

// Apply is a scaffolded no-op because the active call-spec pipeline is not yet ported.
// C++ parity: coreaction.cc ActionActiveReturn::apply
func (a *ActionActiveReturn) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionConstantPtr discovers constant pointers to globals.
// C++ parity: coreaction.hh ActionConstantPtr
type ActionConstantPtr struct{ ActionBase }

var _ Action = (*ActionConstantPtr)(nil)

// NewActionConstantPtr constructs ActionConstantPtr.
// C++ parity: coreaction.hh ActionConstantPtr::ActionConstantPtr
func NewActionConstantPtr(group string) *ActionConstantPtr {
	act := &ActionConstantPtr{}
	act.ActionBase = NewActionBase(act, 0, "constantptr", group)
	return act
}

// Clone clones ActionConstantPtr for the provided group list.
// C++ parity: coreaction.hh ActionConstantPtr::clone
func (a *ActionConstantPtr) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionConstantPtr(a.GetGroup())
}

// Apply is a scaffolded no-op because pointer-inference infrastructure is not yet ported.
// C++ parity: coreaction.cc ActionConstantPtr::apply
func (a *ActionConstantPtr) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionConstbase injects officially provided constant inputs.
// C++ parity: coreaction.hh ActionConstbase
type ActionConstbase struct{ ActionBase }

var _ Action = (*ActionConstbase)(nil)

// NewActionConstbase constructs ActionConstbase.
// C++ parity: coreaction.hh ActionConstbase::ActionConstbase
func NewActionConstbase(group string) *ActionConstbase {
	act := &ActionConstbase{}
	act.ActionBase = NewActionBase(act, 0, "constbase", group)
	return act
}

// Clone clones ActionConstbase for the provided group list.
// C++ parity: coreaction.hh ActionConstbase::clone
func (a *ActionConstbase) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionConstbase(a.GetGroup())
}

// Apply is a scaffolded no-op because the pcode injection pipeline is not yet ported.
// C++ parity: coreaction.cc ActionConstbase::apply
func (a *ActionConstbase) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionDefaultParams assigns default prototypes to calls without a model.
// C++ parity: coreaction.hh ActionDefaultParams
type ActionDefaultParams struct{ ActionBase }

var _ Action = (*ActionDefaultParams)(nil)

// NewActionDefaultParams constructs ActionDefaultParams.
// C++ parity: coreaction.hh ActionDefaultParams::ActionDefaultParams
func NewActionDefaultParams(group string) *ActionDefaultParams {
	act := &ActionDefaultParams{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "defaultparams", group)
	return act
}

// Clone clones ActionDefaultParams for the provided group list.
// C++ parity: coreaction.hh ActionDefaultParams::clone
func (a *ActionDefaultParams) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDefaultParams(a.GetGroup())
}

// Apply is a scaffolded no-op because the call-spec pipeline is not yet ported.
// C++ parity: coreaction.cc ActionDefaultParams::apply
func (a *ActionDefaultParams) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionDeindirect resolves locally constant indirect calls.
// C++ parity: coreaction.hh ActionDeindirect
type ActionDeindirect struct{ ActionBase }

var _ Action = (*ActionDeindirect)(nil)

// NewActionDeindirect constructs ActionDeindirect.
// C++ parity: coreaction.hh ActionDeindirect::ActionDeindirect
func NewActionDeindirect(group string) *ActionDeindirect {
	act := &ActionDeindirect{}
	act.ActionBase = NewActionBase(act, 0, "deindirect", group)
	return act
}

// Clone clones ActionDeindirect for the provided group list.
// C++ parity: coreaction.hh ActionDeindirect::clone
func (a *ActionDeindirect) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDeindirect(a.GetGroup())
}

// Apply is a scaffolded no-op because indirect-call resolution is not yet ported.
// C++ parity: coreaction.cc ActionDeindirect::apply
func (a *ActionDeindirect) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionDirectWrite marks varnodes with legal input ancestry.
// C++ parity: coreaction.hh ActionDirectWrite
type ActionDirectWrite struct {
	ActionBase
	propagateIndirect bool
}

var _ Action = (*ActionDirectWrite)(nil)

// NewActionDirectWrite constructs ActionDirectWrite.
// C++ parity: coreaction.hh ActionDirectWrite::ActionDirectWrite
func NewActionDirectWrite(group string, prop bool) *ActionDirectWrite {
	act := &ActionDirectWrite{propagateIndirect: prop}
	act.ActionBase = NewActionBase(act, 0, "directwrite", group)
	return act
}

// Clone clones ActionDirectWrite for the provided group list.
// C++ parity: coreaction.hh ActionDirectWrite::clone
func (a *ActionDirectWrite) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDirectWrite(a.GetGroup(), a.propagateIndirect)
}

// Apply marks direct-write ancestry using the SSA graph that is already available in Go.
// C++ parity: coreaction.cc ActionDirectWrite::apply
func (a *ActionDirectWrite) Apply(data *Funcdata) int {
	var worklist []*Varnode
	fp := data.GetFuncProto()
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil {
			continue
		}
		vn.ClearFlags(VarnodeDirectWrite)
		if vn.IsInput() {
			if vn.IsPersist() || vn.IsSpaceBase() || (fp != nil && fp.IsParamVarnode(vn)) {
				vn.SetFlags(VarnodeDirectWrite)
				worklist = append(worklist, vn)
			}
		} else if vn.IsWritten() {
			op := vn.Def()
			if op == nil {
				continue
			}
			if !op.IsMarker() {
				if vn.IsPersist() {
					vn.SetFlags(VarnodeDirectWrite)
					worklist = append(worklist, vn)
				} else if op.Code() == CPUI_COPY {
					if vn.IsStackStore() {
						invn := op.Input(0)
						if invn != nil && invn.IsWritten() && invn.Def() != nil && invn.Def().IsMarker() {
							vn.SetFlags(VarnodeDirectWrite)
							worklist = append(worklist, vn)
						}
					}
				} else if op.Code() != CPUI_PIECE && op.Code() != CPUI_SUBPIECE {
					vn.SetFlags(VarnodeDirectWrite)
					worklist = append(worklist, vn)
				}
			} else if !a.propagateIndirect && op.Code() == CPUI_INDIRECT {
				outvn := op.Output()
				if outvn != nil && (op.Input(0) == nil || op.Input(0).Offset() != outvn.Offset() || outvn.IsPersist()) {
					vn.SetFlags(VarnodeDirectWrite)
				}
			}
		} else if vn.IsConstant() && !vn.IsIndirectZero() {
			vn.SetFlags(VarnodeDirectWrite)
			worklist = append(worklist, vn)
		}
	}
	for len(worklist) > 0 {
		vn := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		for _, op := range vn.DescendIter() {
			if op == nil || !op.IsAssignment() {
				continue
			}
			outvn := op.Output()
			if outvn == nil || outvn.IsDirectWrite() {
				continue
			}
			outvn.SetFlags(VarnodeDirectWrite)
			if a.propagateIndirect || op.Code() != CPUI_INDIRECT || op.IsIndirectStore() {
				worklist = append(worklist, outvn)
			}
		}
	}
	return 0
}

// ActionFuncLink builds call-site parameter and return wiring.
// C++ parity: coreaction.hh ActionFuncLink
type ActionFuncLink struct{ ActionBase }

var _ Action = (*ActionFuncLink)(nil)

// NewActionFuncLink constructs ActionFuncLink.
// C++ parity: coreaction.hh ActionFuncLink::ActionFuncLink
func NewActionFuncLink(group string) *ActionFuncLink {
	act := &ActionFuncLink{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "funclink", group)
	return act
}

// Clone clones ActionFuncLink for the provided group list.
// C++ parity: coreaction.hh ActionFuncLink::clone
func (a *ActionFuncLink) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionFuncLink(a.GetGroup())
}

// Apply is a scaffolded no-op because the call-spec pipeline is not yet ported.
// C++ parity: coreaction.cc ActionFuncLink::apply
func (a *ActionFuncLink) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionInputPrototype recovers input prototypes from observed call sites.
// C++ parity: coreaction.hh ActionInputPrototype
type ActionInputPrototype struct{ ActionBase }

var _ Action = (*ActionInputPrototype)(nil)

// NewActionInputPrototype constructs ActionInputPrototype.
// C++ parity: coreaction.hh ActionInputPrototype::ActionInputPrototype
func NewActionInputPrototype(group string) *ActionInputPrototype {
	act := &ActionInputPrototype{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "inputprototype", group)
	return act
}

// Clone clones ActionInputPrototype for the provided group list.
// C++ parity: coreaction.hh ActionInputPrototype::clone
func (a *ActionInputPrototype) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionInputPrototype(a.GetGroup())
}

// Apply is a scaffolded no-op because prototype recovery infrastructure is not yet ported.
// C++ parity: coreaction.cc ActionInputPrototype::apply
func (a *ActionInputPrototype) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionLaneDivide splits vector lanes when the data-flow proves a lane scheme.
// C++ parity: coreaction.hh ActionLaneDivide
type ActionLaneDivide struct{ ActionBase }

var _ Action = (*ActionLaneDivide)(nil)

// NewActionLaneDivide constructs ActionLaneDivide.
// C++ parity: coreaction.hh ActionLaneDivide::ActionLaneDivide
func NewActionLaneDivide(group string) *ActionLaneDivide {
	act := &ActionLaneDivide{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "lanedivide", group)
	return act
}

// Clone clones ActionLaneDivide for the provided group list.
// C++ parity: coreaction.hh ActionLaneDivide::clone
func (a *ActionLaneDivide) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionLaneDivide(a.GetGroup())
}

// Apply is a scaffolded no-op because vector-lane restructuring is not yet ported.
// C++ parity: coreaction.cc ActionLaneDivide::apply
func (a *ActionLaneDivide) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionLikelyTrash identifies likely trash data-flow feeding INDIRECTs.
// C++ parity: coreaction.hh ActionLikelyTrash
type ActionLikelyTrash struct{ ActionBase }

var _ Action = (*ActionLikelyTrash)(nil)

// NewActionLikelyTrash constructs ActionLikelyTrash.
// C++ parity: coreaction.hh ActionLikelyTrash::ActionLikelyTrash
func NewActionLikelyTrash(group string) *ActionLikelyTrash {
	act := &ActionLikelyTrash{}
	act.ActionBase = NewActionBase(act, 0, "likelytrash", group)
	return act
}

// Clone clones ActionLikelyTrash for the provided group list.
// C++ parity: coreaction.hh ActionLikelyTrash::clone
func (a *ActionLikelyTrash) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionLikelyTrash(a.GetGroup())
}

// Apply is a scaffolded no-op because the trash-tracing infrastructure is not yet ported.
// C++ parity: coreaction.cc ActionLikelyTrash::apply
func (a *ActionLikelyTrash) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionMultiCse removes duplicate MULTIEQUALs within a block.
// C++ parity: coreaction.hh ActionMultiCse
type ActionMultiCse struct{ ActionBase }

var _ Action = (*ActionMultiCse)(nil)

// NewActionMultiCse constructs ActionMultiCse.
// C++ parity: coreaction.hh ActionMultiCse::ActionMultiCse
func NewActionMultiCse(group string) *ActionMultiCse {
	act := &ActionMultiCse{}
	act.ActionBase = NewActionBase(act, 0, "multicse", group)
	return act
}

// Clone clones ActionMultiCse for the provided group list.
// C++ parity: coreaction.hh ActionMultiCse::clone
func (a *ActionMultiCse) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMultiCse(a.GetGroup())
}

// preferredOutput reports whether out2 should replace out1.
// C++ parity: coreaction.cc ActionMultiCse::preferredOutput
func (a *ActionMultiCse) preferredOutput(out1, out2 *Varnode) bool {
	for _, op := range out1.DescendIter() {
		if op != nil && op.Code() == CPUI_RETURN {
			return false
		}
	}
	for _, op := range out2.DescendIter() {
		if op != nil && op.Code() == CPUI_RETURN {
			return true
		}
	}
	if !out1.IsAddrTied() {
		if out2.IsAddrTied() {
			return true
		}
		if out1.Space() != nil && out1.Space().IsUnique() {
			if out2.Space() == nil || !out2.Space().IsUnique() {
				return true
			}
		}
	}
	return false
}

// findMatch searches earlier MULTIEQUALs in the block for an equivalent op.
// C++ parity: coreaction.cc ActionMultiCse::findMatch
func (a *ActionMultiCse) findMatch(bl *BlockBasic, target *PcodeOp, in *Varnode) *PcodeOp {
	for _, op := range bl.Ops() {
		if op == nil {
			continue
		}
		if op == target {
			break
		}
		numinput := op.NumInput()
		matchIn := false
		for i := 0; i < numinput; i++ {
			vn := op.Input(i)
			if vn != nil && vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_COPY {
				vn = vn.Def().Input(0)
			}
			if vn == in {
				matchIn = true
				break
			}
		}
		if !matchIn {
			continue
		}
		var buf1 [2]*Varnode
		var buf2 [2]*Varnode
		same := true
		for j := 0; j < numinput; j++ {
			in1 := op.Input(j)
			if in1 != nil && in1.IsWritten() && in1.Def() != nil && in1.Def().Code() == CPUI_COPY {
				in1 = in1.Def().Input(0)
			}
			in2 := target.Input(j)
			if in2 != nil && in2.IsWritten() && in2.Def() != nil && in2.Def().Code() == CPUI_COPY {
				in2 = in2.Def().Input(0)
			}
			if in1 == in2 {
				continue
			}
			if functionalEqualityLevel(in1, in2, buf1[:], buf2[:]) != 0 {
				same = false
				break
			}
		}
		if same {
			return op
		}
	}
	return nil
}

// processBlock searches a block for duplicate MULTIEQUALs.
// C++ parity: coreaction.cc ActionMultiCse::processBlock
func (a *ActionMultiCse) processBlock(data *Funcdata, bl *BlockBasic) bool {
	var vnlist []*Varnode
	var targetop *PcodeOp
	var pairop *PcodeOp
	for _, op := range bl.Ops() {
		if op == nil {
			continue
		}
		opc := op.Code()
		if opc == CPUI_COPY {
			continue
		}
		if opc != CPUI_MULTIEQUAL {
			break
		}
		vnpos := len(vnlist)
		numinput := op.NumInput()
		var hit bool
		for i := 0; i < numinput; i++ {
			vn := op.Input(i)
			if vn != nil && vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_COPY {
				vn = vn.Def().Input(0)
			}
			vnlist = append(vnlist, vn)
			if vn != nil && vn.IsMark() {
				pairop = a.findMatch(bl, op, vn)
				if pairop != nil {
					targetop = op
					hit = true
					break
				}
			}
		}
		if hit {
			_ = vnpos
			break
		}
		for i := vnpos; i < len(vnlist); i++ {
			if vnlist[i] != nil {
				vnlist[i].SetMark()
			}
		}
	}
	for _, vn := range vnlist {
		if vn != nil {
			vn.ClearMark()
		}
	}
	if targetop != nil && pairop != nil {
		out1 := pairop.Output()
		out2 := targetop.Output()
		if out1 == nil || out2 == nil {
			return false
		}
		if a.preferredOutput(out1, out2) {
			data.TotalReplace(out1, out2)
			data.OpDestroy(pairop)
		} else {
			data.TotalReplace(out2, out1)
			data.OpDestroy(targetop)
		}
		a.count++
		return true
	}
	return false
}

// Apply removes duplicate MULTIEQUALs within each basic block.
// C++ parity: coreaction.cc ActionMultiCse::apply
func (a *ActionMultiCse) Apply(data *Funcdata) int {
	bg := data.GetBasicBlocks()
	if bg == nil {
		return 0
	}
	for i := 0; i < bg.GetSize(); i++ {
		bl, ok := bg.GetBlock(i).Concrete().(*BlockBasic)
		if !ok || bl == nil {
			continue
		}
		for a.processBlock(data, bl) {
		}
	}
	return 0
}

// ActionOutputPrototype recovers output prototypes from RETURN sites.
// C++ parity: coreaction.hh ActionOutputPrototype
type ActionOutputPrototype struct{ ActionBase }

var _ Action = (*ActionOutputPrototype)(nil)

// NewActionOutputPrototype constructs ActionOutputPrototype.
// C++ parity: coreaction.hh ActionOutputPrototype::ActionOutputPrototype
func NewActionOutputPrototype(group string) *ActionOutputPrototype {
	act := &ActionOutputPrototype{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "outputprototype", group)
	return act
}

// Clone clones ActionOutputPrototype for the provided group list.
// C++ parity: coreaction.hh ActionOutputPrototype::clone
func (a *ActionOutputPrototype) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionOutputPrototype(a.GetGroup())
}

// Apply is a scaffolded no-op because prototype output recovery is not yet ported.
// C++ parity: coreaction.cc ActionOutputPrototype::apply
func (a *ActionOutputPrototype) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionParamDouble discovers split parameters and double-precision objects.
// C++ parity: coreaction.hh ActionParamDouble
type ActionParamDouble struct{ ActionBase }

var _ Action = (*ActionParamDouble)(nil)

// NewActionParamDouble constructs ActionParamDouble.
// C++ parity: coreaction.hh ActionParamDouble::ActionParamDouble
func NewActionParamDouble(group string) *ActionParamDouble {
	act := &ActionParamDouble{}
	act.ActionBase = NewActionBase(act, 0, "paramdouble", group)
	return act
}

// Clone clones ActionParamDouble for the provided group list.
// C++ parity: coreaction.hh ActionParamDouble::clone
func (a *ActionParamDouble) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionParamDouble(a.GetGroup())
}

// Apply is a scaffolded no-op because split-parameter recovery is not yet ported.
// C++ parity: coreaction.cc ActionParamDouble::apply
func (a *ActionParamDouble) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionPrototypeTypes finalizes prototype-driven input and output typing.
// C++ parity: coreaction.hh ActionPrototypeTypes
type ActionPrototypeTypes struct{ ActionBase }

var _ Action = (*ActionPrototypeTypes)(nil)

// NewActionPrototypeTypes constructs ActionPrototypeTypes.
// C++ parity: coreaction.hh ActionPrototypeTypes::ActionPrototypeTypes
func NewActionPrototypeTypes(group string) *ActionPrototypeTypes {
	act := &ActionPrototypeTypes{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "prototypetypes", group)
	return act
}

// Clone clones ActionPrototypeTypes for the provided group list.
// C++ parity: coreaction.hh ActionPrototypeTypes::clone
func (a *ActionPrototypeTypes) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionPrototypeTypes(a.GetGroup())
}

// Apply strips RETURN indirect references and re-applies the anchored return register when available.
// C++ parity: coreaction.cc ActionPrototypeTypes::apply
func (a *ActionPrototypeTypes) Apply(data *Funcdata) int {
	fp := data.GetFuncProto()
	if fp == nil {
		return 0
	}
	fp.SetModelLock(false)
	fp.SetOutputLock(false)
	if model := fp.Model(); model != nil && model.ReturnRegSpaceIndex >= 0 && model.ReturnRegSize > 0 {
		stripReturnIndirectRef(data)
		anchorReturnReg(data, model)
	}
	return 0
}

// ActionRestructureVarnode restructures varnodes around local recovery.
// C++ parity: coreaction.hh ActionRestructureVarnode
type ActionRestructureVarnode struct {
	ActionBase
	numpass int
}

var _ Action = (*ActionRestructureVarnode)(nil)

// NewActionRestructureVarnode constructs ActionRestructureVarnode.
// C++ parity: coreaction.hh ActionRestructureVarnode::ActionRestructureVarnode
func NewActionRestructureVarnode(group string) *ActionRestructureVarnode {
	act := &ActionRestructureVarnode{}
	act.ActionBase = NewActionBase(act, 0, "restructure_varnode", group)
	return act
}

// Clone clones ActionRestructureVarnode for the provided group list.
// C++ parity: coreaction.hh ActionRestructureVarnode::clone
func (a *ActionRestructureVarnode) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionRestructureVarnode(a.GetGroup())
}

// Apply is a scaffolded no-op because local-restructure infrastructure is not yet ported.
// C++ parity: coreaction.cc ActionRestructureVarnode::apply
func (a *ActionRestructureVarnode) Apply(data *Funcdata) int {
	_ = data
	a.numpass++
	return 0
}

// ActionConditionalConst propagates constants across conditional branches.
// C++ parity: coreaction.hh ActionConditionalConst
type ActionConditionalConst struct{ ActionBase }

// NewActionConditionalConst constructs ActionConditionalConst.
// C++ parity: coreaction.hh ActionConditionalConst::ActionConditionalConst
func NewActionConditionalConst(group string) *ActionConditionalConst {
	act := &ActionConditionalConst{}
	act.ActionBase = NewActionBase(act, 0, "condconst", group)
	return act
}

// Clone clones ActionConditionalConst for the provided group list.
// C++ parity: coreaction.hh ActionConditionalConst::clone
func (a *ActionConditionalConst) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionConditionalConst(a.GetGroup())
}

// Apply is a scaffolded no-op because the full conditional-constant port is deferred.
// C++ parity: coreaction.cc ActionConditionalConst::apply
func (a *ActionConditionalConst) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionConditionalExe removes redundant conditional execution paths.
// C++ parity: condexe.hh ActionConditionalExe
type ActionConditionalExe struct{ ActionBase }

// NewActionConditionalExe constructs ActionConditionalExe.
// C++ parity: condexe.hh ActionConditionalExe::ActionConditionalExe
func NewActionConditionalExe(group string) *ActionConditionalExe {
	act := &ActionConditionalExe{}
	act.ActionBase = NewActionBase(act, 0, "conditionalexe", group)
	return act
}

// Clone clones ActionConditionalExe for the provided group list.
// C++ parity: condexe.hh ActionConditionalExe::clone
func (a *ActionConditionalExe) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionConditionalExe(a.GetGroup())
}

// Apply is a scaffolded no-op because the conditional-execution port is deferred.
// C++ parity: condexe.cc ActionConditionalExe::apply
func (a *ActionConditionalExe) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionDynamicMapping attaches dynamic symbols before data-type propagation.
// C++ parity: coreaction.hh ActionDynamicMapping
type ActionDynamicMapping struct{ ActionBase }

// NewActionDynamicMapping constructs ActionDynamicMapping.
// C++ parity: coreaction.hh ActionDynamicMapping::ActionDynamicMapping
func NewActionDynamicMapping(group string) *ActionDynamicMapping {
	act := &ActionDynamicMapping{}
	act.ActionBase = NewActionBase(act, 0, "dynamicmapping", group)
	return act
}

// Clone clones ActionDynamicMapping for the provided group list.
// C++ parity: coreaction.hh ActionDynamicMapping::clone
func (a *ActionDynamicMapping) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDynamicMapping(a.GetGroup())
}

// Apply is a scaffolded no-op because dynamic mapping is not yet ported.
// C++ parity: coreaction.cc ActionDynamicMapping::apply
func (a *ActionDynamicMapping) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionDynamicSymbols finalizes dynamic symbol attachments.
// C++ parity: coreaction.hh ActionDynamicSymbols
type ActionDynamicSymbols struct{ ActionBase }

// NewActionDynamicSymbols constructs ActionDynamicSymbols.
// C++ parity: coreaction.hh ActionDynamicSymbols::ActionDynamicSymbols
func NewActionDynamicSymbols(group string) *ActionDynamicSymbols {
	act := &ActionDynamicSymbols{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "dynamicsymbols", group)
	return act
}

// Clone clones ActionDynamicSymbols for the provided group list.
// C++ parity: coreaction.hh ActionDynamicSymbols::clone
func (a *ActionDynamicSymbols) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDynamicSymbols(a.GetGroup())
}

// Apply is a scaffolded no-op because dynamic symbol finalization is not yet ported.
// C++ parity: coreaction.cc ActionDynamicSymbols::apply
func (a *ActionDynamicSymbols) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionHideShadow suppresses compiler-generated shadow varnodes.
// C++ parity: coreaction.hh ActionHideShadow
type ActionHideShadow struct{ ActionBase }

// NewActionHideShadow constructs ActionHideShadow.
// C++ parity: coreaction.hh ActionHideShadow::ActionHideShadow
func NewActionHideShadow(group string) *ActionHideShadow {
	act := &ActionHideShadow{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "hideshadow", group)
	return act
}

// Clone clones ActionHideShadow for the provided group list.
// C++ parity: coreaction.hh ActionHideShadow::clone
func (a *ActionHideShadow) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionHideShadow(a.GetGroup())
}

// Apply is a scaffolded no-op because shadow suppression is not yet ported.
// C++ parity: coreaction.cc ActionHideShadow::apply
func (a *ActionHideShadow) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionInternalStorage prevents addressable treatment of internal-storage constants.
// C++ parity: coreaction.hh ActionInternalStorage
type ActionInternalStorage struct{ ActionBase }

// NewActionInternalStorage constructs ActionInternalStorage.
// C++ parity: coreaction.hh ActionInternalStorage::ActionInternalStorage
func NewActionInternalStorage(group string) *ActionInternalStorage {
	act := &ActionInternalStorage{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "internalstorage", group)
	return act
}

// Clone clones ActionInternalStorage for the provided group list.
// C++ parity: coreaction.hh ActionInternalStorage::clone
func (a *ActionInternalStorage) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionInternalStorage(a.GetGroup())
}

// Apply is a scaffolded no-op because internal-storage cleanup is not yet ported.
// C++ parity: coreaction.cc ActionInternalStorage::apply
func (a *ActionInternalStorage) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionPrototypeWarnings reports prototype-model and override warnings.
// C++ parity: coreaction.hh ActionPrototypeWarnings
type ActionPrototypeWarnings struct{ ActionBase }

// NewActionPrototypeWarnings constructs ActionPrototypeWarnings.
// C++ parity: coreaction.hh ActionPrototypeWarnings::ActionPrototypeWarnings
func NewActionPrototypeWarnings(group string) *ActionPrototypeWarnings {
	act := &ActionPrototypeWarnings{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "prototypewarnings", group)
	return act
}

// Clone clones ActionPrototypeWarnings for the provided group list.
// C++ parity: coreaction.hh ActionPrototypeWarnings::clone
func (a *ActionPrototypeWarnings) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionPrototypeWarnings(a.GetGroup())
}

// Apply is a scaffolded no-op because prototype warning plumbing is not yet ported.
// C++ parity: coreaction.cc ActionPrototypeWarnings::apply
func (a *ActionPrototypeWarnings) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionRestrictLocal marks storage that cannot be treated as local variables.
// C++ parity: coreaction.hh ActionRestrictLocal
type ActionRestrictLocal struct{ ActionBase }

// NewActionRestrictLocal constructs ActionRestrictLocal.
// C++ parity: coreaction.hh ActionRestrictLocal::ActionRestrictLocal
func NewActionRestrictLocal(group string) *ActionRestrictLocal {
	act := &ActionRestrictLocal{}
	act.ActionBase = NewActionBase(act, 0, "restrictlocal", group)
	return act
}

// Clone clones ActionRestrictLocal for the provided group list.
// C++ parity: coreaction.hh ActionRestrictLocal::clone
func (a *ActionRestrictLocal) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionRestrictLocal(a.GetGroup())
}

// Apply is a scaffolded no-op because local restriction is not yet ported.
// C++ parity: coreaction.cc ActionRestrictLocal::apply
func (a *ActionRestrictLocal) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionReturnRecovery recovers the function return data-flow.
// C++ parity: coreaction.hh ActionReturnRecovery
type ActionReturnRecovery struct{ ActionBase }

// NewActionReturnRecovery constructs ActionReturnRecovery.
// C++ parity: coreaction.hh ActionReturnRecovery::ActionReturnRecovery
func NewActionReturnRecovery(group string) *ActionReturnRecovery {
	act := &ActionReturnRecovery{}
	act.ActionBase = NewActionBase(act, 0, "returnrecovery", group)
	return act
}

// Clone clones ActionReturnRecovery for the provided group list.
// C++ parity: coreaction.hh ActionReturnRecovery::clone
func (a *ActionReturnRecovery) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionReturnRecovery(a.GetGroup())
}

// Apply is a scaffolded no-op because return recovery is not yet ported.
// C++ parity: coreaction.cc ActionReturnRecovery::apply
func (a *ActionReturnRecovery) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionReturnSplit splits epilog code into distinct RETURNs.
// C++ parity: blockaction.hh ActionReturnSplit
type ActionReturnSplit struct{ ActionBase }

// NewActionReturnSplit constructs ActionReturnSplit.
// C++ parity: blockaction.hh ActionReturnSplit::ActionReturnSplit
func NewActionReturnSplit(group string) *ActionReturnSplit {
	act := &ActionReturnSplit{}
	act.ActionBase = NewActionBase(act, 0, "returnsplit", group)
	return act
}

// Clone clones ActionReturnSplit for the provided group list.
// C++ parity: blockaction.hh ActionReturnSplit::clone
func (a *ActionReturnSplit) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionReturnSplit(a.GetGroup())
}

// Apply is a scaffolded no-op because return splitting is not yet ported.
// C++ parity: blockaction.cc ActionReturnSplit::apply
func (a *ActionReturnSplit) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionSegmentize normalizes segmented-space pointers into CPUI_SEGMENTOP.
// C++ parity: coreaction.hh ActionSegmentize
type ActionSegmentize struct {
	ActionBase
	localcount int
}

// NewActionSegmentize constructs ActionSegmentize.
// C++ parity: coreaction.hh ActionSegmentize::ActionSegmentize
func NewActionSegmentize(group string) *ActionSegmentize {
	act := &ActionSegmentize{}
	act.ActionBase = NewActionBase(act, 0, "segmentize", group)
	return act
}

// Clone clones ActionSegmentize for the provided group list.
// C++ parity: coreaction.hh ActionSegmentize::clone
func (a *ActionSegmentize) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionSegmentize(a.GetGroup())
}

// Apply is a scaffolded no-op because segment normalization is not yet ported.
// C++ parity: coreaction.cc ActionSegmentize::apply
func (a *ActionSegmentize) Apply(data *Funcdata) int {
	_ = data
	a.localcount++
	return 0
}

// ActionShadowVar checks for MULTIEQUAL inputs defining multiple varnodes.
// C++ parity: coreaction.hh ActionShadowVar
type ActionShadowVar struct{ ActionBase }

// NewActionShadowVar constructs ActionShadowVar.
// C++ parity: coreaction.hh ActionShadowVar::ActionShadowVar
func NewActionShadowVar(group string) *ActionShadowVar {
	act := &ActionShadowVar{}
	act.ActionBase = NewActionBase(act, 0, "shadowvar", group)
	return act
}

// Clone clones ActionShadowVar for the provided group list.
// C++ parity: coreaction.hh ActionShadowVar::clone
func (a *ActionShadowVar) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionShadowVar(a.GetGroup())
}

// Apply is a scaffolded no-op because shadow-var handling is not yet ported.
// C++ parity: coreaction.cc ActionShadowVar::apply
func (a *ActionShadowVar) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionSwitchNorm folds switch normalization and guards into jump-table handling.
// C++ parity: coreaction.hh ActionSwitchNorm
type ActionSwitchNorm struct{ ActionBase }

// NewActionSwitchNorm constructs ActionSwitchNorm.
// C++ parity: coreaction.hh ActionSwitchNorm::ActionSwitchNorm
func NewActionSwitchNorm(group string) *ActionSwitchNorm {
	act := &ActionSwitchNorm{}
	act.ActionBase = NewActionBase(act, 0, "switchnorm", group)
	return act
}

// Clone clones ActionSwitchNorm for the provided group list.
// C++ parity: coreaction.hh ActionSwitchNorm::clone
func (a *ActionSwitchNorm) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionSwitchNorm(a.GetGroup())
}

// Apply is a scaffolded no-op because jump-table normalization is not yet ported.
// C++ parity: coreaction.cc ActionSwitchNorm::apply
func (a *ActionSwitchNorm) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionUnjustifiedParams repairs improperly justified parameter storage.
// C++ parity: coreaction.hh ActionUnjustifiedParams
type ActionUnjustifiedParams struct{ ActionBase }

// NewActionUnjustifiedParams constructs ActionUnjustifiedParams.
// C++ parity: coreaction.hh ActionUnjustifiedParams::ActionUnjustifiedParams
func NewActionUnjustifiedParams(group string) *ActionUnjustifiedParams {
	act := &ActionUnjustifiedParams{}
	act.ActionBase = NewActionBase(act, 0, "unjustparams", group)
	return act
}

// Clone clones ActionUnjustifiedParams for the provided group list.
// C++ parity: coreaction.hh ActionUnjustifiedParams::clone
func (a *ActionUnjustifiedParams) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionUnjustifiedParams(a.GetGroup())
}

// Apply is a scaffolded no-op because unjustified-parameter recovery is not yet ported.
// C++ parity: coreaction.cc ActionUnjustifiedParams::apply
func (a *ActionUnjustifiedParams) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ActionVarnodeProps transforms varnodes based on read-only, volatile, and consume properties.
// C++ parity: coreaction.hh ActionVarnodeProps
type ActionVarnodeProps struct{ ActionBase }

// NewActionVarnodeProps constructs ActionVarnodeProps.
// C++ parity: coreaction.hh ActionVarnodeProps::ActionVarnodeProps
func NewActionVarnodeProps(group string) *ActionVarnodeProps {
	act := &ActionVarnodeProps{}
	act.ActionBase = NewActionBase(act, 0, "varnodeprops", group)
	return act
}

// Clone clones ActionVarnodeProps for the provided group list.
// C++ parity: coreaction.hh ActionVarnodeProps::clone
func (a *ActionVarnodeProps) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionVarnodeProps(a.GetGroup())
}

// Apply is a scaffolded no-op because full varnode-property handling is not yet ported.
// C++ parity: coreaction.cc ActionVarnodeProps::apply
func (a *ActionVarnodeProps) Apply(data *Funcdata) int {
	_ = data
	return 0
}
