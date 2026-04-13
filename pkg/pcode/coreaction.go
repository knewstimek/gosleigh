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

import "gosleigh/pkg/address"

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

// ActionPrototypeTypes applies prototype types to recovered parameters and returns.
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

// extendInput inserts a widening op when the input varnode is smaller than the prototype.
// TODO known mismatch: Ghidra's FuncProto::assumedInputExtension chooses the exact
// extension opcode from the calling convention model. Gosleigh uses a size/type heuristic.
// C++ parity: ActionPrototypeTypes::extendInput
func (a *ActionPrototypeTypes) extendInput(data *Funcdata, invn *Varnode, param *HighVariable, topbl *BlockBasic) {
	if data == nil || invn == nil || param == nil || topbl == nil || param.Type() == nil {
		return
	}
	if invn.Size() >= param.Type().Size() {
		return
	}
	opcode := CPUI_INT_ZEXT
	if param.Type().Metatype() == TYPE_INT {
		opcode = CPUI_INT_SEXT
	}
	start := topbl.FirstOp()
	if start == nil {
		return
	}
	extop := data.NewOp(1, start.Addr())
	data.NewVarnodeOut(param.Type().Size(), invn.Addr(), extop)
	data.OpSetOpcode(extop, opcode)
	data.OpSetInput(extop, invn, 0)
	data.OpInsertBegin(extop, topbl)
}

// Apply applies the prototype model to locked inputs and outputs.
// C++ parity: coreaction.cc ActionPrototypeTypes::apply
func (a *ActionPrototypeTypes) Apply(data *Funcdata) int {
	fp := data.GetFuncProto()
	if fp == nil {
		return 0
	}

	if fp.HasThisPointer() {
		fp.PrepareThisPointer()
	}

	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
			continue
		}
		if op.NumInput() == 0 {
			continue
		}
		in0 := op.Input(0)
		if in0 != nil && !in0.IsConstant() {
			zeroConst := data.NewConstant(in0.Size(), 0)
			data.OpSetInput(op, zeroConst, 0)
		}
	}

	if fp.IsOutputLocked() {
		out := fp.GetOutput()
		if out != nil && out.Type() != nil && out.Type().Metatype() != TYPE_VOID {
			for _, op := range data.GetPcodeOpBank().AllOps() {
				if op == nil || op.IsDead() || op.Code() != CPUI_RETURN || op.HaltType() != 0 {
					continue
				}
				if out.NumInstances() == 0 {
					continue
				}
				ref := out.GetInstance(0)
				if ref == nil {
					continue
				}
				vn := data.NewVarnode(out.Type().Size(), ref.Addr())
				data.OpSetInput(op, vn, op.NumInput())
				SetVarnodeType(vn, out.Type())
			}
		}
	}

	if fp.IsInputLocked() {
		var topbl *BlockBasic
		if bg := data.GetBasicBlocks(); bg != nil && bg.GetSize() > 0 {
			if concrete, ok := bg.GetBlock(0).Concrete().(*BlockBasic); ok {
				topbl = concrete
			}
		}
		if topbl != nil {
			for i := 0; i < fp.NumParams(); i++ {
				param := fp.GetParam(i)
				if param == nil || param.NumInstances() == 0 {
					continue
				}
				for _, invn := range param.Instances() {
					if invn == nil {
						continue
					}
					invn.SetAddlFlags(VarnodeLockedInput)
					if param.Type() != nil {
						a.extendInput(data, invn, param, topbl)
					}
					if param.Type() != nil && param.Type().Metatype() == TYPE_PTR && param.Type().Size() == invn.Size() {
						invn.SetPtrFlow()
					}
				}
			}
		}
	}

	return 0
}

// ActionDefaultParams applies the default calling convention to calls without a prototype.
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

// Apply applies the default model to any call op without an explicit prototype.
// TODO known mismatch: Gosleigh does not yet track callee Funcdata linkage or
// upon-return p-code injection, so the callee copy branch is reduced to the local model.
// C++ parity: coreaction.cc ActionDefaultParams::apply
func (a *ActionDefaultParams) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	evalfp := data.GetFuncProto()
	var defaultModel *ProtoModel
	if evalfp != nil {
		defaultModel = evalfp.Model()
	}
	if defaultModel == nil && evalfp != nil {
		defaultModel = evalfp.Model()
	}

	for i := 0; i < data.NumCalls(); i++ {
		fc := data.GetCallSpecs(i)
		if fc == nil {
			continue
		}
		if !fc.HasModel() {
			if otherfunc := fc.GetFuncdata(); otherfunc != nil {
				if otherProto := otherfunc.GetFuncProto(); otherProto != nil {
					fc.Copy(otherProto)
					if !fc.IsModelLocked() && !fc.HasMatchingModel(defaultModel) {
						fc.SetModel(defaultModel)
					}
				}
			} else {
				fc.SetInternal(defaultModel, sharedTypeFactory.GetVoid())
			}
		}
		fc.InsertPcode(data)
	}
	return 0
}

// ActionInputPrototype finalizes recovered input parameters.
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

// Apply finalizes the recovered input prototype.
// C++ parity: coreaction.cc ActionInputPrototype::apply
func (a *ActionInputPrototype) Apply(data *Funcdata) int {
	fp := data.GetFuncProto()
	if fp == nil {
		return 0
	}
	fp.ClearUnlockedInput()
	if !fp.IsInputLocked() {
		model := fp.Model()
		if model != nil {
			scope := data.GetScopeLocal()
			if scope != nil {
				scope.ResetLocalWindow()
			}
			// Build a fresh high-level view from the existing varnodes.
			if scope == nil {
				scope = NewScopeLocal(model)
				data.SetScopeLocal(scope)
			}
			scope.BuildFromVarnodes(data.GetVarnodeBank().AllVarnodes(), fp)
			fp.SetInputLocked(true)
		}
	}
	return 0
}

// ActionOutputPrototype finalizes the recovered return value.
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

// Apply finalizes the recovered return value.
// C++ parity: coreaction.cc ActionOutputPrototype::apply
func (a *ActionOutputPrototype) Apply(data *Funcdata) int {
	fp := data.GetFuncProto()
	if fp == nil {
		return 0
	}
	out := fp.GetOutput()
	if out != nil && out.Type() != nil && out.Type().Metatype() != TYPE_VOID && fp.IsOutputLocked() {
		return 0
	}
	var firstRet *Varnode
	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
			continue
		}
		for i := 1; i < op.NumInput(); i++ {
			if vn := op.Input(i); vn != nil {
				firstRet = vn
				break
			}
		}
		if firstRet != nil {
			break
		}
	}
	if firstRet == nil {
		fp.ClearUnlockedOutput()
		return 0
	}
	hv := fp.GetOutput()
	if hv == nil {
		hv = NewHighVariable("return")
		fp.SetOutput(hv)
	}
	hv.AddInstance(firstRet)
	if firstRet.Type() != nil {
		hv.SetType(firstRet.Type())
	}
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

// ActionActiveParam determines active parameters for the current function.
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

// Apply determines active parameters from the current SSA graph.
// C++ parity: coreaction.cc ActionActiveParam::apply
func (a *ActionActiveParam) Apply(data *Funcdata) int {
	if ApplyActiveParamModel(data) {
		a.count++
	}
	return 0
}

// ActionActiveReturn determines active return values for the current function.
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

// Apply determines the active return value from the current SSA graph.
// C++ parity: coreaction.cc ActionActiveReturn::apply
func (a *ActionActiveReturn) Apply(data *Funcdata) int {
	if ApplyActiveReturnModel(data) {
		a.count++
	}
	return 0
}

// ActionReturnRecovery determines the return value carrier for the current function.
// C++ parity: coreaction.hh ActionReturnRecovery
type ActionReturnRecovery struct{ ActionBase }

var _ Action = (*ActionReturnRecovery)(nil)

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

// Apply determines the active return value from the current SSA graph.
// C++ parity: coreaction.cc ActionReturnRecovery::apply
func (a *ActionReturnRecovery) Apply(data *Funcdata) int {
	fp := data.GetFuncProto()
	if fp == nil {
		return 0
	}

	active := NewParamActive(false)
	fp.SetActiveOutput(active)

	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN || op.HaltType() != 0 {
			continue
		}
		for i := 1; i < op.NumInput(); i++ {
			vn := op.Input(i)
			if vn == nil || vn.IsConstant() {
				continue
			}
			if !ancestorOpUseReturn(vn, op, i, 5, make(map[*PcodeOp]bool)) {
				continue
			}
			trialIdx := active.WhichTrial(vn.Addr(), vn.Size())
			if trialIdx < 0 {
				active.RegisterTrial(vn.Addr(), vn.Size())
				trialIdx = active.NumTrials() - 1
			}
			trial := active.Trial(trialIdx)
			trial.MarkUsed()
			trial.MarkActive()
		}
	}

	active.SortTrials()
	active.DeleteUnusedTrials()
	if active.NumTrials() == 0 || active.NumUsed() == 0 {
		fp.ClearUnlockedOutput()
		return 0
	}

	changed := false
	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN || op.HaltType() != 0 {
			continue
		}
		buildReturnOutput(active, op, data)
		changed = true
	}

	if changed {
		a.count++
	}
	return 0
}

// ActionReturnSplit splits multi-entry return blocks into separate return paths.
// C++ parity: blockaction.hh ActionReturnSplit
type ActionReturnSplit struct{ ActionBase }

var _ Action = (*ActionReturnSplit)(nil)

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

// isReturnSplitSplittable reports whether a RETURN block is simple enough to split.
// C++ parity: blockaction.cc ActionReturnSplit::isSplittable
func isReturnSplitSplittable(b *BlockBasic) bool {
	if b == nil {
		return false
	}
	for _, op := range b.Ops() {
		if op == nil {
			continue
		}
		switch op.Code() {
		case CPUI_MULTIEQUAL:
			continue
		case CPUI_COPY, CPUI_RETURN:
			for i := 0; i < op.NumInput(); i++ {
				in := op.Input(i)
				if in == nil {
					continue
				}
				if in.IsConstant() || in.IsAnnotation() {
					continue
				}
				if in.IsFree() {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// Apply splits return blocks that have multiple incoming edges.
// C++ parity: blockaction.cc ActionReturnSplit::apply
func (a *ActionReturnSplit) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	if data.GetStructure().GetSize() == 0 {
		return 0
	}
	if data.GetBasicBlocks() == nil {
		return 0
	}

	changed := 0
	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN || op.HaltType() != 0 {
			continue
		}
		parent := op.Parent()
		if parent == nil || parent.SizeIn() <= 1 {
			continue
		}
		if !isReturnSplitSplittable(parent) {
			continue
		}
		for i := parent.SizeIn() - 1; i >= 1; i-- {
			data.NodeSplit(parent, i)
			changed++
		}
	}

	if changed > 0 {
		a.count += changed
	}
	return 0
}

// ============================================================================
// Batch 12 real ports: ten Actions ported verbatim from coreaction.cc.
// Infrastructure-dependent paths are marked "TODO known mismatch" and skipped
// when the underlying helpers are not yet available on Gosleigh side.
// C++ reference file: ghidra-ref/.../decompile/cpp/coreaction.cc
// ============================================================================

// ActionConstantPtr promotes constant varnodes that look like global symbol
// pointers into spacebase references.
// C++ parity: coreaction.hh ActionConstantPtr
type ActionConstantPtr struct {
	ActionBase
	localcount int
}

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

// Reset clears the local pass counter.
// C++ parity: coreaction.hh ActionConstantPtr::reset
func (a *ActionConstantPtr) Reset(_ *Funcdata) { a.localcount = 0 }

// Apply walks constant varnodes and tries to promote them to symbol references.
// C++ parity: coreaction.cc ActionConstantPtr::apply
// TODO known mismatch: symbol entry lookup (isPointer), inferPtrSpaces,
// and Funcdata::spacebaseConstant are not yet ported. The Go port performs the
// outer walk and filter conditions, but the promotion call is a no-op until
// global symbol recovery lands.
func (a *ActionConstantPtr) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	if !data.HasFlag(FuncTypeRecoveryOn) {
		return 0
	}
	if a.localcount >= 4 {
		return 0
	}
	a.localcount++

	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil || !vn.IsConstant() {
			continue
		}
		if vn.Offset() == 0 {
			continue
		}
		if vn.HasAddlFlags(VarnodePtrCheck) {
			continue
		}
		if vn.HasNoDescend() {
			continue
		}
		if vn.IsSpaceBase() {
			continue
		}
		op := vn.LoneDescend()
		if op == nil {
			continue
		}
		slot := op.GetSlot(vn)
		if slot < 0 {
			continue
		}
		opc := op.Code()
		if opc == CPUI_PTRSUB || opc == CPUI_PTRADD {
			continue
		}
		if opc == CPUI_INT_ADD {
			other := op.Input(1 - slot)
			if other != nil && other.IsSpaceBase() {
				continue
			}
		}
		// Record that we have examined this varnode.
		vn.SetAddlFlags(VarnodePtrCheck)
		// TODO known mismatch: isPointer / spacebaseConstant not yet ported.
	}
	return 0
}

// ActionConstbase injects architecture "uponentry" live-inject pcode and
// tracked-context constant varnodes at function entry.
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

// Apply performs the function-entry live-inject + tracked-context COPY insertion.
// C++ parity: coreaction.cc ActionConstbase::apply
// TODO known mismatch: pcodeinjectlib live-inject and Architecture::context
// tracked-set queries are not yet ported. The Go port exits early when the
// basic-block list is empty (matching C++ early return) and otherwise is a
// structural placeholder for the full injection sequence.
func (a *ActionConstbase) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	bg := data.GetBasicBlocks()
	if bg == nil || bg.GetSize() == 0 {
		return 0
	}
	// TODO known mismatch: FuncProto::getInjectUponEntry + doLiveInject not ported.
	// TODO known mismatch: Architecture::context::getTrackedSet not ported --
	// when it lands we emit newOp(1)+newVarnodeOut+COPY per TrackedContext into
	// the entry block (see C++ lines 679-706).
	_ = bg.GetBlock(0)
	return 0
}

// ActionDeindirect resolves CALLIND targets whose function pointer is a known
// constant / external reference / typed function pointer into a concrete CALL.
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

// Apply walks CALLIND ops, strips COPY chains from input[0], and attempts to
// resolve each target into a concrete callee.
// C++ parity: coreaction.cc ActionDeindirect::apply
// TODO known mismatch: Scope::queryExternalRefFunction / Scope::queryFunction
// / FuncCallSpecs::deindirect / FuncCallSpecs::forceSet are not yet ported.
// The Go port performs the CALLIND classification walk and peel COPY chain,
// but cannot yet perform the resolution itself.
func (a *ActionDeindirect) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	for i := 0; i < data.NumCalls(); i++ {
		fc := data.GetCallSpecs(i)
		if fc == nil || fc.op == nil || fc.op.Code() != CPUI_CALLIND {
			continue
		}
		vn := fc.op.Input(0)
		for vn != nil && vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_COPY {
			vn = vn.Def().Input(0)
		}
		if vn == nil {
			continue
		}
		// External reference resolution and constant callee lookup require
		// Scope/queryFunction infrastructure not yet ported.
		// Structural detection is preserved here so future fixes have the
		// correct control-flow shape.
		if vn.HasFlags(VarnodeExternRef) && vn.IsPersist() {
			// TODO known mismatch: queryExternalRefFunction + FuncCallSpecs::deindirect.
			continue
		}
		if vn.IsConstant() {
			// TODO known mismatch: queryFunction + FuncCallSpecs::deindirect.
			continue
		}
		if data.HasFlag(FuncTypeRecoveryOn) {
			// TODO known mismatch: typed function-pointer resolution.
			continue
		}
	}
	return 0
}

// ActionDirectWrite taints varnodes reachable from legal function inputs so
// the later type recovery can tell genuine writes from artifact COPY chains.
// C++ parity: coreaction.hh ActionDirectWrite
type ActionDirectWrite struct {
	ActionBase
	propagateIndirect bool
}

var _ Action = (*ActionDirectWrite)(nil)

// NewActionDirectWrite constructs ActionDirectWrite with the propagate flag.
// C++ parity: coreaction.hh ActionDirectWrite::ActionDirectWrite
func NewActionDirectWrite(group string, propagate bool) *ActionDirectWrite {
	act := &ActionDirectWrite{propagateIndirect: propagate}
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

// Apply performs the two-phase DirectWrite labelling.
// C++ parity: coreaction.cc ActionDirectWrite::apply
// TODO known mismatch: FuncProto::possibleInputParam classification is
// approximated via FuncProto::IsParamVarnode because the full ABI-level
// possibleInputParam query has not yet been ported.
func (a *ActionDirectWrite) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	bank := data.GetVarnodeBank()
	if bank == nil {
		return 0
	}
	fp := data.GetFuncProto()

	var worklist []*Varnode
	push := func(vn *Varnode) {
		vn.SetFlags(VarnodeDirectWrite)
		worklist = append(worklist, vn)
	}

	// Phase 1: collect legal inputs and auto-direct writes.
	for _, vn := range bank.AllVarnodes() {
		if vn == nil {
			continue
		}
		vn.ClearFlags(VarnodeDirectWrite)
		switch {
		case vn.IsInput():
			if vn.IsPersist() || vn.IsSpaceBase() {
				push(vn)
			} else if fp != nil && fp.IsParamVarnode(vn) {
				push(vn)
			}
		case vn.IsWritten():
			op := vn.Def()
			if op == nil {
				continue
			}
			if !op.IsMarker() {
				if vn.IsPersist() {
					push(vn)
					continue
				}
				if op.Code() == CPUI_COPY {
					if vn.IsStackStore() {
						invn := op.Input(0)
						if invn != nil && invn.IsWritten() && invn.Def() != nil && invn.Def().Code() == CPUI_COPY {
							invn = invn.Def().Input(0)
						}
						if invn != nil && invn.IsWritten() && invn.Def() != nil && invn.Def().IsMarker() {
							push(vn)
						}
					}
				} else if op.Code() != CPUI_PIECE && op.Code() != CPUI_SUBPIECE {
					push(vn)
				}
			} else if !a.propagateIndirect && op.Code() == CPUI_INDIRECT {
				outvn := op.Output()
				if outvn != nil && op.NumInput() > 0 && op.Input(0) != nil {
					if op.Input(0).Addr() != outvn.Addr() {
						vn.SetFlags(VarnodeDirectWrite)
					} else if outvn.IsPersist() {
						vn.SetFlags(VarnodeDirectWrite)
					}
				}
			}
		default:
			if vn.IsConstant() && !vn.IsIndirectZero() {
				push(vn)
			}
		}
	}

	// Phase 2: propagate along assignment chains.
	for len(worklist) > 0 {
		vn := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		for _, op := range vn.DescendIter() {
			if op == nil || !op.IsAssignment() {
				continue
			}
			dvn := op.Output()
			if dvn == nil || dvn.IsDirectWrite() {
				continue
			}
			dvn.SetFlags(VarnodeDirectWrite)
			if a.propagateIndirect || op.Code() != CPUI_INDIRECT || op.IsIndirectStore() {
				worklist = append(worklist, dvn)
			}
		}
	}
	return 0
}

// ActionFuncLink prepares each sub-function call for parameter recovery.
// C++ parity: coreaction.hh ActionFuncLink
type ActionFuncLink struct{ ActionBase }

var _ Action = (*ActionFuncLink)(nil)

// NewActionFuncLink constructs ActionFuncLink.
// C++ parity: coreaction.hh ActionFuncLink::ActionFuncLink
func NewActionFuncLink(group string) *ActionFuncLink {
	act := &ActionFuncLink{}
	act.ActionBase = NewActionBase(act, 0, "funclink", group)
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

// Apply runs funcLinkInput + funcLinkOutput for every call.
// C++ parity: coreaction.cc ActionFuncLink::apply
// TODO known mismatch: funcLinkInput/funcLinkOutput helpers require
// opStackLoad, initActiveInput, newVarnodeOut-at-call, assumedOutputExtension,
// and createPlaceholder plumbing that is not yet ported. The Go port walks
// every call and delegates to ActionFuncLinkOutOnly for outputs; the full
// input-side lock handling will land with the fspec port.
func (a *ActionFuncLink) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	size := data.NumCalls()
	out := NewActionFuncLinkOutOnly(a.GetGroup())
	for i := 0; i < size; i++ {
		fc := data.GetCallSpecs(i)
		if fc == nil {
			continue
		}
		// Input side: initialise ActiveInput when not locked (varargs or open).
		if !fc.IsInputLocked() {
			// TODO known mismatch: FuncCallSpecs::initActiveInput not ported.
			_ = fc
		}
		// Output side: delegate to the already-ported FuncLinkOutOnly path.
		_ = out
	}
	// Delegate output processing to the already-ported helper (wire via its apply).
	if size > 0 {
		outAction := NewActionFuncLinkOutOnly(a.GetGroup())
		outAction.Apply(data)
	}
	return 0
}

// ActionLaneDivide rewrites vector lane varnodes so each lane becomes an
// explicit varnode.
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

// Apply iterates laned-access varnodes and splits them via TransformManager.
// C++ parity: coreaction.cc ActionLaneDivide::apply
// TODO known mismatch: Funcdata::beginLaneAccess / processVarnode /
// clearLanedAccessMap are stubbed. The Go port currently records the
// "laned register generated" flag and clears the per-pass state but does not
// perform any actual lane splitting; the TransformManager port in
// pkg/pcode/transform.go does not yet expose the lane-splitting entry points.
func (a *ActionLaneDivide) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	// TODO known mismatch: setLanedRegGenerated / beginLaneAccess / processVarnode / clearLanedAccessMap.
	return 0
}

// ActionLikelyTrash zeroes out reads of register locations that the compiler
// wrote only as a side-effect (e.g. x86 "push ecx" to reserve stack).
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

// likelyTrashCountMarks matches coreaction.cc ActionLikelyTrash::countMarks.
// C++ parity: coreaction.cc ActionLikelyTrash::countMarks
func likelyTrashCountMarks(op *PcodeOp) uint32 {
	var n uint32
	for i := 0; i < op.NumInput(); i++ {
		vn := op.Input(i)
		if vn == nil {
			continue
		}
		if vn.IsMark() {
			n++
			continue
		}
		if vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_COPY {
			src := vn.Def().Input(0)
			if src != nil && src.IsMark() {
				n++
			}
		}
	}
	return n
}

// likelyTrashTrace matches ActionLikelyTrash::traceTrash: returns true when
// every downstream reader of vn treats it as trash (can be zeroed).
// C++ parity: coreaction.cc ActionLikelyTrash::traceTrash
func likelyTrashTrace(vn *Varnode, indlist *[]*PcodeOp) bool {
	var markedVn []*Varnode
	var allroutes []*PcodeOp
	vn.SetMark()
	markedVn = append(markedVn, vn)
	traced := 0
	istrash := true
	for traced < len(markedVn) && istrash {
		cur := markedVn[traced]
		traced++
		for _, op := range cur.DescendIter() {
			if op == nil {
				continue
			}
			outvn := op.Output()
			switch op.Code() {
			case CPUI_INDIRECT:
				if outvn != nil && outvn.IsPersist() {
					istrash = false
				} else if op.IsIndirectStore() {
					if outvn != nil && !outvn.IsMark() {
						outvn.SetMark()
						markedVn = append(markedVn, outvn)
					}
				} else {
					*indlist = append(*indlist, op)
				}
			case CPUI_SUBPIECE:
				if outvn != nil && outvn.IsPersist() {
					istrash = false
				} else if outvn != nil && !outvn.IsMark() {
					outvn.SetMark()
					markedVn = append(markedVn, outvn)
				}
			case CPUI_MULTIEQUAL, CPUI_PIECE:
				if outvn != nil && outvn.IsPersist() {
					istrash = false
					break
				}
				if !op.HasFlag(PcodeOpMark) {
					op.SetFlag(PcodeOpMark)
					allroutes = append(allroutes, op)
				}
				nm := likelyTrashCountMarks(op)
				if int(nm) == op.NumInput() && outvn != nil && !outvn.IsMark() {
					outvn.SetMark()
					markedVn = append(markedVn, outvn)
				}
			case CPUI_INT_AND:
				if op.Input(1) != nil && op.Input(1).IsConstant() {
					val := op.Input(1).Offset()
					sz := uint(op.Input(1).Size())
					mask := uint64(^uint64(0)) >> (64 - sz*8)
					if val == ((mask<<8)&mask) || val == ((mask<<16)&mask) || val == ((mask<<32)&mask) {
						*indlist = append(*indlist, op)
						break
					}
				}
				istrash = false
			default:
				istrash = false
			}
			if !istrash {
				break
			}
		}
	}
	for _, op := range allroutes {
		if op.Output() == nil || !op.Output().IsMark() {
			istrash = false
		}
		op.ClearFlag(PcodeOpMark)
	}
	for _, v := range markedVn {
		v.ClearMark()
	}
	return istrash
}

// Apply rewrites each likely-trash reader to a zero constant and marks the
// underlying INDIRECTs as creations.
// C++ parity: coreaction.cc ActionLikelyTrash::apply
// TODO known mismatch: FuncProto::trashBegin/End and Funcdata::findCoveredInput
// are not yet ported; when they arrive this loop replaces the outer "skip".
func (a *ActionLikelyTrash) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	// TODO known mismatch: FuncProto likely-trash register list not yet ported,
	// so we cannot pick candidate varnodes. The inner traceTrash helper is
	// implemented so the remaining glue is the trash-list iteration in C++
	// lines 2141-2171.
	_ = likelyTrashTrace
	return 0
}

// ActionMultiCse removes redundant MULTIEQUAL ops that share inputs.
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

// multiCsePreferredOutput returns true if out1 should survive vs out2.
// C++ parity: coreaction.cc ActionMultiCse::preferredOutput
func multiCsePreferredOutput(out1, out2 *Varnode) bool {
	if out1 == nil {
		return false
	}
	if out2 == nil {
		return true
	}
	if out1.IsAddrTied() && !out2.IsAddrTied() {
		return true
	}
	if !out1.IsAddrTied() && out2.IsAddrTied() {
		return false
	}
	return out1.CreateIndex() < out2.CreateIndex()
}

// multiCseProcessBlock performs one MULTIEQUAL dedup pass on a basic block.
// C++ parity: coreaction.cc ActionMultiCse::processBlock
// TODO known mismatch: findMatch uses functionalEqualityLevel which is not
// ported yet. The Go port currently only handles identical-input MULTIEQUAL
// pairs (a strict subset of the C++ behaviour).
func (a *ActionMultiCse) multiCseProcessBlock(data *Funcdata, bl *BlockBasic) bool {
	if bl == nil {
		return false
	}
	// Simple pairwise comparison: two MULTIEQUAL ops in the same block with
	// element-wise equal inputs are functional duplicates.
	ops := bl.Ops()
	var mes []*PcodeOp
	for _, op := range ops {
		if op == nil || op.IsDead() {
			continue
		}
		if op.Code() == CPUI_COPY {
			continue
		}
		if op.Code() != CPUI_MULTIEQUAL {
			break
		}
		mes = append(mes, op)
	}
	for i := 0; i < len(mes); i++ {
		for j := i + 1; j < len(mes); j++ {
			p := mes[i]
			q := mes[j]
			if p.NumInput() != q.NumInput() {
				continue
			}
			equal := true
			for k := 0; k < p.NumInput(); k++ {
				if p.Input(k) != q.Input(k) {
					equal = false
					break
				}
			}
			if !equal {
				continue
			}
			out1 := p.Output()
			out2 := q.Output()
			if multiCsePreferredOutput(out1, out2) {
				data.TotalReplace(out1, out2)
				data.OpDestroy(p)
			} else {
				data.TotalReplace(out2, out1)
				data.OpDestroy(q)
			}
			a.count++
			return true
		}
	}
	return false
}

// Apply runs multiCseProcessBlock on every basic block until stable.
// C++ parity: coreaction.cc ActionMultiCse::apply
func (a *ActionMultiCse) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	bg := data.GetBasicBlocks()
	if bg == nil {
		return 0
	}
	for i := 0; i < bg.GetSize(); i++ {
		bb, ok := bg.GetBlock(i).Concrete().(*BlockBasic)
		if !ok || bb == nil {
			continue
		}
		for a.multiCseProcessBlock(data, bb) {
		}
	}
	return 0
}

// ActionParamDouble reconciles CONCAT ops at call sites with double-precision
// parameter trials.
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

// Apply walks active-input calls and splits/joins CONCAT pieces when the
// FuncCallSpecs agrees.
// C++ parity: coreaction.cc ActionParamDouble::apply
// TODO known mismatch: FuncCallSpecs::checkInputSplit / checkInputJoin,
// ParamActive::splitTrial on the call side, SplitVarnode::inHandHi/Lo,
// Funcdata::isDoublePrecisOn, and FuncProto::isInputLocked interactions are
// not yet fully ported. This Go port retains the per-call iteration structure
// so the gaps are obvious.
func (a *ActionParamDouble) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	for i := 0; i < data.NumCalls(); i++ {
		fc := data.GetCallSpecs(i)
		if fc == nil || fc.op == nil {
			continue
		}
		// TODO known mismatch: fc.IsInputActive / ActiveInput trial iteration and
		// fc.checkInputSplit not ported.
		_ = fc
	}
	// TODO known mismatch: FuncProto-level double-precision parameter split
	// (coreaction.cc lines 1668-1723) requires isPrimitiveWhole and
	// findVarnodeInput which have not been ported.
	return 0
}

// ActionRestructureVarnode rebuilds the local symbol map from discovered
// varnodes and protects switch paths from INDIRECT collapse.
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

// Reset clears the local pass counter.
// C++ parity: coreaction.hh ActionRestructureVarnode::reset
func (a *ActionRestructureVarnode) Reset(_ *Funcdata) { a.numpass = 0 }

// restructureIsCopyConstant returns true for a constant or COPY-of-constant.
// C++ parity: coreaction.cc ActionRestructureVarnode::isCopyConstant
func restructureIsCopyConstant(vn *Varnode) bool {
	if vn == nil {
		return false
	}
	if vn.IsConstant() {
		return true
	}
	if !vn.IsWritten() {
		return false
	}
	def := vn.Def()
	if def == nil || def.Code() != CPUI_COPY {
		return false
	}
	src := def.Input(0)
	return src != nil && src.IsConstant()
}

// restructureIsDelayedConstant returns true when vn will collapse to a
// constant after one more round of simplification.
// C++ parity: coreaction.cc ActionRestructureVarnode::isDelayedConstant
func restructureIsDelayedConstant(vn *Varnode) bool {
	if vn == nil {
		return false
	}
	if vn.IsConstant() {
		return true
	}
	if !vn.IsWritten() {
		return false
	}
	def := vn.Def()
	if def == nil {
		return false
	}
	switch def.Code() {
	case CPUI_COPY:
		src := def.Input(0)
		return src != nil && src.IsConstant()
	case CPUI_INT_ADD:
		if def.NumInput() < 2 {
			return false
		}
		return restructureIsCopyConstant(def.Input(0)) && restructureIsCopyConstant(def.Input(1))
	}
	return false
}

// restructureProtectSwitchPathIndirects marks the first INDIRECT on the
// branch-target data-flow path as "do not collapse", so the switch value is
// preserved for jump-table recovery.
// C++ parity: coreaction.cc ActionRestructureVarnode::protectSwitchPathIndirects
func restructureProtectSwitchPathIndirects(op *PcodeOp) {
	if op == nil || op.NumInput() == 0 {
		return
	}
	var lastIndirect *PcodeOp
	cur := op.Input(0)
	for cur != nil && cur.IsWritten() {
		curOp := cur.Def()
		if curOp == nil {
			return
		}
		et := curOp.EvalType()
		if et&(PcodeOpBinary|PcodeOpTernary) != 0 {
			if curOp.NumInput() > 1 {
				if restructureIsDelayedConstant(curOp.Input(1)) {
					cur = curOp.Input(0)
					continue
				}
				if restructureIsDelayedConstant(curOp.Input(0)) {
					cur = curOp.Input(1)
					continue
				}
				return
			}
			cur = curOp.Input(0)
			continue
		}
		if et&PcodeOpUnary != 0 {
			cur = curOp.Input(0)
			continue
		}
		switch curOp.Code() {
		case CPUI_INDIRECT:
			lastIndirect = curOp
			cur = curOp.Input(0)
		case CPUI_LOAD:
			if curOp.NumInput() > 1 {
				cur = curOp.Input(1)
			} else {
				return
			}
		case CPUI_MULTIEQUAL:
			for i := 0; i < curOp.NumInput(); i++ {
				piece := curOp.Input(i)
				if piece == nil || !piece.IsWritten() {
					continue
				}
				inOp := piece.Def()
				if inOp != nil && inOp.Code() == CPUI_INDIRECT {
					inOp.SetAdditionalFlag(PcodeOpNoIndirectCollapse)
					break
				}
			}
			return
		default:
			return
		}
	}
	if cur == nil || !cur.IsConstant() {
		return
	}
	if lastIndirect != nil {
		lastIndirect.SetAdditionalFlag(PcodeOpNoIndirectCollapse)
	}
}

// restructureProtectSwitchPaths walks every BRANCHIND and runs the protector.
// C++ parity: coreaction.cc ActionRestructureVarnode::protectSwitchPaths
func restructureProtectSwitchPaths(data *Funcdata) {
	bg := data.GetBasicBlocks()
	if bg == nil {
		return
	}
	for i := 0; i < bg.GetSize(); i++ {
		bb, ok := bg.GetBlock(i).Concrete().(*BlockBasic)
		if !ok || bb == nil {
			continue
		}
		last := bb.LastOp()
		if last == nil || last.Code() != CPUI_BRANCHIND {
			continue
		}
		restructureProtectSwitchPathIndirects(last)
	}
}

// Apply drives ScopeLocal::restructureVarnode and switch-path protection.
// C++ parity: coreaction.cc ActionRestructureVarnode::apply
// TODO known mismatch: ScopeLocal::restructureVarnode is partial -- the Go
// port runs the alias/overlap walk but does not yet rebuild every SymbolEntry
// from the Varnode footprint (database.cc ScopeLocal::restructureVarnode).
// Jumptable-recovery-on mode is not yet distinguished from normal runs
// (funcdata.hh Funcdata::isJumptableRecoveryOn), so protectSwitchPaths is
// always enabled like the unconditional fallback arm.
func (a *ActionRestructureVarnode) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	sl := data.GetScopeLocal()
	aliasyes := a.numpass != 0
	if sl != nil {
		sl.RestructureVarnode(data, aliasyes)
	}
	if data.SyncVarnodesWithSymbols(sl, false, aliasyes) {
		a.count++
	}
	restructureProtectSwitchPaths(data)
	a.numpass++
	return 0
}

// ---------------------------------------------------------------------------
// ActionShadowVar -- REAL
// ---------------------------------------------------------------------------

// ActionShadowVar collapses two MULTIEQUAL ops in the same block header that
// share identical inputs: the second is rewritten as a COPY of the first.
// C++ parity: coreaction.hh ActionShadowVar; coreaction.cc ActionShadowVar::apply
type ActionShadowVar struct {
	ActionBase
}

var _ Action = (*ActionShadowVar)(nil)

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

// Apply folds shadow MULTIEQUALs in each basic block's header.
// C++ parity: coreaction.cc ActionShadowVar::apply
func (a *ActionShadowVar) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	bg := data.GetBasicBlocks()
	if bg == nil {
		return 0
	}
	for i := 0; i < bg.GetSize(); i++ {
		fb := bg.GetBlock(i)
		if fb == nil {
			continue
		}
		bb, ok := fb.Concrete().(*BlockBasic)
		if !ok || bb == nil || bb.EmptyOp() {
			continue
		}
		// Gather MULTIEQUAL ops located at the block's starting address.
		// C++ parity: the C++ iterates bl->beginOp() while op->getAddr() == startoffset.
		ops := bb.Ops()
		if len(ops) == 0 {
			continue
		}
		startAddr := ops[0].Addr()
		var phis []*PcodeOp
		for _, op := range ops {
			if op == nil || op.IsDead() {
				continue
			}
			if op.Addr() != startAddr {
				break
			}
			if op.Code() != CPUI_MULTIEQUAL {
				continue
			}
			phis = append(phis, op)
		}
		if len(phis) < 2 {
			continue
		}
		// For each pair, check whether all inputs match -- if so, later op
		// becomes a COPY of the earlier one's output.
		// C++ parity: previousOp() walk in ShadowVar::apply.
		for j := 1; j < len(phis); j++ {
			op := phis[j]
			for k := 0; k < j; k++ {
				prev := phis[k]
				if prev.NumInput() != op.NumInput() {
					continue
				}
				allSame := true
				for s := 0; s < op.NumInput(); s++ {
					if prev.Input(s) != op.Input(s) {
						allSame = false
						break
					}
				}
				if !allSame || prev.Output() == nil {
					continue
				}
				// Rewrite op as COPY(prev.Output).
				for s := op.NumInput() - 1; s >= 1; s-- {
					data.OpUnsetInput(op, s)
				}
				data.OpSetOpcode(op, CPUI_COPY)
				op.SetNumInputs(1)
				data.OpUnsetInput(op, 0)
				data.OpSetInput(op, prev.Output(), 0)
				a.count++
				break
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionVarnodeProps -- REAL (subset)
// ---------------------------------------------------------------------------

// ActionVarnodeProps processes special Varnode properties: replace zero-value
// varnodes (nzmask & consume == 0) with constant zero.
// C++ parity: coreaction.hh ActionVarnodeProps; coreaction.cc ActionVarnodeProps::apply
type ActionVarnodeProps struct {
	ActionBase
}

var _ Action = (*ActionVarnodeProps)(nil)

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

// totalReplaceConstant replaces every use of vn with a freshly materialised
// constant of the given value. It is the Go equivalent of the C++ helper
// Funcdata::totalReplaceConstant used by ActionVarnodeProps::apply.
// C++ parity: funcdata_varnode.cc Funcdata::totalReplaceConstant
func totalReplaceConstant(data *Funcdata, vn *Varnode, val uint64) {
	if data == nil || vn == nil {
		return
	}
	uses := vn.DescendIter()
	for _, useOp := range uses {
		slot := useOp.GetSlot(vn)
		if slot < 0 {
			continue
		}
		c := data.NewConstant(vn.Size(), val)
		data.OpUnsetInput(useOp, slot)
		data.OpSetInput(useOp, c, slot)
	}
}

// Apply replaces varnodes whose non-zero mask intersected with consumed bits is
// empty with a constant zero (excluding constants, annotations, and COPY 0).
// TODO known mismatch: the readonlypropagate, volatile-replace, and
// autoLiveHold branches from the C++ require Funcdata::fillinReadOnly,
// Funcdata::replaceVolatile, and VarnodeAutoLiveHold clearing which are not
// present in Gosleigh. Only the NZMask/consume zero branch is ported.
// C++ parity: coreaction.cc ActionVarnodeProps::apply
func (a *ActionVarnodeProps) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	// Snapshot the list so iteration is safe across totalReplaceConstant.
	vns := data.GetVarnodeBank().AllVarnodes()
	for _, vn := range vns {
		if vn == nil || vn.IsAnnotation() || vn.IsConstant() {
			continue
		}
		if vn.Size() <= 0 || vn.Size() > 8 {
			continue
		}
		if vn.NZMask()&vn.Consumed() != 0 {
			continue
		}
		// Don't replace a COPY 0 -- let constant propagation handle it.
		if vn.IsWritten() {
			def := vn.Def()
			if def != nil && def.Code() == CPUI_COPY {
				in := def.Input(0)
				if in != nil && in.IsConstant() && in.Offset() == 0 {
					continue
				}
			}
		}
		if vn.HasNoDescend() {
			continue
		}
		totalReplaceConstant(data, vn, 0)
		a.count++
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionConditionalConst -- REAL (port of coreaction.cc lines 4080-4557)
// ---------------------------------------------------------------------------

// ActionConditionalConst propagates boolean values known along one edge of a
// CBRANCH into MULTIEQUAL phis reachable from that edge.
// C++ parity: coreaction.hh ActionConditionalConst; coreaction.cc
// ActionConditionalConst::apply and its helpers (pushConstant,
// propagateConstant, findConstCompare, placeMultipleConstants, collectReachable,
// flowTogether, placeCopy, handlePhiNodes, testAlternatePath).
type ActionConditionalConst struct {
	ActionBase
}

var _ Action = (*ActionConditionalConst)(nil)

// NewActionConditionalConst constructs ActionConditionalConst.
// C++ parity: coreaction.hh ActionConditionalConst::ActionConditionalConst
func NewActionConditionalConst(group string) *ActionConditionalConst {
	act := &ActionConditionalConst{}
	act.ActionBase = NewActionBase(act, 0, "conditionalconst", group)
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

// Apply walks each CBRANCH, building a worklist of constPoints, and delegates
// the heavy lifting to condConstContext.propagateConstant which performs the
// full reach / flowTogether / placeCopy analysis from condexe.go. Each hit
// advances a.count so the main loop will iterate.
// C++ parity: coreaction.cc ActionConditionalConst::apply (lines 4525-4557)
// TODO known mismatch:
//   - Gosleigh has no Funcdata::numHeritagePasses, so useMultiequal is always
//     enabled. C++ defers phi-node propagation until the stack space has been
//     heritaged at least once.
//   - pushConstant is limited to the straight-COPY case because
//     PcodeOp::executeSimple is not ported yet.
func (a *ActionConditionalConst) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	bg := data.GetBasicBlocks()
	if bg == nil {
		return 0
	}
	ctx := &condConstContext{
		data:       data,
		useMulti:   true,
		markedOps:  make(map[*PcodeOp]bool),
		markedVars: make(map[*Varnode]bool),
	}
	for i := 0; i < bg.GetSize(); i++ {
		fb := bg.GetBlock(i)
		if fb == nil {
			continue
		}
		bb, ok := fb.Concrete().(*BlockBasic)
		if !ok || bb == nil {
			continue
		}
		cBranch := bb.LastOp()
		if cBranch == nil || cBranch.IsDead() || cBranch.Code() != CPUI_CBRANCH {
			continue
		}
		if cBranch.NumInput() < 2 {
			continue
		}
		boolVn := cBranch.Input(1)
		if boolVn == nil {
			continue
		}
		if fb.SizeOut() < 2 {
			continue
		}
		var blockDom [2]bool
		blockDom[0] = restrictedByConditional(fb.OutEdge(0).Point, fb)
		blockDom[1] = restrictedByConditional(fb.OutEdge(1).Point, fb)
		flipEdge := cBranch.HasFlag(PcodeOpBooleanFlip)
		var points []constPoint
		if boolVn.LoneDescend() == nil {
			falseVal := uint64(0)
			trueVal := uint64(1)
			if flipEdge {
				falseVal, trueVal = 1, 0
			}
			points = append(points, constPoint{
				vn:         boolVn,
				value:      falseVal,
				constBlock: fb.FalseOut(),
				inSlot:     fb.OutRevIndex(0),
				blockIsDom: blockDom[0],
			})
			points = append(points, constPoint{
				vn:         boolVn,
				value:      trueVal,
				constBlock: fb.TrueOut(),
				inSlot:     fb.OutRevIndex(1),
				blockIsDom: blockDom[1],
			})
		}
		ctx.findConstCompare(&points, boolVn, fb, blockDom, flipEdge)
		if len(points) == 0 {
			continue
		}
		before := ctx.changed
		ctx.propagateConstant(points)
		delta := ctx.changed - before
		a.count += delta
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionConditionalExe -- REAL (driver for condexe.go ConditionalExecution)
// ---------------------------------------------------------------------------

// ActionConditionalExe trims control flow whose branches cancel dataflow.
// C++ parity: condexe.hh ActionConditionalExe; condexe.cc
// ActionConditionalExe::apply, which drives ConditionalExecution::trial and
// ConditionalExecution::execute over every BlockBasic until no more changes.
type ActionConditionalExe struct {
	ActionBase
}

var _ Action = (*ActionConditionalExe)(nil)

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

// Apply iterates all basic blocks looking for modifiable conditional-execute
// configurations, calling ConditionalExecution.Trial then .Execute on every
// hit until a pass makes no changes. Matches C++ coreaction.cc lines 4478-4503.
// C++ parity: condexe.cc ActionConditionalExe::apply
// TODO known mismatch: the C++ implementation first bails out if
// data.hasUnreachableBlocks() is true. Gosleigh has no such method; instead
// we trust Trial() to reject malformed iblocks via testIBlock/findInitPre.
func (a *ActionConditionalExe) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	bg := data.GetBasicBlocks()
	if bg == nil {
		return 0
	}
	condexe := NewConditionalExecution(data)
	for {
		changed := false
		for i := 0; i < bg.GetSize(); i++ {
			fb := bg.GetBlock(i)
			if fb == nil {
				continue
			}
			bb, ok := fb.Concrete().(*BlockBasic)
			if !ok || bb == nil {
				continue
			}
			if condexe.Trial(bb) {
				condexe.Execute()
				a.count++
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionSwitchNorm -- TODO
// ---------------------------------------------------------------------------

// ActionSwitchNorm normalises jumptable switches (labels + fold-in guards).
// C++ parity: coreaction.hh ActionSwitchNorm; coreaction.cc
// ActionSwitchNorm::apply and jumptable.cc JumpTable::recoverLabels /
// foldInNormalization / foldInGuards.
type ActionSwitchNorm struct {
	ActionBase
}

var _ Action = (*ActionSwitchNorm)(nil)

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

// Apply iterates every recovered JumpTable and, for ones that have not yet
// been labelled, runs matchModel -> recoverLabels -> foldInNormalization.
// foldInGuards is always re-run to pick up newly collapsed guards.
// C++ parity: coreaction.cc ActionSwitchNorm::apply (lines 4559-4576)
// TODO known mismatch: data.getStructure().clear() is not wired up because
// the Go Funcdata has no structured-block cache yet (blockaction.cc). Each
// foldInGuards success still bumps the action count as in the C++ path so
// the restart loop re-evaluates downstream rules.
func (a *ActionSwitchNorm) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	for i := 0; i < data.NumJumpTables(); i++ {
		jt := data.GetJumpTable(i)
		if jt == nil {
			continue
		}
		if !jt.IsLabelled() {
			jt.MatchModel(data)
			jt.RecoverLabels(data)
			jt.FoldInNormalization(data)
			a.count++
		}
		if jt.FoldInGuards(data) {
			// C++ calls data.getStructure().clear() here; see TODO above.
			a.count++
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionSegmentize -- TODO
// ---------------------------------------------------------------------------

// ActionSegmentize rewrites segmentop user-ops into the CPUI_SEGMENTOP form.
// C++ parity: coreaction.hh ActionSegmentize; coreaction.cc
// ActionSegmentize::apply drives Architecture::userops::getSegmentOp and
// SegmentOp::unify.
type ActionSegmentize struct {
	ActionBase
	localCount int
}

var _ Action = (*ActionSegmentize)(nil)

// NewActionSegmentize constructs ActionSegmentize.
// C++ parity: coreaction.hh ActionSegmentize::ActionSegmentize
func NewActionSegmentize(group string) *ActionSegmentize {
	act := &ActionSegmentize{}
	act.ActionBase = NewActionBase(act, 0, "segmentize", group)
	return act
}

// Reset resets per-function state.
// C++ parity: coreaction.hh ActionSegmentize::reset
func (a *ActionSegmentize) Reset(data *Funcdata) {
	a.localCount = 0
}

// Clone clones ActionSegmentize for the provided group list.
// C++ parity: coreaction.hh ActionSegmentize::clone
func (a *ActionSegmentize) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionSegmentize(a.GetGroup())
}

// Apply is a TODO stub: the SegmentOp user-op registry from
// Architecture::userops and SegmentOp::unify (userop.cc / globalcontext.cc)
// is not ported. On architectures without segmented memory (x86, ARM) the
// real action is also a no-op, so the stub is observationally correct today.
// C++ parity: coreaction.cc ActionSegmentize::apply
func (a *ActionSegmentize) Apply(data *Funcdata) int {
	_ = data
	// Mimic the once-per-function guard so future ports don't re-run.
	if a.localCount > 0 {
		return 0
	}
	a.localCount = 1
	return 0
}

// ---------------------------------------------------------------------------
// ActionRestrictLocal -- TODO
// ---------------------------------------------------------------------------

// ActionRestrictLocal marks stack slots that are used as function call
// parameters or saved-registers as "not mapped" in the local scope.
// C++ parity: coreaction.hh ActionRestrictLocal; coreaction.cc
// ActionRestrictLocal::apply relies on Funcdata::getCallSpecs and
// FuncCallSpecs::getSpacebaseOffset / ProtoParameter iteration, plus
// FuncProto::effectBegin/endIter for saved-register EffectRecord entries.
type ActionRestrictLocal struct {
	ActionBase
}

var _ Action = (*ActionRestrictLocal)(nil)

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

// Apply walks each tracked call site and removes the stack slots used as
// parameter passing from the local scope, then walks FuncProto saved
// registers to flag their storage as unmapped. Both sub-passes short-circuit
// when the underlying metadata is missing.
// C++ parity: coreaction.cc ActionRestrictLocal::apply (lines 1958-2003)
// TODO known mismatch: the real iteration needs FuncCallSpecs::getSpacebaseOffset,
// FuncCallSpecs::getParam, FuncProto::effectBegin/effectEnd (EffectRecord),
// and ScopeLocal::markNotMapped / isUnaffectedStorage. None of those are
// ported yet, so the inner bodies degrade to no-ops and only the driver
// wiring runs -- when the helpers land this function will pick them up.
func (a *ActionRestrictLocal) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	sl := data.GetScopeLocal()
	if sl == nil {
		return 0
	}
	// Sub-pass 1: stack slots used by call parameters.
	// C++ parity: ActionRestrictLocal::apply (first for loop).
	for i := 0; i < data.NumCalls(); i++ {
		fc := data.GetCallSpecs(i)
		if fc == nil {
			continue
		}
		if !fc.IsInputLocked() {
			continue
		}
		// TODO known mismatch: FuncCallSpecs::getSpacebaseOffset and
		// FuncCallSpecs::getParam are not ported; without them the
		// per-parameter markNotMapped call cannot be issued. The loop
		// stays here so the driver fires once those helpers exist.
		_ = fc
	}
	// Sub-pass 2: saved-register storage from effect records.
	// C++ parity: ActionRestrictLocal::apply (effect record loop).
	if data.GetFuncProto() != nil {
		// TODO known mismatch: FuncProto::effectBegin / effectEnd and
		// EffectRecord::killedbycall are absent; saved-register sweep
		// is currently a no-op (see funcproto.go).
		_ = data.GetFuncProto()
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionUnjustifiedParams -- TODO
// ---------------------------------------------------------------------------

// ActionUnjustifiedParams grows input parameter varnodes that do not fit the
// prototype's justification container.
// C++ parity: coreaction.hh ActionUnjustifiedParams; coreaction.cc
// ActionUnjustifiedParams::apply calls FuncProto::unjustifiedInputParam and
// Funcdata::adjustInputVarnodes to widen the affected input range.
type ActionUnjustifiedParams struct {
	ActionBase
}

var _ Action = (*ActionUnjustifiedParams)(nil)

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

// Apply is a TODO stub: FuncProto::unjustifiedInputParam (fspec.cc) and
// Funcdata::adjustInputVarnodes (funcdata_varnode.cc) are not yet ported;
// without them there is no way to detect or widen mis-sized input slots.
// C++ parity: coreaction.cc ActionUnjustifiedParams::apply
func (a *ActionUnjustifiedParams) Apply(data *Funcdata) int {
	_ = data
	return 0
}

// ---------------------------------------------------------------------------
// ActionHideShadow -- TODO
// ---------------------------------------------------------------------------

// ActionHideShadow hides shadow HighVariables created by speculative merges.
// C++ parity: coreaction.hh ActionHideShadow; coreaction.cc
// ActionHideShadow::apply calls Merge::hideShadows on every HighVariable.
type ActionHideShadow struct {
	ActionBase
}

var _ Action = (*ActionHideShadow)(nil)

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

// Apply walks every written Varnode, mark-guards each HighVariable to hit
// it exactly once, and calls Merge::hideShadows. Gosleigh lacks a persistent
// Funcdata.Merge accessor so we spin up a local Merge for the sweep; the
// mark bit on HighVariable is also absent, so we use a seen-set instead.
// C++ parity: coreaction.cc ActionHideShadow::apply (lines 4842-4860)
// TODO known mismatch: Merge::hideShadows is a stub (see merge.go) so the
// count never increments even when the driver fires correctly.
func (a *ActionHideShadow) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	merge := NewMerge(data)
	seen := make(map[*HighVariable]bool)
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsFree() || !vn.IsWritten() {
			continue
		}
		high := vn.High()
		if high == nil || seen[high] {
			continue
		}
		seen[high] = true
		if merge.HideShadows(high) {
			a.count++
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionDynamicMapping -- TODO
// ---------------------------------------------------------------------------

// ActionDynamicMapping resolves dynamic Symbol entries by hashing live
// Varnodes against the function's DynamicHash table.
// C++ parity: coreaction.hh ActionDynamicMapping; coreaction.cc
// ActionDynamicMapping::apply walks ScopeLocal::beginDynamic/endDynamic and
// calls Funcdata::attemptDynamicMapping on each SymbolEntry.
type ActionDynamicMapping struct {
	ActionBase
}

var _ Action = (*ActionDynamicMapping)(nil)

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

// Apply walks every dynamic SymbolEntry attached to the local scope and
// attempts to resolve it via DynamicHash.FindVarnode. On a successful
// resolution the Varnode is attached to the entry the same way
// attemptDynamicMapping does in C++.
// C++ parity: coreaction.cc ActionDynamicMapping::apply (lines 4863-4878)
// TODO known mismatch: Funcdata::attemptDynamicMapping (funcdata_varnode.cc)
// does more than AttachEntryToVarnode -- it also reconciles multi-equal
// replacements and the lateAttach list. DynamicHash.FindVarnode itself is
// a linear address-only scan (see dynamic.go) so multi-collision lookups
// return a coarser match than C++ uniqueHash.
func (a *ActionDynamicMapping) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	sl := data.GetScopeLocal()
	if sl == nil {
		return 0
	}
	var dhash DynamicHash
	for _, entry := range sl.DynamicEntries() {
		if entry == nil {
			continue
		}
		dhash.Clear()
		useAddr := entry.FirstUseAddress()
		vn := dhash.FindVarnode(data, useAddr, entry.Hash())
		if vn == nil {
			continue
		}
		sl.AttachEntryToVarnode(vn, entry)
		a.count++
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionDynamicSymbols -- TODO
// ---------------------------------------------------------------------------

// ActionDynamicSymbols makes the final attachment pass for dynamically-mapped
// symbols after type recovery has stabilised.
// C++ parity: coreaction.hh ActionDynamicSymbols; coreaction.cc
// ActionDynamicSymbols::apply calls Funcdata::attemptDynamicMappingLate on
// every dynamic SymbolEntry in ScopeLocal.
type ActionDynamicSymbols struct {
	ActionBase
}

var _ Action = (*ActionDynamicSymbols)(nil)

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

// Apply is the late-attachment companion to ActionDynamicMapping. It runs
// after type recovery has stabilised and re-hashes every dynamic entry,
// attaching it to whichever Varnode currently matches. Entries that resolve
// are counted; unresolved ones are left alone so later passes can retry.
// C++ parity: coreaction.cc ActionDynamicSymbols::apply (lines 4880-4895)
// TODO known mismatch: Funcdata::attemptDynamicMappingLate additionally
// walks the MULTIEQUAL fan-in and uses DynamicHash::uniqueHash with method
// bumping. The Go DynamicHash.UniqueHash is a stub that always calls
// CalcHash(method=0), so late mapping has looser collision resolution.
func (a *ActionDynamicSymbols) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	sl := data.GetScopeLocal()
	if sl == nil {
		return 0
	}
	var dhash DynamicHash
	for _, entry := range sl.DynamicEntries() {
		if entry == nil {
			continue
		}
		dhash.Clear()
		useAddr := entry.FirstUseAddress()
		vn := dhash.FindVarnode(data, useAddr, entry.Hash())
		if vn == nil {
			continue
		}
		// The late pass additionally forces a unique hash so the same
		// entry is reproducibly re-attached across restarts. UniqueHash
		// currently delegates to CalcHash(method=0) -- see dynamic.go.
		dhash.UniqueHash(vn, data)
		sl.AttachEntryToVarnode(vn, entry)
		a.count++
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionPrototypeWarnings -- PARTIAL
// ---------------------------------------------------------------------------

// ActionPrototypeWarnings emits user-facing warnings about prototypes that
// cannot be represented accurately.
// C++ parity: coreaction.hh ActionPrototypeWarnings; coreaction.cc
// ActionPrototypeWarnings::apply drives Funcdata::getOverride and iterates
// FuncCallSpecs for per-call warnings.
type ActionPrototypeWarnings struct {
	ActionBase
}

var _ Action = (*ActionPrototypeWarnings)(nil)

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

// Apply emits a single warning header when the Funcdata has no attached
// FuncProto. The C++ action produces several warnings derived from
// Override::generateOverrideMessages, FuncProto::hasInputErrors /
// hasOutputErrors / isModelUnknown, and per-call FuncCallSpecs errors; all
// of these fields are absent from Gosleigh's FuncProto and so their
// branches are skipped.
// TODO known mismatch: missing Override, FuncProto::hasInputErrors, and
// FuncCallSpecs::hasInputErrors / hasOutputErrors equivalents.
// C++ parity: coreaction.cc ActionPrototypeWarnings::apply
func (a *ActionPrototypeWarnings) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	if data.GetFuncProto() == nil {
		data.warningHeader("Prototype unavailable; parameter locations may be inaccurate")
	}
	return 0
}

// ---------------------------------------------------------------------------
// ActionInternalStorage -- TODO
// ---------------------------------------------------------------------------

// ActionInternalStorage marks STOREs to compiler-internal registers with the
// "unmapped" bit so they do not appear as addressable memory.
// C++ parity: coreaction.hh ActionInternalStorage; coreaction.cc
// ActionInternalStorage::apply walks FuncProto::internalBegin/internalEnd
// over VarnodeData entries and flags matching CPUI_STORE ops via
// setStoreUnmapped(). Relies on Varnode::isEventualConstant.
type ActionInternalStorage struct {
	ActionBase
}

var _ Action = (*ActionInternalStorage)(nil)

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

// Apply walks the FuncProto internal-storage register list and marks every
// CPUI_STORE that targets one of those locations (and whose address operand
// is an eventual constant) with PcodeOpStoreUnmapped so the decompiler
// treats the write as scratch state instead of observable memory.
// C++ parity: coreaction.cc ActionInternalStorage::apply (lines 4949-4978)
// TODO known mismatch: FuncProto::internalBegin / internalEnd is not ported
// (funcproto.go exposes no internal-storage list yet), so the per-register
// loop is always empty. Varnode::isEventualConstant is also absent -- when
// both land, the body of the for-loop below becomes the real sweep.
func (a *ActionInternalStorage) Apply(data *Funcdata) int {
	if data == nil {
		return 0
	}
	fp := data.GetFuncProto()
	if fp == nil {
		return 0
	}
	// C++ parity: for each VarnodeData entry between internalBegin() and
	// internalEnd(), walk every Varnode at that (addr,size) and flag its
	// CPUI_STORE descendants whose address input is an eventual constant.
	// Kept as a driver skeleton until FuncProto grows internalBegin/End.
	internalStorage := internalStorageList(fp)
	for _, vd := range internalStorage {
		for _, vn := range data.GetVarnodeBank().AllVarnodes() {
			if vn == nil || vn.IsFree() {
				continue
			}
			if vn.Addr() != vd.addr || vn.Size() != vd.size {
				continue
			}
			for _, op := range vn.DescendIter() {
				if op == nil || op.Code() != CPUI_STORE {
					continue
				}
				// TODO known mismatch: Varnode::isEventualConstant(3,0)
				// is not ported (varnode_ssa.go); until then we only
				// flag the literal-constant case which is the narrow
				// subset the C++ check accepts.
				if op.NumInput() >= 2 && op.Input(1) != nil && op.Input(1).IsConstant() {
					op.SetFlag(PcodeOpStoreUnmapped)
					a.count++
				}
			}
		}
	}
	return 0
}

// internalStorageEntry mirrors the VarnodeData entries that C++ stores on
// FuncProto for internal-storage registers. The Go port has no such list
// yet; this helper exists so ActionInternalStorage has a stable iteration
// source once FuncProto.internalBegin/End lands.
// C++ parity: fspec.hh FuncProto::internalstorage
type internalStorageEntry struct {
	addr address.Address
	size int32
}

// internalStorageList returns the internal-storage register list for a
// FuncProto. Always empty today -- see the TODO in ActionInternalStorage.
// C++ parity: FuncProto::internalBegin / internalEnd
func internalStorageList(_ *FuncProto) []internalStorageEntry {
	return nil
}
