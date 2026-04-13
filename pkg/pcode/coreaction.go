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
