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

// ActionMergeCopy tries to merge COPY inputs and outputs when doing so does not
// violate cover or datatype constraints.
// C++ parity: coreaction.hh ActionMergeCopy, merge.cc Merge::mergeOpcode
type ActionMergeCopy struct {
	ActionBase
}

var _ Action = (*ActionMergeCopy)(nil)

func NewActionMergeCopy(group string) *ActionMergeCopy {
	act := &ActionMergeCopy{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "mergecopy", group)
	return act
}

func (a *ActionMergeCopy) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMergeCopy(a.GetGroup())
}

func (a *ActionMergeCopy) Apply(data *Funcdata) int {
	merge := NewMerge(data)
	merge.mergeOpcode(CPUI_COPY)
	return 0
}

// ActionMergeRequired performs the non-speculative merge phase driven by
// MULTIEQUAL and INDIRECT markers.
// C++ parity: coreaction.hh ActionMergeRequired, merge.cc Merge::mergeMarker
type ActionMergeRequired struct {
	ActionBase
}

var _ Action = (*ActionMergeRequired)(nil)

func NewActionMergeRequired(group string) *ActionMergeRequired {
	act := &ActionMergeRequired{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "mergerequired", group)
	return act
}

func (a *ActionMergeRequired) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMergeRequired(a.GetGroup())
}

func (a *ActionMergeRequired) Apply(data *Funcdata) int {
	// C++ parity: ActionMergeRequired::apply calls mergeAddrTied + groupPartials + mergeMarker.
	// mergeAddrTied and groupPartials are known mismatch stubs (not yet ported).
	merge := NewMerge(data)
	merge.mergeRequired()
	return 0
}
