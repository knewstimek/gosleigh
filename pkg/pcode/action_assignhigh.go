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

// ActionAssignHigh assigns initial HighVariable objects, then performs the
// first speculative merge passes used by the C++ decompiler.
// C++ parity: coreaction.hh ActionAssignHigh, merge.cc Merge::mergeByDatatype,
// Merge::mergeAdjacent
type ActionAssignHigh struct {
	ActionBase
}

var _ Action = (*ActionAssignHigh)(nil)

func NewActionAssignHigh(group string) *ActionAssignHigh {
	act := &ActionAssignHigh{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "assignhigh", group)
	return act
}

func (a *ActionAssignHigh) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionAssignHigh(a.GetGroup())
}

func ensureHighForVarnode(vn *Varnode) *HighVariable {
	if vn == nil {
		return nil
	}
	if high := vn.High(); high != nil {
		return high
	}
	high := NewHighVariable("")
	high.AddInstance(vn)
	return high
}

func assignInitialHighVariables(data *Funcdata) {
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsFree() || vn.IsConstant() || vn.IsAnnotation() {
			continue
		}
		high := ensureHighForVarnode(vn)
		if high != nil && high.Type() == nil {
			high.SetType(vn.Type())
		}
	}
	data.SetFlag(FuncHighLevelOn)
	data.highLevelIndex = data.GetVarnodeBank().createIndex
}

func (a *ActionAssignHigh) Apply(data *Funcdata) int {
	// C++ parity: ActionAssignHigh::apply calls Funcdata::setHighLevel() only.
	// No merging here -- that belongs to ActionMergeRequired/ActionMergeAdjacent/ActionMergeType.
	assignInitialHighVariables(data)
	return 0
}
