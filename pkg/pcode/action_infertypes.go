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

// ActionInferTypes is a data-flow type propagation pass.
// It seeds provisional types (tempType) from HighVariable annotations and
// function prototype information, then propagates them through the SSA graph
// using per-opcode TypeOp.PropagateType rules.  After each sweep it commits
// any provisional type that is more specific than what is already recorded,
// and iterates until convergence (or max 7 rounds).
//
// C++ parity: coreaction.cc ActionInferTypes (simplified E5 subset)
type ActionInferTypes struct {
	ActionBase
}

// NewActionInferTypes creates an ActionInferTypes in the given group.
func NewActionInferTypes(group string) *ActionInferTypes {
	a := &ActionInferTypes{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "infertypes", group)
	return a
}

// Clone returns a copy of the action if it belongs to one of the requested groups.
func (a *ActionInferTypes) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionInferTypes(a.GetGroup())
}

// Apply runs the iterative type-inference loop (max 7 iterations).
// Returns 1 if any type was committed, 0 otherwise.
func (a *ActionInferTypes) Apply(data *Funcdata) int {
	tf := sharedTypeFactory

	const maxIter = 7
	totalCommitted := 0

	for iter := 0; iter < maxIter; iter++ {
		// Phase 1: seed tempType from HighVariable types and prototype params.
		buildLocalTypes(data, tf)

		// Phase 2: propagate tempType across op edges.
		allVarnodes := data.GetVarnodeBank().AllVarnodes()
		for _, vn := range allVarnodes {
			if vn.GetTempType() != nil {
				propagateOneType(vn, tf)
			}
		}

		// Phase 3: commit any tempType that is more specific than current.
		committed := writeBack(data)
		totalCommitted += committed

		// Clear tempType scratch for next round.
		for _, vn := range allVarnodes {
			vn.ClearTempType()
		}

		if committed == 0 {
			break // converged
		}
	}

	if totalCommitted > 0 {
		return 1
	}
	return 0
}

// buildLocalTypes seeds tempType on each varnode from:
//  1. The committed type of the HighVariable it belongs to.
//  2. FuncProto param types (via HighVariable).
//  3. Constant varnodes: use TYPE_UINT with the constant's size.
//
// C++ parity: TypeRecovery::buildLocaltypes (partial)
func buildLocalTypes(data *Funcdata, tf *TypeFactory) {
	allVarnodes := data.GetVarnodeBank().AllVarnodes()
	for _, vn := range allVarnodes {
		if vn.GetTempType() != nil {
			continue
		}
		// Prefer the committed type first.
		if committed := vn.Type(); committed != nil {
			vn.SetTempType(committed)
			continue
		}
		// Fall back to HighVariable type.
		if hv := vn.High(); hv != nil {
			if hvType := hv.Type(); hvType != nil {
				vn.SetTempType(hvType)
				continue
			}
		}
		// Constant varnodes get a generic uint type.
		if vn.IsConstant() {
			vn.SetTempType(tf.GetBase(vn.Size(), TYPE_UINT, "uint"))
		}
	}
}

// propagateOneType spreads the tempType of vn to neighbouring varnodes
// through each op that reads or defines vn.
//
// C++ parity: TypeRecovery::propagateOneType (simplified)
func propagateOneType(vn *Varnode, tf *TypeFactory) {
	inType := vn.GetTempType()
	if inType == nil {
		return
	}

	// Forward: vn is an input of some ops; propagate to their outputs.
	for _, op := range vn.DescendIter() {
		if op == nil || op.IsDead() {
			continue
		}
		if op.HasStopTypePropagation() {
			continue
		}
		typeOp := op.GetOpcode()
		if typeOp == nil {
			continue
		}
		// Find which slot vn occupies in this op.
		slot := -2
		for i := 0; i < op.NumInput(); i++ {
			if op.Input(i) == vn {
				slot = i
				break
			}
		}
		if slot == -2 {
			continue
		}
		derived := typeOp.PropagateType(op, slot, inType, tf)
		if derived == nil {
			continue
		}
		out := op.Output()
		if out != nil {
			trySetTempType(out, derived)
		}
	}

	// Reverse: vn is the output of its defining op; propagate to sibling inputs.
	def := vn.Def()
	if def == nil || def.IsDead() {
		return
	}
	if def.HasStopTypePropagation() {
		return
	}
	typeOp := def.GetOpcode()
	if typeOp == nil {
		return
	}
	// slot=-1 means "from output"
	derived := typeOp.PropagateType(def, -1, inType, tf)
	if derived == nil {
		return
	}
	// Apply the reverse-derived type to input[1] for LOAD, input[1]/input[2] for
	// STORE.  The generic path just tries input[1] as the primary address slot.
	switch def.Code() {
	case CPUI_LOAD:
		if def.NumInput() > 1 && def.Input(1) != nil {
			trySetTempType(def.Input(1), derived)
		}
	case CPUI_STORE:
		if def.NumInput() > 1 && def.Input(1) != nil {
			trySetTempType(def.Input(1), derived)
		}
	}
}

// trySetTempType sets vn.tempType to dt only when dt is more specific
// (lower metatype value = higher specificity in Ghidra's ordering) than
// the current tempType, or when tempType is nil.
func trySetTempType(vn *Varnode, dt Datatype) {
	if vn == nil || dt == nil {
		return
	}
	cur := vn.GetTempType()
	if cur == nil {
		vn.SetTempType(dt)
		return
	}
	// Lower metatype numeric value = more specific (TYPE_STRUCT=4 < TYPE_UINT=13).
	if dt.Metatype() < cur.Metatype() {
		vn.SetTempType(dt)
	}
}

// writeBack commits tempType to the permanent varnode type when tempType is
// more specific than the currently committed type.
// Returns the number of varnodes updated.
//
// C++ parity: TypeRecovery::writeBack (simplified)
func writeBack(data *Funcdata) int {
	count := 0
	allVarnodes := data.GetVarnodeBank().AllVarnodes()
	for _, vn := range allVarnodes {
		proposed := vn.GetTempType()
		if proposed == nil {
			continue
		}
		current := vn.Type()
		if current == nil {
			// No committed type yet -- commit if proposed is not generic unknown/uint.
			if proposed.Metatype() != TYPE_UNKNOWN {
				SetVarnodeType(vn, proposed)
				// Propagate to HighVariable as well.
				if hv := vn.High(); hv != nil && hv.Type() == nil {
					hv.SetType(proposed)
				}
				count++
			}
			continue
		}
		if proposed.Metatype() < current.Metatype() {
			SetVarnodeType(vn, proposed)
			if hv := vn.High(); hv != nil {
				hv.SetType(proposed)
			}
			count++
		}
	}
	return count
}
