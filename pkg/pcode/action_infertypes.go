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

// seedLoadPointers seeds a pointer type on the address input of each LOAD op.
// When a varnode is used as the LOAD address, it must hold a pointer;
// the pointee type is inferred from the LOAD output size.
// Running this before the main inference loop lets type propagation (TypeOpLoad,
// TypeOpIntAdd, TypeOpMultiequal) cascade int* -> int (LOAD result) -> int (local_8).
// C++ parity: TypeOpLoad::getInputLocal (typeop.cc) -- address varnode seeding.
func seedLoadPointers(data *Funcdata, tf *TypeFactory) {
	for _, op := range data.allOpsOrdered() {
		if op.IsDead() || op.Code() != CPUI_LOAD {
			continue
		}
		if op.Output() == nil || op.NumInput() < 2 || op.Input(1) == nil {
			continue
		}
		addr := op.Input(1)
		cur := addr.Type()
		if cur != nil && cur.Metatype() <= TYPE_PTR {
			continue // already a pointer type or more specific -- don't override
		}
		outSize := op.Output().Size()
		pointee := tf.GetBase(outSize, TYPE_INT, "int")
		ptrType := tf.GetPointerTo(pointee, addr.Size())
		SetVarnodeType(addr, ptrType)
		if hv := addr.High(); hv != nil {
			if hvt := hv.Type(); hvt == nil || hvt.Metatype() > TYPE_PTR {
				hv.SetType(ptrType)
			}
		}
	}
}

// Apply runs the iterative type-inference loop (max 7 iterations).
// Returns 1 if any type was committed, 0 otherwise.
func (a *ActionInferTypes) Apply(data *Funcdata) int {
	tf := sharedTypeFactory

	// Pre-pass: seed LOAD address inputs as pointer types before type propagation.
	// This is needed because BatchA (which converts INT_ADD->PTRADD via RulePtrArith)
	// already ran before ActionInferTypes. Without this pre-seed, param3 stays int
	// and the LOAD address has no pointer type to propagate from.
	seedLoadPointers(data, tf)

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

	// Don't propagate TYPE_UINT forward from constant varnodes. Constants carry
	// a TYPE_UINT assignment as their intrinsic type, but that should not seed
	// the type of variables that merely hold their value. Variable types come
	// from semantic ops (SLESS -> INT, ZEXT -> UINT, pointer deref -> PTR).
	// Skipping the forward direction for constants mirrors the Ghidra behavior
	// where simple loop counters / accumulators remain undefined4 rather than
	// being promoted to "unsigned int" by the constant initialiser.
	// C++ parity: TypeRecovery::propagateOneType -- constants are not pushed
	// as type sources in the forward direction (typeop.cc / coreaction.cc).
	if !vn.IsConstant() {
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
	} // end !vn.IsConstant() guard

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
	case CPUI_COPY:
		// Reverse: output type flows back to input[0].
		// Allows TYPE_INT seeded by ActionSeedSignedOps to reach constant varnodes.
		// C++ parity: TypeOpCopy propagation symmetry (typeop.cc)
		if def.NumInput() > 0 && def.Input(0) != nil {
			trySetTempType(def.Input(0), derived)
		}
	case CPUI_MULTIEQUAL:
		// Reverse: output type flows back to all phi inputs.
		// C++ parity: TypeOpMultiequal propagation (typeop.cc)
		for i := 0; i < def.NumInput(); i++ {
			if def.Input(i) != nil {
				trySetTempType(def.Input(i), derived)
			}
		}
	case CPUI_INT_MULT:
		// Reverse: if output is TYPE_INT, propagate to both multiply inputs.
		// C++ parity: TypeOpIntMult::propagateType passes TYPE_INT bidirectionally.
		// Required for IMUL type inference: EAX(int) -> both IMUL operands(int).
		for i := 0; i < def.NumInput(); i++ {
			if def.Input(i) != nil {
				trySetTempType(def.Input(i), derived)
			}
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
