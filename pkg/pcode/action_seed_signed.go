// Copyright 2026 The Gosleigh Authors.
// Apache 2.0

package pcode

// ActionSeedSignedOps seeds TYPE_INT on inputs of signed arithmetic/comparison opcodes:
//   INT_SLESS, INT_SLESSEQUAL, INT_SRIGHT, INT_SDIV, INT_SREM, INT_SBORROW, INT_SCARRY, INT_2COMP.
//
// After seeding, ActionInferTypes propagates TYPE_INT through COPY/MULTIEQUAL chains to
// reach all varnodes in the same SSA equivalence class, including constant varnodes.
//
// C++ parity: TypeOpIntSless::propagateType input->input edge (typeop.cc ~line 1036).
// In C++, type propagation traverses input<->input edges for signed ops. Go's PropagateType
// only supports input->output and output->input[addr], so we seed TYPE_INT directly here.
type ActionSeedSignedOps struct {
	ActionBase
}

func NewActionSeedSignedOps(group string) *ActionSeedSignedOps {
	a := &ActionSeedSignedOps{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "seedsignedops", group)
	return a
}

func (a *ActionSeedSignedOps) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionSeedSignedOps(a.GetGroup())
}

func (a *ActionSeedSignedOps) Apply(data *Funcdata) int {
	tf := sharedTypeFactory
	count := 0
	for _, op := range data.allOpsOrdered() {
		if op.IsDead() {
			continue
		}
		switch op.Code() {
		case CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
			CPUI_INT_SRIGHT, CPUI_INT_SDIV, CPUI_INT_SREM,
			CPUI_INT_SBORROW, CPUI_INT_SCARRY, CPUI_INT_2COMP:
			for i := 0; i < op.NumInput(); i++ {
				vn := op.Input(i)
				if vn == nil {
					continue
				}
				cur := vn.Type()
				// Only seed if no type is set or current type is less specific than TYPE_INT.
				// TYPE_INT=14, TYPE_UINT=13: do NOT override TYPE_UINT (more specific).
				// TYPE_PTR (9) and below are even more specific; never override.
				if cur != nil && cur.Metatype() <= TYPE_INT {
					continue
				}
				signed := tf.GetExactType(vn.Size(), TYPE_INT)
				if signed == nil {
					continue
				}
				SetVarnodeType(vn, signed)
				if hv := vn.High(); hv != nil {
					if hvt := hv.Type(); hvt == nil || hvt.Metatype() > TYPE_INT {
						hv.SetType(signed)
					}
				}
				count++
			}
		}
	}
	if count > 0 {
		return 1
	}
	return 0
}
