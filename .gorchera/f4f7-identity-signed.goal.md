# Goal: F4 + F7 -- RuleIdentityEl + signed type propagation

## Background

Gosleigh is a Go port of the Ghidra decompiler. The current `TestX86ClassifySignFunction`
test produces output like:

```c
unsigned int classify_sign(...) {
    if (tmp_0 + -0 == 0) {           // F4: INT_ADD(x, 0) is not folded to x
        ...
            EAX = 0xffffffff;        // F7: should be -1 (signed int)
        ...
    }
}
```

Two bugs to fix:
- **F4**: `INT_ADD(x, 0) -> x` identity rule is missing.
- **F7**: Signed type is not propagated to varnode used in INT_SLESS, so 0xffffffff prints as hex instead of -1.

## Reference: C++ originals (read-only, do NOT modify ghidra-ref)

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc`
  `RuleIdentityEl` (~line 3679): handles INT_ADD/INT_XOR/INT_OR/BOOL_XOR/BOOL_OR with zero
  in input[1], and INT_MULT with 1 in input[1]. Collapses to COPY(input[0]).

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/typeop.cc`
  `TypeOpIntSless::propagateType` (~line 1036): propagates TYPE_INT between sibling inputs
  (inslot!=-1 && outslot!=-1) when alttype metatype == TYPE_INT. Same for TypeOpIntSlessEqual.
  `TypeOpIntAdd` constructor (~line 1170): `addlflags = arithmetic_op | inherits_sign`.

- `pkg/pcode/printc.go` `renderConstant` (~line 1082): already handles `TYPE_INT` case with
  `int32(vn.Offset())`. Bug is that varnode never gets TYPE_INT set.

## Current Go code state

Read these files before implementing:

1. `pkg/pcode/rules_copy.go` -- `batchARuleFactories` list and `NewBatchAActionPool`.
   New rules must be appended to `batchARuleFactories`.
2. `pkg/pcode/rules_arith.go` -- `batchRule`, `rewriteToCopy`, `rewriteToConst`,
   `isZeroConst`, `constantValue`, `maskForSize`. Add new rules here.
3. `pkg/pcode/typeop.go` -- TypeOp interface, `typeOpIntCmp`, `RegisterTypeOps`.
   SLESS/SLESSEQUAL currently use plain `typeOpIntCmp`.
4. `pkg/pcode/action_infertypes.go` -- `propagateOneType` reverse path only handles
   LOAD/STORE. COPY reverse path missing -- TYPE_INT cannot flow backward through COPY.
5. `pkg/pcode/datatype.go` -- `TYPE_INT = 14`, `TYPE_UINT = 13` (lower = more specific).

## F4: RuleIdentityEl

### C++ logic (ruleaction.cc ~line 3696)

```
applyOp:
  constvn = op->getIn(1)         // always slot 1
  if (!constvn->isConstant()) return 0
  val = constvn->getOffset()
  if (val == 0 && op->code() != INT_MULT):
    op -> COPY(getIn(0))         // collapse to identity
    return 1
  if (op->code() != INT_MULT) return 0
  if (val == 1): op -> COPY(getIn(0)); return 1
  if (val == 0): op -> COPY(newConst(0)); return 1
```

### Go implementation in `pkg/pcode/rules_arith.go`

```go
// RuleIdentityEl collapses identity-element operations:
//   INT_ADD(x,0)->x, INT_XOR(x,0)->x, INT_OR(x,0)->x,
//   BOOL_XOR(x,0)->x, BOOL_OR(x,0)->x,
//   INT_MULT(x,1)->x, INT_MULT(x,0)->0
// C++ parity: RuleIdentityEl::applyOp (ruleaction.cc ~line 3696)
type RuleIdentityEl struct{ batchRule }

func NewRuleIdentityEl(group string) *RuleIdentityEl {
	opcodes := []OpCode{
		CPUI_INT_ADD, CPUI_INT_XOR, CPUI_INT_OR,
		CPUI_BOOL_XOR, CPUI_BOOL_OR, CPUI_INT_MULT,
	}
	r := &RuleIdentityEl{}
	r.batchRule = newBatchRule(group, "identityel", opcodes, r.apply,
		func(g string) Rule { return NewRuleIdentityEl(g) })
	return r
}

func (r *RuleIdentityEl) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 2 {
		return 0
	}
	constvn := op.Input(1)
	if constvn == nil || !constvn.IsConstant() {
		return 0
	}
	val, _ := constantValue(constvn)
	switch op.Code() {
	case CPUI_INT_ADD, CPUI_INT_XOR, CPUI_INT_OR, CPUI_BOOL_XOR, CPUI_BOOL_OR:
		if val == 0 {
			return rewriteToCopy(data, op, op.Input(0))
		}
	case CPUI_INT_MULT:
		if val == 1 {
			return rewriteToCopy(data, op, op.Input(0))
		}
		if val == 0 {
			return rewriteToConst(data, op, 0)
		}
	}
	return 0
}
```

Register in `pkg/pcode/rules_copy.go` `batchARuleFactories` (append to the end, before the closing brace):
```go
func(group string) Rule { return NewRuleIdentityEl(group) },
```

The test `TestBatchARulesCount` checks `count < 40`. Verify the new count still passes (it just adds 1 more rule).

## F7: Signed type propagation

### Architecture note

Go's `PropagateType(op, slot, inType, tf)` can only express:
- slot >= 0: input[slot] has inType -> return output type
- slot == -1: output has inType -> return input type (applied to addr slot only)

C++ `propagateType` supports input[i] -> input[j] edges (inslot != -1 && outslot != -1).
We bridge this gap with a dedicated action that seeds TYPE_INT directly.

### Step 3a: Add ActionSeedSignedOps (new file `pkg/pcode/action_seed_signed.go`)

```go
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
```

### Step 3b: Fix COPY reverse propagation in `action_infertypes.go`

In `propagateOneType`, the reverse path (slot==-1 from output, passed to typeOp.PropagateType)
currently only routes the result to LOAD and STORE addr inputs. We need it to also route
TYPE_INT backward through COPY and MULTIEQUAL.

Find the switch at the bottom of `propagateOneType` (~line 177) and extend it:

```go
case CPUI_COPY:
    // Reverse: output type flows back to input[0].
    if def.NumInput() > 0 && def.Input(0) != nil {
        trySetTempType(def.Input(0), derived)
    }
case CPUI_MULTIEQUAL:
    // Reverse: output type flows back to all phi inputs.
    for i := 0; i < def.NumInput(); i++ {
        if def.Input(i) != nil {
            trySetTempType(def.Input(i), derived)
        }
    }
```

Also ensure `typeOpCopy.PropagateType` returns `inType` for slot==-1 (it already does -- it
returns `inType` for all slots including -1). So once derived != nil for COPY reverse, the
above case routes it.

### Step 3c: Wire ActionSeedSignedOps into the test

In `TestX86ClassifySignFunction` in `pkg/loader/loader_test.go`, after `ActionConstantFold`
and `ActionDeadCode` but before or after `BatchA`, add:

```go
pcode.NewActionSeedSignedOps("analysis").Apply(result.Funcdata)
pcode.NewActionInferTypes("analysis").Apply(result.Funcdata)
```

The exact position: run SeedSignedOps after BatchA (which may transform ops), then
InferTypes to propagate signed types backward through COPY chains.

Check if `ActionInferTypes` is already called anywhere in the test. If already called,
just add `NewActionSeedSignedOps` before it. If not called, add both.

Current pipeline in test:
```go
pcode.NewActionConstantFold("analysis").Apply(result.Funcdata)
pcode.NewActionDeadCode("analysis").Apply(result.Funcdata)
pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)
```

Add after BatchA:
```go
pcode.NewActionSeedSignedOps("analysis").Apply(result.Funcdata)
pcode.NewActionInferTypes("analysis").Apply(result.Funcdata)
```

### Step 3d: Check TypeFactory.GetExactType

In `pkg/pcode/typefactory.go`, verify `GetExactType(size, TYPE_INT)` exists and works.
If not, use `GetBase(size, TYPE_INT, "int")` or equivalent. Use whatever already exists.

## Step 4: Unit tests

### TestRuleIdentityEl_IntAdd

In `pkg/pcode/rules_arith_test.go` (or new `pkg/pcode/rules_identity_test.go`):

Create a minimal Funcdata with an INT_ADD(x, const(0)) op. Apply RuleIdentityEl.
Verify the op is now CPUI_COPY with input[0] == x.

### TestRuleIdentityEl_IntMult

Create INT_MULT(x, const(1)). Apply. Verify CPUI_COPY with input[0] == x.

### TestSignedConstantPrint

Create a 4-byte constant varnode with value 0xffffffff. Set its type to
`tf.GetBase(4, TYPE_INT, "int")`. Call renderConstant (expose it or test via
printc internal path). Verify result is "-1".

OR: add it to `printc_test.go` if there is an existing test helper that builds
a small Funcdata and calls PrintC.Emit.

### TestActionSeedSignedOps_SetsTypeInt

Create a Funcdata with INT_SLESS(vn_a, vn_b) where vn_a and vn_b have no type.
Run ActionSeedSignedOps. Verify vn_a.Type().Metatype() == TYPE_INT.

## Step 5: Run all tests

```
cd D:\News\Business\Gosleigh
go build ./...
go test ./...
```

All existing tests must continue to pass.

## Verification criteria

1. `go build ./...` -- clean
2. `go test ./...` -- all pass
3. `TestX86ClassifySignFunction` PrintC output:
   - Does NOT contain `+ -0` (INT_ADD(x,0) folded away by RuleIdentityEl)
   - Does NOT contain `0xffffffff` (signed constant prints as -1)
   - Contains `-1` as a literal somewhere
4. At least 2 new unit tests pass (names containing "IdentityEl" and "Signed" or similar)

## Code rules

- Tab indentation, ASCII-only, no emojis in code/comments
- Code comments in English; explain intent and invariants
- C++ parity comment: // C++ parity: ClassName::method (file ~line)
- Apache 2.0 header on every new file
- Do NOT modify anything under ghidra-ref/
- Do NOT change existing test assertions

## Final report

Report:
1. Full TestX86ClassifySignFunction PrintC output after fix
2. Files changed (list)
3. New test names
