# E5: Struct/Pointer/Array Type Recovery

## Objective

Enable pointer arithmetic to produce array subscript syntax (`base[i]`) in PrintC output.
The foundation already exists (Pointer/Array/Struct types in datatype.go, renderPtrAdd in
printc.go, RulePtrArith in rules_pointer.go) but the pipeline gate `FuncTypeRecoveryOn`
is never set, so pointer rules never run.

Current output (pointer offset access):
```c
*(param_0 + 4)
```

Target output after E5:
```c
param_0[1]   // PTRADD subscript syntax
```

## Root cause of previous failures (CRITICAL -- read this before implementing)

Previous attempts failed because:

1. **RETURN(EIP) not RETURN(EAX)**: x86 Sleigh RET semantics emit `RETURN(EIP)`, not
   `RETURN(EAX)`. EIP = register space offset 0x284; EAX = register space offset 0x0.
   ActionDeadCode eliminates any op chain whose output has no consumers. Since RETURN
   only references EIP, any computation that writes only to EAX (loads, arithmetic) is
   dead and gets eliminated. The struct access chain (MOV EAX,[EBP+8]; ADD EAX,4) is
   completely eliminated unless it flows into a STORE instruction.

2. **Test binaries had no STORE**: The original E5 test binaries only LOAD from a pointer
   offset and put the result in EAX, then RET. After ActionDeadCode, all those ops are
   eliminated. ActionTypeRecover Phase 1 finds zero INT_ADD ops feeding LOAD/STORE,
   returns 0, and nothing happens. RulePtrArith never fires.

3. **Fix**: Test binaries MUST include a STORE instruction to keep the computation chain
   alive through DeadCode. `MOV [EAX],0` (C7 00 00 00 00 00) after `ADD EAX,4` keeps
   the entire chain alive because STORE has side effects and is never eliminated.

4. **Verified working**: This binary was confirmed to produce `param_0[1]` subscript:
   `{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x83, 0xC0, 0x04, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3}`
   = PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; ADD EAX,4; MOV [EAX],0; POP EBP; RET
   ActionTypeRecover seeds EAX as *Pointer(unknown,4). BatchA sees INT_ADD(EAX,4)
   feeding STORE -- seeds type, converts to PTRADD(EAX,1,4). PrintC renders param_0[1].

## What is already implemented (DO NOT re-implement):

- pkg/pcode/datatype.go: Pointer, Array, Struct types, TypeField, FieldAt(), NewPointer()
- pkg/pcode/printc.go: renderPtrAdd (already handles PTRADD with TYPE_PTR check)
- pkg/pcode/printc.go: renderPtrSub -> renderPtrSubField (already emits field access)
- pkg/pcode/rules_pointer.go: RulePtrArith (INT_ADD -> PTRADD/PTRSUB conversion) -- gated by HasTypeRecoveryStarted()
- pkg/pcode/addtreestate.go: AddTreeState, evaluatePointerExpression, ptrInputSlot
- pkg/pcode/funcdata.go: FuncTypeRecoveryOn flag, HasTypeRecoveryStarted(), SetFlag()
- pkg/pcode/typefactory.go: TypeFactory, GetPointer(), GetStruct(), sharedTypeFactory
- pkg/pcode/varnode.go: SetVarnodeType(), TypeReadFacing()
- pkg/pcode/action_deadcode.go: ActionDeadCode (eliminates dead ops post-Heritage)
- pkg/pcode/action_batchA.go: BatchAActionPool (runs RulePtrArith when type recovery on)

## Part 1: ActionTypeRecover (new file)

### pkg/pcode/action_typerecover.go

Create this file. It performs two-phase type seeding and propagation:

```go
// Copyright 2026 The Gosleigh Authors.
// Licensed under the Apache License, Version 2.0.

package pcode

// ActionTypeRecover is a single-pass type propagation action.
// It seeds *Pointer types onto INT_ADD inputs feeding LOAD/STORE (Phase 1),
// then propagates types through PTRADD/PTRSUB/COPY/LOAD ops (Phase 2).
//
// Must be called BEFORE BatchA (Phase 1 seeds types for RulePtrArith to consume)
// and AGAIN AFTER BatchA (Phase 2 propagates through new PTRADD/PTRSUB ops).
//
// C++ parity: simplified ActionInferTypes from action.hh
type ActionTypeRecover struct {
	ActionBase
}

func NewActionTypeRecover(group string) *ActionTypeRecover {
	a := &ActionTypeRecover{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "typerecover", group)
	return a
}

func (a *ActionTypeRecover) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionTypeRecover(a.GetGroup())
}

// Apply performs two-phase type seeding and propagation.
//
// Sets FuncTypeRecoveryOn unconditionally (required by RulePtrArith gate).
//
// Phase 1: for each alive INT_ADD op whose output feeds a LOAD/STORE address slot,
// seed a *Pointer type on the non-constant, non-spacebase input that lacks a type.
// Constant offsets: seed *Pointer to a Struct with one field at that offset.
// Variable index: seed *Pointer to TYPE_UNKNOWN element.
//
// Phase 2 (up to 10 iterations until stable):
//   - PTRADD input[0]: seed *Pointer if missing, propagate to output.
//   - PTRSUB input[0]: seed *Pointer if missing, propagate field pointer to output.
//   - COPY: propagate *Pointer/*Struct/*Array from input to output.
//   - LOAD: if address has *Pointer type, set output = Pointee().
//
// Returns 1 if any type was assigned; 0 otherwise.
func (a *ActionTypeRecover) Apply(data *Funcdata) int {
	data.SetFlag(FuncTypeRecoveryOn)

	// Phase 1: seed *Pointer on INT_ADD inputs that feed LOAD/STORE addresses.
	// SpaceBase varnodes (e.g. EBP as frame pointer) are excluded because they
	// represent stack-relative addresses, not heap/segment pointers.
	seedCount := 0
	for _, op := range data.allOpsOrdered() {
		if op.IsDead() || op.Code() != CPUI_INT_ADD || op.NumInput() < 2 {
			continue
		}
		out := op.Output()
		if out == nil {
			continue
		}

		// Only seed when this INT_ADD's output is consumed as a LOAD/STORE address.
		feedsLoadStore := false
		for _, desc := range out.DescendIter() {
			code := desc.Code()
			if (code == CPUI_LOAD || code == CPUI_STORE) && desc.NumInput() > 1 && desc.Input(1) == out {
				feedsLoadStore = true
				break
			}
		}
		if !feedsLoadStore {
			continue
		}

		in0, in1 := op.Input(0), op.Input(1)
		if in0 == nil || in1 == nil {
			continue
		}

		// Determine which input is the base and which is the offset/index.
		// Struct-like: constant offset + non-constant non-spacebase base.
		// Array-like: variable index -- seed whichever non-spacebase input lacks a type.
		if in1.IsConstant() && !in0.IsConstant() && !in0.IsSpaceBase() && in0.Type() == nil {
			offset := int32(in1.Offset())
			if offset > 0 {
				elemSize := int32(4)
				for _, desc := range out.DescendIter() {
					if desc.Code() == CPUI_LOAD && desc.Output() != nil {
						elemSize = desc.Output().Size()
						break
					}
				}
				fieldType := sharedTypeFactory.GetBase(elemSize, TYPE_UNKNOWN, "unknown")
				structType := sharedTypeFactory.GetStruct("struct_"+typerecoverUitoa(uint64(offset)), []TypeField{
					{Offset: offset, Name: "field_" + typerecoverUitoa(uint64(offset)), Type: fieldType},
				})
				SetVarnodeType(in0, NewPointer(in0.Size(), structType, 0))
				seedCount++
			}
		} else if in0.IsConstant() && !in1.IsConstant() && !in1.IsSpaceBase() && in1.Type() == nil {
			offset := int32(in0.Offset())
			if offset > 0 {
				elemSize := int32(4)
				for _, desc := range out.DescendIter() {
					if desc.Code() == CPUI_LOAD && desc.Output() != nil {
						elemSize = desc.Output().Size()
						break
					}
				}
				fieldType := sharedTypeFactory.GetBase(elemSize, TYPE_UNKNOWN, "unknown")
				structType := sharedTypeFactory.GetStruct("struct_"+typerecoverUitoa(uint64(offset)), []TypeField{
					{Offset: offset, Name: "field_" + typerecoverUitoa(uint64(offset)), Type: fieldType},
				})
				SetVarnodeType(in1, NewPointer(in1.Size(), structType, 0))
				seedCount++
			}
		} else {
			// Variable index: seed the non-spacebase, non-constant, untyped input.
			for i := 0; i < 2; i++ {
				vn := op.Input(i)
				if vn != nil && !vn.IsConstant() && !vn.IsSpaceBase() && vn.Type() == nil {
					unknown := sharedTypeFactory.GetBase(4, TYPE_UNKNOWN, "unknown")
					SetVarnodeType(vn, NewPointer(vn.Size(), unknown, 0))
					seedCount++
					break
				}
			}
		}
	}

	// Phase 2: fixed-point propagation through PTRADD/PTRSUB/COPY/LOAD.
	total := seedCount
	for iter := 0; iter < 10; iter++ {
		changed := 0
		for _, op := range data.allOpsOrdered() {
			if op.IsDead() {
				continue
			}
			out := op.Output()

			switch op.Code() {
			case CPUI_PTRADD:
				if op.NumInput() < 1 {
					continue
				}
				base := op.Input(0)
				if base == nil {
					continue
				}
				if base.Type() == nil {
					elemSize := int32(4)
					if op.NumInput() > 2 {
						if scaleVn := op.Input(2); scaleVn != nil && scaleVn.IsConstant() {
							elemSize = int32(scaleVn.Offset())
							if elemSize <= 0 {
								elemSize = 1
							}
						}
					}
					elemType := sharedTypeFactory.GetBase(elemSize, TYPE_UNKNOWN, "unknown")
					SetVarnodeType(base, NewPointer(base.Size(), elemType, 0))
					changed++
				}
				if out != nil && out.Type() == nil {
					if pt, ok := base.Type().(*Pointer); ok {
						SetVarnodeType(out, pt)
						changed++
					}
				}

			case CPUI_PTRSUB:
				if op.NumInput() < 2 {
					continue
				}
				base := op.Input(0)
				offVn := op.Input(1)
				if base == nil || offVn == nil || !offVn.IsConstant() {
					continue
				}
				if base.Type() == nil {
					unknown := sharedTypeFactory.GetBase(base.Size(), TYPE_UNKNOWN, "unknown")
					SetVarnodeType(base, NewPointer(base.Size(), unknown, 0))
					changed++
				}
				if out != nil && out.Type() == nil {
					if ptrType, ok := base.Type().(*Pointer); ok {
						if structType, ok := ptrType.Pointee().(*Struct); ok {
							if field, ok := structType.FieldAt(int32(offVn.Offset())); ok && field.Type != nil {
								fieldPtr := NewPointer(out.Size(), field.Type, ptrType.WordSize())
								SetVarnodeType(out, fieldPtr)
								changed++
							}
						}
					}
				}

			case CPUI_COPY:
				if op.NumInput() < 1 || out == nil || out.Type() != nil {
					continue
				}
				src := op.Input(0)
				if src == nil {
					continue
				}
				srcType := src.Type()
				if srcType == nil {
					continue
				}
				switch srcType.(type) {
				case *Pointer, *Struct, *Array:
					SetVarnodeType(out, srcType)
					changed++
				}

			case CPUI_LOAD:
				if op.NumInput() < 2 || out == nil || out.Type() != nil {
					continue
				}
				addrVn := op.Input(1)
				if addrVn == nil {
					continue
				}
				pt, ok := addrVn.Type().(*Pointer)
				if !ok {
					continue
				}
				pointee := pt.Pointee()
				if pointee == nil {
					continue
				}
				SetVarnodeType(out, pointee)
				changed++
			}
		}
		total += changed
		if changed == 0 {
			break
		}
	}

	if total > 0 {
		return 1
	}
	return 0
}

// typerecoverUitoa converts a uint64 to its decimal string representation.
func typerecoverUitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf) - 1
	for v > 0 {
		buf[i] = byte('0' + v%10)
		v /= 10
		i--
	}
	return string(buf[i+1:])
}
```

Note: `sharedTypeFactory` is the global `*TypeFactory` already declared in typefactory.go.
`SetVarnodeType`, `NewPointer`, `TYPE_UNKNOWN` are all already in the pcode package.
Do NOT re-declare `sharedTypeFactory` -- it already exists.

## Part 2: Tests (pkg/loader/loader_test.go)

Add these two test functions. CRITICAL: binaries MUST include a STORE instruction.

### TestE5StructPointerAccess

Models `void store_via_offset(int *p) { *(p+1) = 0; }`:
- PUSH EBP; MOV EBP,ESP
- MOV EAX,[EBP+8]   -- load p (param)
- ADD EAX,4         -- p+4 offset (= p[1] for int32*)
- MOV [EAX],0       -- STORE 0 at p+4 (keeps chain alive through DeadCode!)
- POP EBP; RET

Binary: `{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x83, 0xC0, 0x04, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3}`

Pipeline (in test, after bridge.Build and heritage.Heritage):
```go
pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
pcode.NewActionDeadCode("analysis").Apply(result.Funcdata)
// Phase 1: seed *Pointer types on INT_ADD inputs feeding LOAD/STORE
pcode.NewActionTypeRecover("analysis").Apply(result.Funcdata)
// BatchA: RulePtrArith converts INT_ADD(ptr,4) -> PTRADD(ptr,1,4)
pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
// Phase 2: propagate types through new PTRADD/PTRSUB ops
pcode.NewActionTypeRecover("analysis").Apply(result.Funcdata)
pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)
// ... ApplyCallingConvention, PrintC as usual
```

Assertions:
```go
// subscript syntax: PTRADD should render as base[index]
if !strings.Contains(output, "[") {
    t.Errorf("expected subscript syntax '[' in output, got:\n%s", output)
}
// param naming still works
if !strings.Contains(output, "param") {
    t.Errorf("expected 'param' in output, got:\n%s", output)
}
```

### TestE5ArrayIndexAccess

Models `void store_arr_elem(int *arr, int i) { arr[i] = 0; }`:
- PUSH EBP; MOV EBP,ESP
- MOV EAX,[EBP+8]    -- arr
- MOV ECX,[EBP+12]   -- i
- MOV [EAX+ECX*4],0  -- arr[i] = 0 (STORE; keeps chain alive!)
- POP EBP; RET

Binary: `{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0x0C, 0xC7, 0x04, 0x88, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3}`

Same pipeline as above.

Assertions:
```go
// pipeline runs to completion without panic
if output == "" {
    t.Errorf("expected non-empty output")
}
// two params should be named
if !strings.Contains(output, "param_0") {
    t.Errorf("expected param_0 in output, got:\n%s", output)
}
if !strings.Contains(output, "param_1") {
    t.Errorf("expected param_1 in output, got:\n%s", output)
}
```

The SLA/pspec paths for both tests use the x86-32 paths (same as existing tests):
- slaPath: `filepath.Join(dir, "../sla/testdata/x86-packed.sla")`
- pspecPath: `filepath.Join(dir, "../../testdata/sla/x86.pspec")`
- cspecPath: `filepath.Join(dir, "../../testdata/sla/x86.cspec")`

Look at existing tests (e.g. TestX86DeadCodeElimination around line 1430 of loader_test.go)
for the exact path and pipeline pattern to follow.

## Part 3: Unit test pkg/pcode/funcdata_typerecover_test.go (new file)

```go
package pcode

import (
	"testing"
)

func TestE5TypeRecoveryFlagBehavior(t *testing.T) {
	// Verify HasTypeRecoveryStarted() honors FuncTypeRecoveryOn.
	fd := newMinimalFuncdata()
	if fd.HasTypeRecoveryStarted() {
		t.Fatal("expected false before SetFlag")
	}
	fd.SetFlag(FuncTypeRecoveryOn)
	if !fd.HasTypeRecoveryStarted() {
		t.Fatal("expected true after SetFlag")
	}
}

func TestE5ActionTypeRecoverApply(t *testing.T) {
	// Verify ActionTypeRecover.Apply sets FuncTypeRecoveryOn.
	fd := newMinimalFuncdata()
	a := NewActionTypeRecover("test")
	a.Apply(fd)
	if !fd.HasTypeRecoveryStarted() {
		t.Fatal("expected FuncTypeRecoveryOn to be set by Apply")
	}
}
```

`newMinimalFuncdata()` -- look for an existing helper in the pcode test files; if none,
create one that calls NewFuncdata with minimal valid arguments (e.g. dummy spaces).
Check existing test helpers in pcode package before implementing one from scratch.

## Part 4: Docs

### docs/STATUS.md

Add E5 entry under E-phase section:

```
## E5: Struct/Pointer/Array Type Recovery [DONE 2026-04-XX]
- ActionTypeRecover: two-phase type seeding and propagation
- RulePtrArith now runs when FuncTypeRecoveryOn is set (was always-gated before)
- INT_ADD(ptr, const) -> PTRADD -> subscript syntax in PrintC
- Test: TestE5StructPointerAccess, TestE5ArrayIndexAccess
```

### docs/E_PHASE_ROADMAP.md

Mark E5 as done: change `## E5: Type System` line to include `[DONE 2026-04-XX]`.

## In-scope

1. pkg/pcode/action_typerecover.go (new file)
2. pkg/loader/loader_test.go: add TestE5StructPointerAccess, TestE5ArrayIndexAccess
3. pkg/pcode/funcdata_typerecover_test.go (new file)
4. docs/STATUS.md: add E5 entry
5. docs/E_PHASE_ROADMAP.md: mark E5 done

## Out-of-scope

- Automatic struct definition recovery from unknown pointer accesses
- DWARF struct type import
- "->": arrow operator for named struct fields (requires type injection not in scope)
- TypePointer::downChain full port
- Bridge.go changes (pipeline is assembled in tests, not in Bridge)

## Invariants

- All existing tests pass (go test ./... green)
- Setting FuncTypeRecoveryOn does NOT break existing E2E tests (flag is additive)
- No new external dependencies
- ASCII-only identifiers and comments; tabs for indentation (Go standard)

## Done when

- go test ./... passes green (all existing tests + new E5 tests)
- TestE5StructPointerAccess: output contains "[" (subscript syntax)
- TestE5ArrayIndexAccess: output contains "param_0" and "param_1"
- TestE5TypeRecoveryFlagBehavior and TestE5ActionTypeRecoverApply compile and pass
- docs/STATUS.md has E5 entry
- docs/E_PHASE_ROADMAP.md marks E5 done
