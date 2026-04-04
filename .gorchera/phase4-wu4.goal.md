# Phase 4 WU4: Pointer and Memory Rules -- Batch B

## Goal
Implement pointer arithmetic recovery and memory access rules for the Gosleigh decompiler.

## Context
- WU1 (Action/Rule framework) and WU2 (Type system) must be complete
- C++ reference: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh/cc
- Key C++ class: AddTreeState (pointer arithmetic tree walker)
- These rules transform raw INT_ADD+INT_MULT into PTRADD/PTRSUB for struct/array access
- IMPORTANT: Read CLAUDE.md and docs/DECOMPILER_PIPELINE_ROADMAP.md first

## Deliverables
1. pkg/pcode/addtreestate.go -- AddTreeState pointer arithmetic tree walker
2. pkg/pcode/rules_pointer.go -- Pointer rules: RulePtrArith, RulePushPtr, RulePtrFlow, RulePtrsubUndo, etc.
3. pkg/pcode/rules_loadstore.go -- Load/store rules: RuleLoadVarnode, RuleStoreVarnode, etc.
4. Tests for each file
5. All rules registered

## Constraints
- AddTreeState must walk INT_ADD expressions and classify pointer arithmetic
- Rules need TypeFactory (WU2) for pointer type construction
- C++ parity in AddTreeState classification logic

## Done Criteria
- AddTreeState can walk a pointer expression tree and classify offsets
- At least 20 pointer/memory rules implemented
- go test ./... passes with zero failures
