# Phase 4 WU3: Core Rules -- Batch A (Arithmetic/Bitwise/Boolean)

## Goal
Implement ~50 core transformation rules for the Gosleigh decompiler fixpoint loop.

## Context
- Phase 3 complete (SSA IR: PcodeOp, Varnode, FlowBlock, Heritage)
- WU1 (Action/Rule framework) must be complete before this starts
- C++ reference: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh/cc
- These are the highest-frequency rules in the decompiler fixpoint loop
- IMPORTANT: Read CLAUDE.md, docs/DECOMPILER_PIPELINE_ROADMAP.md, and WU1's action.go/rule.go first

## Deliverables
1. pkg/pcode/rules_arith.go -- Arithmetic rules: RuleEarlyRemoval, RuleCollapse, RuleIntArithOps, etc.
2. pkg/pcode/rules_bitwise.go -- Bitwise rules: RuleAndMask, RuleOrCollapse, RuleXorCollapse, shifts, etc.
3. pkg/pcode/rules_bool.go -- Boolean/comparison rules: RuleBoolNegate, RuleEquality, RuleLess2Zero, etc.
4. pkg/pcode/rules_ext.go -- Extension/truncation: RuleZextEliminate, RuleSextEliminate, RuleTruncShift, etc.
5. pkg/pcode/rules_copy.go -- Copy propagation: RuleCopyPropagate, RuleMultiCse, etc.
6. Tests for each rule file
7. Rules registered into ActionPool via registration function

## Constraints
- Each Rule must implement the Rule interface from WU1
- getOpcode() returns the CPUI_* constant this rule matches
- applyOp() returns true if the rule made a change
- C++ parity in rule behavior (read the C++ before implementing)
- go test ./... must pass

## Done Criteria
- At least 40 rules implemented and registered
- Each rule has at least one test showing it fires correctly
- ActionPool can iterate rules and find matches by opcode
- go test ./... passes with zero failures
