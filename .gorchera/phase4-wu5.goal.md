# Phase 4 WU5: Remaining Rules -- Batch C (Division/Float/Misc)

## Goal
Implement the remaining ~55 transformation rules for the Gosleigh decompiler.

## Context
- WU1 (Action/Rule) and WU2 (Type system) must be complete
- C++ reference: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh/cc
- These rules handle less common but important patterns
- IMPORTANT: Read CLAUDE.md and docs/DECOMPILER_PIPELINE_ROADMAP.md first

## Deliverables
1. pkg/pcode/rules_divmod.go -- Division/modulo strength reduction: RuleDivOpt, RuleSignDiv2, RuleModOpt, etc.
2. pkg/pcode/rules_float.go -- Float-specific rules: RuleFloatRange, RuleNegateNegate, etc.
3. pkg/pcode/rules_misc.go -- Switch, cpool, segment, humpty/dumpty concat, etc.
4. Tests for each file
5. All rules registered

## Constraints
- Division idiom recognition must match C++ exactly (compiler-specific patterns)
- Float rules need proper NaN/infinity handling
- C++ parity priority

## Done Criteria
- At least 45 remaining rules implemented
- Division idiom detection works for common compilers (MSVC, GCC, clang patterns)
- go test ./... passes with zero failures
