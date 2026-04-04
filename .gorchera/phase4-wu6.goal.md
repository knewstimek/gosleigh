# Phase 4 WU6: Block Structuring

## Goal
Implement control flow structuring that converts flat CFG into nested if/while/do/switch blocks.

## Context
- WU1 (Action/Rule framework) must be complete
- Phase 3 BlockGraph/FlowBlock types are the foundation
- C++ reference: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.hh/cc
- This is what turns goto spaghetti into readable if/while/switch
- IMPORTANT: Read CLAUDE.md and docs/DECOMPILER_PIPELINE_ROADMAP.md first

## Deliverables
1. pkg/pcode/collapse.go -- CollapseStructure: iterative structural pattern matching
2. pkg/pcode/loopbody.go -- LoopBody: loop membership and nesting tracking
3. pkg/pcode/tracedag.go -- TraceDAG: switch-case edge recognition
4. pkg/pcode/block_actions.go -- ActionBlockStructure, ActionNodeJoin, ActionNormalizeBranches, etc.
5. Tests with CFG examples (if-then-else, while loop, do-while, switch, nested)

## Constraints
- CollapseStructure must handle irreducible graphs gracefully (goto fallback)
- Block type hierarchy from Phase 3 (BlockIf, BlockWhile, etc.) must be extended
- out[0] = false branch, out[1] = true branch convention must be maintained
- C++ parity in structuring decisions

## Done Criteria
- Diamond CFG -> BlockIf structured correctly
- Loop CFG -> BlockWhileDo structured correctly
- Switch CFG -> BlockSwitch structured correctly
- Irreducible graphs produce BlockGoto fallbacks instead of crashing
- go test ./... passes with zero failures
