# Phase 4 WU1: Action/Rule Framework

## Goal
Implement the Action/Rule execution framework for the Gosleigh decompiler (Ghidra C++ to Go port).

## Context
- Gosleigh is at Phase 3 complete (SSA IR: PcodeOp, Varnode, FlowBlock, Heritage)
- Phase 4 builds the decompilation pipeline on top of the SSA graph
- WU1 is the execution engine that all transformation rules run through
- C++ reference: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/action.hh/cc
- Existing Go types are in pkg/pcode/ (PcodeOp, Varnode, Funcdata, etc.)
- IMPORTANT: Read CLAUDE.md and docs/DECOMPILER_PIPELINE_ROADMAP.md first

## Deliverables
1. pkg/pcode/action.go -- Action base interface, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase
2. pkg/pcode/rule.go -- Rule base interface with opcode dispatch
3. pkg/pcode/action_test.go -- Tests for action framework
4. All existing 142 tests must still pass
5. go build ./... must succeed

## Constraints
- C++ parity is the top priority
- Indent with tabs (Go standard)
- No non-ASCII characters in code (cp949 compat)
- Comments in English
- Do not modify ghidra-ref/ (read-only reference)

## Done Criteria
- Action/ActionGroup/ActionPool/Rule types compile and have tests
- A simple mock Rule can be registered and fired through ActionPool
- go test ./... passes with zero failures
