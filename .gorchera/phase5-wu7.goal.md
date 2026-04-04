# Phase 5 WU7: PrintC (C Code Emitter)

## Goal
Implement the C code output printer that converts structured SSA IR into readable C source code.

## Context
- ALL previous WUs (1-6) must be complete
- C++ reference: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/printc.hh/cc
- Also: ghidra-ref/.../printlanguage.hh/cc (base class)
- This is the final phase -- output is human-readable C code
- IMPORTANT: Read CLAUDE.md and docs/DECOMPILER_PIPELINE_ROADMAP.md first

## Deliverables
1. pkg/pcode/printlanguage.go -- PrintLanguage base interface (emit tokens, indentation, newlines)
2. pkg/pcode/printc.go -- PrintC: ~50 opcode emit handlers, ~11 block emit methods
3. pkg/pcode/printc_decl.go -- Type declarations, variable declarations, function signatures
4. pkg/pcode/printc_test.go -- Tests with expected C output strings
5. pkg/pcode/emitter.go -- Token emitter interface (for output formatting)

## Constraints
- Each CPUI_* opcode needs a corresponding emit method
- Each block type (BlockIf, BlockWhile, BlockSwitch, etc.) needs an emit method
- Operator precedence must be handled correctly (parentheses)
- C type declarations must be syntactically valid
- Output should be close to what Ghidra produces (C++ parity)

## Done Criteria
- Simple function (assignments, arithmetic) produces valid C output
- if/else produces correct C syntax
- while/do-while produces correct C syntax
- switch/case produces correct C syntax
- Function prototype and variable declarations are printed
- go test ./... passes with zero failures
- A small end-to-end test: raw p-code -> SSA -> rules -> structure -> PrintC -> C string
