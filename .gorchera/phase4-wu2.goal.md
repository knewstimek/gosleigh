# Phase 4 WU2: Type System

## Goal
Implement the Datatype hierarchy and TypeFactory for the Gosleigh decompiler.

## Context
- Gosleigh Phase 3 complete (SSA IR ready)
- Type system is needed by pointer rules (WU4) and PrintC (WU7)
- C++ reference: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/type.hh/cc
- Can be implemented independently of WU1 (no dependency)
- IMPORTANT: Read CLAUDE.md and docs/DECOMPILER_PIPELINE_ROADMAP.md first

## Deliverables
1. pkg/pcode/datatype.go -- Datatype interface/hierarchy (Base, Void, Pointer, Array, Struct, Union, Enum, Code)
2. pkg/pcode/typefactory.go -- TypeFactory intern pool (create/lookup/cache)
3. pkg/pcode/datatype_test.go -- Tests
4. All existing 142 tests must still pass

## Constraints
- C++ parity is the top priority
- metatype enum must match C++ exactly (TYPE_VOID, TYPE_INT, TYPE_UINT, etc.)
- TypeFactory must intern types (same parameters = same pointer)
- Indent with tabs, no non-ASCII in code, English comments

## Done Criteria
- Full Datatype hierarchy compiles
- TypeFactory can create and intern all basic types
- Struct/Union/Array types can hold fields
- go test ./... passes with zero failures
