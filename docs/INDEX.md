# Indexing

## Purpose

This project uses `agent-tool` `codegraph` indexing for two separate goals:

- C++ reference lookup in `ghidra-ref/` during porting
- Go code lookup in the Gosleigh implementation as the port grows

The current priority is the Ghidra C++ reference index.

## C++ Reference Index

- Source root: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/`
- Index DB: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/.codegraph.db`
- Indexed on: `2026-03-31`

Current index stats:

- Files: 230
- Classes/Structs: 1548
- Functions: 112
- Methods: 10365
- Call sites: 38115
- Imports/Includes: 483
- Inheritance relations: 881

## Rebuild

Rebuild the C++ index when:

- `ghidra-ref/` is re-synced or replaced
- Ghidra reference files are added to the sparse checkout
- symbol lookup results look stale or incomplete

`codegraph` index target:

- `D:\News\Business\Gosleigh\ghidra-ref\Ghidra\Features\Decompiler\src\decompile\cpp`

## Query Pattern

Use `codegraph` as the first pass for navigation:

- `find` for a type or function name
- `methods` for a class
- `inherits` for a class hierarchy
- `callers` and `callees` for local flow
- `call_tree` for broader traversal

For C++, `find` often returns forward declarations from unrelated headers. Treat the real definition in the main header or source file as the authority, then continue from there.

Useful starting symbols:

- `Address`
- `AddrSpace`
- `Varnode`
- `PcodeOp`
- `PcodeEmit`
- `Translate`
- `Sleigh`
- `Architecture`

Known definition anchors:

- `Address`: `address.hh:59`
- `AddrSpace`: `space.hh:40`
- `Varnode`: `varnode.hh:73`
- `PcodeOp`: `op.hh:63`
- `PcodeEmit`: `translate.hh:94`
- `Translate`: `translate.hh:75`
- `Sleigh`: `sleigh.hh:162`
- `Architecture`: `architecture.hh:64`

## Go Index

Go indexing is also supported by `codegraph`, but there is not enough Go code in this repository yet to justify a stable workflow. Add the Go index location and query conventions here once the Go module and package layout exist.
