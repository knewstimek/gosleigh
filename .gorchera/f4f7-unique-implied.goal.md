# Goal: Eliminate unique_* variables from decompiled C output

## Problem

Gosleigh decompiled output for multiply, add3, and aarch64_add_ret contains
unique-space temporary variables (e.g. unique_41500_4, unique_87304_4) as
explicit C statements. Ghidra's actual output does not contain these.

Example bad output:
```c
unsigned int multiply(unsigned int param_0, unsigned int param_1) {
    unique_41500_4 = register_14_4;
    unique_87308_4 = -4;
    unique_87304_4 = param_0 * param_1;
    register_0_4 = unique_87304_4;
    return register_0_4;
}
```

Expected (unique_* gone, expression inlined):
```c
unsigned int multiply(unsigned int param_0, unsigned int param_1) {
    return param_0 * param_1;
}
```

## How Ghidra eliminates these

Read the following C++ files in ghidra-ref/ first:

1. `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc`
   - `ActionMarkImplied::apply()` at line 3423
   - `ActionMarkImplied::checkImpliedCover()` at line 3383

2. `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/merge.cc`
   - `Merge::markImplied()` at line 1595

3. `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc`
   - Op emission loop around line 2835 -- the `isImplied()` check that skips implied varnodes

4. `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/varnode.hh`
   - `implied` flag (0x40), `setImplied()`, `isImplied()` at line 235

Summary of the mechanism:
- `ActionMarkImplied` runs and marks varnodes as "implied" when they can be safely
  inlined into the expression tree (no aliasing hazard, single use, etc.)
- The printc emission loop skips ops whose output `isImplied()` -- they are not printed
  as standalone statements; their defining expression is inlined at the use site
- Unique-space temporaries with a single consumer are the primary target

## Gosleigh current state

- `VarnodeImplied = 0x40` and `IsImplied()` already exist in `pkg/pcode/varnode_ssa.go`
- `ActionMarkImplied` is NOT implemented -- nothing calls `SetImplied()`
- The emission loop in `pkg/pcode/printc.go emitOps()` does not check `IsImplied()`

## Task

Implement `ActionMarkImplied` (or equivalent) in Gosleigh that:
1. Reads the C++ implementation first
2. Marks unique-space temporaries as implied when safe to do so
3. Wires the action into the decompile pipeline before printc emission
4. Updates `emitOps()` in printc.go to skip implied-output ops (matching C++ behavior)

The full `checkImpliedCover()` with LOAD/STORE alias analysis is complex. A
justified subset that covers unique-space one-consumer varnodes is acceptable,
provided it is documented as a known partial implementation.

## Invariants

- `go test ./...` must pass throughout
- Do NOT modify `ghidra-ref/` (read-only reference)
- Code comments in English, no non-ASCII characters in code
- Indent with tabs (Go standard)
- `TestX86ClassifySignFunction` must not regress -- still shows if/else structure

## Done when

1. `go test ./...` passes
2. Output for TestX86MultiplyFunction and TestX86Add3Function contains NO `unique_` prefixed variables
3. Output for TestAARCH64SimpleFunction contains NO `unique_` prefixed variables
4. TestX86ClassifySignFunction output still shows the correct if/else structure (no regression)
