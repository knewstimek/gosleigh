# Differences from Ghidra

Gosleigh's baseline is the output of Ghidra 12's decompiler for the same input. This file lists
every place where Gosleigh behaves differently on purpose. Anything not listed here and not equal
to Ghidra is a bug.

## Always on

These differ from Ghidra with no option to turn them off.

| Area | Ghidra | Gosleigh | Why | Upstream |
|---|---|---|---|---|
| Order of call parameter trials | Sorted by pointer address (`ParamTrial::operator<`), so the result can change between runs | Sorted by position in the compiler spec | Same input, same output | [ghidra#9750](https://github.com/NationalSecurityAgency/ghidra/pull/9750) |
| Constant stored into a bitfield as `(v & clear) \| set` where neither mask covers the whole field | Ghidra 12.1 prints the masks | Prints `p->mode = 5` | Reads as the source wrote it | [ghidra#9836](https://github.com/NationalSecurityAgency/ghidra/pull/9836) |
| Default instruction limit for flow (`decomp.DefaultMaxInstructions`) | 100000 | 20000; set `decomp.Function.MaxInstructions` to change it | Bounds time and memory per function. As in Ghidra, a flow over the limit fails the function (`bridge.ErrTooManyInstructions`) instead of being cut short | - |

## Opt-in

Without these options the decompiler behaves as Ghidra does.

| Option | Ghidra | Gosleigh with the option | Use |
|---|---|---|---|
| `decomp.Function.FlowBounds` | A decompile always follows flow over the whole address space | Flow is limited to the given ranges (several for a split function); leaving them ends in Ghidra's own out-of-bounds handling ("Function flow out of bounds" + `halt_missing()`) | Functions whose whole-space flow runs into junk bytes |
| `decomp.Function.Extensions.NestedPieceTrials` | When an XMM register is written lane by lane (`cvtdq2ps`), as a scalar (`movss` from memory zeroes the upper lanes) and whole (`movaps`) in one function, heritage joins it in nested PIECEs; `AncestorRealistic` and `ancestorOpUse` then reject the value, so a float return prints as `void` and a float argument of a call without a prototype is dropped, each with the code computing it | Such a trial is followed into a low piece that holds it, and PIECE / same-register SUBPIECE steps do not use up `ancestorOpUse`'s 5 recursion levels. For call arguments the extension only fills a parameter slot Ghidra left empty: if Ghidra accepted another register of the same slot (RDX for XMM1), Ghidra's argument stays | x64 code that passes or returns floats in XMM registers |
| `decomp.Function.InstructionHooks` (`bridge.InstructionHook`) | No equivalent | Callers change instructions before flow is followed. Extensions in `pkg/ext` plug in here | Extension point |
| `pkg/ext/branchassume` | `Funcdata::overrideFlow` rejects overrides of conditional branches | Fixes chosen conditional branches to one side, as a user would patch `jz` to `jmp` or to no-ops. The dropped side is not decompiled, each fixed branch is marked in the output, and `Hook.Unapplied` lists addresses no flow reached | Junk-byte obfuscation, with directions from a runtime trace |
