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

To get everything that is measured to keep every function Ghidra decompiles
correctly unchanged, a host does not pick options one by one: it makes
`analysis.NewEnhanced(prog)` once per program and calls `Apply(&fn)` on each
`decomp.Function`. An option joins that preset only after the measurement
(real-binary goldens, `tools/realexe/realexe.py measure-all`) shows no
function Ghidra gets right changing for the worse.

| Option | Ghidra | Gosleigh with the option | Use |
|---|---|---|---|
| `decomp.Function.FlowBounds` | A decompile always follows flow over the whole address space | Flow is limited to the given ranges (several for a split function); leaving them ends in Ghidra's own out-of-bounds handling ("Function flow out of bounds" + `halt_missing()`) | Functions whose whole-space flow runs into junk bytes |
| `decomp.Function.Extensions.NestedPieceTrials` | When an XMM register is written lane by lane (`cvtdq2ps`), as a scalar (`movss` from memory zeroes the upper lanes) and whole (`movaps`) in one function, heritage joins it in nested PIECEs; `AncestorRealistic` and `ancestorOpUse` then reject the value, so a float return prints as `void` and a float argument of a call without a prototype is dropped, each with the code computing it | Such a trial is followed into a low piece that holds it, and PIECE / same-register SUBPIECE steps do not use up `ancestorOpUse`'s 5 recursion levels. For call arguments the extension only fills a parameter slot Ghidra left empty: if Ghidra accepted another register of the same slot (RDX for XMM1), Ghidra's argument stays | x64 code that passes or returns floats in XMM registers |
| `decomp.Function.Extensions.NarrowFloatReturns` | A float returned in an 8-byte slot (x64 XMM0_Qa) keeps all 8 bytes alive when one path returns a float parameter register unchanged (`movaps xmm0, xmm1`): the function returns `ulonglong`, results print as `(ulonglong)(uint)(...)` and the parameter becomes an integer | The return is cut to its low 4 bytes when every path returns a 4-byte float result, a 4-byte value, a constant, a call result or a float parameter unchanged, and at least one path is a 4-byte float operation; a double (8-byte float operation) is never cut | x64 functions returning `float` |
| `decomp.Function.Extensions.NaNExactCompares` | The negation of a float order comparison is rewritten to the swapped comparison (`!(a < b)` to `b <= a`, `get_booleanflip` in RuleBoolNegate and the printer's negated tokens); the two differ when an operand is NaN, so `minss` prints with the NaN case taken the wrong way | The negation stays: `!(a < b)`. For NaN tests the decompiler itself drops, see `NaNIgnore` below | Code where NaN matters |
| `decomp.Function.Extensions.BitCastSyntax` | A CAST between a float and an integer (a bit reinterpretation such as `movd xmm0, edx`) and a numeric conversion (`INT2FLOAT`) both print as `(float)x` | The CAST prints as `bit_cast<float>(x)`; a conversion stays `(float)x` | Float tricks such as `bit_cast<float>(x >> 9 \| 0x3f800000) - 1.0` |
| `decomp.Function.Extensions.FloatLoads` | A narrow load through a pointer to a wider integer is widened to the element and truncated (RuleExpandLoad), so a float field read through a `longlong *` prints as `(int)p[0x3c8]` | A load whose value is used as a float (a float operation, or a float parameter slot of a call) stays a load: `*(undefined4 *)(p + 0x3c8)` | Float fields in objects typed as integer arrays |
| `decomp.Function.NaNIgnore` (Ghidra's `nanignore` option) | Default `compare`: NaN tests protecting a float comparison are dropped (RuleIgnoreNan), so `comiss`/`ja` code assumes no NaN | `pcode.NaNIgnoreNone` keeps them (`!NAN(x) && 0.0 <= x`), `pcode.NaNIgnoreAll` drops every NaN test. This is a port of Ghidra's own option, not part of the `Enhanced` preset: it adds a NaN test to most float comparisons | Exact NaN behaviour, together with `NaNExactCompares` |
| `decomp.Function.CalleeReads` (`analysis.CalleeReads`) | The core never takes the caller's own input passed on unchanged to a call as an argument, nor a value that is also read after the call (`AncestorRealistic`, `ancestorOpUse`); Ghidra's Java side covers this by committing the callee's prototype first (Decompiler Parameter ID) | `pkg/analysis` scans the callee's entry path (64 instructions, one path, stopping at a call) for registers it reads before writing; such an argument candidate Ghidra left inactive is kept. Storing a register to the home area (`[rsp+8..0x20]`, also through a copy of RSP) is not a read, so a varargs callee does not gain arguments. Only fills a slot Ghidra left empty; a register the caller never touches has no candidate and stays out | Wrappers that forward their parameters, and calls whose argument registers are read again after the call (obfuscation junk) |
| `decomp.Function.CalleeReads`, return side (`analysis.CalleeReads.CalleeFloatReturn`) | A callee without a prototype has an unknown return, so a float it returns is printed through a cast: `(float)FUN_x()` | The callee's path to its first `ret` is scanned; when the low lane of XMM0 was last written with a 4- or 8-byte value and RAX not after it, the callee's return is locked to `float`/`double` (only when the host does not lock it) | Calls to float getters and math helpers |
| `decomp.Function.InstructionHooks` (`bridge.InstructionHook`) | No equivalent | Callers change instructions before flow is followed. Extensions in `pkg/ext` plug in here | Extension point |
| `pkg/ext/branchassume` | `Funcdata::overrideFlow` rejects overrides of conditional branches | Fixes chosen conditional branches to one side, as a user would patch `jz` to `jmp` or to no-ops. The dropped side is not decompiled, each fixed branch is marked in the output, and `Hook.Unapplied` lists addresses no flow reached | Junk-byte obfuscation, with directions from a runtime trace |
