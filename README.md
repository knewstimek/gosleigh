# Gosleigh

A Go port of the Ghidra decompiler: the C++ decompiler core (p-code analysis, type recovery,
structuring, C printing) and the Sleigh runtime that turns machine code into p-code. Pure Go, no
cgo, no Java, no Ghidra installation.

The goal is the same output as Ghidra's decompiler for the same input. Ghidra's x86/x64 language
specs are embedded, so a host only supplies image bytes and whatever it knows about the program.

```
go get github.com/knewstimek/gosleigh@latest
```

Go 1.25 or later.

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

func main() {
	// lea eax, [rcx+rdx]; ret
	code := []byte{0x8d, 0x04, 0x11, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc}

	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		log.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: 0x140001000, Data: code}})
	if err != nil {
		log.Fatal(err)
	}
	res, err := prog.Decompile(decomp.Function{Entry: 0x140001000})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(res.C)
}
```

```c
int FUN_140001000(int param_1, int param_2) {
    return param_1 + param_2;
}
```

- `specs.X86(bits, compiler)`: 32 or 64 bit with `CompilerWindows` (Visual Studio), `CompilerGCC`
  or `CompilerGolang` (the Go toolchain's register ABI). The `.sla`, `.pspec` and `.cspec` files
  are embedded. Another architecture can be loaded by filling `decomp.Spec` with its compiled
  files, but only x86/x64 are measured.
- `decomp.Load(spec, sections)` maps the image once; each `Program.Decompile` call builds a fresh
  engine over the shared `.sla` decode.
- `decomp.Function` carries what the host knows, as Ghidra's host does for a decompile request:
  a `pcode.HostScope` for callee names, prototypes, global data and external references, flow
  overrides (tail calls), tracked register values, and named and typed stack locals. Types are
  described with `pcode.HostTypeDesc` (structures, unions, enums, bitfields, pointers, arrays,
  function types). Without a host the output is what Ghidra prints for a program with no symbols.
- `GhidraFormat: true` prints Ghidra's exact layout (no indentation, brace on its own line); the
  default is indented.

`Decompile` runs in the calling goroutine and cannot be cancelled, and the engine can grow without
bound on some real functions. A long-lived host should run it in a separate process with a time
and memory limit.

## Accuracy

Measured against the output of Ghidra 12's own decompiler, given the same host information
(function bounds, symbols, types and prototypes exported from Ghidra), on functions sampled from
two MSVC executables:

| Sample | Result |
|---|---|
| x86-32, 50 seeds of 200 functions | all 200/200 identical |
| x64 (Unreal Engine 4 game), 49 seeds of 200 functions | 47 seeds 200/200; the other two differ only where Ghidra itself is nondeterministic (parameter trial order in [DIFFERENCES.md](DIFFERENCES.md)) |

The samples are functions up to 4 KB from MSVC PE images. GCC/Clang output, ELF, other
architectures, larger functions, speed and memory use are not part of this measurement.

## Differences from Ghidra

Every intentional difference, always-on or opt-in, is listed in [DIFFERENCES.md](DIFFERENCES.md).

## Layout

| Package | Contents |
|---|---|
| `pkg/decomp` | Library entry point: `Load`, `Program.Decompile` |
| `pkg/specs` | Embedded x86/x64 language, processor and compiler specs |
| `pkg/pcode` | Decompiler core: actions and rules, types, structuring, C printer |
| `pkg/sla` | Sleigh runtime: `.sla` decoding and instruction translation to p-code |
| `pkg/bridge`, `pkg/loader` | Wiring between the Sleigh runtime and the core |
| `pkg/ext` | Extensions beyond Ghidra, opt-in (see [DIFFERENCES.md](DIFFERENCES.md)) |
| `pkg/address` | Address spaces |
| `cmd/` | Development tools (golden comparison, SSA dump); not a supported CLI |

## Used by

[agent-tool](https://github.com/knewstimek/agent-tool), an MCP server for AI coding agents, uses
Gosleigh for `analyze(operation="decompile")` on x86/x64 PE and ELF binaries, with PDB and DWARF
information supplied through the host interface.

## License

Apache License 2.0, see [LICENSE](LICENSE). Gosleigh is a reimplementation of the Ghidra
decompiler and Sleigh, developed by the National Security Agency
([NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)); see
[NOTICE](NOTICE).
