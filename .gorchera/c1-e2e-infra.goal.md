# C1+C4: File-based input, CLI, and E2E x86 decompilation

## Objective

Implement file-based instruction input (pkg/loader), wire a minimal CLI
(cmd/gosleigh/main.go), and validate the full decompilation pipeline from
x86 binary bytes to C output using bridge.Build() -> Heritage -> PrintC.

## Why

Phase B8 confirmed that x86 p-code translation works for 10 opcodes. The
existing runtime (Engine, bridge.Build, Heritage, PrintC) is all present
but has no file-based entry point. The MCP tool needs to call Gosleigh with
a file path + offset + size to avoid embedding raw bytes in the prompt. This
is Phase C of the roadmap: E2E infrastructure.

## Pipeline summary (existing code)

All these functions already exist and work (no modifications needed to them
as long as the pipeline is wired correctly):

  bridge.Build(engine *sla.Engine, cfg bridge.BuildConfig) (*bridge.Result, error)
    -> returns Result{Funcdata *pcode.Funcdata, Graph *pcode.BlockGraph, HeritageSpaces}

  h := pcode.NewHeritage(result.Funcdata, result.HeritageSpaces)
  h.Heritage(result.Graph)
    -> runs SSA construction on the CFG

  p := pcode.NewPrintC()
  output, err := p.Emit(result.Funcdata)
    -> returns C code as string

## In-scope

### 1. pkg/loader/loader.go -- new file

Define `EngineBuilder` struct and `Build()` method for x86:

```
type EngineBuilder struct {
    SLAPath    string  // path to packed .sla file
    PspecPath  string  // path to .pspec file (optional; empty = no defaults)
    BinaryPath string  // path to binary file to read instruction bytes from
    BaseOffset uint64  // byte offset within binary file to start reading
    BaseAddr   uint64  // virtual address to map bytes at in the engine
    ReadSize   uint64  // number of bytes to read from binary (0 = read all remaining)
}

func (b *EngineBuilder) Build() (*sla.Engine, address.Address, error)
```

`Build()` implementation:
a. Read SLA file: sla.Read(bytes.NewReader(data))
b. Decode: sla.DecodeBoundariesPayload(container.Payload)
c. BuildXrefs: boundaries.BuildXrefs()
d. Find default address space (boundaries.Metadata.DefaultSpace)
e. backend := sla.NewBackend()
f. Register context variables from xrefs.ContextFields
g. If PspecPath != "", parse and apply defaults:
   pspecData, _ := sla.ParsePspec(b.PspecPath)
   for _, entry := range pspecData.ContextSet:
     backend.SetVariableDefault(entry.Name, entry.Value)
h. Read instruction bytes from BinaryPath at BaseOffset for ReadSize bytes
   (if ReadSize == 0, read to end of file)
i. base := address.Address{Space: ram, Offset: b.BaseAddr}
j. backend.SetInstructionBytes(base, instructionBytes)
k. loweringCtx := sla.NewLoweringContext(boundaries.Metadata, base)
   if loweringCtx.ConstantSpace != nil {
     loweringCtx.SpacesByIndex[0] = loweringCtx.ConstantSpace
   }
   (This is the ConstantSpace[0] fix needed by x86 -- const space must be at index 0
    for IPTR_CONSTANT = 0; NewLoweringContext does not register it automatically.)
l. engine, err := sla.NewEngineFromBoundaries(boundaries, sla.EngineConfig{
     LoweringTemplate: loweringCtx,
     Backend: sla.EngineBackendAdapter{
       LoadMatchInput: backend.PayloadLoader(sla.BackendPayloadConfig{}),
       Commits:        backend.CommitHooks(),
     },
   })
m. return engine, base, nil

### 2. pkg/loader/loader_test.go -- new file (package loader)

E2E integration test `TestX86SimpleFunction`:

a. Write test bytes to a temp file:
   bytes: {0x01, 0xD8, 0xC3}
     0x01 0xD8 = ADD EAX, EBX (INT_ADD + EFLAGS ops)
     0xC3      = RET           (LOAD + INT_ADD + RETURN)
   Use os.WriteFile to a temp file created with os.CreateTemp.

b. Resolve SLA path: same pattern as goldenEngineX86 (runtime.Caller),
   pointing to pkg/sla/testdata/x86-packed.sla (relative from pkg/loader/).
   From pkg/loader/, the path is: ../sla/testdata/x86-packed.sla

c. Resolve pspec path: same pattern,
   pointing to testdata/sla/x86.pspec (project root).
   From pkg/loader/, the path is: ../../testdata/sla/x86.pspec

d. Build engine:
   eb := &loader.EngineBuilder{
     SLAPath:    slaPath,
     PspecPath:  pspecPath,
     BinaryPath: tmpFile,
     BaseOffset: 0,
     BaseAddr:   0,
     ReadSize:   0,
   }
   engine, base, err := eb.Build()
   t.Fatal if err != nil

e. bridge.Build:
   cfg := bridge.BuildConfig{
     Name:            "test_x86_add",
     Entry:           base,
     MaxInstructions: 20,
   }
   result, err := bridge.Build(engine, cfg)
   t.Fatal if err != nil
   assert len(result.Instructions) > 0
   assert result.Funcdata != nil

f. Heritage pass:
   h := pcode.NewHeritage(result.Funcdata, result.HeritageSpaces)
   h.Heritage(result.Graph)
   (no error return; just runs)

g. PrintC:
   p := pcode.NewPrintC()
   output, err := p.Emit(result.Funcdata)
   t.Fatal if err != nil
   t.Logf("PrintC output: %s", output)
   assert len(output) > 0 (non-empty C string)

h. The test must NOT skip -- if any step fails, t.Fatal with the exact error.
   This test is the E2E proof that the full pipeline works.

### 3. cmd/gosleigh/main.go -- implement the CLI

Replace the empty main.go with a real CLI:
  - subcommand: `translate`
  - flags: --sla, --pspec (optional), --binary, --offset (hex, default 0),
           --size (bytes to read, default 0=all), --entry (virtual base addr, default 0),
           --output (json|c, default c)
  - reads the binary, builds engine via EngineBuilder, calls bridge.Build,
    optionally Heritage+PrintC for --output c, and prints result to stdout
  - exit 0 on success, exit 1 on error (stderr for errors)

Example usage:
  gosleigh translate --sla x86.sla --pspec x86.pspec --binary func.bin --output c

Flag parsing with standard `flag` package. No third-party deps.

For --output c: run Heritage then PrintC, print C string.
For --output json: skip Heritage/PrintC, marshal result.Instructions as JSON.

## Out-of-scope

- No ELF/PE section parsing. Binary file is raw bytes at the given offset.
- No x86-64 (64-bit). Only x86 32-bit (current architecture).
- No multiple-function analysis (just one function at a time).
- No DWARF or symbol table integration.
- No MCP server changes. The CLI is the integration point.
- Do not modify: bridge.go, bridge_test.go, heritage.go, printc.go, or any
  existing sla/pcode production files. Loader and CLI are new files only.

## Invariants

- All existing tests (go test ./...) must pass.
- pkg/loader package is new: no existing tests will break.
- cmd/gosleigh/main.go currently has `package main; func main() {}` -- replace it.
- ASCII-only in all code and output. Tabs for indentation.
- Comments in English. No third-party dependencies.
- go build ./... must pass.

## Constraints

- Paths in tests use runtime.Caller(0) to be correct regardless of cwd.
- pkg/loader/loader_test.go is package `loader` (internal test, no _test suffix needed
  since it's testing the exported API).
- Actually: use package `loader_test` for the E2E test to mirror sla_test pattern.
  This means the test file imports "gosleigh/pkg/loader" etc.
- If Heritage or PrintC panic or return errors for simple x86 p-code:
  trace the failure, cross-reference ghidra-ref/ C++ (heritage.cc, print_c.cc),
  and fix the specific gap. A parity gap must not be silently swallowed.
- If PrintC output is empty (len == 0) but no error: this is a bug -- t.Fatal.
- The 3-byte function {0x01, 0xD8, 0xC3} is known to work (Phase B8 verified ADD and RET).

## Imports needed

- gosleigh/pkg/loader (for EngineBuilder)
- gosleigh/pkg/bridge (for Build, BuildConfig)
- gosleigh/pkg/pcode (for NewHeritage, NewPrintC)
- gosleigh/pkg/sla (for ParsePspec)
- gosleigh/pkg/address (for Address)

## Done when

- `go build ./...` passes.
- `go test ./pkg/loader/... -v -run TestX86SimpleFunction` passes and prints non-empty C output.
- `go test ./...` passes (all existing tests green).
- `cmd/gosleigh/main.go` compiles with a real `translate` subcommand.
- The printed C output for the 3-byte ADD+RET function contains some recognizable
  C syntax (at minimum: a function signature or a return statement).
