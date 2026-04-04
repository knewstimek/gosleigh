# E1: Calling Convention + Variable Recovery

## Objective

Port the core variable recovery layer from Ghidra C++. After this phase, the decompiler
must output named function parameters and local variables instead of raw EBP+8 offsets.

Current output (broken):
  void func(void) {
      *(ulong *)(ESP - 4) = EAX;
      EAX = *(ulong *)(EBP + 8);
  }

Target output (after E1):
  int classify2(int param1, int param2) {
      int local1;
      ...
  }

This is the highest-impact quality improvement possible. All other analysis phases build
on top of it.

## C++ reference files (read before implementing)

- ghidra-ref/.../cpp/variable.hh + variable.cc (~1200 lines): HighVariable, HighParam, HighLocal, HighGlobal, HighOther
- ghidra-ref/.../cpp/varmap.hh + varmap.cc (~1620 lines): ScopeLocal, MapState, AliasChecker, AddressRange, VarnodeData map -> HighVariable
- ghidra-ref/.../cpp/fspec.hh + fspec.cc (~5976 lines): ProtoModel, FuncProto, ParamEntry, ParamList, PrototypePieces
- ghidra-ref/.../cpp/cover.hh + cover.cc (~654 lines): Cover, LocationRange (varnode liveness)
- ghidra-ref/.../cpp/merge.hh + merge.cc (~1695 lines): Merge class, phi-node merging

Focus on the subset needed to produce named params and stack locals. Do NOT port the
entire fspec.cc -- only the cdecl/ProtoModel core.

## Part 1: HighVariable layer (variable.cc port)

### pkg/pcode/variable.go (new file)

Port from variable.hh/variable.cc:

```
HighVariable interface {
    Symbol() *Symbol            // named symbol (param1, local1, etc.)
    Type() DataType             // inferred type
    Varnodes() []*Varnode       // all varnodes merged into this high var
    Name() string               // display name
}

HighParam struct  -- function parameter (EBP+8, EBP+12, ...)
HighLocal struct  -- stack local (EBP-4, EBP-8, ...)
HighGlobal struct -- global (absolute address)
HighOther struct  -- unclassified

Symbol struct {
    Name string
    Type DataType
    Category int  // 0=local, 1=param, 2=global
    Offset int64  // stack offset for locals/params
}
```

Key methods:
- `MergeWith(other HighVariable)` -- merge two high vars (for SSA phi merging)
- `SetType(t DataType)`
- `IsAddrTied() bool` -- varnode is address-taken

### Funcdata integration

Add to Funcdata:
```
LocalSyms   *ScopeLocal  // local variable scope
ProtoModel  *ProtoModel  // calling convention
```

## Part 2: ProtoModel / cdecl calling convention (fspec.cc subset)

### pkg/pcode/fspec.go (new file)

Port the MINIMAL subset of fspec.cc needed for cdecl x86-32:

```
ProtoModel struct {
    Name       string    // "cdecl", "stdcall", etc.
    IsVarargs  bool
    Params     []ParamEntry
    ReturnLoc  ParamEntry
}

ParamEntry struct {
    Space   string   // "stack" or register name
    Offset  int64    // stack offset (for stack params: 8, 12, 16, ...)
    Size    int      // 4 for int
    Type    DataType
}

FuncProto struct {
    Model      *ProtoModel
    Params     []*HighParam  // discovered parameters
    ReturnType DataType
    NumParams  int
}
```

cdecl model (x86-32 default):
- Parameters: stack at [EBP+8], [EBP+12], [EBP+16], ... (4 bytes each)
- Return: EAX (size 4) or EDX:EAX (size 8)
- Caller cleans up stack

### Parameter detection heuristic

Scan Funcdata.Instructions for LOAD ops targeting [EBP+N] where N >= 8:
- N=8 -> param1 (int)
- N=12 -> param2 (int)
- N=16 -> param3 (int)
Assign HighParam for each unique positive EBP offset >= 8.

### Local variable detection heuristic

Scan for LOAD/STORE ops targeting [EBP-N] where N > 0:
- EBP-4 -> local1 (int)
- EBP-8 -> local2 (int)
Assign HighLocal for each unique negative EBP offset.

## Part 3: ScopeLocal -- variable map (varmap.cc subset)

### pkg/pcode/varmap.go (new file)

```
ScopeLocal struct {
    Params  map[int64]*HighParam  // EBP offset -> HighParam
    Locals  map[int64]*HighLocal  // EBP offset -> HighLocal
    nextParamIdx int
    nextLocalIdx int
}

func NewScopeLocal() *ScopeLocal
func (s *ScopeLocal) GetOrCreateParam(offset int64, size int) *HighParam
func (s *ScopeLocal) GetOrCreateLocal(offset int64, size int) *HighLocal
func (s *ScopeLocal) AllParams() []*HighParam  // sorted by offset (param1 first)
func (s *ScopeLocal) AllLocals() []*HighLocal
```

Naming convention: param1, param2, ... / local1, local2, ... (matching Ghidra defaults).

## Part 4: Cover + Merge stubs (cover.cc + merge.cc)

### pkg/pcode/cover.go (new file)

Minimal Cover struct -- tracks which program points a varnode is live:
```
Cover struct {
    Blocks []int  // block indices where this varnode is live
}

func (c *Cover) IsIntersect(other *Cover) bool
func (c *Cover) Merge(other *Cover)
```

### pkg/pcode/merge.go (new file)

Merge handles phi-node merging for SSA -> high variable assignment:
```
Merge struct {
    Funcdata *Funcdata
}

func NewMerge(fd *Funcdata) *Merge
func (m *Merge) MergeOpcode(opcode OpCode)  -- merge COPY/MULTIEQUAL defs
func (m *Merge) MergeAddrTied()             -- merge address-taken varnodes
```

These can be stubs that pass tests -- full implementation is optional for E1.

## Part 5: Wire into Heritage + PrintC

### Heritage modification

After Heritage SSA construction, call:
```
scopeLocal := NewScopeLocal()
fd.LocalSyms = scopeLocal
fd.buildHighVariables(scopeLocal)  // scan varnodes, assign HighParam/HighLocal
```

### PrintC modification

Update `printc.go`:
- `emitFunctionDecl()`: emit `int func_name(int param1, int param2)` using FuncProto
- `emitLocalDecls()`: emit `int local1;` etc. for stack locals
- `emitVarnodeRef()`: if varnode has HighVariable, emit name instead of raw address

The function name should use: `func_<entry_address>` as default if no symbol table.

## Part 6: E2E tests

### TestE1ClassifyNamed (pkg/loader/loader_test.go)

Use the classify2 binary from D19 (35 bytes). After E1:
- PrintC output must contain "param" somewhere (param1 or param2)
- PrintC output must contain a function signature line with parameters
- Must NOT contain raw "EBP" address expressions

```go
if !strings.Contains(output, "param") {
    t.Errorf("expected named parameters in output, got:\n%s", output)
}
```

### TestE1LocalVarNamed (pkg/loader/loader_test.go)

Use a function with a local variable at EBP-4:
  PUSH EBP; MOV EBP,ESP; SUB ESP,4;  // allocate local
  MOV [EBP-4], EAX;  // store to local
  MOV EAX, [EBP-4];  // load from local
  MOV ESP,EBP; POP EBP; RET

After E1: PrintC output contains "local" in variable reference.

## Part 7: Docs

Update docs/STATUS.md with E1 entry.
Update docs/E_PHASE_ROADMAP.md: mark E1 complete.

## In-scope

1. pkg/pcode/variable.go (new): HighVariable, HighParam, HighLocal, Symbol
2. pkg/pcode/fspec.go (new): ProtoModel cdecl, FuncProto, ParamEntry
3. pkg/pcode/varmap.go (new): ScopeLocal, param/local name assignment
4. pkg/pcode/cover.go (new): Cover stub
5. pkg/pcode/merge.go (new): Merge stub
6. pkg/pcode/funcdata.go: add LocalSyms, FuncProto fields + buildHighVariables()
7. pkg/pcode/printc.go: emit named params/locals in function decl + body
8. pkg/loader/loader_test.go: TestE1ClassifyNamed, TestE1LocalVarNamed
9. docs/STATUS.md + docs/E_PHASE_ROADMAP.md

## Out-of-scope

- Full fspec.cc port (register calling conventions, stdcall, fastcall) -- only cdecl stack params
- Full varmap.cc alias analysis
- Full cover.cc/merge.cc (stubs acceptable)
- x86-64, ARM calling conventions
- DWARF symbol names
- Type recovery beyond int/void/pointer

## Invariants

- All existing tests pass (113 golden subtests, 21 E2E tests)
- go test ./... passes green
- No new external dependencies
- ASCII-only, tabs for indentation, English comments
- Must NOT break existing E2E tests (they may now produce different -- better -- output, but must not error)

## Done when

- go test ./... passes green
- TestE1ClassifyNamed passes: output contains "param"
- TestE1LocalVarNamed passes: output contains "local"
- PrintC emits function signature with at least 1 parameter name for classify2
- docs/STATUS.md has E1 entry
