# E2+E3: Dead Code Elimination + Cast Insertion + FP Heritage/PrintC Layer

## Objective

Two E-phase items bundled: eliminate flag dead-code clutter from PrintC output (E2),
and add float/double type inference + emission (E3). Both are output quality improvements
that directly affect how readable the decompiled C looks.

Current output (classify2 / add_and_store):
```
unsigned int add_and_store(unsigned int param_0, unsigned int param_1) {
    unsigned int local_0;
    ...
    unsigned char local_10;   // CF
    unsigned char local_11;   // OF
    unsigned char local_12;   // ZF
    ...unsigned char local_19; // PF/SF
    local_10 = local_3 < 4;   // dead flag assignment
    local_18 = SBORROW(local_3, 4);  // dead flag assignment
    local_16 = local_4 < 0;   // dead flag assignment
    ...
}
```

Target output after E2+E3:
```
unsigned int add_and_store(unsigned int param_0, unsigned int param_1) {
    unsigned int local_0;
    // no flag locals, no dead assignments
    ...
}
```

And for FP functions:
```
float compute_fp(float param_0) {
    float local_0;
    local_0 = param_0 + 1.0f;
    return local_0;
}
```

## C++ reference files

- ghidra-ref/.../cpp/coreaction.hh + coreaction.cc (~5758 lines): ActionDeadCode, ActionSetCasts
- ghidra-ref/.../cpp/cast.hh + cast.cc (~546 lines): CastStrategy, CastStrategyC
- ghidra-ref/.../cpp/type.hh + type.cc: DataType hierarchy, float type detection
- ghidra-ref/.../cpp/heritage.hh + heritage.cc: float type annotation in Heritage pass

Focus: DO NOT port the full ActionDeadCode consume-propagation engine (3936..4100 lines).
Instead, implement a practical subset that handles the most common cases. See Part 1.

## Part 1: ActionDeadCode -- simplified dead store elimination

### pkg/pcode/action_deadcode.go (new file)

The full Ghidra ActionDeadCode uses consume-mask propagation (complex). For E2, implement
a simplified two-pass dead store eliminator that removes 90% of flag clutter:

**Pass 1: Unconditional dead output removal**

Walk all live PcodeOps. If ALL of these are true, remove the op:
  - op.Out() != nil (has output varnode)
  - op.Out().HasNoDescend() == true (no one reads the output)
  - op.Out().IsAddrTied() == false (not address-taken)
  - op.Code() is not CPUI_CALL, CPUI_CALLIND, CPUI_STORE (these have side effects)
  - op.Code() is not CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND (control flow)
  - op.Code() is not CPUI_RETURN (return value)
  - op.Code() is not CPUI_INDIRECT (aliasing op)

Use data.OpUnlink(op) + data.OpDestroy(op) to remove. Repeat until no more changes.

This removes: flag computations (INT_LESS, INT_SLESS, INT_CARRY, BOOL_XOR for OF, etc.),
temporaries used only once in a chain that feeds a dead store, most POPCOUNT/BOOL ops.

**Pass 2: Constant folding of dead branches (optional)**

If a CBRANCH condition input is a constant 0 or 1, eliminate the branch:
- Constant 0: remove the conditional branch (fall-through always taken)
- Constant 1: convert to unconditional BRANCH

This is already partially in existing code; wire it if not done.

```go
type ActionDeadCode struct {
    ActionBase
}

func NewActionDeadCode(group string) *ActionDeadCode
func (a *ActionDeadCode) Clone(groups ActionGroupList) Action
func (a *ActionDeadCode) Apply(data *Funcdata) int
```

Apply returns count of ops removed. If count > 0, returns 1 (changed). Else 0.
Runs multiple times (ActionRuleRepeatApply flag) until stable.

### Integration

Wire ActionDeadCode into the Heritage pipeline after SSA construction:
In pkg/bridge/bridge.go or pkg/pcode/heritage.go, after Heritage() call, run:
```go
deadcode := NewActionDeadCode("deadcode")
for {
    if deadcode.Apply(fd) == 0 { break }
}
```

Run at least 3 iterations (flags feed flags, which feed flags).

### Funcdata helpers needed

If not already present, add to funcdata.go or varnode_ssa.go:
- `func (fd *Funcdata) OpUnlink(op *PcodeOp)` -- removes op from its block and unlinks all varnode connections
- `func (fd *Funcdata) OpDestroy(op *PcodeOp)` -- marks op dead and removes from live list

Check if these exist. If they exist under different names, use those.

## Part 2: ActionSetCasts -- minimal cast insertion

### pkg/pcode/action_setcasts.go (new file)

Ghidra's ActionSetCasts (coreaction.cc ~320-430) inserts explicit casts when type
mismatch is detected. For E2, port the minimal subset needed to handle:

1. **Pointer-to-int and int-to-pointer**: If LOAD/STORE input is wrong size, insert cast.
2. **Size mismatch on COPY**: If sizes differ, emit (type) cast in PrintC.

The cast is currently handled in printc.go renderCast(). The issue is that when no
explicit cast node exists, type mismatches are silently emitted wrong.

For E2: scan PrintC output for COPY ops where input and output DataType differ
significantly (e.g., pointer vs int, different sizes). Insert a CAST op or mark the
op for explicit cast rendering.

Simplest correct approach: after dead code pass, walk all live ops. For each COPY/CAST
op, if input type != output type and the op is not already a CPUI_CAST, check if
insertion is needed based on DataType compatibility. If incompatible, insert a
CPUI_CAST op between them.

```go
type ActionSetCasts struct {
    ActionBase
}

func NewActionSetCasts(group string) *ActionSetCasts
func (a *ActionSetCasts) Clone(groups ActionGroupList) Action
func (a *ActionSetCasts) Apply(data *Funcdata) int
```

This can be a lightweight stub for E2 -- the key deliverable is ActionDeadCode.
ActionSetCasts can be minimal (return 0 for now) as long as it compiles and is wired.

## Part 3: FP Heritage type annotation (E3)

### Modify pkg/pcode/heritage.go or pkg/pcode/heritage_types.go

After Heritage SSA construction, walk all written varnodes. For each varnode that is
the output of a FLOAT_* opcode, set its DataType to float/double:

```go
// markFloatTypes sets float/double DataType on outputs of FLOAT_* ops.
func markFloatTypes(fd *Funcdata) {
    for _, op := range fd.AllLiveOps() {
        if !isFloatOpcode(op.Code()) { continue }
        out := op.Out()
        if out == nil { continue }
        switch out.Size() {
        case 4:  out.SetType(sharedTypeFactory.GetBase(4, TYPE_FLOAT, "float"))
        case 8:  out.SetType(sharedTypeFactory.GetBase(8, TYPE_FLOAT, "double"))
        case 10: out.SetType(sharedTypeFactory.GetBase(10, TYPE_FLOAT, "long double"))
        }
    }
}

func isFloatOpcode(opc OpCode) bool {
    switch opc {
    case CPUI_FLOAT_ADD, CPUI_FLOAT_SUB, CPUI_FLOAT_MULT, CPUI_FLOAT_DIV,
         CPUI_FLOAT_NEG, CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT,
         CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_TRUNC,
         CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND,
         CPUI_FLOAT_NAN, CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL,
         CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL:
        return true
    }
    return false
}
```

Call markFloatTypes(fd) after Heritage in the bridge pipeline (same place as dead code).

Also: propagate float type through COPY chains -- if varnode is defined by COPY of a
float-typed varnode, set its type to float too. Single pass is enough.

### FP calling convention in ProtoModel/ScopeLocal

When classifying params/locals: if a varnode has TYPE_FLOAT, ScopeLocal should use
the float type from the varnode rather than defaulting to int. This feeds into
PrintC's type emission so params show as `float param_0` not `unsigned int param_0`.

## Part 4: PrintC float literal emission

### Modify pkg/pcode/printc.go

Currently, float constants are emitted as integer hex. Fix:

In `renderVarnode()` or `emitConstant()`: when varnode IsConstant() and its type is
TYPE_FLOAT, interpret the raw bits as IEEE-754 float/double and emit as decimal literal:

```go
// emitFloatLiteral converts a constant varnode's bits to float literal string.
func emitFloatLiteral(vn *Varnode) string {
    bits := vn.Offset()  // raw bits from constant varnode
    switch vn.Size() {
    case 4:
        f := math.Float32frombits(uint32(bits))
        if math.IsInf(float64(f), 0) || math.IsNaN(float64(f)) {
            return fmt.Sprintf("0x%xp0f", bits)
        }
        return strconv.FormatFloat(float64(f), 'g', -1, 32) + "f"
    case 8:
        f := math.Float64frombits(bits)
        if math.IsInf(f, 0) || math.IsNaN(f) {
            return fmt.Sprintf("0x%xp0", bits)
        }
        return strconv.FormatFloat(f, 'g', -1, 64)
    default:
        return fmt.Sprintf("0x%x", bits)
    }
}
```

Use this in renderVarnode() when the varnode is a constant with TYPE_FLOAT.

Example: 0x3f800000 -> "1.0f", 0x0 (float) -> "0.0f", 0x4000000000000000 -> "2.0".

## Part 5: Wire into pipeline

### pkg/bridge/bridge.go modifications

After Heritage() returns, add in order:
1. `markFloatTypes(fd)` (E3)
2. `propagateFloatCopy(fd)` (E3)
3. Dead code loop: run ActionDeadCode until stable (E2)
4. `ActionSetCasts.Apply(fd)` once (E2, stub ok)
5. `buildHighVariables(fd.LocalSyms, fd)` -- already from E1, but now with float types
   (so float params/locals get correct type)

The exact function names may differ -- check what E1 wired. The key invariant is:
float type marking happens BEFORE buildHighVariables so params/locals get float type.

## Part 6: E2E tests

### TestE2DeadCodeElimination (pkg/loader/loader_test.go)

Use the existing classify2 binary (35 bytes, TestX86NestedIfFunction).
After E2, the PrintC output must NOT contain:
- "SBORROW" (subtraction borrow op, dead flag)
- "POPCOUNT" (parity flag, dead)
- More than 8 locals declared (currently 25+; after dead code, should be <= 8)

```go
func TestE2DeadCodeElimination(t *testing.T) {
    // ... build classify2 binary ...
    // ... get PrintC output ...
    if strings.Contains(output, "SBORROW") {
        t.Errorf("dead flag op SBORROW should be eliminated, got:\n%s", output)
    }
    if strings.Contains(output, "POPCOUNT") {
        t.Errorf("dead flag op POPCOUNT should be eliminated, got:\n%s", output)
    }
    // Count "local_" declarations
    localCount := strings.Count(output, "local_")
    if localCount > 12 {
        t.Errorf("expected <= 12 locals after dead code elim, got %d:\n%s", localCount, output)
    }
    t.Logf("classify2 E2 output:\n%s", output)
}
```

### TestE3FloatTypeAnnotation (pkg/loader/loader_test.go)

Build a minimal function that uses FLOAT_ADD:
```
FLD  [EBP+8]   (load float param)
FLD1           (push 1.0)
FADD           (add)
FSTP [EBP-4]   (store to local)
```

Actually, since FP decode already works (D20), use the FLD1+FLDZ golden bytes from D20
to construct a simple function that uses FLOAT_ADD p-code.

For E3, the simpler test: build a Funcdata manually, inject a FLOAT_ADD op with two
constant inputs, call markFloatTypes(), verify output varnode has TYPE_FLOAT.

Unit test in pkg/pcode/heritage_test.go or new float_test.go:
```go
func TestMarkFloatTypes(t *testing.T) {
    // Create Funcdata with a FLOAT_ADD op
    // Call markFloatTypes
    // Verify output varnode type == TYPE_FLOAT
}
```

### TestE3FloatLiteralEmit (pkg/pcode/printc_test.go)

Test that emitFloatLiteral(0x3f800000, size=4) == "1.0f"
Test that emitFloatLiteral(0x0, size=4) == "0.0f"
Test that emitFloatLiteral(0x4000000000000000, size=8) == "2.0"

## Part 7: Docs

Update docs/STATUS.md: add E2 and E3 entries.
Update docs/E_PHASE_ROADMAP.md: mark E2 and E3 complete.

## In-scope

1. pkg/pcode/action_deadcode.go (new): ActionDeadCode -- simplified dead store elimination
2. pkg/pcode/action_setcasts.go (new): ActionSetCasts stub
3. pkg/pcode/action_deadcode_test.go (new): unit tests
4. Modify pkg/pcode/heritage.go or heritage_types.go: markFloatTypes, propagateFloatCopy
5. Modify pkg/pcode/printc.go: emitFloatLiteral for constant float varnodes
6. Modify pkg/bridge/bridge.go: wire dead code pass + float type marking
7. Modify pkg/pcode/scopelocal.go: use float type for float varnodes in param/local naming
8. pkg/loader/loader_test.go: TestE2DeadCodeElimination, TestE3FloatLiteralEmit E2E tests
9. pkg/pcode/printc_test.go: TestE3FloatLiteralEmit unit test
10. docs/STATUS.md, docs/E_PHASE_ROADMAP.md

## Out-of-scope

- Full consume-mask propagation (Ghidra's 400-line ActionDeadCode::apply) -- simplified ok
- Aggressive dead code beyond flag stores (keeps the test invariant simple)
- Full CastStrategy port -- ActionSetCasts stub is acceptable
- FP calling conventions (register-passed floats, SSE xmm0) -- x87 stack only
- NaN/Inf special-casing beyond basic rendering
- x86-64 FP

## Invariants

- All existing tests pass (113 golden subtests, 21+ E2E tests including E1's)
- go test ./... passes green
- No new external dependencies (math, strconv, fmt are stdlib -- ok)
- ASCII-only, tabs for indentation, English comments
- Dead code pass must NOT remove ops with side effects (STORE, CALL, BRANCH, RETURN)
- Float literal rendering must not panic on NaN/Inf inputs (use fallback hex format)

## Done when

- go test ./... passes green
- TestE2DeadCodeElimination passes: output contains no SBORROW, no POPCOUNT
- TestE3FloatLiteralEmit unit test passes: 1.0f, 0.0f, 2.0 literals correct
- classify2 PrintC output has <= 12 locals (flag clutter removed)
- docs/STATUS.md has E2+E3 entries
