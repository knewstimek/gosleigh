# Goal 02: cmd/gosleigh CLI + Action Rule Oscillation Fix

## Part A: Fix addunsigned/sub2add oscillation

The bridge test (pkg/bridge/bridge_test.go) currently disables `addunsigned` and `sub2add` rules because they oscillate (infinite loop) on translated 6502 p-code in the batch-A action pool.

This is a parity gap: Ghidra's C++ rules do not oscillate. The Go implementations must match the C++ guard conditions that prevent re-application.

### Investigation
1. Read pkg/pcode/action.go or the file containing addunsigned/sub2add rule implementations
2. Read the corresponding C++ rules in ghidra-ref/.../decompile/cpp/ (likely ruleaction.cc or similar)
3. Compare guard conditions -- what prevents re-triggering in C++?
4. Fix the Go rules to match C++ guards
5. Remove the rule disabling in bridge_test.go and verify no oscillation

### Success criteria
- Bridge test passes WITHOUT disabling addunsigned/sub2add
- go test ./pkg/bridge/... passes
- go test ./... passes

## Part B: cmd/gosleigh CLI

Build a minimal CLI that:
1. Takes a binary file path and an architecture .sla file path as arguments
2. Optionally takes a function entry address (default 0x0)
3. Loads the .sla, sets up the Engine with the binary as raw instruction source
4. Runs the bridge (pkg/bridge) to produce Funcdata
5. Runs Heritage -> Actions -> PrintC
6. Prints the C output to stdout

### Usage
```
gosleigh -sla <path.sla> -bin <binary> [-entry 0x1000] [-size 32]
```

### Files
- cmd/gosleigh/main.go -- the CLI entry point

### Success criteria
- `go build ./cmd/gosleigh/` produces a working binary
- Running it with testdata/6502.sla and a small 6502 binary produces C output on stdout
- go test ./... passes

## Constraints
- Use mcp__agent-tool__* tools
- Tabs indentation, English comments, no non-ASCII in code
- Check C++ reference for rule guard conditions before fixing oscillation
