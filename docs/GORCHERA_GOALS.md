# Gorchera Chain Goals -- Gosleigh Sleigh Runtime Parity (v2)

이 문서는 Gosleigh Sleigh runtime parity 작업을 gorchera chain 4개로 나눈 goal 초안이다.
기존 3-chain 구조에서 Chain 1을 1a/1b로 분할했다.
각 chain은 하나의 gorchera start_chain 호출에 대응한다.
오케스트레이터가 각 chain 완료 후 결과를 확인하고 다음 chain을 시작한다.

## 공통 전제

- 원본 C++ 참조 경로: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/`
- 구현 대상 패키지: `pkg/sla/`, `pkg/bridge/`
- 현재 브랜치: `master`
- 모든 변경 후 `go test ./...` 통과 필수
- parity가 안 맞으면 `known mismatch` / `unimplemented` 주석으로 명시하고 넘어간다
- 코드 주석은 영어, 비ASCII 문자 금지

## 공통 gorchera 설정

```
context_mode: summary
strictness: strict
pipeline_mode: light
ambition_level: high
provider: claude
```

---

## Chain 1a: oneInstruction() Catch Parity (max_steps: 8)

### 목적

`oneInstruction()` catch 블록 full coverage.
`LowlevelError` vs `*UnimplError` 분리, `wrapTranslateUnimplError()` 모든 실패 경로 커버.
Chain 1a는 1b와 독립적으로 실행 가능하다.

### Goal 텍스트

```
You are implementing oneInstruction() catch parity for Gosleigh, a Go port of the Ghidra decompiler.

ACCEPTANCE CRITERIA (verify these pass before marking done):
- translate_test.go has tests for each catch branch: *UnimplError path, LowlevelError path, unexpected error path.
- All existing tests in translate_test.go pass without regression.
- wrapTranslateUnimplError() is called on every failure exit inside the build/resolve/emit tail block.
- Plain infrastructure errors (LowlevelError equivalent) pass through unchanged (not promoted to UnimplError).
- go test ./... passes.

ALREADY TRUE:
- pkg/sla/translate.go TranslateSubtable() has the main oneInstruction() tail: alignment gate, delay-slot prep, ParserWalker, build -> resolveRelatives -> emit order.
- wrapTranslateUnimplError() exists and handles the *UnimplError typed subset.
- builder_delay.go and builder_cross.go return errors on failure paths.

MUST CHANGE:
1. oneInstruction() catch parity tightening (translate.go, builder_delay.go, builder_cross.go):
   - Audit all failure paths inside the build/resolve/emit tail block in TranslateSubtable().
   - Ensure wrapTranslateUnimplError() covers ALL failure paths, not just the typed *UnimplError subset.
   - LowlevelError equivalent (plain infrastructure error from builder_delay.go / builder_cross.go) must pass through unchanged -- do NOT promote to UnimplError.
   - *UnimplError must be rewritten in place with explain text from the current walker state.
   - Audit builder_delay.go and builder_cross.go for any remaining catch-path gaps vs C++ oneInstruction() catch(UnimplError&) / catch(LowlevelError&) / catch(...) blocks.
   - Reference: ghidra-ref/.../sleigh.cc Sleigh::oneInstruction() lines ~450-520.
2. Add tests in translate_test.go for each catch branch (UnimplError rewrite, LowlevelError passthrough, unexpected error passthrough).

MUST NOT REGRESS:
- All existing tests in translate_test.go.
- Any existing test that exercises the build/resolve/emit path in TranslateSubtable().
```

### 대상 Go 파일 목록

```
pkg/sla/translate.go            -- wrapTranslateUnimplError() catch coverage
pkg/sla/builder_delay.go        -- LowlevelError vs UnimplError separation audit
pkg/sla/builder_cross.go        -- LowlevelError vs UnimplError separation audit
pkg/sla/translate_test.go       -- catch branch tests (추가)
```

### 참조 C++ 파일 목록

```
ghidra-ref/.../sleigh.cc        -- Sleigh::oneInstruction() catch blocks (~450-520)
```

(실제 전체 경로: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/`)

### 완료 기준

1. `go test ./...` 전체 통과
2. `translate_test.go`에 catch 분기별 테스트 추가, 통과
3. 기존 `translate_test.go` 테스트 전부 통과 (회귀 없음)

### 의존성 / 선행 조건

없음. 현재 master 브랜치 그대로 시작 가능. Chain 1b와 독립적.

### 예상 리스크

- builder_delay.go / builder_cross.go 에서 반환하는 에러 타입이 일관성 없을 수 있음.
  catch 분기 분리 전에 두 파일의 에러 반환 경로를 전부 목록화하고 진행할 것.

---

## Chain 1b: PcodeCacher + BuildXrefs + Handle Paths (max_steps: 10)

### Gorchera 설정 오버라이드

```
role_overrides:
  director:
    provider: codex
  evaluator:
    provider: codex
```

(executor는 공통 설정대로 claude. GPT 5.4가 계획/검증, Sonnet이 구현.)

### 목적

`PcodeCacher` pool/lifecycle 완성, `BuildXrefs()` runtime 연결,
`ContextSymbol` / `ValueMapSymbol` `getFixedHandle()` 자동 경로.
Chain 1b의 task들은 서로 커플링되어 있어 단일 chain으로 묶는다.
Chain 1a 완료 여부와 무관하게 실행 가능하나 1a와 병렬로 시작할 경우 translate.go 충돌 주의.

### Goal 텍스트

```
You are implementing PcodeCacher pool integration, BuildXrefs runtime wiring, and symbol handle paths for Gosleigh.

ACCEPTANCE CRITERIA (verify these pass before marking done):
- discache_test.go: pool direct path test (allocateInstruction() called per issued op) passes.
- xrefs_test.go: BuildXrefs wiring test (UserOpNames lookup, ContextFields access) passes.
- resolve_handles_test.go: ContextSymbol fixed-handle automatic path test passes.
- resolve_handles_test.go: ValueMapSymbol fixed-handle automatic path test passes.
- PARITY_AUDIT.md updated for changed symbols.
- go test ./... passes.

ALREADY TRUE:
- pkg/sla/discache.go has PcodeCacher pool mirrors: allocateInstruction, reset pool-retain, 600 initial size. AppendRawBuild uses appendIssued() wrapper rather than allocateInstruction() directly. allocateVarnodes() integration is partial.
- pkg/sla/xrefs.go BuildXrefs() is implemented and registers xref/userop/context tables, but those tables are NOT wired into runtime resolve or pattern-evaluation paths.
- pkg/sla/resolve_handles.go getFixedHandle() covers: NameSymbol, EpsilonSymbol, VarnodeSymbol, VarnodeListSymbol, OperandSymbol handoff, flow-symbol safe opaque-boundary path.
- ContextSymbolBoundary and PatternSymbolBoundary are decoded and stored in symbols.go.

MUST CHANGE:
1. AppendRawBuild -> allocateInstruction() direct integration (discache.go):
   - Connect AppendRawBuild() to allocateInstruction() so each issued op is appended via the mirrored allocateInstruction() path instead of the current appendIssued() wrapper.
   - Connect allocateVarnodes() as the bump-allocator for input/output varnode slots before filling them.
   - After change: AppendRawBuild must mirror C++ PcodeCacher::dump() flow: allocateVarnodes(n) -> fill varnodeData -> allocateInstruction() -> fill PcodeData.
   - Verify expandPool() rebind logic still works after this change (existing pool growth test must pass).
   - Reference: ghidra-ref/.../sleigh.cc PcodeCacher::dump().

2. infallible sink semantics documentation (discache.go):
   - C++ PcodeEmit::dump() is void (infallible). Current Go sink returns error. Add a note documenting this known Go-only gap.
   - Optionally add a wrapper that converts sink errors into panic with a clear message so callers get the same abort-on-failure behavior as C++.
   - Document this explicitly as a known mismatch in PARITY_AUDIT.md.
   - Reference: ghidra-ref/.../pcoderaw.hh PcodeEmit::dump().

3. BuildXrefs() runtime wiring (xrefs.go, resolve_handles.go, patexpr.go, engine.go):
   - Wire the XRefs table built by BuildXrefs() into runtime paths:
     (a) UserOpNames: when builder encounters CALLOTHER op, look up user-op name from XRefs.UserOpNames by index.
     (b) ContextFields: when patexpr.go evaluates a ContextSymbol node, use XRefs.ContextFields to find the bit-range (low/high) and read from parser context's context word array. Currently ContextSymbol pattern access uses ContextSymbolBoundary directly; verify consistency or add fallback.
     (c) If XRefs is nil, fall back to existing paths gracefully.
   - Update Engine struct to hold *XRefs and pass it through TranslateInput so resolve/patexpr paths can access it.
   - Reference: ghidra-ref/.../sleighbase.cc SleighBase::buildXrefs(), ghidra-ref/.../slghsymbol.cc ContextSymbol::getPatternValue().

4. ContextSymbol getFixedHandle() automatic path (resolve_handles.go):
   - C++ ContextSymbol inherits ValueSymbol::getFixedHandle (slghsymbol.hh).
   - ValueSymbol::getFixedHandle sets handle.space = constant_space, handle.offset_offset = getPatternValue(walker), handle.size = patval->size().
   - Use ContextSymbolBoundary.Varnode to find size; evaluate pattern value via GetPatternExpressionValue() using ContextSymbolBoundary.Pattern.
   - If pattern evaluation fails, return typed *UnimplError with explain text.
   - Reference: ghidra-ref/.../slghsymbol.cc ValueSymbol::getFixedHandle(), ghidra-ref/.../slghsymbol.hh ContextSymbol class declaration.

5. ValueMapSymbol getFixedHandle() automatic path (resolve_handles.go):
   - C++ ValueMapSymbol::getFixedHandle reads selector via getPatternValue(), uses valuetable[selector] as offset_offset, sets space = constant_space.
   - Use PatternSymbolBoundary.ValueTable (already persisted in symbols.go).
   - Out-of-range selector: return typed *UnimplError.
   - Reference: ghidra-ref/.../slghsymbol.cc ValueMapSymbol::getFixedHandle().

After all tasks:
- Run go test ./... and fix any regressions.
- Add targeted unit tests for each new automatic path.
- Update PARITY_AUDIT.md entries for changed symbols.
- Update docs/RUNTIME_FLOW.md "currently automatic path" section to reflect new coverage.
- Do NOT modify ghidra-ref/ (read-only reference).
- Do NOT introduce non-ASCII characters in code or output.
- Indent with tabs (Go standard).

MUST NOT REGRESS:
- Existing pool growth test in discache_test.go (expandPool rebind).
- All existing tests in resolve_handles_test.go.
- All existing tests in xrefs_test.go.
```

### 대상 Go 파일 목록

```
pkg/sla/discache.go             -- PcodeCacher pool direct integration, sink semantics
pkg/sla/xrefs.go                -- BuildXrefs runtime wiring
pkg/sla/resolve_handles.go      -- ContextSymbol / ValueMapSymbol getFixedHandle()
pkg/sla/patexpr.go              -- ContextFields wiring from XRefs
pkg/sla/engine.go               -- XRefs field addition, pass-through to TranslateInput
pkg/sla/symbols.go              -- (read) ContextSymbolBoundary, PatternSymbolBoundary
pkg/sla/discache_test.go        -- pool direct path tests (추가)
pkg/sla/xrefs_test.go           -- BuildXrefs wiring tests (추가)
pkg/sla/resolve_handles_test.go -- ContextSymbol / ValueMap handle tests (추가)
docs/PARITY_AUDIT.md            -- changed entries update
docs/RUNTIME_FLOW.md            -- automatic path section update
```

### 참조 C++ 파일 목록

```
ghidra-ref/.../sleigh.cc        -- PcodeCacher::dump(), emit()
ghidra-ref/.../sleigh.hh        -- PcodeCacher class, PcodeEmit interface
ghidra-ref/.../slghsymbol.cc    -- ValueSymbol::getFixedHandle(), ContextSymbol, ValueMapSymbol
ghidra-ref/.../slghsymbol.hh    -- class declarations
ghidra-ref/.../slghpatexpress.cc -- ContextSymbol::getPatternValue()
ghidra-ref/.../sleighbase.cc    -- SleighBase::buildXrefs()
ghidra-ref/.../pcoderaw.hh      -- PcodeEmit::dump() signature
```

(실제 전체 경로: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/`)

### 완료 기준

1. `go test ./...` 전체 통과
2. `discache_test.go`에 allocateInstruction() direct path 테스트 추가, 통과
3. `xrefs_test.go`에 BuildXrefs-wired ContextSymbol pattern evaluation 테스트 추가, 통과
4. `resolve_handles_test.go`에 ContextSymbol fixed-handle 자동 경로 테스트 추가, 통과
5. `resolve_handles_test.go`에 ValueMapSymbol fixed-handle 자동 경로 테스트 추가, 통과
6. `PARITY_AUDIT.md`에 변경된 항목 업데이트 확인 (infallible sink known mismatch 포함)
7. `RUNTIME_FLOW.md` 자동 경로 섹션 업데이트 확인

### 의존성 / 선행 조건

Chain 1a와 독립적으로 실행 가능. translate.go를 직접 수정하지 않으므로 1a와 병렬 실행 허용.
단, 같은 파일(engine.go 등)을 동시에 수정하면 충돌 가능 -- 병렬 실행 시 오케스트레이터가 워크트리 격리 여부 판단.

### 예상 리스크

- allocateInstruction() 통합 후 pool growth rebind 경로가 인덱스 기준으로 동작하는지 주의.
  기존 `discache_test.go` pool growth 테스트로 회귀 감지 가능.
- BuildXrefs() wiring 시 XRefs nil 체크를 빠뜨리면 engine 미초기화 경로에서 패닉 발생.
  Engine 구성 경로(NewEngineFromBoundaries 등)에서 nil XRefs graceful 처리 필수.
- ContextSymbol pattern evaluation이 기존 ContextSymbolBoundary 직접 접근 경로와 중복될 수 있음.
  충돌 시 기존 동작 우선, 새 경로는 보조로 추가.

---

## Chain 2: Decode Pipeline + Data Parity (max_steps: 10)

### 목적

decode pipeline이 synthetic setup 없이 `DisassemblyCache`를 실제로 채우는 경로 완성,
`ContextSymbolBoundary` / `ContextOpBoundary` runtime 활용 연결.
이 chain이 끝나면 실제 instruction bytes + context만으로 translation path가
처음부터 끝까지 자동으로 동작하는 기반이 생긴다.

### Goal 텍스트

```
You are implementing decode pipeline and .sla runtime data parity for Gosleigh.

ACCEPTANCE CRITERIA (verify these pass before marking done):
- load_context_test.go: ContextOpBoundary application test passes (context word modified at correct bit range).
- integration_test.go: same-address cache-hit second-call test passes (second TranslateInstructionAt() does not re-run Resolve()).
- GetN2addr() unavailable path returns typed *UnimplError, test passes.
- go test ./... passes.
- PARITY_AUDIT.md ContextSymbolBoundary/ContextOpBoundary entries updated.

ALREADY TRUE:
- DisassemblyCache circular parser-context reuse path exists (ObtainContext).
- Translation entry has address-scoped payload sourcing (ByAddress map, Lookup callback, Loader(addr) first-class route). Split LoadFill/LoadContext hooks exist.
- ObtainPcodeContext() has lazy inst_next2 derivation via GetN2addr().
- ParserContext.GetN2addr() has lazy resolver binding.
- ContextSymbolBoundary (varnode/low/high/flow) and ContextOpBoundary (num/shift/mask) are decoded and stored in symbols.go, but NOT yet used in runtime resolve or context commit paths.
- BuildXrefs() (from Chain 1b) registers context field tables.
- Current decode pipeline still relies on synthetic test seeding for most paths.

MUST CHANGE:
1. ContextSymbolBoundary runtime activation (load_context.go ApplyCommits()):
   - When a context commit references a ContextSymbol, use ContextSymbolBoundary fields (low/high for bit-range, flow for flow-type) to write the context word at the correct bit range in the parser context's context word array. Currently this path is behind a hook or unimplemented.
   - Reference: ghidra-ref/.../context.cc ParserContext::applyCommits(), ghidra-ref/.../slghsymbol.cc ContextSymbol fields (low/high/flow), ghidra-ref/.../context.hh ContextSet struct.

2. ContextOpBoundary runtime activation (load_context.go or new context_op.go):
   - Implement ContextOp application using ContextOpBoundary (num/shift/mask).
   - C++ applyContextBlock() iterates ContextOp entries and applies them to context word.
   - Go equivalent: iterate ContextOpBoundary entries for the matched constructor and apply (value << shift) & mask to context word [num].
   - Reference: ghidra-ref/.../sleigh.cc Sleigh::applyContext() / applyContextBlock(), ghidra-ref/.../context.hh ContextOp struct.

3. Decode pipeline DisassemblyCache population (obtain_context.go, resolve.go):
   - After a successful Resolve() pass, ensure the resolved parser context (handles, constructor, length, naddr, calladdr) is fully committed into DisassemblyCache so a subsequent cache hit returns a fully populated entry.
   - After setParserState(disassembly) is called at the end of Resolve(), the DisassemblyCache entry for that address should be queryable by subsequent ObtainContext() calls at the same address without re-running Resolve().
   - Current gap: circular reuse resets parse state on address mismatch (correct), but after a successful resolve the cache population path may not propagate all resolved fields (handles, calladdr) back into the cache entry in a way that survives a subsequent same-address lookup.
   - Reference: ghidra-ref/.../sleigh.cc Sleigh::resolve() end, DisassemblyCache::getParserContext().

4. ParserContext::getN2addr() unavailable path cleanup (walker.go, instruction_context.go):
   - C++ ParserContext::getN2addr() throws when next address is unavailable. Current Go returns an invalid address instead.
   - Add an explicit typed *UnimplError for the unavailable case so callers can distinguish "not computed yet" (lazy resolver pending) from "computed but invalid" from "address space unavailable".
   - Update callers to handle the new error gracefully (fall back to invalid addr).
   - Reference: ghidra-ref/.../context.cc ParserContext::getN2addr().

5. delay/crossbuild cache population without synthetic setup (builder_delay.go, builder_cross.go):
   - Currently require that the target parser context for the inner instruction already exists in DisassemblyCache; if not, return unimplemented error.
   - Improve: if target address context is missing, attempt to obtain it via ObtainContext(targetAddr, ParseStateDisassembly) before the inner build. This triggers a real decode pass for the delay-slot instruction.
   - Only do this if a Loader is available in the current translate context; if no loader exists, keep the existing unimplemented error path.
   - Reference: ghidra-ref/.../sleigh.cc SleighBuilder::delaySlot(), ghidra-ref/.../sleigh.cc SleighBuilder::appendCrossBuild().

6. slice-return compatibility cleanup (translate.go, discache.go, engine.go):
   - Audit for any remaining slice-return compatibility paths (helper slice materialised before sink emission) that were supposed to be removed.
   - Remove any that remain; ensure all raw-op consumption goes through the sink/cache path.
   - This is a cleanup step; no new behavior, only parity maintenance.

After all tasks:
- Run go test ./... and fix any regressions.
- Add integration test: build a minimal Engine from a real 6502.sla (testdata/6502.sla or testdata/6502-packed.sla), load a short instruction sequence (e.g. BRK = 0x00), run TranslateInstructionAt(), verify that a second call at the same address hits the cache and returns the same ops without re-running Resolve().
- Add test for ContextOp application: construct a minimal ContextOpBoundary, apply it, verify the context word is modified at the correct bit range.
- Update PARITY_AUDIT.md for ContextSymbolBoundary/ContextOpBoundary runtime status.
- Update docs/RUNTIME_FLOW.md section 3 (Pcode Context Preparation) and section 1 (Disassembly Resolve) to reflect the new cache population path.
- Do NOT modify ghidra-ref/.
- Do NOT introduce non-ASCII characters in code or output.
- Indent with tabs.

MUST NOT REGRESS:
- All existing tests in load_context_test.go, walker_test.go, integration_test.go.
- Existing builder_delay / builder_cross tests.
```

### 대상 Go 파일 목록

```
pkg/sla/load_context.go         -- ContextSymbolBoundary / ContextOpBoundary apply
pkg/sla/obtain_context.go       -- DisassemblyCache population after Resolve()
pkg/sla/resolve.go              -- cache population wiring at Resolve() end
pkg/sla/walker.go               -- GetN2addr() unavailable path typed error
pkg/sla/instruction_context.go  -- ObtainPcodeContext() GetN2addr error handling
pkg/sla/builder_delay.go        -- auto-obtain delay-slot context if loader available
pkg/sla/builder_cross.go        -- auto-obtain crossbuild context if loader available
pkg/sla/translate.go            -- slice-return cleanup audit
pkg/sla/discache.go             -- slice-return cleanup, population visibility
pkg/sla/engine.go               -- slice-return cleanup
pkg/sla/load_context_test.go    -- ContextOp application test (추가)
pkg/sla/integration_test.go     -- cache-hit second-call test (추가)
docs/PARITY_AUDIT.md
docs/RUNTIME_FLOW.md
```

### 참조 C++ 파일 목록

```
ghidra-ref/.../context.cc       -- ParserContext::applyCommits(), getN2addr(), loadContext()
ghidra-ref/.../context.hh       -- ContextSet, ContextOp structs
ghidra-ref/.../sleigh.cc        -- Sleigh::resolve() end, applyContext(), SleighBuilder::delaySlot()
ghidra-ref/.../sleigh.hh        -- DisassemblyCache::getParserContext()
ghidra-ref/.../slghsymbol.cc    -- ContextSymbol fields (low/high/flow)
```

(실제 전체 경로: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/`)

### 완료 기준

1. `go test ./...` 전체 통과
2. `load_context_test.go`에 ContextOpBoundary 적용 테스트 추가, 통과
3. `integration_test.go`에 same-address cache-hit 두 번째 호출 테스트 추가, 통과
4. `GetN2addr()` unavailable 경로가 typed *UnimplError를 반환하는 테스트 추가, 통과
5. `PARITY_AUDIT.md`의 ContextSymbolBoundary / ContextOpBoundary 항목 status 갱신
6. `RUNTIME_FLOW.md` Disassembly Resolve + Pcode Context Preparation 섹션 갱신

### 의존성 / 선행 조건

- Chain 1a + 1b 완료가 선행되어야 한다.
  ContextSymbolBoundary runtime 활용이 BuildXrefs() 등록 테이블(Chain 1b)과 일관성을 가져야 하기 때문.
- Chain 1b가 완료되지 않았다면 ContextSymbol 관련 task는 독립적으로 구현하고 나중에 reconcile한다.

### 예상 리스크

- DisassemblyCache population 후 circular reuse slot이 overwrite되는 타이밍 문제.
  실제 .sla 기반 integration test로만 발견 가능한 버그이므로 반드시 real-file test 추가.
- delay-slot auto-obtain 시 Loader nil 체크를 빠뜨리면 nil 역참조. 명시적 nil guard 필수.
- ContextOp apply 시 shift/mask 순서가 C++ 원본과 달라질 수 있음. 원본 context.cc 정확히 참조.

---

## Chain 3: Verification + E2E Integration (max_steps: 10)

### 목적

Golden test harness 구축, bridge 패키지 완성, 다양한 아키텍처 테스트.
Phase 4-5 (decompiler pipeline, C output)는 이미 구현 완료 상태이므로 이 chain은
verification/stabilization에 집중한다.
광범위한 fix는 하지 않고, 발견된 gap은 triage/document만 한다.
"unimplemented"는 golden fixture에 expected output으로 기록하며 CI를 막지 않는다.

### Goal 텍스트

```
You are implementing verification, golden testing, and E2E integration for Gosleigh.
This is a stabilization chain -- do NOT attempt broad new fixes. Triage and document gaps.

ACCEPTANCE CRITERIA (verify these pass before marking done):
- pkg/sla/golden_test.go exists; testdata/golden/ has at least 3 fixtures for 6502.
- Each golden test passes as "match" or "unimplemented" -- no hard failure.
- pkg/bridge/bridge_test.go TestBuildE2EWithRealSLA passes (skip allowed, hard fail not allowed).
- bridge.Result.Warnings field exists and UnimplError graceful handling works.
- docs/STATUS.md marks WU6 (Verification) as complete.
- go test ./... passes.

ALREADY TRUE:
- Phase 4-5 (decompiler pipeline: Funcdata, BlockGraph, SSA construction, C output ~120 rules, PrintC) is implemented and committed.
- pkg/sla/ runtime translation path is largely complete with parity for most symbol kinds (after Chain 1a, 1b).
- pkg/bridge/ Build() and BuildFuncdata() work: translate instructions via Engine, build basic blocks, discover CFG edges, build Funcdata + BlockGraph.
- bridge_test.go has TestBuild6502ProgramToC and TestBuildSplitsAfterFlowBreak tests using real 6502.sla.
- testdata/ contains 6502.sla (XML v3) and 6502-packed.sla (packed v4).
- No golden comparison test exists yet.

MUST CHANGE:
1. Golden test harness (pkg/sla/golden_test.go, testdata/golden/):
   - Create testdata/golden/ directory.
   - Create pkg/sla/golden_test.go that:
     (a) Loads 6502.sla.
     (b) Builds an Engine with a known byte sequence.
     (c) Calls TranslateInstructionAt() and captures emitted raw ops.
     (d) Compares against a golden JSON fixture stored in testdata/golden/.
     (e) If GOSLEIGH_UPDATE_GOLDEN=1 env var is set, writes fixture instead of comparing (update mode).
   - Golden fixture format: JSON array of objects with fields: address (hex string), opcode (string name), inputs (array of varnode desc), output (varnode desc or null).
   - If TranslateInstructionAt() returns *UnimplError for some instructions, record as "unimplemented" in the fixture rather than failing. This lets the golden suite evolve as parity improves.
   - Seed at least 3 golden fixtures for 6502: BRK (0x00), NOP (if available), one addressing mode instruction.

2. Bridge E2E completeness test (pkg/bridge/bridge_test.go):
   - Add TestBuildE2EWithRealSLA that:
     (a) Loads 6502.sla from testdata/.
     (b) Builds Engine with a short multi-instruction byte sequence including at least one branch (block splitting exercised).
     (c) Calls bridge.Build() and verifies: Result.Funcdata non-nil, Result.Graph has at least 2 basic blocks, Result.Instructions has expected count.
     (d) If TranslateInstructionAt() fails mid-sequence, log the error and skip -- do NOT hard-fail.
   - This test augments existing TestBuild6502ProgramToC.

3. bridge.Build() robustness (pkg/bridge/bridge.go):
   - In collectInstructions(): currently returns error if TranslateInstructionAt() fails. Change to: if error is *sla.UnimplError, record failure with address in Warnings []string field on Result and stop collection (treat as end of function). Only hard-fail on non-unimplemented errors.
   - Add Warnings field to bridge.Result struct.
   - Update TestBuildE2EWithRealSLA to check Warnings if present.
   - Reference: pkg/sla/translate.go UnimplError type.

4. Multi-architecture fixture expansion (testdata/):
   - Add at least one additional architecture .sla fixture: prefer x86.sla (32-bit) if available in local Ghidra installation, otherwise ARM or MIPS.
   - If no additional .sla is available on the build machine, add a test that skips with t.Skip("no additional arch .sla available").
   - For additional architecture: add one golden test entry in the same format as task 1.

5. Parity gap triage from Chain 1a/1b/2 (PARITY_AUDIT.md):
   - After running golden tests and bridge E2E, collect all unimplemented errors that appear.
   - For each distinct error: check if it corresponds to a known PARITY_AUDIT.md entry. If not, add a new entry with status "unimplemented" and describe what is missing.
   - Fix regressions introduced by Chain 1a/1b/2 changes that break existing translate_test.go / integration_test.go tests.
   - Do NOT attempt to fix broad new unimplemented paths in this chain. Goal is a stable, documented regression baseline.
   - Unimplemented paths discovered here become expected outputs in golden fixtures, not failures.

6. STATUS.md and PARITY_AUDIT.md update:
   - Update docs/STATUS.md to mark WU6 (Verification) as complete.
   - Update docs/PARITY_AUDIT.md with any new entries from task 5.
   - Update docs/RUNTIME_FLOW.md if the cache population path from Chain 2 changed any documented section.

After all tasks:
- Run go test ./... and fix any regressions.
- Confirm golden fixtures exist and at least 3 pass (match or unimplemented -- no hard fail).
- Confirm bridge E2E test runs without hard failure on at least the BRK sequence.
- Do NOT modify ghidra-ref/.
- Do NOT introduce non-ASCII characters in code or output.
- Indent with tabs.

MUST NOT REGRESS:
- All existing tests in pkg/bridge/bridge_test.go (TestBuild6502ProgramToC, TestBuildSplitsAfterFlowBreak).
- All existing tests in pkg/sla/translate_test.go and integration_test.go.
```

### 대상 Go 파일 목록

```
pkg/sla/golden_test.go          -- (신규) golden test harness
pkg/sla/integration_test.go     -- 기존 integration test 보강
pkg/bridge/bridge.go            -- Warnings field, UnimplError graceful handling
pkg/bridge/bridge_test.go       -- TestBuildE2EWithRealSLA 추가
testdata/golden/                -- (신규 디렉토리) golden JSON fixtures
testdata/                       -- 추가 arch .sla fixture (있는 경우)
docs/STATUS.md                  -- WU6 완료 표시
docs/PARITY_AUDIT.md            -- 신규 parity gap 항목
docs/RUNTIME_FLOW.md            -- 필요 시 갱신
```

### 참조 C++ 파일 목록

```
ghidra-ref/.../sleigh.cc        -- Sleigh::oneInstruction() emitted op reference behavior
ghidra-ref/.../pcoderaw.hh      -- PcodeEmit::dump() signature -- golden format 기준
ghidra-ref/.../slghsymbol.cc    -- constructor print paths -- mnemonic/body for fixture labeling
```

(실제 전체 경로: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/`)

### 완료 기준

1. `go test ./...` 전체 통과
2. `pkg/sla/golden_test.go` 존재, `testdata/golden/` 아래 6502 fixture 3개 이상
3. 각 golden test가 "match" 또는 "unimplemented" 상태로 통과 (hard fail 없음)
4. `pkg/bridge/bridge_test.go`의 TestBuildE2EWithRealSLA 통과 (skip 허용, hard fail 불가)
5. `bridge.Result.Warnings` 필드 존재, UnimplError graceful handling 동작
6. `docs/STATUS.md` WU6 완료 체크 추가
7. `docs/PARITY_AUDIT.md` 신규 unimplemented 항목 추가 (발견된 경우)

### 의존성 / 선행 조건

- Chain 1a + 1b 완료 필수.
- Chain 2 완료 권장이나 필수는 아님.
  Chain 2 미완 상태에서 Chain 3을 실행하면 일부 golden이 "unimplemented"로 기록되며,
  Chain 2 완료 후 golden을 업데이트(GOSLEIGH_UPDATE_GOLDEN=1)하면 된다.

### 예상 리스크

- 6502 BRK 등 실제 instruction이 Chain 1a/1b/2 이후에도 unimplemented error를 낼 수 있음.
  golden test가 "unimplemented" 기록 모드를 가져야 CI가 막히지 않음.
- bridge.go collectInstructions() 변경이 기존 TestBuildSplitsAfterFlowBreak 같은
  테스트의 기대 동작을 바꿀 수 있음. 기존 테스트 동작을 먼저 확인하고 호환 유지.
- 추가 arch .sla가 없는 환경에서 t.Skip() 처리가 누락되면 CI에서 hard fail.
  반드시 t.Skip() + 명시적 skip 메시지 필수.

---

## 실행 순서 요약

| 순서 | Chain | 선행 조건 | max_steps |
|------|-------|-----------|-----------|
| 1a | oneInstruction() Catch Parity | 없음 (1b와 독립) | 8 |
| 1b | PcodeCacher + BuildXrefs + Handle Paths | 없음 (1a와 독립) | 10 |
| 2 | Decode Pipeline + Data Parity | Chain 1a + 1b 완료 | 10 |
| 3 | Verification + E2E Integration | Chain 1a + 1b 필수, Chain 2 권장 | 10 |

Chain 1a와 1b는 병렬 실행 가능 (translate.go 수정이 겹치지 않는 경우).
각 chain 완료 후 오케스트레이터가 `go test ./...` 결과와 PARITY_AUDIT.md 변경을 확인한다.
다음 chain은 그 확인 후 시작한다.
