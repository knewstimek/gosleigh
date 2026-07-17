# Runtime Flow

## 목적

이 문서는 현재 Gosleigh의 runtime parity 경로를 원본 Ghidra C++ 기준으로 고정하는 작업 노트다.
충돌이 있으면 이 문서보다 `ghidra-ref/` 원본 C++가 우선한다.

현재 기준 권위 경로는 아래 네 축이다.

- `Resolve()`
- `ResolveHandles()`
- `LoadContext()` / `AddCommit()` / `ApplyCommits()`
- `ObtainPcodeContext()`

이 문서는 `translate.go`의 옛 boundary-only 흐름보다 위 네 축을 우선 경로로 본다.
현재 `TranslateSubtable()`는 실제로 이 권위 경로를 진입점으로 사용한다.
다만 아직 원본 `Sleigh::oneInstruction()`의 전체 후반부와 완전히 동등한 상태는 아니다.

## 원본 기준점

직접 대조한 핵심 원본 위치:

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.cc`
  - `Sleigh::resolve()`
  - `Sleigh::resolveHandles()`
  - `oneInstruction()` 준비 경로
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/context.cc`
  - `ParserContext::loadContext()`
  - `ParserContext::addCommit()`
  - `ParserContext::applyCommits()`
  - `ParserWalker::setOutOfBandState()`
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/slghsymbol.cc`
  - `OperandSymbol::decode()`
  - `OperandSymbol::getFixedHandle()`
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/slghpatexpress.cc`
  - `PatternExpression::getValue()`
  - `OperandValue::getValue()`

## 현재 권위 실행 순서

### 1. Disassembly Resolve

원본 `Sleigh::resolve()` 기준 현재 Go shell 순서는 아래와 같다.

1. `LoadFill`
2. `ParserWalkerChange` 생성
3. root state reset
4. `setDelaySlot(0)`
5. `setOffset(0)`
6. `ClearCommits()`
7. `LoadContext()`
8. root constructor resolve
9. `setConstructor()`
10. constructor-local context 적용 결과를 commit queue로 예약
11. operand descent
12. child constructor resolve 반복
13. `calcCurrentLength()`
14. `delay slot` 반영
15. `setNaddr()`
16. `setParserState(disassembly)`

현재 구현 파일:

- `pkg/sla/resolve.go`
- `pkg/sla/load_context.go`
- `pkg/sla/walker_change.go`

### 2. Pending Context Commits

원본 `ParserContext::addCommit()` / `applyCommits()` 기준 현재 Go shell은 아래를 보존한다.

1. commit은 `ContextSet` queue에 저장한다
2. 저장 값은 `context[num] & mask`다
3. operand symbol commit이면 commit point의 operand child handle을 우선 사용한다
4. operand symbol이 아니면 symbol fixed handle 경로를 탄다
5. constant space address는 current instruction space byte address로 정규화한다
6. non-flow commit은 `nextaddr` 범위를 같이 계산한다

현재 구현 파일:

- `pkg/sla/load_context.go`

### 3. Pcode Context Preparation

원본 `oneInstruction()` 준비 경로에서 중요한 순서는 `obtainContext(..., pcode)` 뒤에 `applyCommits()`가 온다는 점이다.
현재 Go에서는 이 순서를 helper로 고정했다.

1. `ObtainContext(..., ParseStatePcode)`
2. `ApplyCommits()`
3. 이후 builder/build 경로로 진입

현재 `ObtainPcodeContext()` helper는 아래 보강도 가진다.

1. pcode obtain마다 stale `N2Addr`를 먼저 비운다
2. fallthrough는 cached `naddr`를 바로 믿지 않고 우선 `addr + length`로 계산한다
3. `inst_next2`는 eager prefetch가 아니라 lazy resolver를 먼저 바인딩한다
4. 첫 `GetN2addr()` 시도에서 same authoritative `ObtainContext(..., ParseStateDisassembly)` route를 탄다
5. adjacent context에 constant space가 비어 있으면 request constant space를 fallback으로 쓴다
6. `GetN2addrE()`는 `inst_next2` 주소가 unavailable일 때 generic `error` 대신 typed `*UnimplError`를 반환한다. 이를 통해 호출자가 unimplemented 경계와 인프라 에러를 명시적으로 구분할 수 있다

현재 구현 파일:

- `pkg/sla/instruction_context.go`
- `pkg/sla/translate.go`
- `pkg/sla/obtain_context.go`
- `pkg/sla/discache.go`

추가로 현재 cache entry는 original `DisassemblyCache::getParserContext()` 방향으로 한 단계 더 올라갔다.

1. same-address hit면 기존 `ParserContext`를 그대로 재사용한다
2. miss면 circular slot을 재사용한다
3. 재사용 슬롯은 `addr`를 바꾸고 `parser state = uninitialized`로 reset한다
4. `N2Addr`는 address reassignment 시 invalid로 되돌린다
5. **(세션4, `8b23afa`) in-flight pin**: `TranslateSubtable()`이 pcode 빌드 구간 동안 자기 컨텍스트를
   `PinContext()`로 고정하고, `nextReuseSlotLocked()`가 핀 슬롯을 재사용에서 건너뛴다. eager inst_next2
   해석(`translateRuntimeContext`)이 같은 풀에서 `ObtainContext()`를 호출해 빌드 중인 슬롯을 recycle ->
   naddr/ops 오염 -> 다음 명령어 삼킴(디코드 순서 의존 비결정 오염)을 일으키던 버그의 근절. C++
   `Sleigh::oneInstruction()`이 `pos`를 build 전체에 걸쳐 살려두는 계약(minimumreuse window)의 명시화.
   회귀 테스트: `pkg/sla/discache_test.go TestPinContextSurvivesReuseWrap`.

`ObtainContext()` 내부에서 cache hit 시 단락(short-circuit) 경로가 추가됐다.

- 요청 주소의 `ParserContext`가 이미 `parsestate >= ParseStateDisassembly`이면 `Resolve()`를 다시 실행하지 않고 즉시 해당 context를 반환한다.
- 이 경로는 원본 `Sleigh::obtainContext()`의 parse-state guard와 대응된다.

### 3.5. Translation Entry

현재 `TranslateSubtable()`는 아래 순서로 runtime 권위 경로에 진입한다.

1. alignment gate
2. `ObtainPcodeContext()`
3. delay-slot context preparation loop
4. `ParserWalker` 생성
5. section 선택
6. builder-owned raw-build begin
7. `SleighBuilder.Build()`
8. cache-backed `ResolveRawBuild()`
9. cache-backed `EmitRawBuildTo()` after explicit `ResolveRawBuild()`
10. translation-owned sink capture chained through builder/cache emit for the current Go translation API

현재 translation entry는 root instruction address를 sink-visible emission address로 따로 들고 간다. active parser-context address는 template fixing과 operand semantics에 쓰이고, raw-op `SeqNum.Address`는 `oneInstruction(baseaddr)` parity를 위해 root instruction address를 따른다.
현재 concrete backend는 in-memory payload뿐 아니라 `RawLoadImage`-style reader/file-backed raw instruction source도 가질 수 있다.

현재 translation entry의 load 단계는 더 이상 base instruction의 `MatchInput` 하나에만 묶여 있지 않다.

1. 기본 base `MatchInput`
2. address-scoped payload map
3. address-scoped payload lookup callback
4. authoritative `Loader(addr)` callback

위 순서로 payload source를 찾고, 현재 parser-context address에 맞는 instruction/context bytes를 주입한다.
다만 explicit `LoadFill` / `LoadContext` hook이 있으면 해당 phase에서는 bundled payload fallback을 생략하고, fallback이 필요한 phase만 주소별 cached lookup을 사용한다.
그래도 payload가 없고 user hook도 없으면 typed `*UnimplError`로 남긴다.
현재는 이 `Loader(addr)`를 concrete in-memory `Backend.PayloadLoader()`가 직접 제공할 수 있다.
또한 `Engine.TranslateInstructionAt()`가 이 backend loader와 split `LoadFill` / `LoadContext` authority path, cache/runtime authority path를 묶는 high-level entry가 된다.
`Engine`는 이제 decoded symbol table에서 global-scope `instruction` subtable을 자동으로 찾아 standalone engine 구성에도 쓸 수 있다.

현재 구현 파일:

- `pkg/sla/translate.go`
- `pkg/sla/builder.go`
- `pkg/sla/builder_delay.go`
- `pkg/sla/builder_cross.go`
- `pkg/sla/discache.go`
- `pkg/sla/lower.go`
- `pkg/sla/backend.go`
- `pkg/sla/engine.go`

### 3.6. Original Tail Still Missing

원본 `Sleigh::oneInstruction()`에서 build 이후 tail 순서는 아래와 같이 고정된다.

1. `pcode_cache.clear()`
2. `SleighBuilder builder(...)`
3. `builder.build(walker.getConstructor()->getTempl(), -1)`
4. `pcode_cache.resolveRelatives()`
5. `pcode_cache.emit(baseaddr, &emit)`

현재 Gosleigh는 이 tail을 `DisassemblyCache` ownership 경로로 반영한다.
이제 local raw-cache stopgap은 제거됐고, builder/cache가 explicit `resolve -> emit` tail을 가진다. helper-side slice-return emission은 제거됐고, caller는 먼저 `ResolveRawBuild()`를 마친 뒤 sink-facing `EmitRawBuildTo()`만 사용한다.
다만 아직 full `PcodeCacher` issued-op ownership, varnode pool allocation discipline, exact `PcodeEmit` sink parity는 아니다.
현재 staged raw-build는 issued-op record와 owned varnode storage를 분리해 보관하고, issued op가 cache-owned varnode storage를 직접 가리키며 pool growth 시 rebind도 한다.
raw-build staging은 이제 map+reusable-indirection 대신 single active reusable stage object를 직접 쓰는 구조로 줄었지만, 아직 full `PcodeCacher` object lifecycle과 동일하지는 않다.
relative-label patching도 이제 helper resolver 추상화보다 direct `labelRefs` / `labels` vector를 따라가며, undefined label은 explicit failure로 남긴다.

### 4. Handle Resolution

원본 `Sleigh::resolveHandles()` 기준 현재 Go shell은 아래 경계를 가진다.

1. base state에서 시작
2. constructor state loop
3. operand push/pop
4. subtable operand면 하위 state로 계속 진행
5. non-subtable operand면 fixed handle 또는 expression value 계산
6. constructor 종료 시 main template result propagation
7. `setParserState(pcode)`

현재 구현 파일:

- `pkg/sla/resolve_handles.go`
- `pkg/sla/runtime.go`

## 현재 자동 경로

현재 hook 없이 자동으로 되는 것:

- `DecisionNode::resolve()` shell
- `PatternBlock` instruction/context match
- `PatternExpression::getValue()`의 constant/start/end/next2/token/context/basic unary-binary
- `OperandSymbolBoundary`가 가진 `defexp` 또는 일부 boundary symbol 기반 operand value 경로
- `ApplyCommits()`의 operand-symbol commit address 해석
- `ResolveHandles()`의 일부 operand metadata 자동 처리
- `Resolve()`의 flow address propagation과 calladdr-style fallback
- `ResolveHandles()`의 `NameSymbol` / `EpsilonSymbol` automatic fixed-handle path
- `ResolveHandles()`의 pre-resolved static `VarnodeSymbol` / `VarnodeListSymbol` automatic fixed-handle path
- persisted `.sla` IDs가 없는 flow symbols (`inst_dest`, `inst_ref`)에 대한 safe opaque-boundary runtime reconstruction path
- `symbols.go`가 persisted `VarnodeSymbol` fixed tuple과 `VarnodeListSymbol` selector/table body를 boundary decode에 보존하는 경로
- `ResolveHandles()`가 persisted `VarnodeSymbol` fixed tuple과 `VarnodeListSymbol` selector/table body를 직접 automatic fixed-handle reconstruction에 쓰는 경로
- `ResolveHandles()`가 `OperandSymbol::getFixedHandle()` handoff를 `walker.GetFixedHandle(index)`로 automatic 처리하는 경로
- `PatternExpression::getValue()`가 constructor-relative operand에 대해 prebuilt child state 없이도 `setOutOfBandState()`를 통해 값을 계산하는 경로
- builder/cache tail이 builder-owned emitted slice 없이 cache/sink-owned `resolve -> emit`를 authoritative 경로로 사용하고, translation은 sink capture를 체인해 결과를 받는 구조
- root builder tail은 외부 `RawEmitter`가 없을 때도 internal no-op sink를 써서 `PcodeCacher::emit(addr, PcodeEmit*)`와 같은 sink-facing 모양을 유지한다
- `DisassemblyCache.EmitRawBuildTo()`는 staged op 자체를 sink에 넘기지 않고 clone을 내보내서, sink mutation 실패가 retryable staging state를 오염시키지 않게 한다
- translation catch rewrap은 이제 strict typed `*UnimplError`만 대상으로 하고, builder sentinel만으로는 promotion하지 않는다
- builder/resolve/resolve-handles의 일부 sentinel 경로는 이제 upstream에서 typed `*UnimplError`로 정규화되어 translation catch까지 전달된다
- builder helper / obtain-context / pattern-expression 경계도 같은 방식으로 typed `*UnimplError` 정규화 범위가 늘어났다
- translation entry 내부의 load-fill/load-context hook-required 경로와 delay-slot length parity gap도 이제 typed `*UnimplError`로 정규화된다
- `DisassemblyCache.EmitRawBuildTo()`를 통해 sink-style emission을 수행하는 경로
- translation entry가 address-scoped payload source를 통해 adjacent parser context의 instruction/context를 자동 주입하는 경로
- `ObtainPcodeContext()`가 stale `N2Addr`를 지우고 `addr + length` 기반 fallthrough prefetch를 수행하는 경로
- `GetN2addrE()`가 unavailable `inst_next2`에 대해 typed `*UnimplError`를 반환하는 경로
- raw-build staging이 explicit resolved/unresolved phase를 가져서 unchanged state 재-resolve를 막는 경로
- `EmitRawBuildTo()`가 unresolved staged raw build를 하드 에러로 거부하는 경로
- dynamic `LOAD`/`STORE`가 process-local pointer-identity space selector와 deterministic unique-space fallback을 사용하는 경로
- nested `DELAY_SLOT` translation에서도 active walker 기준 unique-temp bits와 root `SeqNum.Address`가 동시에 맞는 end-to-end proof test가 있다

## 아직 hook 경계 뒤에 있는 것

현재도 명시적으로 미완인 부분:

- `TripleSymbol::getFixedHandle()`의 나머지 symbol 종류
- preserved `varnode_sym / varlist_sym` body를 runtime automatic fixed-handle reconstruction으로 연결하는 경로
- flow-symbol fixed-handle (`FlowDestSymbol`, `FlowRefSymbol`) automatic path
- `OperandValue::getValue()`의 full parity 경로
- decode pipeline이 `DisassemblyCache`를 실제로 채우는 broader end-to-end 경로
- in-memory backend를 넘는 external/file-backed loader가 instruction/context payload를 자동 공급하는 end-to-end 경로
- exact typed `UnimplError` mutation/rethrow semantics
- catch-format full parity
- `PcodeCacher`의 full reusable pool / relocation ownership 모델
- `PcodeCacher`의 strict resolve-before-emit lifecycle enforcement
- sink-style `emit(addr, PcodeEmit*)` parity
- in-memory backend를 넘는 broader `LoadImage` / `ContextDatabase` parity surface
현재 key runtime/translation shell은 package-wide typed `UnimplError`를 쓰고, typed translation error는 in-place rewrite까지 들어갔다. catch formatting도 더 concrete한 operand text를 출력한다. 다만 아직 full catch coverage와 exact same-object mutation semantics, fallback-free parity는 없다.

## 참고: 디컴파일러 트리 액션의 스택 공간 복구 경로 (범위 밖 -- pkg/pcode, 2026-07-02)

아래는 Sleigh 번역 경로(위 네 축)가 아니라 디컴파일러 액션/룰 파이프라인(`pkg/pcode`)의 변경이다. 이 문서의
주 범위와는 다른 층이지만, "runtime 실행 경로가 바뀌면 문서를 갱신한다" 원칙에 따라 짧게 기록한다.

universal-action 트리에서 스택 접근 복구는 이제 Ghidra 충실 경로가 기본이다. `Funcdata.Spacebase()`가 RSP
계열 varnode(input/sub-result/phi)에 spacebase 마킹을 걸고, `RuleLoadVarnode`/`RuleStoreVarnode`가 그 마킹을
따라 `[rsp+k]` LOAD/STORE를 스택 공간 varnode로 변환한다. `sub rsp,N` 오프셋 누적은
`RuleSub2Add`+`RuleCollapseConstants`+`RuleAddMultCollapse`가 담당한다. C++ 참조:
`ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.cc:230-269`(Funcdata::spacebase),
`ruleaction.cc:4193-4361`(RuleLoadVarnode), `ruleaction.cc:4113-4182`(RuleAddMultCollapse 계열).

H8-debt-2 Step 1-2 완료(2026-07-03): production `bridge.Decompile`이 손정렬 41-call subset을 버리고
`db.BuildUniversalAction(nil)` + `SetCurrent("decompile").Perform(fd)` 트리 경로로 교체됐다. 유일한
load-bearing 배선 차이는 콜러가 `bridge.Build`에 cspec(+entry-point 함수는 EntryPoint)을 공급하는
것뿐이다 -- cspec `<stackpointer>`가 있어야 faithful StackSpace가 생성되고 ActionSpacebase +
RuleLoadVarnode/RuleStoreVarnode가 스택 프레임을 복구한다. 검증: MSVC 골든 5개 byte-identical,
tree 10/10, x64 corpus 7/8 무회귀. bespoke `ActionStackPtrFlow`(action_stack_ptr_flow.go)는 이제
production 경로에서 은퇴했고 레거시 테스트 하네스(loader_test.go의 직접 heritage 테스트, 비-Ghidra
`runPipeline`)에만 남아 있다. 완전 제거(Step 3)는 그 하네스들을 트리로 이전한 뒤 진행하는 후속 작업이다.

콜러 계약: `bridge.Decompile`은 `bridge.Build`가 cspec을 받았다고 가정한다(레포 내 콜러는 현재
골든 테스트 하네스뿐). 실 다운스트림 통합 시 cspec 공급 계약을 지켜야 스택 로컬이 복구된다.

## 현재 설계 원칙

- 원본 C++가 있는 구간에서는 추정 구현 금지
- parity가 안 맞으면 `known mismatch` 또는 `unimplemented`로 남긴다
- runtime 실행 순서가 바뀌면 반드시 이 문서와 `docs/PARITY_AUDIT.md`, `docs/STATUS.md`를 같이 갱신한다
- 코드 주석은 영어로 쓰고, parity-sensitive 구간에서는 가능하면 대응되는 원본 Ghidra C++ class/function을 짧게 적는다
- 큰 실행 순서와 권위 경로는 문서에 두고, 세부 C++ 대응점은 코드 옆 주석에 둔다
- 다음 작업자는 `docs/RUNTIME_FLOW.md`를 먼저 읽고, 그 다음 `docs/PARITY_AUDIT.md`를 읽는다

## 다음 큰 작업

현재 기준 가장 큰 다음 작업은 두 가지다.

1. decode pipeline이 `DisassemblyCache`를 실제로 채우게 만들기
2. `PcodeCacher` full ownership parity를 위한 pool/allocation 모델 올리기
