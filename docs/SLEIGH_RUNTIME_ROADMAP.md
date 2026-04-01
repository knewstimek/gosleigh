# Sleigh Runtime Roadmap

## 목적

이 문서는 `Sleigh runtime/.sla translation path`만 100%까지 끌어올리기 위한 전용 로드맵이다.
여기서 말하는 100%는 `원본 Ghidra Sleigh runtime 경로와 동등한 수준으로 .sla를 읽고, instruction bytes/context를 받아 constructor를 선택하고, p-code를 생성하고, 관련 runtime state를 처리하는 것`이다.

이 문서는 decompiler 전체 로드맵이 아니다.
디컴파일러 전체 완성은 이 문서 범위 바깥이다.

## 현재 상태

현재는 runtime/translation path 기준으로 후반부다.

이미 있는 것:

- `.sla` container (packed v4 + XML v3 auto-detect), packed decode (type 1-6), metadata, symbol/pattern/template boundary decode
- XML v3 `.sla` loading via `encoding/xml` -- Ghidra 12 `6502.sla` (XML v3) 7단계 integration test 7/7 pass
- `TYPECODE_ADDRESSSPACE` (type 5) and `TYPECODE_SPECIALSPACE` (type 6) decoding
- `ContextSymbolBoundary` (varnode/low/high/flow) and `ContextOpBoundary` (num/shift/mask) in symbol boundary decode
- `BuildXrefs()` -- post-decode xref/userop/context registration pass mirroring `SleighBase::buildXrefs()`
- `Resolve`, `ResolveHandles`, `LoadContext`, `AddCommit`, `ApplyCommits` shell
  - `runtimeContextForWalker` now passes child handles and `SpacesByIndex` to `HandleTpl::fix()` parity path
  - `findWalkerSpaceByIndex` now prefers `SpacesByIndex` lookup
  - `ParserContext` carries `SpacesByIndex` field
- `PatternExpression` 기본 경로 -- `ContextSymbol` pattern access (Context/Pattern both checked)
- `Builder`, `BUILD`, `CROSSBUILD`, `DELAY_SLOT`, `LABELBUILD` shell
- `TranslateSubtable()` 진입 경로
- concrete backend for the current runtime path
  - in-memory LoadImage-style instruction fetch
  - RawLoadImage-style reader/file-backed instruction fetch
  - RawLoadImage-style `adjustVma(long)` rebasing with word-size scaling
  - ContextDatabase/ContextCache-style context reads/writes
  - named context variable registration/default/value access
  - conservative context-range query
- reusable `Engine.TranslateInstructionAt()` entry over backend + cache + runtime path
- root instruction subtable auto-discovery from decoded symbol data, mirroring `sleighbase.cc` global-scope `instruction` lookup
- nested delay-slot proof that dynamic unique-temp bits follow the active instruction while emitted raw-op addresses stay on the root instruction
- `oneInstruction()` 일부 tail
  - alignment gate
  - builder/cache-owned raw-build begin
  - build
  - explicit `resolve -> emit` tail
  - raw-op cache ownership
  - direct staged `labelRefs` / `labels` relative patching
  - conservative `UnimplError` rewrap with `oneInstruction()`-style explain text
  - emit/resolve error messages aligned to C++ `PcodeCacher` text
- `varnode_sym` fixed tuple and `varlist_sym` selector/table body persisted in boundary decode
- parser-context circular reuse path for `DisassemblyCache::getParserContext()` / `Sleigh::obtainContext()` direction

아직 없는 것:

- `oneInstruction()` strict parity 마감
- full `PcodeCacher` parity
- `BuildXrefs()` 등록 테이블의 runtime resolve/pattern-evaluation 연결
- operand semantics parity (SpacesByIndex 경로는 연결됨; 나머지 symbol 종류별 자동 경로 확장 필요)
- decode pipeline parity
- hook 의존 제거

## 100% 완료 기준

다음이 모두 만족되면 이 문서 기준 100%로 본다.

- `.sla` persisted runtime data를 실제 실행에 필요한 수준까지 읽는다
- instruction bytes + context + address를 받아 원본과 같은 흐름으로 constructor를 고른다
- `Resolve`, `ResolveHandles`, `ApplyCommits`, `ParserWalker`, `SleighBuilder`, `PcodeCacher` 역할이 원본과 동등하다
- `oneInstruction()` 경로가 원본과 같은 책임 분리를 가진다
- hook 없이 자동으로 가는 경로가 기준이 된다
- golden comparison으로 원본 Ghidra와 비교 가능하다

## 큰 작업 단위

### 1. Instruction Execution Parity

목표:

- 원본 `Sleigh::oneInstruction()` 한 덩어리를 사실상 닫는다

포함 범위:

- alignment gate
- `obtainContext(..., pcode)`
- `applyCommits()`
- delay-slot loop
- `ParserWalker`
- `pcode_cache.clear()`
- `SleighBuilder.build()`
- `pcode_cache.resolveRelatives()`
- `pcode_cache.emit(...)`
- `UnimplError` 재포장

현재 상태:

- 절반 이상 진행
- alignment gate, delay-slot prep, `ParserWalker`, local clear/build/relative-label-fixup/emit 순서는 들어갔다
- builder/cache가 raw-build lifecycle을 소유하고 root tail은 explicit `resolve -> emit` 순서를 가진다
- `ErrBuilderUnimplemented` 계열에 대한 보수적 `UnimplError` 재포장도 들어갔다
- alignment failure도 typed local unimplemented path로 정규화됐다
- staged raw-build는 issued-op record와 owned varnode storage를 분리해 보관한다
- released raw-build state 1개를 재사용하는 reset 성질도 들어갔다
- 기존 typed translation error는 in-place rewrite까지 들어갔다
- key runtime/translation shell은 package-wide typed `UnimplError`를 사용한다
- catch formatting은 더 concrete한 operand text를 출력하고 Go-only gap suffix는 제거됐다
- staged issued op는 cache-owned varnode storage를 직접 가리키고, pool growth 시 rebind를 수행한다
- resolve path는 flow address를 `ParserContext`에 실어 나르고 calladdr-style fallback을 수행한다

남은 핵심:

- full `PcodeCacher` reusable pool / relocation ownership
- full catch coverage와 exact same-object mutation semantics
- fallback-free operand print full parity와 catch-path formatting parity 보강
- decode pipeline parity

완료 기준:

- `TranslateSubtable()` 또는 그 후속 정식 entry가 원본 `oneInstruction()`을 문서상/코드상 한 경로로 설명할 수 있어야 한다

### 2. PcodeCacher And Builder Parity

목표:

- 현재 local raw cache/helper 수준을 원본 `PcodeCacher` 수준으로 올린다

포함 범위:

- issued op ownership
- varnode pool semantics
- label ref tracking
- label resolution
- emit ownership
- `buildEmpty()` recursion parity
- dynamic load/store generation 책임 분리

현재 상태:

- 일부 shell + 일부 helper

남은 핵심:

- `PcodeCacher::dump/emit/resolveRelatives` 전체 구조
- builder가 authoritative emission owner가 되도록 정리
- sink-style `emit(addr, PcodeEmit*)` parity
- Go-only sink error semantics gap 정리
- remaining internal ownership/sink differences around the single reusable staging object
- remaining container-shape parity against original `allocateInstruction` / `allocateVarnodes` / `expandPool`

완료 기준:

- translation path의 raw-op emission이 helper 모음이 아니라 builder/cache 중심 구조로 정리되어야 한다

### 3. Operand Semantics Parity

목표:

- operand/fixed-handle/pattern expression 쪽 hook 의존을 크게 없앤다

포함 범위:

- `TripleSymbol::getFixedHandle()`
- `OperandValue::getValue()`
- `setOutOfBandState()`
- `ResolveHandles()`
- `HandleTpl::fix()`
- `ConstTpl::fix()`

현재 상태:

- 일부 자동 경로 + 많은 shell
- `NameSymbol`, `EpsilonSymbol`, pre-resolved static varnode-style handle 수용은 automatic path가 있다
- persisted `VarnodeSymbol` / `VarnodeListSymbol` body 데이터는 이제 runtime automatic reconstruction까지 연결됐다
- parser-context obtain path는 same-address hit reuse, circular slot reuse, parse-state reset 방향으로 올라왔다
- `OperandSymbol::getFixedHandle()` handoff와 constructor-relative `OperandValue` out-of-band evaluation도 automatic path로 올라왔다
- builder-owned emitted slice는 제거됐고, translation tail은 이제 builder/cache sink emission에 capture sink를 체인해서 결과를 받는다
- sink-style `EmitRawBuildTo(addr, RawEmitter)` 경로도 들어왔다
- `lower.go`는 dynamic varnode를 더 이상 concrete raw varnode로 추정해서 낮추지 않고, explicit typed parity gap으로 돌려세운다
- raw-build varnode-pool ownership은 explicit issued-op record 기반 deterministic rebind로 조여졌고, sink emission은 staged op clone을 사용해 retryable state를 보호한다
- `wrapTranslateUnimplError()`는 이제 strict typed `*UnimplError`만 rewrite하고, builder sentinel-only errors는 더 이상 promotion하지 않는다
- safe subset의 dynamic varnode expansion은 들어갔다: dynamic input은 pre-op `LOAD`, dynamic output은 post-op `STORE`
- dynamic `v_offset_plus`는 low-16 split까지 반영돼, low-16 `0` subset은 통과하고 non-zero low-16만 explicit parity gap으로 남긴다
- constant-pointer dynamic `v_offset_plus`는 non-zero low-16도 immediate folding으로 safe subset 처리한다
- non-constant-pointer dynamic `v_offset_plus`는 `INT_ADD` side-op + runtime temp `UniqueBase + 0x100`으로 내려간다
- dynamic unique-space location/pointer는 `uniqueoffset = (instruction.offset & UniqueMask) << 8`를 반영한다
- builder/resolve/resolve-handles 일부 sentinel 경로는 upstream에서 typed `*UnimplError`로 정규화된다
- builder helper / obtain-context / pattern-expression 경계도 typed `*UnimplError` 정규화 범위에 포함됐다
- translation entry 내부의 hook/cached-state parity-gap 경로도 typed `*UnimplError` 정규화 범위에 포함됐다

남은 핵심:

- symbol 종류별 fixed handle 해석 (`ContextSymbol` 등 신설 boundary 활용 포함)
- completed flow-symbol fixed-handle parity (`inst_dest`, `inst_ref`) needs to be preserved while broader symbol coverage expands
- `BuildXrefs()` 등록 테이블 연결 -- context variable 및 userop이 실제 resolve/evaluation에 영향을 미쳐야 한다
- dynamic handle semantics
- remaining exact C++ pointer-space payload parity
- remaining explicit no-`UniqueSpace` runtime-temp gap
- operand metadata 기반 자동 경로 확대 (SpacesByIndex/child-handle wiring은 완료)
- remaining non-typed unimplemented paths outside current normalization scope

완료 기준:

- 현재 hook 기반 분기 대부분이 원본 symbol/operand 경로로 대체되어야 한다

### 4. Decode Pipeline Parity

목표:

- synthetic test seeding 없이 실제 decode pipeline이 `DisassemblyCache`를 채운다

포함 범위:

- instruction byte load
- context load
- parser-context lifecycle
- constructor tree allocation
- section/constructor selection
- cache re-entry

현재 상태:

- shell과 test-driven seed 중심이지만, translation entry는 이제 address-scoped payload source(`ByAddress` / `Lookup`)를 받아 adjacent parser context에도 instruction/context를 공급할 수 있다
- translation entry는 이제 first-class `Loader(addr)` callback을 address-scoped authoritative load route로 우선 사용한다
- `Engine` backend adapter는 split `LoadFill` / `LoadContext` hooks를 지원해 bundled `MatchInput`보다 더 원본에 가까운 authority path를 우선 사용할 수 있다
- `translateResolveHooks()`는 이제 explicit hook이 있는 phase에서는 bundled payload fallback을 건너뛰고, fallback이 필요한 phase만 주소별 cached lookup을 쓴다
- `ObtainPcodeContext()`는 stale `inst_next2`를 pcode obtain마다 지우고 lazy resolver를 바인딩한다. `GetN2addr()` 첫 호출 시 `addr + length` 기반 fallthrough로 adjacent disassembly를 유도한다
- raw-build staging은 now explicit resolved/unresolved phase를 가져 unchanged state 재-resolve를 막는다
- `EmitRawBuildTo()`는 unresolved staged raw build를 거부하고, resolved state만 sink emission/commit 대상으로 받는다
- dynamic `LOAD`/`STORE` space-selector payload는 process-local pointer identity를 사용하고, runtime temp unique space는 deterministic fallback을 가진다

남은 핵심:

- broader external/file-backed load/database parity beyond the current raw reader/file-backed backend
- cache population ownership
- delay/crossbuild가 synthetic setup 없이 동작
- `ParserContext::getN2addr()` unavailable path를 current invalid-address fallback보다 더 원본에 가깝게 정리
- remaining slice-return compatibility cleanup
- cross-run stable parity for C++ pointer-space payload semantics
- broader `LoadImage` / `ContextDatabase` parity surface beyond the current in-memory backend

완료 기준:

- 실제 입력 바이트와 context만으로 translation path가 자연스럽게 돈다

### 5. .sla Runtime Data Parity

목표:

- 현재 boundary decode를 runtime execution에 필요한 수준까지 승격한다

포함 범위:

- symbol bodies
- pattern tree
- constructor data
- sections
- context metadata
- processor/space metadata

현재 상태:

- decode boundary는 많이 있음
- `TYPECODE_ADDRESSSPACE` (type 5), `TYPECODE_SPECIALSPACE` (type 6) 디코딩 추가됨
- `ContextSymbolBoundary` (varnode/low/high/flow), `ContextOpBoundary` (num/shift/mask) 신설
- XML v3 `.sla` 자동 감지 및 파싱 추가됨 (Ghidra 12 `6502.sla` 실 파일 검증 완료)
- `BuildXrefs()` 구현으로 post-decode xref/userop/context 등록 경로 완성
- `SpacesByIndex`가 `ParserContext`에 연결되어 handle resolve 시 space lookup 경로 개선
- runtime 사용률은 여전히 부분적 -- `ContextSymbolBoundary` 등 신설 boundary의 runtime 활용은 아직 `BuildXrefs()` 등록 단계까지만

남은 핵심:

- `ContextSymbolBoundary`, `ContextOpBoundary` 등 신설 boundary를 runtime resolve/evaluation에 연결
- `BuildXrefs()` 등록 테이블을 runtime 경로에서 실제 사용
- boundary로만 저장된 나머지 데이터를 runtime이 직접 사용하게 연결

완료 기준:

- persisted `.sla` 정보가 단순 보관이 아니라 실제 runtime 행동을 결정해야 한다

### 6. Verification And Golden Parity

목표:

- “돌아감”이 아니라 “원본과 맞음”을 증명한다

포함 범위:

- instruction corpus
- architecture별 fixture
- emitted raw ops 비교
- constructor selection 비교
- delay/crossbuild/label fixup 비교

현재 상태:

- 단위 테스트 중심
- 실제 Ghidra 12 `6502.sla` (XML v3, packed v4 양쪽)로 7단계 integration test 7/7 통과 -- `.sla` 로딩/메타데이터/심볼 경계까지의 end-to-end 흐름이 실 파일로 검증됨
- `testdata/6502.sla` (XML v3), `testdata/6502-packed.sla` (packed v4) fixture 추가됨

남은 핵심:

- 실제 instruction bytes 입력 + emitted p-code golden 비교
- 복수 아키텍처 fixture 확대
- original Ghidra output 대조 harness

완료 기준:

- 중요한 instruction families에 대해 원본과 비교 가능한 regression suite가 있어야 한다

## 권장 실행 순서

순서는 아래처럼 고정한다.

1. `Instruction Execution Parity`
2. `PcodeCacher And Builder Parity`
3. `Operand Semantics Parity`
4. `Decode Pipeline Parity`
5. `.sla Runtime Data Parity`
6. `Verification And Golden Parity`

이 순서를 택하는 이유:

- 지금 가장 큰 병목은 `entry -> build -> emit` 한 덩어리가 아직 완전히 닫히지 않았기 때문이다
- 그 다음 병목은 helper성 raw-op path가 아직 authoritative 구조가 아니라는 점이다
- operand semantics와 decode pipeline은 그 위에 얹혀야 의미가 있다

## 앞으로의 작업 단위 규칙

이제부터 `Sleigh runtime/.sla translation path` 작업은 아래 단위로만 자른다.

- 작은 함수 단위로 자르지 않는다
- 반드시 위 큰 작업 단위 중 하나를 끝내는 식으로 자른다
- 각 라운드는 최소한 아래 중 하나를 닫아야 한다
  - `Instruction Execution Parity`
  - `PcodeCacher And Builder Parity`
  - `Operand Semantics Parity`
  - `Decode Pipeline Parity`

예:

- 좋은 단위: `oneInstruction() strict parity 전체`
- 나쁜 단위: `alignment 검사만`

## 현재 바로 다음 작업

다음 작업은 `Instruction Execution Parity` 전체다.

정확한 범위:

- `UnimplError` 재포장
- full tail ownership 정리
- translation entry의 legacy helper 축소
- builder/cache/emit 책임 경계 정리

이 단위가 닫히기 전까지는 다른 축으로 새지 않는다.
