# CHANGELOG

Gosleigh 프로젝트 이력. 완료된 마일스톤과 파동별 포팅 기록을 축적.
현재 상태는 `docs/STATUS.md` 참조.

---

### 2026-07-03: H-dispatch Component 1 -- FlowInfo::truncateIndirectJump 충실 포팅 (jump-table 실패 폴백)
breadth 디스커버리(바로 아래 항목, master `5276375`)에서 매핑된 dispatch(dense switch) 갭의 첫 조각을
닫았다. Ghidra의 raw-flow jump-table 복구 드라이버와 그 실패 폴백을 포팅해, 복구 불가능한 BRANCHIND를
CALLIND 콜사이트 + artificial return으로 강등한다(`FlowInfo::generateOps` -> `recoverJumpTables` ->
`truncateIndirectJump` 대응). 이전에는 모든 BRANCHIND가 raw `goto *(...)`로 남아 있었는데, 이는 Ghidra가
절대 출력하지 않는 형태다. master `a02b1a6`.

- **신규 `pkg/pcode/flow_jumptable.go`(+222)**:
  - `Funcdata.ArtificialHalt`(flow.cc:592, `FlowInfo::artificialHalt`)
  - `Funcdata.OpMarkHalt`(funcdata_op.cc:37, `Funcdata::opMarkHalt`)
  - `Funcdata.RecoverJumpTables`(flow.cc:1427/785, 구동 드라이버 + `generateOps` 순회 루프)
  - `Funcdata.recoverJumpTable`(funcdata_block.cc:639, `JumpTable.RecoverAddresses`로 실제 복구를 먼저
    시도하고 실패 시에만 모드 진입)
  - `Funcdata.linkJumpTable`(funcdata_block.cc:426)
  - `Funcdata.setupCallindSpecs`(flow.cc:704)
  - `Funcdata.TruncateIndirectJump`(flow.cc:727, 4개 RecoveryMode 분기 전부)
  - 부속: `FuncProto` `badJumpTable`/`noReturn` 플래그(fspec.hh), 갓 강등된 CALLIND를 추적하는 lazy
    `Funcdata.rebuildCallSpecs`. 드라이버는 `bridge.Build`의 block structuring 직후, universal-action
    트리 이전에 배선(Ghidra의 pre-Action `generateOps` 순서 대응).
- **충실성**: 무조건 truncate가 아니다 -- 기존 jumptable 머신러리(`RecoverAddresses`)로 복구를 먼저
  실제 시도하고, 실패했을 때만 truncate한다. 향후 reloc 인식 로더가 복구를 성공시키면 테이블이 그대로
  보존되는 구조. 현재 단일 `.text` 하네스에서는 항상 복구 실패(테이블 주소 에뮬레이션에 필요한
  reloc/.rdata 부재, BRANCHIND 부모 블록에 out-edge 없음) -- **Ghidra 자신도 동일 입력에서
  `fail_normal`로 떨어지는 이유와 정확히 같다.**
- **dispatch 결과**: `goto *(...)`는 제거됐다(CALLIND + artificial RETURN 강등). 그러나 완전한
  `uVar1 = (*(code*)(...))(); return uVar1;` 렌더까지는 아직 아니다 -- 별개의 기존 갭(project-wide)이
  여전히 막고 있다: **IOP-space 인코딩 미포팅**(INDIRECT input(1)이 cause-ref를 못 갖고 rename
  same-time 조정도 없음, heritage.cc:2506-2517)으로 CALLIND 타깃(RAX)이 유실돼 `(*0)()`로 렌더되고,
  거기에 reloc 주소상수 + printc 타입명(uint/undefined8) 갭이 더해진다.
- **게이트**: `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1 TestX64CorpusGoldenMap` 7/8
  (process만 기존 MISMATCH 유지, 무회귀), `X64_BREADTH=1 TestX64BreadthGoldenMap` dist_sq/sum2d MATCH
  유지, production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*` PASS, `go build` 클린,
  `go test ./...` 클린(symbols_test 3건 missing-.exe 기존과 동일 제외).
- **전략 확정(사용자 합의)**: bare `.obj` 위 dispatch는 Ghidra 자신도 복구 실패하므로 parity 타깃은
  CALLIND 폴백이다. "진짜 switch 복구로 Ghidra를 능가할 수 있는가"라는 질문의 답은 원리상 가능하나
  (1) `jumptable.go`(1671줄, 이미 포팅됨)가 실전 미검증이고 (2) 엔진 우위가 아니라 로딩 정책 차이일
  뿐이며(Ghidra도 full image면 복구) (3) 골든 없이는 검증 불가라 parity 규칙 위반이다. **올바른 경로는
  track B** -- Ghidra도 switch를 복구하는 full 링크 x64 `.exe` 코퍼스로 새 골든을 만들어
  `jumptable.go` 구동 드라이버(이번 커밋의 `RecoverJumpTables` 성공 경로)를 실검증하고, 그 switch
  골든과 MATCH시키는 것.
- C++ 참조: `flow.cc:592`(artificialHalt), `flow.cc:704`(setupCallindSpecs), `flow.cc:727`
  (truncateIndirectJump), `flow.cc:785/1427`(recoverJumpTables 구동), `funcdata_block.cc:426`
  (linkJumpTable)/`:639`(recoverJumpTable attempt-then-fallback), `funcdata_op.cc:37`(opMarkHalt),
  `heritage.cc:2506-2517`(INDIRECT same-time rename, 다음 블로커).

### 2026-07-03: H8-debt-2 Step3(bespoke ActionStackPtrFlow 은퇴) + breadth 디스커버리(struct/2d/switch 갭 맵)
H8-debt-2 본체(트리를 production 경로로, master `eadd9c0`) + process gap1/ActionDoNothing 직후 이어진
세션. 두 가지를 완료했다: (A) 레거시 테스트 하네스를 트리 경로로 이전하고 bespoke `ActionStackPtrFlow`를
완전히 삭제(H8-debt-2 Step3, master `accd8a9`), (B) struct/2D 배열/switch 패턴의 별도 x64 breadth corpus를
구축해 신규 갭을 매핑(master `5276375`). **이로써 H8-debt-2(Step1+Step2+Step3)가 완전히 종료됐다.** master
HEAD `accd8a9`, origin 푸시됨.

- **완료 A: H8-debt-2 Step3 -- bespoke ActionStackPtrFlow 은퇴 (master `accd8a9`)**:
  - `pkg/pcode/action_stack_ptr_flow.go`(619줄) 삭제. `loader_test.go`의 legacy 직접-heritage 테스트
    13개를 트리 경로(`bridge.Build(+CspecPath[+EntryPoint])` -> `bridge.Decompile`이 universal-action
    트리를 구동)로 이전, 원본 assertion은 무수정. x86 non-processEntry(CountedLoop/IfElse/Multiply/Add3/
    ClassifySign/Switch/StructAccess/ArrayIndex/CdeclParamLocal) + x86gcc.cspec, AArch64
    (AARCH64SimpleFunction) + AARCH64.cspec, x86 processEntry(ClassifySign/Multiply/Add3
    GoldenProcessEntry) + x86gcc.cspec + EntryPoint(`Decompile(ProcessEntryName, GhostParams=2)`).
  - 은퇴한 경로만 운동시키던 진단/중복 하네스도 함께 삭제: `classify2diag_main.go`(scratch), `msvc_debug_test.go`
    (assertion 없는 debug dump 2건), `msvc_diag_test.go`의 `runPipeline`(출력만 로깅하고 assert 없음 --
    골든 assertion은 이미 트리 경로인 `runPipelineGhidra`가 담당), `tree_output_diag_test.go`의
    `TestProductionStagesDiag`+`blockShape`(은퇴한 손정렬 파이프라인의 단계별 복제),
    `tree_accum_diag_test.go`의 RAW_DUMP spf 라인.
  - diff: +59/-1794(7파일). `NewActionStackPtrFlow` Go 호출처 0건(잔존은 과거 커밋 메시지/주석/assertion
    문자열뿐).
  - 게이트: `go build` 클린, `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1
    TestX64CorpusGoldenMap` 7/8(무회귀, process는 기존 MISMATCH 유지), `go test ./...` 전 패키지 그린
    (symbols_test 3건은 missing `simple_add_sym.exe` 사전조건 미충족으로 무시, 기존과 동일).
  - **이로써 H8-debt-2 = Step1(cspec/EntryPoint 배선) + Step2(`Decompile` 트리 교체) + Step3(bespoke 파일
    삭제) 완전 종료.** 잔여는 런타임 코드 주석 일부가 아직 `ActionStackPtrFlow`를 언급하는 것뿐(동작
    무관, 후속 정리 가능).

- **완료 B: breadth 디스커버리 -- struct/2D/switch corpus + 갭 맵 (master `5276375`)**:
  - 기존 `testdata/x64_corpus/`(8함수, 7/8 baseline)는 건드리지 않고 별도 `testdata/x64_breadth/`를
    신설(파이프라인은 동일 -- MSVC x64 `/Od` -> COFF obj -> Ghidra 12 헤드리스 `GenGoldens.java` 재사용).
    신규 하네스 `TestX64BreadthGoldenMap`(X64_BREADTH=1). 3함수 2/3 MATCH:
    - `dist_sq`(struct Point* 필드 접근, offset 0/8) MATCH -- multi-offset 포인터 deref parity 확인.
    - `sum2d`(2D 배열 `m[i*cols+j]` 인덱싱) MATCH -- 중첩 주소산술 parity 확인.
    - `dispatch`(dense switch 0..7, MSVC `/Od`가 jump table로 lowering) MISMATCH -- 신규 매핑된 갭.
  - **dispatch 갭의 근본 분류(4가지, 상세 `testdata/x64_breadth/README.md`)**:
    1. jumptable 복구가 파이프라인에서 미구동: `JumpTable`/`JumpModel` 머신러리는 `pkg/pcode/jumptable.go`
       (1671줄)에 포팅돼 있으나, decompile 경로에 `AddJumpTable`을 채우는 신규 등록 드라이버 호출자가
       없다. C++ 대응: `FlowInfo::generateOps`(flow.cc:799)가 `tablelist`를 순회하며
       `FlowInfo::recoverJumpTables`(flow.hh:138, flow.cc:1427)를 호출하는 구동 루프 -- Go 측
       `ActionSwitchNorm`(coreaction.go:3157)은 이미 등록된 JumpTable을 소비만 할 뿐, recoverJumpTables에
       대응하는 신규 등록 드라이버가 없다.
    2. `truncateIndirectJump` 실패 폴백 미포팅: 테이블 복구가 실패한 BRANCHIND를 CALLIND + artificial
       return으로 강등하는 전환이 없다. C++: `FlowInfo::truncateIndirectJump`(flow.cc:727,
       `setBadJumpTable(true)`). `void`+`goto *(...)` vs `undefined8`+`uVar1=(*(code*)(...))()`+`return`
       차이의 직접 원인.
    3. `goto label_missing` 파생: range guard의 default(범위 밖) 타깃 블록이 링크되지 않아 발생 -- #1/#2의
       파생 증상이지 별개 근본이 아니다.
    4. `&__ImageBase` 부재: 단일 `.text` 하네스가 image base/.rdata/reloc을 갖지 않아 트리의 테이블
       base가 raw 상수(`13952`/`0x1150`)로 남는다 -- loader/harness 계층 갭(별개, 낮은 우선순위).
  - **핵심 통찰**: 이 jump table은 `.rdata`의 `&__ImageBase` 상대 오프셋이라 relocation을 요구하는데,
    단일 `.text` 블롭 하네스에는 image base/reloc/.rdata가 없다. **Ghidra 자신도** headless로 이 테이블
    복구에 실패해(`WARNING: Could not emulate address calculation`) 동일 폴백(`truncateIndirectJump`,
    fail_normal)을 탄다 -- 따라서 parity 타깃은 완전한 switch 테이블 복구가 아니라 CALLIND 폴백 자체다.
  - **breadth 우선순위(ROI)**: (1) `truncateIndirectJump` 폴백[저비용, 즉시 parity 달성] -> (2)
    multi-section+reloc 로더[테이블 실복구 전제조건] -> (3) struct 타입 복구[저우선, dist_sq는 이미
    타입-미복구 상태로 MATCH]. breadth는 다세션 규모 작업.
  - 게이트: `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1 TestX64CorpusGoldenMap` 7/8 무회귀,
    `go build` + `go test ./pkg/...` 그린. `breadth.obj`는 gitignore(`*.obj`).
- C++ 참조: `flow.cc:799`(FlowInfo::generateOps jumptable 구동 루프), `flow.hh:138`/`flow.cc:1427`
  (FlowInfo::recoverJumpTables), `flow.cc:727`(FlowInfo::truncateIndirectJump).

### 2026-07-03: H8-debt-2 완료 -- production을 universal-action 트리로 (미션 #1 게이트)
process gap1 + ActionDoNothing 세션(바로 아래 항목) 직후 이어진 세션. `bridge.Decompile`의 41-call 손정렬
subset을 버리고 `db.BuildUniversalAction(nil)+BuildDefaultGroups()+SetCurrent("decompile").Perform(fd)`
(universal-action 트리)로 교체했다. 이걸로 미션 #1 게이트("트리를 production 경로로")가 달성됐다. 모든
production 골든이 byte-identical. master `eadd9c0`.
- **근본**: 트리와 41-call subset은 액션 목록이 아니라 단 하나의 배선(setup wiring) 차이만 있었다. production
  콜러가 `bridge.Result`를 cspec 없이(CspecData=nil) 만들어 cspec-less cdecl + 하드코딩 EAX 반환 + bespoke
  `ActionStackPtrFlow`를 강제하고 있었다. 트리는 cspec `<stackpointer>`가 있어야 faithful ActionSpacebase +
  RuleLoadVarnode/RuleStoreVarnode 경로가 실제 StackSpace를 갖는다. `bridge.Build`에 cspec+EntryPoint를
  공급(이미 Build 내부에서 arch-aware default ProtoModel + faithful stack spacebase로 파싱됨)하면 이 갭이
  닫힌다. Ghidra는 항상 cspec을 갖고 있으므로 cspec 요구는 근사가 아니라 충실 조건이다.
- **구현**: Step1 = cspec/EntryPoint를 production 하네스(`msvc_diag_test.go` `runPipelineGhidra`)의
  `bridge.Build` 호출에 배선(CspecPath x86gcc.cspec + EntryPoint). Step2 = `Decompile` 본문을 트리로 교체
  (ApplyCallingConvention/bespoke ActionStackPtrFlow/수동 Heritage/DeadCode/Merge/InferTypes 손정렬 제거).
  cspec 공급 계약 주석(`decompile.go`: 콜러가 CspecPath+EntryPoint 필수, 없으면 스택 로컬 미복구; Ghidra는
  항상 cspec 보유라 충실; 실 다운스트림 콜러는 테스트 하네스뿐).
- **게이트(감독관 독립 검증)**: `TestMSVC_{CountedLoop,SumList,AbsVal,Classify2,Gcd}` 5/5 byte-identical +
  `TestAARCH64`/`TestX8664`/`TestX64RegParam` PASS + tree 10/10 + x64 corpus 7/8(무회귀) + `go test ./...` 클린.
- **Step3(bespoke 파일 삭제) = 후속(별도 세션)**: `action_stack_ptr_flow.go`가 아직 legacy 테스트 하네스
  ~15개(`loader_test.go` 직접-heritage 테스트, 비-Ghidra `runPipeline`, diag 테스트)에서 직접 호출된다.
  production 경로에선 이미 은퇴했으나, 파일 자체를 삭제하려면 그 하네스들을 먼저 트리로 이전해야 한다.
- **process 3갭은 H8-debt-2로 자동 해소되지 않는다(중요 정정)**: 바로 아래 항목이 "H8-debt-2가
  merge/structuring/snapshot parity를 정면으로 다루므로 process 3갭이 그 과정에서 해소될 경로"라고 적었으나,
  실측 결과 그렇지 않았다. x64 corpus는 애초에 트리 경로(`BuildUniversalAction+Perform`)로 돌고 있었으므로
  process는 이미 트리 위에서 발현 중이었다 -- 이번 배선교체(production을 트리로)는 process와 무관하다.
  process 3갭(gap2 RuleSubCommute/RuleSubZext 순서, gap3 블록구조화 오폴딩, gap4 eax merge/copyprop)은 트리
  액션 내부의 deep-parity 부채로 별도 세션이 필요하다. H8-debt-2와는 "같은 서브시스템에 수렴"할 뿐
  "배선교체로 해소"되는 관계가 아니다.
- C++ 참조: `coreaction.cc`(`ActionDatabase::universalAction`).

### 2026-07-03: process gap1(포인터 배열 deref) + ActionDoNothing 포팅 -- 잔여 3갭 deep-debt 확정 (x64 corpus 7/8 유지)
grid_score 선언순서 완료(`8d007b5`) 이후 이어진 세션. process의 4개 근본 후보 중 gap1을 닫고
`ActionDoNothing`/`RemoveDoNothingBlock`을 충실 포팅했다. ActionDoNothing의 A/B 실측으로 "do-nothing 제거가
gap3/gap4의 공통 근본"이라는 gap34-invest 가설을 반증하고, gap34-v2 재규명(실제 MSVC 디스어셈블 + Ghidra
golden ground-truth 대조)으로 남은 3갭(gap2/gap3/gap4)의 진짜 근본을 확정했다. master `7a7b203`(gap1),
`c4d85ea`(ActionDoNothing). x64 corpus는 7/8 유지(process는 여전히 MISMATCH -- 근본 규명은 깊어졌으나
미해소).
- **완료 1: process gap1(포인터-파라미터 배열 deref, 실 correctness 버그) -- master `7a7b203`**:
  - 현상: golden `iVar1 = *(int *)(param_1 + (longlong)local_14 * 4);` 누락 -> iVar1 미초기화 read.
  - 근본: `pkg/pcode/printc.go` emitOps가 unique-space 출력을 무조건 억제(예외 = named MULTIEQUAL의 단독
    consumer뿐). Ghidra `PrintC::emitBlockBasic`(printc.cc:2836)는 `isImplied()`로만 억제하지 unique-space
    여부로 억제하지 않는다 -- 우리 blanket 억제는 근사고, `IsExplicit` 기준 emit이 충실하다. explicit
    플래그는 `ActionMarkExplicit`(coreaction.cc:3244, baseExplicit 3009)가 세팅.
  - 수정: 억제 가드에 `out.IsExplicit() && out.NumDescend()>0` 예외 추가. `NumDescend()>0`은 휴리스틱이
    아니라 충실 프록시다 -- `ActionMarkExplicit`는 `ActionDeadCode` 이후 실행되고(coreaction.cc:3252,
    beginDef(0)가 no-descendant dead op을 print 전에 제거) 실제 explicit def는 print 시점에 항상 live
    descendant를 가진다.
  - KNOWN-GAP: `sub rsp,0x18` 프레임 COPY가 faithful-stack ActionDeadCode를 통과해 잔존(unique, explicit,
    NumDescend==0)하는 경우가 있어 `uVarN = 0x18;`로 샐 수 있다 -- Ghidra처럼 ActionDeadCode가 그 COPY를
    제거해야 하나 후속 과제, 그때까지 NumDescend>0 가드가 대리.
  - 게이트: tree 10/10, x64 7/8(deref 라인 정확 렌더), production green.
- **완료 2: `ActionDoNothing`/`RemoveDoNothingBlock` 충실 포팅 -- master `c4d85ea`**:
  - 이전 no-op 스텁이던 `ActionDoNothing.Apply`(coreaction.go:594)/`RemoveDoNothingBlock`(funcdata.go:713)을
    C++ 그대로 포팅(coreaction.cc:3473-3497, funcdata_block.cc:327). 신규 `pkg/pcode/funcdata_donothing.go`:
    pushMultiequals(funcdata_block.cc:84), opZeroMulti(:177), descendantsOutside(:233),
    blockRemoveInternal(:254), removeDoNothingBlock(:327). `pkg/pcode/block_basic.go`에 술어 추가:
    hasOnlyMarkers(block.cc:2578), isDoNothing(:2596), unblockedMulti(:2534).
  - **A/B 결과(결정적, gap34-invest 반증)**: ActionDoNothing이 실제 발화해 do-nothing 블록을 제거하는데도
    (classify/grid_score/process에서 확인) 골든 출력은 전부 byte-identical하게 유지된다 -- grid_score/
    classify/max3/sum_array는 undefined4 MATCH 그대로(무회귀), process도 변화 없음(&& 여전히 미렌더 +
    undefined 여전히 유지). 즉 "do-nothing 제거가 gap3(&&)/gap4(타입누수)로 캐스케이드된다"는 gap34-invest의
    예측은 실측으로 반증됐다.
  - 커밋 유지 이유: 충실 포팅 + 무회귀 + H8-debt-2에 필요한 선행 인프라이기 때문(A/B가 가설을 반증해도
    포팅 자체는 정답).
  - 게이트: tree 10/10, x64 7/8, production green.
- **판정: process 잔여 3갭(gap2/gap3/gap4) = deep-debt, H8-debt-2와 묶음(1세션 착지 불가)**:
  gap34-v2 재규명(실제 MSVC 디스어셈블 + Ghidra golden ground-truth)으로 확정.
  - process 트리 출력은 코스메틱이 아니라 의미적 붕괴다 -- count++가 범위 밖 가드 안(정답 범위 안)에 있고,
    범위 안 v(local_18)는 미초기화, 로드 대입문이 드롭돼 있었다(gap1로 그 중 하나는 닫힘).
  - **gap3 진짜 근본**: RuleBlockOr/comma가 아니다(RuleBlockOr는 발화하나 이미 붕괴된 그래프 위에서
    오극성으로 발화, condexe는 process에서 애초 미발화). 실체 = 비대칭 clamp의 단일-스토어 블록(v=hi)이
    sibling count 블록으로 오폴딩(블록구조화 collapse 또는 RuleStoreVarnode heritage 결함).
  - **gap4 진짜 근본**: 스냅샷 타이밍이 아니다. MSVC eax 스크래치 임시가 스택-로컬로 미접힘(Merge/copyprop
    parity 갭).
  - **gap2 진짜 근본**(구현 시도는 미커밋, gcd 회귀로 기각): 과축소 주체 = `RuleSubCommute`(rules_ext.go:225).
    Go의 `RuleSubvarZext`(return narrowing)가 ZEXT를 RuleSubCommute의 overlap 체크 전에 제거해 순서가
    이탈한다. 충실 SEXT 가드 포팅 시 gcd 회귀(packed .sla가 dividend를 INT_OR로 인코딩하는데 Ghidra는
    INT_SEXT로 처리 -- `RuleOrSextForm` 미정규화). return-recovery/type-snapshot 타이밍과 얽혀 있다.
  - **결론**: 3갭 전부 return-recovery/type-snapshot/merge/structuring 파이프라인 재작업으로 수렴한다 --
    H8-debt-2와 분리할 수 없다. process는 코퍼스 중 유일하게 3-way clamp + count + 64비트 나눗셈 +
    early-return이 eax를 공유하는 특이 케이스다.
- **다음 = H8-debt-2 피벗**: `bridge.Decompile`의 41-call 손정렬 subset을 `db.BuildUniversalAction+Perform`
  (universal-action 트리)로 교체 -> bespoke `ActionStackPtrFlow` 은퇴. 트리는 이미 10/10 + 7/8로 우수.
  H8-debt-2가 merge/structuring/snapshot parity를 정면으로 다루므로 process 3갭이 그 과정에서 해소될
  경로다. `ActionDoNothing`(완료 2, `c4d85ea`)은 이 작업의 선행 인프라. 상세는 `docs/STATUS.md` 미시작 +
  `NEXT_SESSION_PROMPT.md` 참고.
- C++ 참조: `printc.cc:2836`(emitBlockBasic), `coreaction.cc:3244`(ActionMarkExplicit)/`:3252`(ActionDeadCode
  beginDef)/`:3473-3497`(ActionDoNothing), `funcdata_block.cc:84/177/233/254/327`(pushMultiequals/
  opZeroMulti/descendantsOutside/blockRemoveInternal/RemoveDoNothingBlock), `block.cc:2534/2578/2596`
  (UnblockedMulti/HasOnlyMarkers/IsDoNothing), `rules_ext.go:225`(RuleSubCommute, Go).

### 2026-07-03: grid_score 선언순서 완료 -- stack space index overflow + getNameRepresentative 포팅 (x64 corpus 7/8)
이전 세션이 남긴 "얽힘" 가설(stack space index 변경이 RestructureVarnode/ActionInferTypes 타입-스냅샷 타이밍에
영향)을 ACTTRACE 실측으로 반증하고, 진짜 근본(printc 선언-대표 선택의 loc_tree 의존 포팅 버그)을 규명해 해소.
master `8d007b5`. grid_score의 유일 잔여 diff(선언 순서)가 닫혀 x64 corpus 6/8 -> **7/8**.
- **기존 가설 반증**: stack idx 0 vs high로 ACTTRACE를 대조한 결과 counted_loop의 counted-action 트레이스가
  바이트 동일 -- pass 수/스냅샷 타이밍 불변. 타입 추론은 typeOrder 단조하강 fixpoint + count 미증가라 순서
  무관. 기존 "stack index 변경이 type-snapshot 타이밍과 얽혀있다"는 진단은 오진이었음.
- **진짜 근본**: `pkg/pcode/printc.go`의 `collectSymbols`가 named HighVariable의 선언 대표(representative)를
  loc_tree first-wins로 골라서, stack space index가 바뀌면 rep가 stack/register 인스턴스 사이로 뒤집히고
  선언 순서 + 선언 타입 소스가 같이 이동했다. Ghidra는 대표를 `HighVariable::getNameRepresentative`
  (variable.cc:492, compareName variable.cc:456)로 골라 인스턴스 순서 무관이다. 선언은 scope 심볼맵 주소순
  으로 방출된다(`emitScopeVarDecls` printc.cc:2650).
- **수정 1 -- stack space index overflow**(`pkg/bridge/bridge.go registerSpaceByIndex`): maxIdx 스캔에서
  const space를 포함해서 우리 const space(Index=0xFFFF)가 `maxIdx+1`을 uint16 overflow시켜 stack space가
  index 0(최저)으로 떨어졌다. Ghidra는 const을 index 0 고정(translate.cc:362)하고 spacebase/stack은 로드 시
  실공간 위에 append한다(architecture.cc:563 `addSpacebase` = `numSpaces()`). const space를 maxIdx 스캔에서
  제외해 stack이 실제 높은 index를 받도록 수정.
- **수정 2 -- getNameRepresentative 포팅**(`pkg/pcode/printc.go collectSymbols` + 신규 `pkg/pcode/
  action_name_vars.go highNameRepresentativeLive`): named HV 선언 대표를 loc_tree-order 무관
  `getNameRepresentative`(compareName 기반)로 재선택. live 제한이 필요한 이유: C++
  `HighVariable::getNameRepresentative`가 스캔하는 `hv->inst`는 `HighVariable::remove`(variable.cc:515)가
  Varnode 파괴 시 dead member를 즉시 퍼지해서 항상 live만 담는다. Gosleigh는 `remove`를 포팅하지 않아 dead
  인스턴스가 잔존할 수 있고, unfiltered 스캔이 dead 인스턴스를 rep로 고를 수 있다(34개 골든 중 sum_list 1건
  실측: Def==nil, bank 비멤버). live(bank 멤버십) 제한으로 C++ `inst` 불변식을 국소 재현. (검토했던
  `s.names[rep]=name` 직접 바인딩 workaround는 live 제한으로 대체되어 불필요해져 제거.)
- **결과**: `X64_CORPUS=1 TestX64CorpusGoldenMap` grid_score 신규 MATCH(6/8 -> **7/8**, process만 잔여).
  `TREE_MAP=1 TestTreeFullGoldenMap` 10/10 byte-identical 무회귀. production `TestMSVC*`/`TestAARCH64*`/
  `TestX8664*`/`TestX64RegParam*` 전부 PASS. `go test ./...` 클린.
- **process = 별개 근본 확정**: grid_score와 "공통 근본" 추정은 반증됨. process는 여전히
  `TestX64CorpusGoldenMap` MISMATCH(반환타입 `ulonglong` vs golden `int` 등). 근본 별개: (1) undefined4
  diamond 타입누수 = `ActionDoNothing`/`RemoveDoNothingBlock` 미포팅(coreaction.cc:3473-3497,
  funcdata_block.cc:327; Go 스텁 coreaction.go:592/funcdata.go:614), (2) 포인터-파라미터 배열 deref
  `*(int*)(param_1+(longlong)local_14*4)` 누락(heap access, correctness 갭), (3) 64비트 signed division
  반환 렌더링, (4) 단축평가 `&&` + comma 연산자 조건 구조화. 전부 기지의 독립 항목(상세는 `docs/STATUS.md`
  미시작 참고).
- **남은 리스크/known-gap**: const space가 여전히 0xFFFF(Ghidra는 const이 loc_tree 맨 앞 index 0, 우리는
  맨 뒤) -- 현 corpus 무해(실측), const=0 이관은 별도 세션. `HighVariable::remove`(variable.cc:515) 미포팅 =
  인스턴스 수명 갭의 근본. live-제한은 국소 보정이고 완전 해소는 remove 포팅(후속 과제).
- C++ 참조: `translate.cc:362`(const space index 0 고정), `architecture.cc:563`(addSpacebase numSpaces()),
  `variable.cc:456-511`(HighVariable::getNameRepresentative/compareName), `variable.cc:515`
  (HighVariable::remove), `printc.cc:2650`(emitScopeVarDecls).

### 2026-07-02: grid_score/process 스택프레임 복구 -- 충실 spacebase 경로 (x64 corpus 프레임 갭 해소)
이전 진단("heritage 이전으로 스택 인식 이동" Fix A / "def-use walk 패치" Fix B)을 폐기하고 Ghidra의 실제 스택
인식 경로를 그대로 포팅. master `c87debe`(이전 flag-gated 구현 `602dde8`). grid_score/process의
`stackOffsets=[]` -> `(int*)(lVar1-24)` 포인터 쓰레기 렌더를 해소.
- **근본 재규명**: Ghidra는 `Funcdata::spacebase`(funcdata.cc:230-269)가 모든 RSP 계열 varnode(input/
  sub-result/phi)에 spacebase 마킹을 걸고, 이미 충실 포팅돼 있던 `RuleLoadVarnode`/`RuleStoreVarnode`가 그
  마킹을 따라 `[rsp+k]` LOAD/STORE를 스택 공간 varnode로 변환한다. `sub rsp,N` 오프셋 누적은 RuleSub2Add +
  RuleCollapseConstants + `RuleAddMultCollapse`(ruleaction.cc:4113-4182)가 담당. x86-32 EBP 프레임도 동일
  경로(RulePropagateCopy가 `MOV EBP,ESP`를 인라인 -> `[EBP+k]`가 `[ESP_input+k]`로 정규화).
- **메운 갭**: (1) `Funcdata.Spacebase()` no-op stub -> 충실 구현. (2) 주소공간 spacebase-register 인프라
  신규(`pkg/address/space.go`). (3) cspec `<stackpointer>`를 스택 spacebase 공간으로 배선(bridge.go
  buildFaithfulStackSpace/bindLoadStoreSpaces). (4) `RuleAddMultCollapse` 누락 분기 + `RuleCollapseConstants`
  신규 추가. (5) 새 스택 varnode에 불충실 타입 시드 제거(rules_loadstore.go -- C++ RuleLoadVarnode는 타입
  미설정, ruleaction.cc:4310). (6) `HighVariable::getNameRepresentative`/`compareName` 포팅
  (variable.cc:456-511) -- 병합된 스택+레지스터 누산기 HV가 스택 Symbol 이름을 따르도록.
- **딜리버리 구조**: faithful 경로는 universal-action 트리의 기본값(`GOSLEIGH_FAITHFUL_STACK` 플래그 제거,
  무조건 실행). production `bridge.Decompile`(41-call subset)은 ActionSpacebase/RuleLoadVarnode를 안 돌리므로
  기존 bespoke `ActionStackPtrFlow`를 그대로 유지 -- **구조적 분리**(bespoke는 트리 액션 리스트에서 빠지고
  production 전용으로 존속, 완전 폐기는 트리가 production 경로가 되는 H8-debt-2 이후).
- **회귀 0**: `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1 TestX64CorpusGoldenMap` 6/8, production
  `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*` 전부 PASS, `go test ./...` 클린.
- **남은 것**: grid_score/process는 스택 프레임이 복구됐지만 별도 non-stack 사유로 여전히 MISMATCH(선언순서/
  상수접미사/포인터-파라미터 배열 deref/64비트 나눗셈 반환/단축평가 조건 구조화/타입 누수) -- 상세는
  `docs/STATUS.md` 미시작 참고.
- C++ 참조: `funcdata.cc:230-269`(Funcdata::spacebase), `ruleaction.cc:4193-4361`(RuleLoadVarnode),
  `ruleaction.cc:4113-4182`(RuleAddMultCollapse 등), `variable.cc:456-511`(HighVariable::getNameRepresentative/
  compareName).

### 2026-07-02: sum_array x64 MATCH (6/8) -- 데이터모델 long/longlong + printc 잔차 2건
type-leak 완료 후 sum_array의 유일 잔차(시그니처 `long` vs golden `longlong`)를 닫고 본문 잔차 2건 해소. 3커밋.
- **데이터모델 8바이트 int 이름**(cspec.go/protomodel.go/printc.go): Win x64는 LLP64(long=4/longlong=8)라 8바이트
  signed = `longlong`, LP64(aarch64/Linux x64)는 `long`. cspec `<data_organization><long_size>`를 파싱해
  ProtoModel.LongSize -> printc normalizedBaseType으로 배선(기존 8바이트 INT="long" 하드코딩 제거). C++ parity:
  TypeFactory::setupSizes/sizeOfLong. LP64 기본값 8이라 aarch64/x86-32 무회귀.
- **8바이트 상수 LL 접미사 제거**(printc.go renderConstant): `4LL` -> `4`. C++ push_integer(printc.cc:1354)는
  `sizeSuffix`를 `vn->isLongPrint()`일 때만 붙이고, 그건 CastStrategyC(cast.cc:103)의 shift-피연산자 int-promotion
  회피 케이스에서만 세팅됨(미모델) -> 기본 무접미사.
- **cast==unary precedence로 여분 괄호 제거**(printlanguage.go): `*((int *)x)` -> `*(int *)x`. ExprPrecCast를
  ExprPrecUnary와 동급 alias. C++ parity: PrintC::dereference/typecast OpToken 둘 다 precedence 62(printc.cc:34-35),
  PrintLanguage::parentheses가 unary_prefix 부모 아래 presurround(cast) 자식을 동급에서 무괄호.
- **회귀 0**: x64 6/8(sum_array 추가), tree 10/10, production TestMSVC*/pcode/bridge green. 남은 2개 =
  grid_score/process(스택프레임 미복구 + step5 ActionDoNothing).

### 2026-07-02: TYPE-LEAK 충실 포팅 -> x64 corpus 5/8 (max3 신규 MATCH), tree 10/10 유지
`int local_N` vs golden `undefined4 local_N` 미스매치(max3/sum_to_n/sum_array/grid_score 공통)의 근본을
규명하고 충실 포팅. master `be0999c` 머지(7커밋). 팀 작업(Fable 심층 C++ 규명 + 변형 corpus 3라운드 실측 +
Opus 구현/SSA 진단).
- **근본 = 심볼 스냅샷 타이밍**(이전 "committed 타입이 함수별로 갈린다/전파 strength" 가설은 오답 -- 둘 다
  fixpoint에선 committed int 도달). 로컬 선언 타입 = 마지막 `ActionRestructureVarnode`의 committed varnode
  타입 스냅샷. `ActionInferTypes`가 count 미보고(coreaction.cc:5422)라 순수 타입 커밋으로는 restructure
  추가 pass 없음. no-diamond(counted_loop/max3/sum_to_n)는 fullloop iter-2가 1 pass로 수렴 -> 마지막
  restructure가 pre-typeprop TYPE_UNKNOWN 스냅샷 -> undefined4. diamond(else 분기, process)는 iter-1 tail의
  `ActionDoNothing`이 marker-only 블록 제거(count+1) -> iter-2가 2 pass -> pass2 restructure가 커밋 후 int
  gather -> int. 변형 corpus 실측으로 else-분기가 트리거임을 확정(나눗셈/다중return은 반증).
- **7 fixes**: (1) `TypeOrder`(datatype.go, type.cc:216-222). (2) faithful `ActionInferTypes` count=0, tree
  전용(action_infertypes.go); production/bridge는 `action_infertypes_legacy.go`로 격리 보존. (3) `ActionDeadCode`
  OncePerFunc->flags=0(action_deadcode.go, coreaction.hh:560/cc:5514) = **uint-flood 근본**: in-loop DeadCode가
  매 pass 재실행돼 orphan `RAX=ZEXT(EAX)` 제거(안 죽이면 getLocalType이 ZEXT의 UINT input-local을 집어
  params/return까지 flood). (4) 중복 post-cleanup DeadCode 제거. (5) `RangeHint` symbol 타입(rangehint.go;
  varmap.cc gatherVarnodes:1124/isReadActive:1088 -- read-active loop phi는 gather됨, undefined4는 순수 타이밍
  이지 필터 아님). (6) decl-from-symbol(printc.go). (7) `RulePtrFlow` dormant(rules_pointer.go GetOpList +
  space.go IsTruncated; ruleaction.cc:9058-9068) -- **오역 수정**: 우리 RulePtrFlow가 "STORE 주소가 pointer
  타이핑되면 발화"로 잘못 포팅돼 counted_loop 스택 STORE에 spurious late 발화 -> 여분 pass -> int. C++는
  포인터 폭-절단 rule로 non-truncated 아키텍처(x86/x64/aarch64)에선 op pool 미등록=휴면. sum_list `int local_8`은
  RulePtrArith(실 param_3 int* 체이스)가 담당, 오역 rule 안 되살림.
- **회귀 0**: tree 10/10 byte-identical(counted_loop undefined4 복원 + sum_list int 유지), x64 5/8, production
  TestMSVC*/pcode/bridge/sla green.
- **남은 3개(별도 블로커)**: sum_array = 유일 차이 `longlong` vs `long`(데이터모델 LLP64, normalizedBaseType
  printc.go:1177). grid_score/process = 스택프레임 미복구(stackOffsets=[]) + step5 `ActionDoNothing`(현재 no-op
  스텁 coreaction.go:594; diamond->int)은 스택프레임 복구 후에나 유효.

### 2026-06-30: x86-64 SysV 파라미터 선언 순서 버그 수정 (breadth probe로 발견)
표본 충분성 점검차 x64 add 스니펫을 non-processEntry 모드로 트리에 돌려 register-param 복구를 확인하다
**시그니처 파라미터 순서 역전 버그**를 발견. `entry(long param_1,long param_2)` 대신 `entry(long param_2,long param_1)`
출력(본문은 정상). 원인: x86-64 SysV는 register offset 순서가 인자 순서와 반대(RDI=0x38=arg0, RSI=0x30=arg1)인데
printc가 param을 storage offset(CompareLocDef)으로 정렬 -> 역전. aarch64(x0<x1, offset순=인덱스순)는 우연히
정상이라 안 걸렸고, 유일 x64 골든은 processEntry(in_RDI)라 param 복구를 아예 미테스트 -> 표본이 작아 숨었던 버그.
- **수정**(printc.go FuncProto param 정렬): param을 ABI 슬롯 인덱스로 정렬 -- register 인자는 calling-convention
  순서(IsRegParam index)로 먼저, stack 인자는 frame offset 오름차순으로 뒤에. C++ 참조: FuncProto는 파라미터를
  ParamList 슬롯 인덱스(ParamEntry 순서)로 순회, storage address가 아님.
- **회귀 가드 추가**(x64_regparam_test.go TestX64RegParamOrder): x64 add2/add3를 non-processEntry로 돌려
  `entry(long param_1,long param_2[,param_3])` 순서 단언(ABI 구조적 불변식, 골든 무관). RDI/RSI/RDX 3인자 복구도 커버.
- **무회귀**: TREE_MAP 10/10 유지, x86-32(stack param, offset순=인덱스순)/aarch64 무영향, 전 패키지 그린.
- **시사**: 골든 표본이 tiny + processEntry 편중이라 실제 x64 register-param 경로(named param 복구)가 사실상
  미검증이었음. 실함수 breadth(#2/#3)로 새 Ghidra 골든 생성 필요성 재확인.

### 2026-06-30: H8-debt-2 -- x64 processEntry in_RDI (entry-point void proto + irregular input 네이밍) = 멀티아치 10/10
유일 잔여 x64_add_ret를 닫아 **트리 전체 골든 맵 10/10 byte-identical** 달성. entry-point(processEntry) 함수의
register 인자를 param이 아닌 live-on-entry `in_<reg>`로 렌더 + void 프로토타입. x86-32 8/8 + aarch64 무회귀,
production `TestMSVC*`/`TestAARCH64SimpleFunction`/`TestX8664` 무회귀, 전 패키지 그린.
- **현상**: x64_add_ret GOT `entry(undefined4 p1,p2,long p3,long p4){return p4+p3;}` vs WANT
  `long processEntry entry(void){ long in_RSI; long in_RDI; return in_RDI+in_RSI;}`. 갭 = entry-point 의미:
  golden은 void 프로토타입 + register 인자를 `in_RDI`/`in_RSI`로, 트리는 param_3/param_4로 복구.
- **근본(2개, 같은 뿌리, 코드 추적)**: processEntry는 스택 컨벤션이라 register 인자가 param 슬롯(index)을 안 받음.
  (a) 트리는 RegParamOffsets 게이트로 RDI/RSI를 param 복구. (b) 미복구 register 입력의 `in_<reg>` 네이밍이
  printc에 미구현(`isSpecialInputRegister`는 pc/sp/lr만). 추가로 반환 타입 `undefined8` = RDI/RSI 미시드 시
  InferTypes가 long 추론 실패.
- **수정 1 -- EntryPoint 모델 플래그**(protomodel.go ProtoModel.EntryPoint + bridge.go BuildConfig.EntryPoint):
  buildDefaultModel이 entryPoint를 모델에 전파. RegParamOffsets는 **유지**(인자 레지스터 식별용).
- **수정 2 -- scopelocal regparam 분리**(scopelocal.go BuildFromVarnodes): EntryPoint면 regParamSlots 수집 +
  **타입 시드(TYPE_INT)는 유지**하되 **param HighVariable 생성 + fp.AddParam만 스킵**. 타입 시드 유지로
  ActionInferTypes가 RDI/RSI -> ADD -> 반환을 long으로 추론(undefined8 해소). regParamCount=0(스택 param은 0부터).
- **수정 3 -- printc in_<reg> 네이밍**(printc.go FuncProto 경로, HV 디스패치 직전): EntryPoint && input &&
  register space && IsRegParam(offset) && live 인 varnode를 `in_<regname>`로 네이밍 + locals 선언. HV 디스패치
  전에 둬서 machine-generated HV로 인한 `local_<createindex>` 폴백을 차단. EntryPoint 게이트로 aarch64
  (non-processEntry, x0/x1 정상 param 복구) 무영향 -- 이 게이트 없으면 aarch64 param이 in_x0로 오네이밍됨(회귀).
  C++ 참조: ScopeInternal::buildVariableName database.cc:2470 (input && index<0 -> "in_" + regname).
- **수정 4 -- runTreeCase**(tree_fullmap_diag_test.go): procEntry != "" 케이스에 BuildConfig.EntryPoint=true
  (SetProcessEntry 프린트 어노테이션과 짝).
- **무회귀 근거**: in_ 네이밍은 EntryPoint && IsRegParam(arg 레지스터)로 이중 게이트 -- x86-32(인자 레지스터 없음)/
  aarch64(non-entry) 미발동, frame/callee-saved 레지스터 제외. production decompile.go는 EntryPoint 미설정(기본 false).

### 2026-06-30: H8-debt-2 -- 트리 default ProtoModel arch-aware 화 (cspec 구동), aarch64 register-param 복구 = 멀티아치 9/10
트리가 쓰는 default ProtoModel을 x86-32 하드코딩에서 cspec 구동 arch-aware로 교체. register-param 아키텍처
(x86-64 SysV, AArch64 AAPCS64)의 (1) 레지스터 파라미터 복구, (2) signed-long 반환 타입, (3) 반환값 복구가 트리
파이프라인에서 동작. **aarch64_add_ret = void 붕괴 -> `long entry(long param_1,long param_2)` MATCH**. 멀티아치
8/10 -> 9/10. x86-32 8/8 무회귀, 전 패키지 그린.
- **근본(전 세션 코드 추적 검증됨)**: `bridge.go buildDefaultModel`이 `NewProtoModelFromCspec(cspec, nil, nil)`
  (regLookup=nil -> RegParamOffsets 미설정) + `WithReturnReg(sp.Index, 0, 4)`(x86 EAX 하드코딩)이라 x64/aarch64에서
  scopelocal.go:110 register-param 게이트 미발동 + 반환 레지스터 오설정. 추가로 `runTreeCase`가 CspecPath 미전달이라
  CspecData=nil(ABI 정보 전무).
- **수정 1 -- buildDefaultModel arch-aware**(bridge.go): regLookup(`xr.RegisterByName`)을 NewProtoModelFromCspec에
  전달 -> cspec IntegerRegParams()로 RegParamOffsets 채움. 반환 레지스터를 cspec default-proto `<output>` 첫 정수
  register pentry(EAX/RAX/x0)에서 유도 -> 자연 폭(EAX 4/RAX 8/x0 8)으로 WithReturnReg. cspec nil이면 기존 EAX(0,4)
  스캔 fallback(gcd 트리 가드 등 cspec-less 경로 byte-identical 유지).
- **수정 2 -- cspec storage 속성 파싱**(cspec.go): AArch64 cspec은 `metatype` 대신 `storage="float"`/`"hiddenret"`
  사용. CspecPentry에 Storage 추가 + `isIntegerRegPentry` 헬퍼(register && !addr && metatype!=float &&
  storage!=float/hiddenret)로 IntegerRegParams/신규 IntegerReturnReg 공통화. x86-64 metatype 경로 무영향.
- **수정 3 -- runTreeCase cspec 전달**(tree_fullmap_diag_test.go): treeMapCase에 cspecRel 추가, BuildConfig.CspecPath
  배선. x86-32=x86gcc.cspec(no reg param, EAX), x64=x86-64-gcc.cspec(RDI/RSI.., RAX), aarch64=AARCH64.cspec(x0/x1.., x0).
  AARCH64.cspec를 Ghidra 12.0.4에서 testdata/sla로 복사.
- **검증**: RegisterByName 덤프로 cspec 소문자 이름 해석 확인(x0=0x4000/8, RDI=0x38/8, RAX=0x0/8; 대문자 X0는 미해석=케이스민감).
- **x64 잔여(별도 경로)**: x64_add_ret은 register 복구 + long 반환은 됐으나 processEntry 모드라 golden은
  `entry(void)` + live-on-entry `in_RDI`/`in_RSI` 형태를 원함. 트리는 param_3/param_4로 복구. 필요한 것:
  (a) entry-point void 프로토타입(register-param 복구 억제), (b) `in_<reg>` 입력 레지스터 네이밍(printc 미구현 --
  `isSpecialInputRegister`는 pc/sp/lr만 처리). aarch64(non-processEntry)는 영향 없음.
- C++ 참조: Architecture::defaultfp/PrototypeModel cspec 구성, ProtoModel output ParamList(반환 슬롯),
  ScopeLocal::buildFromVarnodes(scopelocal.go register-param 게이트).

### 2026-06-30: H8-debt-2 -- RuleRangeMeld 충실 포팅 (CircleRange subset), x86-32 8/8 byte-identical
classify_sign 잔여(BOOL_OR comparison-merge 미구현)를 닫아 트리 x86-32 전 골든(8/8) byte-identical 달성.
멀티아치 전체 7/10 -> 8/10. 전 패키지 그린, production `TestMSVC*` 무회귀.
- **RuleRangeMeld 실구현**(rules_ghidra_port.go RuleRangeMeld.apply + 신규 circlerange.go): 기존
  newKnownMismatchBatchRule stub을 Ghidra CircleRange subset 충실 포팅으로 교체. 트리 잔여
  `BOOL_OR(INT_EQUAL(p,0), INT_SLESS(p,0))`를 `INT_SLESS(p,1)`(= `param_3 < 1` golden)로 collapse.
  applyOp 흐름: 두 bool-output 입력을 각각 CircleRange로 pullBack -> BOOL_AND이면 intersect, BOOL_OR이면
  circleUnion -> translate2Op로 단일 비교 op 복원(restype 0=비교, 1=항상참 COPY 1, 2=불가 no-op, 3=항상거짓 COPY 0).
- **CircleRange subset 포팅**(circlerange.go, 신규): 모듈러 반열린구간 [left,right)+step+mask 표현.
  rangeutil.cc에서 직접 포팅 -- pullBack/pullBackUnary(BOOL_NEGATE/COPY/2COMP/NEGATE/ZEXT/SEXT)/
  pullBackBinary(EQUAL/NOTEQUAL/LESS/LESSEQUAL/SLESS/SLESSEQUAL/CARRY/ADD/SUB/RIGHT/SRIGHT)/intersect/
  circleUnion/translate2Op + normalize/complement/convertToBoolean/contains/isSingle/newStride/newDomain/
  encodeRangeOverlaps(arrange 테이블 verbatim). **의도적 미포팅**: usenzmask 경로(setNZMask, rule이 항상
  usenzmask=false 호출) + constant Symbol markup(copySymbolIfValid, Gosleigh는 per-Varnode 상수 심볼 markup
  미보유 -- 명명/enum 상수 표시에만 영향). 코드 주석에 명시.
- **무회귀 근거**: RuleRangeMeld는 공유 rule이나 production은 비교를 다른 순서로 일찍 단일화해 BOOL_OR/BOOL_AND
  comparison-pair를 형성하지 않으므로 충돌 없음. TestMSVC* 전수 + TestUniversalActionTreeGcdGolden/Converges 그린.
- C++ 참조: ruleaction.cc:1357 RuleRangeMeld::applyOp, rangeutil.cc(CircleRange 전반), rangeutil.hh:50/358.

### 2026-06-30: H8-debt-2 -- De Morgan 분기반전 수정 + 트리 전체 골든 갭 지도 (멀티아치 7/10)
5/5 후 breadth 확장(x86-32 8개 + x64 + aarch64 = 10 testable)으로 트리 전체 갭 지도 작성. classify_sign에서
진짜 De Morgan 버그를 잡아 의미 정확성 확보. 전 패키지 그린.
- **De Morgan connective flip 수정**(prefer_complement.go getBooleanFlipOpcode): `getBooleanFlipOpcode`가
  CPUI_BOOL_AND/CPUI_BOOL_OR를 미처리해 `(CPUI_MAX,false,false)`(ok=false) 반환 -> opFlipInPlaceExecute의
  `if !ok { continue }`가 AND<->OR swap 코드(`case flipOpc==CPUI_MAX`) 도달 전 skip. 즉 De Morgan connective
  flip이 unreachable 죽은 코드. 분기 반전 시 operand는 뒤집히나 connective AND 유지 -> `!(a!=0 && a>=0)`가
  `(a==0 && a<0)`(모순)로 잘못 렌더(classify_sign). `(CPUI_MAX,false,true)` 반환으로 swap 분기 활성화.
  C++ parity: funcdata_op.cc opFlipInPlaceExecute가 BOOL_AND/BOOL_OR를 뒤집음. **모든 BOOL_AND/BOOL_OR 분기
  조건에 영향하는 correctness 수정.** classify_sign `(p==0)&&(p<0)`(모순) -> `(p==0)||(p<0)`(=p<=0, 정확).
- **트리 전체 골든 갭 지도**(TestTreeFullGoldenMap, TREE_MAP=1): **7/10 byte-identical**. x86-32 7/8(classify_sign만
  잔여=RuleRangeMeld stub), complex_max 바이트 미보유. **x64_add_ret MISMATCH**: 입력 레지스터 RDI/RSI가
  in_RDI 아닌 local_31/local_30 오분류 + 반환 undefined8 vs long. **aarch64_add_ret 완전 붕괴**: void entry(void)
  -- register-param + 반환값 복구 트리 미배선. 결론: 트리는 x86-32(스택)엔 견고하나 register-param 아키(x64/ARM)
  복구가 트리 전용 미배선 = 미션 x64 register param 목표의 직접 블로커.
- C++ 참조: funcdata_op.cc opFlipInPlaceExecute(BOOL_AND/BOOL_OR), ruleaction.cc RuleRangeMeld(1341), circlerange.cc.

### 2026-06-30: H8-debt-2 -- 트리 x86-32 골든 5/5 byte-identical (sum_list -- detached dead COPY 정리)
트리 universal-action 파이프라인이 **5개 x86-32 골든(gcd/abs_val/classify2/counted_loop/sum_list)을 전부
byte-identical** 출력. 미션 #1 게이트(트리가 손정렬 41-call subset 대체)의 결정적 전진. 전 패키지 그린,
production(`TestMSVC*`) 무회귀.
- **근본 (sum_list 포인터-iterate)**: `param_3 = (int *)param_3[1]` iterate의 주소 계산이 트리에서 잘못
  렌더(phantom `int *uVar3;` 선언 + `while` 유지). AddTreeState.buildTree(addtreestate.go)는 PTRADD/COPY를
  `NewOpBefore`로 만드는데 이 함수는 OpMarkAlive만 하고 **블록에 삽입하지 않음**(detached-alive = 인라인 렌더용
  implied 표현식 op, production도 동일). 원래 LOAD은 COPY 출력(원본 addr temp)을 읽음. RulePropagateCopy가
  LOAD 주소를 COPY 너머 PTRADD 출력으로 propagate(C++ RulePropagateCopy::applyOp ruleaction.cc:3946과 동일)
  -> COPY가 dead. C++은 이 dead COPY를 dead-code가 제거하나, Gosleigh는 (a) COPY가 detached-alive라 OpDestroy
  대상이나 (b) universal-action 트리에서 이 oppool propagation 이후 ActionDeadCode가 다시 안 돌아 잔존.
  잔존 dead COPY가 PTRADD 출력을 2-descendant로 유지 -> MarkExplicit이 explicit + NameVars가 uVar3 명명 ->
  선언 + for-fold 거부(testIterateForm이 explicit multi-use 노드에서 truncate).
- **수정**(rules_copy.go RulePropagateCopy): propagation이 detached COPY를 dead로 만들면 즉시 OpDestroy(C++
  dead-code가 in-block COPY에 해주는 정리를 eager하게). detached COPY로 한정(addrtied/persist 제외) -- in-block
  스냅샷(gcd loop-head trimOpOutput COPY)은 일반 dead-code에 위임해 gcd 무회귀. PTRADD가 single-use ->
  implied/inline(`param_3[1]`) -> uVar3 선언 소멸 + for-fold DFS가 param_3 도달.
- C++ 참조: ruleaction.cc RulePropagateCopy::applyOp(3946), addtreestate.cc AddTreeState::buildTree,
  block.cc BlockWhileDo::testIterateForm.

### 2026-06-30: H8-debt-2 -- 루프 누산기 dead-temp 근본 해소 (BuildFromVarnodes가 병합 high를 훔치던 버그)
counted_loop/sum_list의 루프 본문이 dead temp(`uVar2 = local_c + local_8`)로 새던 블로커를 충실히 잡음.
이전 세션의 "loop-snapshot 누산기 미통합" 가설(trimOpOutput 확장 필요)은 **오진**이었음 -- 계측으로
실제 경로를 추적해 진짜 원인을 규명. counted_loop의 두 루프변수 write-back이 모두 정상 복구됨
(`local_c = local_c + local_8`, `local_8 = local_8 + 1`). gcd/abs_val/classify2 무회귀, 전 패키지 그린.
- **오진 정정**: register:0x0(counter)/register:0x4(accumulator)가 mergeByDatatype에 over-merge된다고 봤으나,
  High 그룹 덤프 결과 둘은 **분리**돼 있었음(이전 세션 addrtied 수정으로 해소됨). 또 mergeMarker(MergeOp)는
  phi 입력 register를 stack local high에 **정상 병합**함(MERGE_DBG 계측: phase2 allOK, phase3 MERGE 확인).
- **진짜 근본**: merge 이후 실행되는 `ActionInputPrototype.Apply`(coreaction.go:986)가 `BuildFromVarnodes`를
  호출 -> local 루프(scopelocal.go:281)가 `NewHighVariable("local_c")` + AddInstance로 stack varnode를 **새 high로
  훔쳐**, 병합 high에 들어있던 register:0x4를 orphan(uVar2)으로 남김. C++ `ActionInputPrototype::apply`
  (coreaction.cc:4718)는 HighVariable을 **재생성하지 않음** -- 입력 param trial resolve + updateInputTypes만 하고
  local high는 안 건드림(이름은 Symbol에서 파생). Go의 high 재생성이 비충실.
- **수정**(scopelocal.go BuildFromVarnodes local 루프): 새 high 생성 대신 그룹 stack varnode가 **이미 속한 병합
  high를 재사용 + SetName**. claimedHigh 가드로 두 offset이 한 high를 공유(over-merge)하면 새 high로 폴백해
  변수 붕괴 방지. register-backed 누산기/카운터가 stack local에 따라옴 -> write-back 렌더.
- **남은 갭(counted_loop/sum_list 공통)**: 이제 둘 다 의미 정확, 유일 차이는 **for-loop fold**(`while`->`for`).
  sum_list는 추가로 stray `int *uVar3;` 미사용 선언. production은 for-fold 동작(골든 통과) -> 트리만 미적용.
- C++ 참조: coreaction.cc ActionInputPrototype::apply(4718)/ActionOutputPrototype::apply(4776),
  merge.cc mergeMarker(889)/mergeOp(719).

### 2026-06-30: H8-debt-2 step4-후속 -- counted_loop 누산기 갭 딥다이브 (merge/cover/addrtied 진짜 버그 5개 충실 수정)
step4(트리 1/5->3/5) 후 남은 counted_loop/sum_list(루프 본문 누산기가 dead temp `uVar2`로 렌더)를 SSA-버전
레벨까지 해부해 진짜 C++ parity 버그 5개를 잡음. 골든 숫자는 3/5 유지지만 **스택 로컬 over-merge라는 한 층을
실제로 뚫음**(stack:fff4/fff8이 더는 한 덩어리로 안 합쳐짐). 전 패키지 그린, gcd/production 무회귀.
- **ActionOutputPrototype AddInstance 도둑질 제거**(f66a2b5): C++ ActionOutputPrototype::apply(coreaction.cc:
  4776)는 updateOutputTypes로 출력 **타입만** 갱신하나 Go는 `hv.AddInstance(firstRet)`로 반환 varnode를
  병합 High에서 훔쳐, 루프-누산기 반환에서 register를 local과 분리. 제거(SetInternal과 동일하게 타입만).
- **스택 심볼 addrtied**(f66a2b5): RestructureVarnode가 stack-slot 심볼에 addrtied 미부여
  (database.cc ScopeInternal::buildFrom은 usepoint 무제한 entry에 addrtied). 부여. 단 syncVarnodeFlags가
  C++ "addrtied는 clear만, set 불가" 의미라 varnode엔 전파 안 됨 -> 아래 setVarnodeProperties로 해결.
- **Funcdata::setVarnodeProperties 포팅**(44f6e80): C++(funcdata_varnode.cc:25)은 varnode 생성 시
  localmap에서 SymbolEntry 조회해 addrtied를 stamp(Varnode::setSymbolProperties, setFlags 무제한). Go의
  NewVarnode/NewVarnodeOut가 이걸 안 해 심볼 생성 후 만들어진 stack COPY가 addrtied 미상속. 포팅 +
  RestructureVarnode가 기존 stack varnode를 re-stamp(StackPtrFlow가 심볼 전에 만든 것). **결과: 두 스택
  로컬이 addrtied가 돼 mergeByDatatype의 addr-tied 가드가 작동, stack over-merge 소멸(MERGE_DBG 실측).**
- **HighIntersectTest::moveIntersectTests 충실 포팅**(d265c2a): Go는 흡수된 High의 캐시만 지우고 survivor의
  stale `false`는 안 지움. survivor가 흡수로 cover가 커지면 "X와 안 겹침" 캐시가 stale. C++(variable.cc:1091)은
  survivor의 false 테스트를 (흡수 High도 X와 false였던 경우만 빼고) 삭제 + 흡수 High의 true 테스트를 survivor로
  re-key. 충실 포팅(잠재 선행수정).
- **남은 단일 블로커(정밀)**: 루프 본문 누산기 INT_ADD 출력 register:0x4가 스택 로컬 local_c와 통합 안 됨
  (`local_cT = MULTIEQUAL register:0x4#uVar2 ...`, phi 출력=local_c, 입력=uVar2 별도). gcd iVar1과 같은
  loop-snapshot/trimOpOutput 머신이 누산기(non-cond phi)에서 snapshot을 로컬과 통합 못 함. 다음: MergeOp
  phi-trim + trimOpOutput 누산기 확장(gcd 회귀 위험).
- C++ 참조: funcdata_varnode.cc setVarnodeProperties(25)/syncVarnodesWithSymbol(949), varnode.cc
  setSymbolProperties(410), variable.cc moveIntersectTests(1091), merge.cc mergeByDatatype(359)/merge(1565),
  coreaction.cc ActionOutputPrototype::apply(4776).

### 2026-06-30: H8-debt-2 step4 -- AncestorRealistic 포팅 + 트리 return-value 복구 (트리 골든 1/5 -> 3/5)
트리 x86-32 골든이 1/5 -> **3/5 byte-identical**(abs_val/classify2 신규 MATCH + 기존 gcd). 값 반환
함수가 트리에서 void + dead-code로 렌더되던 공통 블로커를 해소. 미션 #1 게이트 핵심 전진. 전 패키지 그린,
production 무영향.
- **AncestorRealistic 충실 포팅**(`ancestor_realistic.go`): C++ funcdata_varnode.cc:2016-2256 +
  funcdata.hh:656 State를 그대로 옮긴 backward stack-DFS. 반환 varnode의 조상이 realistic한지(solid
  movement vs unaffected/killedbycall/bare-input pass-through)를 enterNode/uponPop/checkConditionalExe/
  execute로 판정. 선행 플래그(IsDirectWrite/IsUnaffected/IsIncidentalCopy/IsStoreUnmapped 등)는 대부분
  이미 존재, 누락 접근자 3개(op.IsIncidentalCopy/op.IsStoreUnmapped/vn.IsIncidentalCopy)만 추가.
- **트리 guardReturns 배선**(`action_guardreturns.go` ActionGuardReturns, once-per-func): production
  드라이버가 heritage/stack 해석 직후 1회 호출하는 ApplyGuardReturnsLive(격리 heritage 패스, return
  범위만 BuildADT+Rename)를 트리 파이프라인 안에서 재현. mainloop의 ActionReturnRecovery 직전 배치.
  트리 모델은 buildDefaultModel이 WithReturnReg를, ActionPrototypeTypes가 active output을 이미 설치하므로
  guardReturns가 발화. 이게 RETURN에 반환 레지스터를 엮어 본문을 살림(consume-bit DeadCode 보존).
- **ActionReturnRecovery에 AncestorRealistic 게이트**: trial markActive를 execute(realistic) AND
  ancestorOpUse(active use) 둘 다 통과 시로 제한(C++ ActionReturnRecovery::apply 충실). gcd의 param_3는
  bare input(루프 통과)이라 execute 실패 -> void 유지. abs_val의 -param_3는 solid NEG -> 성공 -> int.
- **수렴 버그 -> once-per-func**: guardReturns가 반환값을 엮자 abs_val/classify2가 mainloop hang.
  진단(processOp histogram: 22 op이 15만+회 처리, 룰 fire 0) = ActionReturnRecovery(flags=0)가 active
  return이 있으면 매 pass buildReturnOutput+count++ -> repeat-group 수렴 불가. C++는 multi-pass
  ParamActive(finishPass->markFullyChecked->build 1회->clearActiveOutput)로 수렴하나 이 ad-hoc 포팅은
  매번 RETURN 입력 스캔 재발견+재빌드. -> ActionReturnRecovery를 once-per-func로(guardReturns 직후 1회
  빌드 = single-build 수렴 재현). hang 해소.
- **propagateConstant nil-parent 가드**(condexe.go): guardReturns 트랜지언트가 잠시 "모든 op은 parent를
  가진다" 불변식을 깨 ConditionalConst에서 nil deref. 위쪽 MULTIEQUAL nil-parent 가드와 동일하게 detached
  op skip(CFG 밖이라 dominate 불가).
- **회귀 가드**: 기존 `TestUniversalActionTreeGcdGolden`(gcd void byte-identical) + production
  `TestMSVC*` 전부 그린. production은 decompile.go가 ActionDirectWrite를 안 돌려 param이 directwrite가
  아니므로 production applyReturnRecovery 판정은 ancestorOpUse 단독 유지(AncestorRealistic 게이트는 트리
  전용 -- 트리는 mainloop에 ActionDirectWrite 있음). production 무회귀 확인 후 게이트를 production에
  적용하지 않음.
- **남은 갭(트리 2/5)**: counted_loop/sum_list는 반환값은 복구됐으나(int, return local_c/local_8)
  for-loop fold 미인식(while로 렌더) + 루프-carried 스택 로컬 누산기 phi 미병합(본문 갱신이 dead temp
  uVar1/uVar2로 새고 local_c/local_8에 write-back 안됨) + sum_list 변수명 "return" 충돌. 둘 다 production
  골든이고 production은 통과 -> 트리 vs production SSA 대조(dumpSSA/TestProductionStagesDiag)로 localize
  가능. 별개 다운스트림 영역(step3b류 merge/snapshot 갭 가능).
- C++ 참조: funcdata_varnode.cc AncestorRealistic(2016-2256), funcdata.hh State(656-725), coreaction.cc
  ActionReturnRecovery::apply(1909-1956), heritage.cc guardReturns.

### 2026-06-30: H8-debt-2 step3b COMPLETE -- universal 트리가 gcd를 golden과 byte-identical 출력 (루프 회전 완성)
이전 step3b 항목(아래)에서 edge-정렬 블로커로 정밀화한 뒤, 5개 parity 버그를 모두 잡아 **트리가 gcd를
golden과 완전히 동일**하게 출력. 미션 #1 게이트의 결정적 전진(트리가 손정렬 41-call subset 없이 정확한
출력 생성 입증). 전 골든 + 전 패키지 그린, production 무영향.
- **최종 5개 버그 (전부 충실 C++ parity)**:
  1. `RuleCondNegate` 임포스터 -> 충실 포팅(CBRANCH+boolean_flip -> BOOL_NEGATE + clear, ruleaction.cc:5492).
  2. `ActionNodeJoin`/`ActionNormalizeBranches` `ActionRuleOncePerFunc` -> **flags=0**(C++ Action(0,...),
     blockaction.hh:352/286). 매 mainloop pass 재실행돼야 RuleCondNegate가 flip 푼 뒤 join 재시도 가능.
  3. **`BlockBasic.NegateCondition`이 소스 기본블록 edge 미swap** -> C++ BlockCopy::negateCondition
     (block.hh:534)처럼 srcDelegate(소스) edge도 swap. **이게 핵심 블로커**: collapse가 clone edge만 swap +
     공유 op flip만 leak해 소스 기본블록 branch 순서가 stale -> NodeJoin이 mirror된 entry/loop edge를 못 맞춰
     do-while 고정. 수정 후 if-collapse negate가 entry를 loop와 정렬 -> join 성공 -> while 회전.
  4. 트리 풀이 **잘못된 `RulePushMulti`(arithmetic 트리거)** 등록 -> 충실 `RulePushMultiME`
     (CPUI_MULTIEQUAL 트리거, ruleaction.cc:5529 C++ RulePushMulti). join된 boolean MULTIEQUAL을 merge
     블록으로 밀어 `MULTIEQUAL(a,b)!=0` 인라인(`while(uVar1)` 물질화 -> `while(iVar1=param_4, iVar1!=0)`).
  5. `ActionInferTypes` `ActionRuleOncePerFunc` -> **flags=0**(coreaction.hh:974). 매 pass 재실행돼야
     RulePushMultiME가 나중에 만든 스냅샷 MULTIEQUAL을 타입(undefined4 uVar1 -> int iVar1).
- **공통 패턴**: step3b 근본은 "C++ flags=0(매 pass 재실행)인 액션을 Gosleigh가 once-per-func로 오등록" +
  "동명 임포스터 rule" + "BlockCopy edge-forward 누락" 클러스터. production은 이 액션/rule을 .Apply 직접
  호출(액션 프레임워크 밖)이라 무영향 -- 트리 전용 수정.
- **진단 경로**: NJ_CFG로 NodeJoin 시점 CFG edge 덤프(entry=[loop,end] vs loop=[end,loop] mirror 확정,
  production은 NormalizeBranches 후 정렬됨 확인) -> negateCondition 소스-swap 누락 규명. 단계별 트레이스로
  RuleCondNegate/flag/RulePushMultiME/InferTypes 순차 확인 후 디버그 전량 제거.
- **회귀 가드**: `TestUniversalActionTreeGcdGolden`(트리 -> gcd golden byte-identical 단언, 일반 스위트 실행).
  진단 `TestTreeGoldensDiag`(TREE_DIAG=1, 트리를 5개 x86-32 골든에 돌려 match/mismatch 보고).
- **다음 단계 평가(TestTreeGoldensDiag)**: 트리 x86-32 골든 **1/5 byte-identical**(gcd만). 나머지 4개
  (counted_loop/sum_list/abs_val/classify2)는 EBP-프레임 + 스택 로컬 함수라 갭 큼: 예) counted_loop 트리는
  `void`(return 값 미복구) + local_c 누락 + for-loop 미인식(while) + 루프 본체 dead. 즉 트리의 EBP-프레임
  스택-로컬/return-value/for-fold 경로가 미완. gcd는 frameless라 통과. #1 게이트(41-call subset 대체)는
  이 갭들 해소 후 가능 -- 별도 세션 다수.
- C++ 참조: ruleaction.cc RuleCondNegate(5492)/RulePushMulti(1062-1137), block.hh BlockCopy::negateCondition
  (534)/block.cc BlockBasic::negateCondition(2351), blockaction.hh ActionNodeJoin/NormalizeBranches(352/286),
  coreaction.hh ActionInferTypes(974), coreaction.cc universalAction(5529 RulePushMulti).

### 2026-06-30: H8-debt-2 step3b -- 충실 RuleCondNegate + NodeJoin flags 수정 (루프 회전 2개 parity 버그 해소, edge-정렬 블로커로 정밀화)
do-while -> while 루프 회전을 막던 2개 진짜 C++ parity 버그를 C++ 코드 근거로 규명/수정. 전 패키지 그린.
production 무영향(production은 이 rule/flags를 .Apply 직접 호출 경로 밖에서 안 씀). 트리 출력은 아직 do-while
(남은 블로커는 edge-정렬, 아래). 계측 트레이스로 단계별 확정 후 디버그 전량 제거.
- **버그1 -- RuleCondNegate 임포스터**: Gosleigh `RuleCondNegate`(rules_bool.go)는 C++와 **완전히 다른**
  변환(`(!a)==(!b) => a==b`, INT_EQUAL/INT_NOTEQUAL 트리거)을 이름만 빌려 씀. 진짜 C++ RuleCondNegate
  (ruleaction.cc:5492)는 **CPUI_CBRANCH** 트리거 + `isBooleanFlip()`이면 BOOL_NEGATE 삽입 + opFlipCondition
  으로 flip clear ("Flip conditions to match structuring cues"). 이게 ConditionalJoin.findDups의
  "flip hasn't propagated through yet"(blockaction.cc:1920) 주석이 기대하는 flip 전파 주체. 충실 포팅
  (CBRANCH+flip -> BOOL_NEGATE+clear, RuleBoolNegate가 후속 폴드). 트리 전용 등록이라 production/골든 무영향.
- **버그2 -- NodeJoin/NormalizeBranches가 once-per-func 오등록**: C++ `ActionNodeJoin`/
  `ActionNormalizeBranches`는 `Action(0,...)`(blockaction.hh:352/286), 즉 flags=0 -> 매 mainloop pass
  재실행(status가 status_start로 복귀). Gosleigh는 `ActionRuleOncePerFunc`로 등록 -> 1회 실행 후 status_end
  고정 -> mainloop이 BlockStructure(do-while collapse가 flip 설정) -> NodeJoin(flip때문에 reject) 후
  RuleCondNegate가 flip을 풀어도 **NodeJoin이 다시 안 돔**. flags=0으로 수정 -> NodeJoin 매 pass 재실행.
  C++ ActionGroup::apply는 repeat 시 state만 리셋하고 자식 status는 reset 안 함(action.cc 확인) -> flags=0
  자식만 재실행되는 게 정상 메커니즘.
- **계측으로 확정한 진행**: 두 수정 후 트리에서 (a) NodeJoin이 매 pass ENTER, (b) RuleCondNegate FIRED
  (flip clear), (c) loop CBRANCH 조건이 `INT_EQUAL+flip` -> 폴드 `INT_NOTEQUAL+noflip`, (d) entry/loop 둘 다
  `INT_NOTEQUAL flip=false`로 **조건은 일치**. (참고: NodeJoinCreateBlock->StructureReset->BlockStructure
  재빌드 경로(가설 나)는 이미 구현돼 있어, NodeJoin만 fire하면 BlockStructure가 while로 재빌드함을 production
  경로에서 확인.)
- **남은 블로커 = edge-order mismatch (정밀화)**: match()가 findDups(조건)보다 **먼저** 실패 --
  `b2.FalseOut != exita`(ConditionalJoin::match, blockaction.cc:2077의 `block2->getOut(0)!=exita`).
  entry guard와 loop self-block의 out-edge가 **mirror**(entry out0=loop/out1=end vs loop out0=end/out1=self).
  production은 ActionNormalizeBranches(opFlipInPlaceExecute가 loop의 INT_NOTEQUAL을 normalize -> 물리 flip +
  **edge swap**)가 NodeJoin 전에 돌아 정렬. 그러나 C++ universalAction은 NormalizeBranches가 **post-mainloop**
  (coreaction.cc:5733)이라 faithful mainloop NodeJoin엔 edge-정렬 패스가 없음. collapse의 negateCondition은
  기본 블록으로 forward(faithful, collapse.go:227->block_basic.go:175 SwapEdges)하나 do-while i==0 케이스만
  swap -- gcd self-edge는 jnz 분기타겟이라 out1(i==1) -> negate 안 함.
- **샤프해진 C++ 모순**: golden은 while(production이 byte-identical 재현 = Ghidra가 universalAction으로 while
  생성 확정, 가설 라 배제). 그런데 faithful C++ 순서의 mainloop엔 gcd loop edge를 정렬하는 패스가 없음. 미해결
  = Ghidra mainloop이 edge를 **어떻게** 정렬하는가. 후보: (A) Ghidra CFG 구성 시 entry/loop edge가 자연
  정렬(Gosleigh buildGcd는 mirror), (C) 미식별 mainloop 액션(condexe 등)이 edge swap. 다음 세션: 실제 Ghidra
  런타임 trace 또는 Ghidra CFG edge-ordering을 Gosleigh와 대조해 (A)/(C) 확정.
- C++ 참조: ruleaction.cc RuleCondNegate(5479-5510)/RuleBoolNegate(5512-5555), blockaction.cc
  ConditionalJoin::findDups(1912)/match(2065)/ActionNodeJoin::apply(2326), funcdata_op.cc opFlipInPlace*(1223/
  1282), block.cc BlockBasic::negateCondition(2351)/flipInPlaceExecute(2378), coreaction.cc universalAction
  순서(5670 BlockStructure / 5685 NodeJoin / 5733 NormalizeBranches), funcdata_block.cc nodeJoinCreateBlock
  ->structureReset(779/704), action.cc Action::perform/ActionGroup::apply/reset.

### 2026-06-30: H8-debt-2 step1~3b-1 -- 트리 proto 배선 + incremental heritage + 충실 ReturnSplit (의미적으로 정확한 gcd)
universal 트리의 출력을 골든에 근접시킴. 미션 #1 게이트 핵심 전진. production 무영향(전 패키지 그린).
- **step1 (proto/param/ScopeLocal 배선)**: 트리는 FuncProto/ScopeLocal을 전혀 안 만들었음(트리 실행 후에도
  둘 다 nil) -> ActionDefaultParams/PrototypeTypes/RestructureVarnode 전부 early-return, 파라미터/로컬
  미명명 + return 쓰레기(`return *local_91`). 근본: C++ Funcdata는 생성 시 FuncProto+ScopeLocal 부착
  (funcdata.cc:66-70) 후 ActionPrototypeTypes::apply가 setModel(defaultfp)+initActiveOutput
  (coreaction.cc:4626-4662)하나 Gosleigh 포팅은 둘 다 누락. 수정: (a) `Funcdata.defaultModel`
  (Architecture::defaultfp 등가) + bridge.Build이 buildDefaultModel(NewProtoModelFromCspec+
  WithEffectOffsets+WithReturnReg)로 부착, (b) ActionPrototypeTypes 충실화(fp 없으면 default model로
  FuncProto+ScopeLocal 생성, output unlocked면 SetActiveOutput). 결과: 트리 gcd 시그니처가 골든과
  byte-match(`void processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4)`),
  파라미터/로컬 명명, 쓰레기 return 소멸.
- **step2 (incremental heritage + activeparam 멱등)**: step1 후에도 루프 본체가 스택 파라미터 대신 register
  temp(iVar) 사용 -- StackPtrFlow가 만든 스택 슬롯이 heritage 안됨(heritage-once + build-time space set에
  스택 부재). heritage를 매 pass 돌리면 oscillation 재발. 계측(per-pass/per-action probe)으로 2개 근본 규명:
  (1) **incremental heritage**(heritage-once 대체, H7 step3 multi-pass도 해결): Heritage()가 이후 pass에서
  heritage-known varnode 범위 skip(`Varnode.IsHeritageKnown`=constant|annotation|written|input,
  heritage.cc:2704-2719) -> 새 free varnode만 재배치. OpHeritage가 persistent Heritage 재사용
  (pass+globalDisjoint 유지) + 스택 슬롯은 HeritageRange로 슬롯별 1회씩(full task list는 인접 오프셋을
  병합해 wrong-size phi 생성, heritagedStackSlots 가드). 해석된 스택 space를 proto model에 기록.
  (2) **ApplyActiveParamModel 멱등**: 매 호출 ScopeLocal 재구축+true 반환 -> 스택 파라미터 가시화 후
  ActionRestructureVarnode와 영원히 oscillate(각 ~118k회). input-lock 시 early-return으로 수정(C++
  ActionActiveParam은 call input trial을 1회 resolve 후 markFullyChecked로 종료; call-less 함수는 fixpoint).
  결과: 트리 수렴 + param_3가 루프 본체에 fold(`iVar2 = param_3 % iVar1; param_3 = iVar1`).
- **step3a (early stack heritage)**: SSA 대조(tree vs production, dumpSSA)로 param_4 미fold 근본 규명 --
  트리 루프 ECX phi가 stack:0x8([esp+8]) 대신 `COPY const:0` 추적(production은 param_4 phi가 stack:0x8 +
  register:0x8(EDX) 병합). 근본: Ghidra는 스택을 pass 0에 register와 함께 heritage하나 Gosleigh는
  StackPtrFlow가 mainloop 깊숙이(stackstall) 있어 rule pool이 register 읽기를 변형한 뒤 stack heritage가
  늦게 실행. 수정: OpHeritage가 첫 register heritage 직후(GetPass()==1) ActionStackPtrFlow 실행 -> stack을
  rule 전에 heritage(production driver와 같은 순서). 결과: param_3/param_4 모두 fold, 의미적으로 정확한
  gcd(`if (param_4) { do { iVar1 = param_3 % param_4; param_3 = param_4; param_4 = iVar1; } while (param_4); ...}`).
- **step3b-1 (충실 ActionReturnSplit)**: CFG 대조로 트리가 return 블록을 2개로 과분리함을 규명(gcd는 RET
  1개). C++ ActionReturnSplit는 goto-to-return 엣지만 분리(gatherReturnGotos, blockaction.cc)하고 모든
  in-edge를 분리하지 않으나 Gosleigh는 index>=1 모든 in-edge를 무조건 분리. 수정: goto in-edge만 분리
  (parent.IsGotoIn, "can't split all" 가드). Gosleigh는 getCopyMap 부재라 블록 자체 goto in-edge 플래그로
  근사. -> 단일 return 복원, double-return 제거. production은 ReturnSplit 미실행이라 무영향(전 골든 그린).
- **남은 갭(step3b) -- BooleanFlip 수준까지 완전 root-cause**: do-while -> while 루프 회전만 남음. 단계별
  bisect(`TestProductionStagesDiag`)로 회전 패스 = **NodeJoin(ConditionalJoin)** 규명(production:
  NormalizeBranches 후 blocks=3 -> NodeJoin 후 blocks=4, self-loop 블록을 while head+body로 분리).
  NodeJoin 분리의 2개 전제: (1) entry/loop CBRANCH 조건 일치(NormalizeBranches가 loop INT_NOTEQUAL을 flip
  해 entry INT_EQUAL과 functionalEquality 매칭), (2) BlockStructure가 먼저 돌면 안 됨 -- collapse의
  negateCondition(ruleBlockDoWhile)이 루프 CBRANCH에 `PcodeOpBooleanFlip` 설정(공유 op) -> findDups가
  BooleanFlip 있으면 reject(action_nodejoin.go:147). 트리 mainloop은 BlockStructure(1349)->NodeJoin(1364)
  순서 + 구조 build-once라 NodeJoin 영원히 reject -> do-while 고정. production decompile.go는
  NodeJoin->BlockStructure 순서라 무사. **C++ 모순**: C++ universalAction도 BlockStructure->NodeJoin인데
  golden은 while -> C++는 BooleanFlip을 propagate(실제 flip+플래그 clear)하는 rule이 있어 후속 iteration에서
  NodeJoin 매칭 + execute가 구조 무효화로 추정. Gosleigh의 propagation 불완전. 다음 세션: BooleanFlip
  propagation rule 포팅 + ConditionalJoin.execute의 구조 무효화 확인. 상세 STATUS step3b.
- 회귀 가드 `TestUniversalActionTreeConverges`(수렴 단언). production-safe: Heritage() incremental gating은
  single-pass(production)에선 inert, OpHeritage/ApplyActiveParamModel/early-stack은 트리 전용. 진단
  `TestTreeOutputDiag`(TREE_DIAG=1; GCD_DUMP=1로 tree/production SSA 대조).

### 2026-06-30: H8-debt-2 -- universal 트리 수렴 달성 (heritage-once); end-to-end 실행
universal-action 트리가 gcd에서 hang -> 수렴+C출력으로 전환. 미션 #1 게이트 핵심 전진. production 무영향.
- **근본 규명**: SKIP_ACTION bisect로 비수렴원을 {oppool1,conditionalconst,multicse}로 좁힘(varnodeprops
  무죄). 진짜 근본 = **`OpHeritage`가 매 mainloop iteration마다 full 비-incremental heritage 재실행 ->
  phi 재생성 -> 위 액션들이 매번 변환 -> oscillation**. C++ Heritage는 incremental(새 free varnode만).
- **수정(interim)**: OpHeritage에 `heritageDone` 가드 -> 1회만 실행. universal 트리가 gcd에서 수렴하고
  C 출력을 생성(end-to-end). 회귀 가드 테스트 `TestUniversalActionTreeConverges`(30s timeout fail).
  production-safe: decompile.go는 OpHeritage 미호출.
- **남은 갭(트리 출력 부정확)**: `int entry(param_1,param_2){...return *local_91;}` -- param_3/4 미복구 +
  stack heritage 누락 + return 쓰레기. 원인: 트리 경로 proto/param 셋업 부재 + heritage-once의 stack-var
  2차 heritage 누락. 다음: 트리 proto/param 배선 + incremental heritage 포팅 -> gcd 골든 일치까지 단계 검증.

### 2026-06-30: H7 step4 -- 실제 CalcNZMask 포팅 (production-safe, validated)
nzmask 전파를 stub(~0)에서 충실 구현으로 교체. 미래 universal-tree 수렴의 필요 조건.
- **추가**: `Funcdata.CalcNZMask`(funcdata.cc Funcdata::calcNZMask 충실 -- DFS post-order로 input부터
  계산 후 getNZMaskLocal, 이후 MULTIEQUAL loop edge worklist 전파) + `PcodeOp.getNZMaskLocal`(op.cc:548
  전 opcode switch: COPY/ZEXT/SEXT/AND/OR/XOR/shift/DIV/REM/SUBPIECE/PIECE/MULT/ADD/MULTIEQUAL/비교=1bit 등).
  size>8은 보수적 fullmask(extended-precision 미포팅, 넓은 마스크는 항상 sound).
- **검증**: 단위테스트 `TestCalcNZMaskPropagation`(AND 0x0f->0x0f, ZEXT byte->0xff, LEFT 8, COPY).
  **production-safe**: decompile.go가 CalcNZMask 미호출 -> 골든 무영향, 전 패키지 그린.
- **한계(실측)**: 실제 CalcNZMask 단독으론 universal 트리 hang 미해결(scratch 30s timeout). Consumed 기본
  ~0이라 VarnodeProps 초기 skip이고, 비수렴 근본은 후기 oscillation(VarnodeProps/conditionalconst/multicse/
  oppool1)으로 미확정. CalcNZMask는 필요조건이자 foundational, 트리 수렴은 추가 조사 필요.

### 2026-06-30: H8-debt-2 재정의 + 첫 fill -- universal 트리는 hollow, Funcdata self-contain 시작
미션 #1 게이트(universalAction 단일화)를 측정으로 재정의하고 첫 action 본체를 채움. 무회귀.
- **측정 발견**: `BuildUniversalAction`(250 action/rule)은 구조 스켈레톤 + **대부분 decompile.go와 동일한
  real action impl 공유**(InferTypes/BlockStructure/StackPtrFlow 등). hollow은 한정적: Funcdata가
  graph/spaces 미보유(self-contained 불가) + `OpHeritage` 등 6개 stub delegate. 즉 H8-debt-2는 "패스 순서
  reconcile"가 아니라 "Funcdata self-contain + 소수 stub 채우기 + full-pool 수렴 문제 해결".
- **추가**: Funcdata에 `SetAnalysisContext(graph, heritageSpaces)`/`Graph()`/`HeritageSpaces()` +
  bridge.Build이 채움(additive). `OpHeritage`를 fd.graph/spaces 기반 register heritage로 실화.
  단위테스트 `TestUniversalActionHeritageBuildsSSA`(ActionHeritage 후 MULTIEQUAL>0)로 검증.
- **수렴 블로커 root-cause(CONV_PROBE 계측)**: 전체 트리가 gcd에서 hang. 근본은 `ActionVarnodeProps`가
  `NZMask & Consumed == 0` varnode를 const 0으로 교체하는데, 트리엔 CalcNZMask가 stub(~0) + consume 미계산
  -> 모든 varnode가 Consumed==0으로 보여 매 iteration마다 live varnode를 0으로 교체 -> 무한 비수렴.
  **즉 트리 수렴이 H7 step4(실제 CalcNZMask)에 직결**. repeat-apply max-iter cap 부재는 부차적.
- 프로덕션(decompile.go)은 외부 NewHeritage 유지 + ActionVarnodeProps 미실행 -> 무영향, 전 패키지 그린.

### 2026-06-30: H7 step3 완결 -- anchorReturnReg 물리 제거 (guardReturns가 유일 return 경로)
guardReturns가 기본값으로 검증된 뒤, 레거시 anchorReturnReg 경로를 완전 삭제(-161줄). 전 패키지 그린.
- **삭제**: `anchorReturnReg`(funcproto.go, SeqNum 휴리스틱), `ApplyActiveReturnModel`(paramactive.go,
  Go-local return-anchoring helper), `guardReturnsLiveEnabled`(게이트) + `GOSL_LEGACY_ANCHOR_RETURN` 폐기.
- **ApplyCallingConvention**: 이제 stripReturnIndirectRef만 수행(epilogue 체인 절단). return 값 wiring은
  ApplyGuardReturnsLive(bridge.Decompile + 레거시 테스트 사이트)가 무조건 전담.
- **ActionActiveReturn.Apply**: no-op 스텁화. 이 액션의 충실 C++ 본체는 CALL-site output trial 복구
  (checkOutputTrialUse/deriveOutputMap/buildOutputFromTrials)인데 Gosleigh의 기존 본체는 함수 자기
  return을 anchorReturnReg로 처리하던 비충실 Go-local 헬퍼였음. 함수 return은 guardReturns가 전담하므로
  헬퍼 제거. actfullloop엔 구조 parity 위해 액션은 유지(call-output 본체는 unported로 명시).
- **fallback 폐기 근거**: guardReturns는 blast radius가 작고(RETURN input만) 전 corpus byte-identical
  검증됨 -> GOSL_DESCENDANT_DC(전 dead-code 영향)와 달리 escape hatch 불필요.
- printc/action_deadcode/funcproto의 anchorReturnReg 참조 주석을 "return-value wiring"으로 정정.
- 결과: 전 골든 + 전 패키지 그린. anchorReturnReg 휴리스틱 완전 소멸.

### 2026-06-30: H8-debt-1 완료 -- TrimJoinblockMultiequals 제거, 충실 mergeOp trimOpOutput으로 대체
swapped-loop snapshot(iVar1)을 Gosleigh-고안 forward-snip 워크어라운드 대신 실제 C++ mergeOp
trimOpOutput 메커니즘으로 생성. 전 골든 + 전 패키지 그린(guardReturns 양쪽 상태).
- **메커니즘 확인(FORCE_TRIMOUT 실험)**: loop-cond MULTIEQUAL에 trimOpOutput 강제(input-trim skip) +
  TrimJoin off -> gcd가 정확한 golden(iVar1 while) 출력, 전 loader 스위트 그린. trimOpOutput이
  올바른 메커니즘임을 결정적으로 확인.
- **정식화**: `Merge.MergeOp`에서 !allOK(cover 충돌)인 loop-cond phi는 input-trim 루프를 건너뛰고
  곧장 `TrimOpOutput`(merge.cc:759-760). 이유: 그 phi의 back-edge input이 출력을 transitively 읽어
  (cyclic) 모든 input-trim COPY가 여전히 출력의 loop-spanning cover 안에 있음 -- C++는 input-trim 소진
  후 trimOpOutput에 도달하나 Gosleigh input-trim 재테스트는 spurious 성공(residual loop-carried Cover
  gap)이라 우회.
- **삭제**: `TrimJoinblockMultiequals`(별도 pass, forward-snip, unique-output/anyPhysical/IsAddrTied
  게이트) + `hasPhysicalSource` 헬퍼 + decompile.go/msvc_diag_test.go의 호출. `isLoopCondMultiequal`은
  이제 mergeOp가 사용(유지).
- **잔여(저우선)**: isLoopCondMultiequal 게이트는 cyclic-phi의 stand-in. 완전 원리화는 Cover/mergeTest
  fidelity 수정(input-trim이 자연 실패하게)으로 게이트 제거 -- broad cover 변경이라 별도 세션.
- 결과: gcd/SumList/CountedLoop 등 전 골든 PASS, TrimJoinblockMultiequals 휴리스틱 제거 완료.

### 2026-06-30: H8-debt-1 진단 재정정 -- phi-storage 가설도 반증, divergence는 mergeOp trim 선택
GCD_DUMP + C++ 대조로 이전(같은 날) "phi 출력 storage(unique vs param)" 가설을 반증. 코드 변경 없음.
- **phi-storage 가설 반증**: C++ `ConditionalExecution::getNewMulti`(condexe.cc:206)는 join MULTIEQUAL
  출력에 `newUniqueOut`을 씀(addr-tied는 "merge conflicts" 우려로 주석처리). GCD_DUMP: Gosleigh NodeJoin도
  register-tied loop phi를 unique-output phi로 변환(C++와 동일). 즉 join phi 출력은 양쪽 다 unique --
  "Gosleigh만 unique, C++는 param-storage"는 틀림.
- **확정된 divergence**: MERGE_PROBE -- Gosleigh mergeOp는 loop-cond phi 충돌을 TrimOpInput으로 해소
  (trimmed=true)해 trimOpOutput 미발화. C++ mergeOp(merge.cc:747-761)는 동일 구조지만 input trim으로
  해소 안 돼 trimOpOutput(iVar1 snapshot)으로 떨어짐. 즉 Cover/mergeTest 또는 trimOpInput의 cover 영향
  fidelity 차이. 다음 세션 런타임 조사 대상.
- **for-fold 부적합 확인**: TrimJoin off의 for-loop는 iterate가 body 뒤 실행이라 swap이 깨짐(lost-copy).
  snapshot 필수 -- 단순 for-fold 거부론 부족. TrimJoinblockMultiequals는 mergeOp trimOpOutput을 대체하는
  필수 워크어라운드(제거 시 gcd 회귀). STATUS H8-debt-1에 반영.

### 2026-06-30: H7 step 3c -- guardReturns를 프로덕션 기본 return 경로로 전환
충실 Heritage::guardReturns + dominance rename을 anchorReturnReg SeqNum 휴리스틱 대신 **기본값**으로
승격. 전 테스트 corpus(골든 + ~14개 레거시 파이프라인) byte-identical 검증 후 전환. 전 패키지 그린.
- **corpus 검증(step3c-prep)**: `ApplyGuardReturnsLive`를 self-contained화(spaces+graph로 자체 heritage
  빌드) + loader_test.go의 14개 ApplyCallingConvention 사이트마다 호출 추가. 플래그 ON에서 전 패키지
  그린 -> guardReturns-live가 anchorReturnReg의 완전한 drop-in 대체임을 전 corpus에서 확인.
- **기본값 전환**: `guardReturnsLiveEnabled()`를 invert -- 이제 guardReturns가 기본, anchorReturnReg는
  `GOSL_LEGACY_ANCHOR_RETURN` opt-out fallback(GOSL_DESCENDANT_DC와 동일 패턴). ApplyCallingConvention은
  기본적으로 anchorReturnReg 스킵, bridge.Decompile/테스트가 ApplyGuardReturnsLive로 return 값 wiring.
- **검증**: 기본(guardReturns) + GOSL_LEGACY_ANCHOR_RETURN(anchorReturnReg) 양쪽 전 패키지 그린.
- **남은 tail(저위험 follow-up)**: anchorReturnReg 함수 자체 + ApplyActiveReturnModel(anchorReturnReg
  호출, ActionActiveReturn 본체, 골든 파이프라인 미배선) 정리 + printc.go anchorReturnReg 주석(11개,
  로직은 input[1] 기반이라 mechanism-agnostic, 갱신만) 정리. 기능 영향 없음.

### 2026-06-30: H7 step 3b -- guardReturns live wiring 검증 (GOSL_GUARD_RETURNS 플래그 뒤)
충실 guardReturns + rename 경로를 anchorReturnReg 대체로 배선하고, 프로덕션 경로(bridge.Decompile)
전 MSVC 골든에서 byte-identical임을 검증. 플래그 default off라 무회귀.
- **배선**: `ApplyGuardReturnsLive`(paramactive.go) -- activeoutput 설치 -> `h.guardReturns`로 각
  RETURN에 fresh return-reg varnode append -> 기존 return-reg def/input을 ActiveHeritage 재마킹 ->
  `h.Rename`으로 fresh varnode를 dominating def에 연결. placeMultiequals 미재실행(중복 phi 회피).
  activeoutput은 종료 전 clear(downstream consume-DeadCode를 anchorReturnReg 경로와 동일 상태로).
- **gate**: `GOSL_GUARD_RETURNS` 시 ApplyCallingConvention이 anchorReturnReg 스킵(funcproto.go),
  bridge.Decompile이 regHeritage+graph로 ApplyGuardReturnsLive 호출(decompile.go).
- **검증 결과**: 플래그 ON에서 전 MSVC 골든 PASS = anchorReturnReg와 byte-identical(**gcd void
  포함**). 즉 충실 메커니즘(guardReturns + dominance rename)이 SeqNum 휴리스틱을 정확히 재현.
- **step3c 블로커**: anchorReturnReg를 default에서 제거하려면 ~14개 레거시 손조립 테스트
  파이프라인(loader_test.go, ApplyCallingConvention 직접 호출 + bridge.Decompile 미경유)을
  bridge.Decompile로 마이그레이션 선행 필요(= H8-debt-2). 플래그 ON 시 이 테스트 중 비-void
  반환 단언 5개가 void로 렌더(ApplyGuardReturnsLive 미호출 경로). default OFF에선 전 패키지 그린.
- 결과: default 전 패키지 그린, 플래그 ON에서 프로덕션 골든 byte-identical 검증.

### 2026-06-29: H7 step 3a -- Heritage::guardReturns 충실 포팅 (dormant foundation)
anchorReturnReg(SeqNum 휴리스틱)을 대체할 C++ 메커니즘을 dormant로 포팅. 무회귀, 전 패키지 그린.
- **포팅**: `pkg/pcode/heritage.go`에 `guardReturns`/`guardReturnsOverlapping`/`characterizeReturnOutput`
  추가(heritage.cc 1609-1692 충실). activeoutput 존재 시 RETURN마다 fresh return-reg varnode를
  append(exact/overlap), contained_by는 SUBPIECE 절단. callerless `Guard()`에 배선해 dormant 유지.
- **omission**: ParamEntry 출력 모델 미포팅이라 characterizeReturnOutput은 model.ReturnReg* 기반
  register subset. persist 분기(global address-forced COPY)는 register return엔 미발화 + markReturnCopy/
  setAddrForce 미포팅이라 생략(주석 명시).
- **단위테스트**: `TestGuardReturns{AppendsReturnInput,NoActiveOutput,NoContainment,Overlapping}`.
- **step 3b 블로커(분석 확정)**: live 배선 시 fresh varnode를 renaming으로 dominating def에 연결해야 하나
  Gosleigh `placeMultiequals`가 idempotent 아님 -> 단순 2nd-pass 재-heritage는 중복 phi 생성.
  충실 경로 2안: (1) **1st-pass 통합** -- guardReturns를 Heritage() 루프의 Collect 전에 호출(단일 rename,
  중복 phi 없음). activeoutput+return-reg 위치를 heritage 전 셋업하는 파이프라인 재정렬 필요(현재
  WithReturnReg/ApplyCallingConvention이 heritage 후). (2) **2nd-pass + re-mark** -- 기존 def/phi를
  ActiveHeritage 재마킹 후 placeMultiequals 생략, Rename만 실행(기존 SSA 변형 위험). (1)이 정공법.
- 결과: anchorReturnReg(live) 유지, 전 골든 + 전 패키지 그린. master `34e5d6b`.

### 2026-06-29: H8-debt-1 측정 진단 정정 (lost-copy는 상류 phi-storage 문제, MergeMarker 순서 아님)
TrimJoinblockMultiequals 제거 가능성을 MERGE_PROBE 계측 + 조기 MergeMarker 제거 실험으로 측정.
이전 "MergeMarker 순서" 가설을 실측으로 반증/정정(코드 변경 없음, 진단만).
- **의존 범위**: TrimJoinblockMultiequals off 시 **gcd 하나만** 회귀(나머지 전 골든 PASS).
  gcd: `for(param_4=param_4;...)` (잘못) vs golden `while(iVar1=param_4,...)` lost-copy snapshot.
- **MergeMarker 순서 반증**: 조기 MergeMarker(decompile.go:84,91) 제거 실험에도 gcd 출력 불변.
- **실측 divergence**: MERGE_PROBE 계측 결과 loop-cond phi(isLoopCond=true)가 MergeOp에서 cover
  충돌(allOK=false)을 감지하나 TrimOpInput으로 해소(trimmed=true) -> trimOpOutput 미발화. 원인:
  Gosleigh는 phi 출력이 unique+fresh HV(충돌=input-vs-output-unique, input trim으로 해소),
  C++는 phi 출력이 param-storage varnode(충돌=output-vs-param, input trim 불가 -> trimOpOutput ->
  iVar1). 근본은 상류 phi 출력 storage/HV 배정(NodeJoin/Heritage + AssignHigh) 차이.
- 결론: TrimJoinblockMultiequals는 필수 워크어라운드(제거 시 gcd 회귀). 원리적 제거는 상류 수정
  선행(대형). STATUS H8-debt-1에 측정 진단 반영. 전 패키지 그린 유지.

### 2026-06-29: H7 step 1+2 -- consume-bit DeadCode를 충실 프로덕션 기본값으로 LIVE
anchorReturnReg 휴리스틱을 둘러싼 핵심 서브시스템(consume-bit DeadCode)을 충실 포팅하고
프로덕션 DeadCode 경로로 배선. 전 골든 + 전 패키지 byte-identical 통과.
- **H7 bedrock 진단**: anchorReturnReg를 끄면(GOSL_NO_ANCHOR 실험) 전 non-void 골든이 void로
  붕괴(DeadCode가 return-reg 쓰기 prune). C++는 consume-bit 전파로 return값을 보존하나 Gosleigh
  DeadCode는 descendant-count 기반. 충실 경로는 3개 부재 서브시스템 요구: ①consume-bit DeadCode
  ②heritage-pass 추적 ③실제 CalcNZMask.
- **step 1 (`42069c4`)**: `pkg/pcode/deadcode_consume.go` -- C++ ActionDeadCode consume 절반 충실
  포팅(pushConsumed/propagateConsumed ~20 opcode + gatherConsumedReturn/markConsumedParameters +
  coveringmask/minimalmask/leastsigbit). 단위테스트 `TestConsumeAnalysisReturnReachable`(RETURN
  도달 체인=consumed, 죽은 varnode=0). 헬퍼는 C++ 정의 대조.
- **step 2 (`ef53e39`)**: `ActionDeadCode.applyConsume`가 consume 분석으로 "consume 미도달 출력"을
  fixpoint 제거 -> **프로덕션 기본 DeadCode 경로**. descendant 경로는 GOSL_DESCENDANT_DC fallback.
  안전성: 모든 omission(pre-live/neverConsumed/>8byte/call-param)이 보수적(과보존, 오삭제 X)이고
  Gosleigh DeadCode는 전부 post-heritage라 pre-live 미발화. return값은 anchorReturnReg가 RETURN에
  배선한 input을 gatherConsumedReturn이 보존.
- **step 3 블로커(재진단)**: anchorReturnReg 제거는 C++ Heritage::guardReturns(heritage.cc:1652,
  getActiveOutput()!=null 조건 + multi-pass heritage)에 의존 -> Gosleigh single-pass라 부재. 사이즈 큼.
- 결과: gcd/sum_list/counted_loop/abs/nested_if + 전 패키지 그린.

### 2026-06-29: H9 assignCastStr 전면 제거 (for-fold를 ActionSetCasts 뒤로 재배치)
render-time 캐스트 fallback을 완전히 제거하고 메커니즘 parity 달성. 전 패키지 그린.
- **재배치**: ActionForLoops를 ActionSetCasts **뒤**로 이동(decompile.go). C++ 순서와
  일치 -- ActionSetCasts는 분석 루프에서, for-loop fold는 print-time(block.cc
  BlockWhileDo::finalTransform/finalizePrinting)에서. for-detection은 cast-transparent
  (findLoopVariable/testIterateForm가 CAST를 call/marker 아니므로 그대로 통과). 이로써
  for-iterate op이 실제 삽입된 CPUI_CAST를 보유(sum_list `param_3 = (int *)param_3[1]`의
  cast는 LOAD 출력 캐스트라 castOutput이 공급).
- **근본 블로커 진단(런타임 op 덤프)**: 재배치 시 SetCasts가 param_3 loop phi(MULTIEQUAL)에
  castOutput을 걸어 출력을 High 없는 unknown unique로 split -> ActionForLoops가 loop변수
  phi의 High를 못 찾아(`testIterateForm: high nil`) while+comma로 폴백. C++는
  `tokenct == outHighType` short-circuit(coreaction.cc:2546)으로 phi cast를 회피(phi
  outputTypeLocal 토큰 == high 타입). Gosleigh는 InferTypes가 int*를 phi high에 전파하나
  base 토큰은 TYPE_UNKNOWN이라 short-circuit이 miss. **수정**: castOutput에서 marker
  (MULTIEQUAL/INDIRECT) skip(action_deadcode.go) -- phi/indirect는 C 표현식이 아니므로
  출력 캐스트 비대상(C++의 marker no-op과 동등).
- **제거**: printc.go `assignCastStr` + `effectiveLoadResultType` 완전 삭제(-116줄). 모든
  출력 캐스트가 ActionSetCasts 삽입 CPUI_CAST에서 나옴. renderForPartOp/op-statement 렌더는
  renderOpExpr만 호출(이중 캐스트 없음).
- 결과: 전 MSVC 골든(sum_list/counted_loop/gcd/abs_ifelse/nested_if) + 전 패키지(loader/
  pcode/sla/bridge) 그린.

### 2026-06-29: H9 ActionSetCasts 정식 배선 완료 (분석-time CPUI_CAST 라이브)
`51edf33`+`03ef9d2`: ActionSetCasts를 bridge.Decompile에 배선, 전 패키지 그린.
배선 블로커였던 PTRADD 미형성을 런타임 프로브로 진단/해결한 연쇄:
- **근본 원인**: `ActionStartTypes`가 bridge.Decompile에 미배선 ->
  HasTypeRecoveryStarted() 영구 false -> RulePtrArith가 포인터 룰을 절대 안 켰음.
  최종 InferTypes 뒤 ActionStartTypes + RulePtrArith(단일 룰 풀) 재발화 배선 -> PTRADD 형성.
- **렌더**: PrintC가 LOAD[PTRADD]를 subscript로 안 만듦(tryRenderSubscript는 INT_ADD만).
  PTRADD 분기 추가 + buildTree가 남기는 COPY(PTRADD) 통과 -> `param_3[1]` (printc.go).
- **read-facing 갭**: undefined4 피연산자가 비교(careUI=true) getInputCast에서 `(int)`로
  스퓨리어스 캐스트(CountedLoop `(int)local_8 < 5`). Ghidra는 inherits_sign으로
  read-facing이 int라 무캐스트. Gosleigh는 read/def-facing 구분 부재 -> `castStandardRead`
  (cast.go)로 비교/확장에서 curtype UNKNOWN이면 무캐스트 보정.
- **assignCastStr**: 전면 제거 시 sum_list 회귀(for-loop iterate op은 NonPrinting이라
  ActionSetCasts 스킵 -> 출력 CAST 삽입 시 for-구조 깨짐). 하이브리드 유지: 정상 op은
  ActionSetCasts 실제 CAST, NonPrinting for-loop op만 assignCastStr 잔여 fallback(이중 없음).
- 결과: sum_list `(int *)param_3[1]`, gcd/counted_loop/absval/classify2 전부 통과.

### 2026-06-29: H9 ActionSetCasts 본체 + 출력타입 인프라 + 배선 블로커 진단
`705d5eb`+`483d3f9`:
- 출력측 인프라(typeop_cast.go): opOutputMeta + OutputTypeLocal/GetOutputToken.
  오버라이드 Copy/Load/IntAdd(arithmeticOutputStandard)/Ptradd. Ptrsub(downChain)/
  Subpiece(findTruncation, 전용 struct 부재)는 TODO.
- cast.go: arithmeticOutputStandard(cast.cc:394, typeOrder 단순화).
- funcdata.go: NewUnique(castOutput용).
- action_deadcode.go: ActionSetCasts.Apply/castInput/castOutput 본체
  (coreaction.cc 2534-2776). union/testStructOffset0/markExplicit*/PTRADD-PTRSUB
  refit 생략(문서화). 격리 테스트 TestActionSetCastsInsertsCopyCast PASS.
- **배선 블로커 경험적 입증(`483d3f9`)**: bridge.Decompile 시험 배선 -> sum_list/
  counted_loop 회귀(`(int *)param_3[1]` -> `(int *)*((int *)((int)param_3+4))`).
  근본: Gosleigh는 포인터 산술을 INT_ADD 유지+tryRenderSubscript로 `ptr[index]`
  합성하나 base getInputCast(INT_ADD)가 포인터를 `(int)` 캐스트해 subscript 파괴.
  Ghidra는 PTRADD라 no-cast. 선행: 최종 InferTypes 후 PTRADD 형성(RulePtrArith
  재발화). parity상 hack 억제 금지 -> 배선 되돌리고 본체는 unwired 유지.

### 2026-06-29: H9 입력타입 인프라 (getInputCast/inputTypeLocal) 포팅
ActionSetCasts driver의 documented core blocker(컴포넌트 2) 해소. `432b30e`:
- TypeOp 인터페이스에 `InputTypeLocal`/`GetInputCast` 추가 (typeop_cast.go).
  `opInputMeta` per-opcode metain 테이블은 typeop.cc TypeOpBinary/Unary/Func 생성자
  metain + PTRADD/PTRSUB getInputLocal(TYPE_INT) 대응. base getInputCast =
  CastStandard(inputTypeLocal, vn.readFacing, false, true) (typeop.cc:296). 충실
  오버라이드: Copy/Load/Store/Zext/Sext/comparison(Equal-NotEqual-Sless-Less)/Ptradd/Ptrsub.
- cast.go: int-promotion 머신리 포팅 (cast.cc:107-247) -- intPromotionType/
  localExtensionType/checkIntPromotionForCompare/checkIntPromotionForExtension +
  promoteSize(=4) + signbitNegative. 비교/확장 getInputCast의 정수승격 게이트 충족.
- Gosleigh 단순화(문서화): HighVariable 부재로 read-facing vs def/own-type가
  vn.TypeReadFacing(op)로 collapse -> PTRADD/PTRSUB slot0 캐스트 테스트 항상 no-cast;
  Equal/NotEqual은 typeOrder 미포팅으로 in0 타입을 reqtype으로 사용(TODO).
- 미배선: Apply/castInput/castOutput 본체 + 파이프라인 배선 + render-time assignCastStr
  제거는 다음 체크포인트(Apply 전 op 순회라 부분 배선 불가). 단위 테스트 typeop_cast_test.go.

### 2026-06-29: H8 gcd_x86_32 golden parity 완료 (TestMSVC_Gcd PASS)
오랜 gcd 갭 종료. 전 패키지(loader/pcode/sla/bridge) 그린. 근본 원인 5개 순차 수정:
- `7975188` RulePropagateCopy addr-tied guard -> 실제 IsAddrTied (ruleaction.cc:3969).
  `isEffectivelyAddrTied`(register/stack 전부 addrtied 오인) 제거 -> 스택파람<->레지스터 SSA 통합.
- `e114152` RuleMultiCollapse mark-based self-ref skip 포팅 (ruleaction.cc:3254) +
  OpDestroy dead-flag latent 버그 (PcodeOpDead 미설정으로 action IsDead 가드 무력화).
- `06260bd` CoverBlock.Empty: `start==nil`만 -> `start==0 && stop==0` (cover.hh). 근본
  cover 버그, loop-carried 교차 감지 복원 (다수 cover 의존 분석 영향).
- `dac34ef` ActionNameVars explicit-unique 명명 + allocateCopyTrim 타입 상속.
- `6d9ff29` TrimJoinblockMultiequals unique-output 게이트(스냅샷 발화) + printc
  explicit-unique 선언/blank line + golden 파이프라인 snapshot+InferTypes.
교훈: cover 교차(level 2)는 gcd/SumList 동일 -> 스냅샷 판별자 아님; unique-vs-addrtied
출력이 (휴리스틱) 판별자. 잔여 부채는 STATUS H8-debt-1/2.

### 2026-06-29: 프로덕션 디컴파일 진입점 + H9 cast 프리미티브
- `5a39f6c` **bridge.Decompile** 프로덕션 진입점 추출 (H8-debt-2 부분). 골든 디컴파일
  파이프라인(proto 셋업 + Heritage + ActionStackPtrFlow + actmainloop 순서 action subset
  + PrintC)이 테스트 헬퍼 `runPipelineGhidra`에만 있던 것을 프로덕션 `bridge.Decompile`로
  추출, 테스트는 호출만. universalAction 전체 reconcile은 미완(STATUS H8-debt-2).
- `f545917`+`64e8c90` **CastStrategyC.CastStandard** 포팅 (cast.cc:300-392) + 단위 테스트.
  printc `assignCastStr`의 COPY/LOAD 캐스트 판정에 배선 -> render-time 판정 C++ 충실화.
- `7c350d3`+`3b64207` **IsSubpieceCast/IsSextCast/IsZextCast** 포팅 (cast.cc:411-469) +
  단위 테스트. PrintC 배선+검증: SUBPIECE offset0 정수 truncation -> `(int)x`;
  SEXT/ZEXT는 natural일 때만 cast, 아니면 SEXT()/ZEXT(). (render 테스트
  TestPrintCSubpieceCast/TestPrintCZextNotCast)
- 남은 H9: ActionSetCasts driver(분석-time CPUI_CAST 삽입) -- getInputCast/inputTypeLocal
  인프라(전무)부터. STATUS H9 참조.

### Keystones 완료 (real port)
- K1a/b/c: ParamActive + FuncProto 확장 + 8 prototype action real (ActionActiveParam,
  ActiveReturn, InputPrototype, OutputPrototype, PrototypeTypes, DefaultParams,
  ReturnRecovery, ReturnSplit)
- K2 (A6): ScopeLocal + SymbolEntry + DynamicHash (~1376줄)
- K3 (A8): JumpTable + JumpModel + JumpBasic scaffold + LoadTable (~1738줄)
- K4+K5 helpers (A7): Datatype bitfield 모델 + GetInternalString + UserOpManage (~500줄)
- Transform infrastructure: TransformManager/Var/Op + LaneDescription (926줄)

### 2차 파동 real 포팅 (commits 57e2853 / fec6c90 / c6700b2 / 1dd9a66)
- A9: actmainloop universalAction 순서 + Heritage guard/protectFreeStores/heritageTree
  /placeMultiEquals/buildRefinement real (+499줄)
- A10: 9 actions scaffold -> real (MapGlobals/HideShadow/RestrictLocal/InternalStorage
  /DynamicMapping/DynamicSymbols/ShadowVar/SwitchNorm/RestructureVarnode) (+248줄)
- A11: String rules transform() real (CALLOTHER + BUILTIN_STRNCPY 등) + BitField
  PullAbsorb/InsertAbsorb absorb helpers real + TypeStruct bitfield decode path (+859줄)
- A12: SplitVarnode Form classes 7 real (AddForm/SubForm/LogicalForm/ShiftForm
  /PhiForm/CopyForceForm/LessConstForm) + RuleDouble* 실제 collapse 작동 (+1392줄)

### 여전히 스캐폴드/스텁 (3차 파동 target)
- ~~H8 (TestMSVC_Gcd)~~ **완료 2026-06-29** (위 엔트리 참조).
- ActionConditionalConst/ConditionalExe 는 still TODO (condexe.cc 인프라 미포팅)
- SplitVarnode Form 중 Equal1/2/3, LessThreeWay, MultForm, IndirectForm 는 stub
- RuleDoubleStore reassignIndirects 는 stub (newVarnodeIop 의존)
- A1 TODO-stubs: ConstantPtr, Constbase, Deindirect, FuncLink, LaneDivide,
  LikelyTrash, ParamDouble 일부는 partial/low confidence
- BitField rules 발화 체인: establishFields 의 worklist seed 가 빈 list,
  type decode 측에 bitfield 값 주입 경로 미완

### 완료
- [x] Git repo initialized
- [x] Ghidra decompiler C++ source sparse-checked out to ghidra-ref/
- [x] Apache 2.0 LICENSE + NOTICE (Ghidra attribution)
- [x] .gitignore
- [x] Launcher scripts (Gosleigh.bat, Gosleigh-codex.bat)
- [x] C++ reference codegraph index created for `ghidra-ref/.../decompile/cpp`
- [x] Indexing workflow documented in `docs/INDEX.md`
- [x] Detailed implementation plan documented (archived)
- [x] Parity audit document added for current runtime mismatches: `docs/PARITY_AUDIT.md`
- [x] Go module initialized
- [x] Initial Go package layout created
- [x] First core types added: `Address`, `Space`, `VarnodeData`, `OpCode`
- [x] First raw p-code op container added
- [x] `.sla` container layer added: header plus compressed payload
- [x] Minimal packed marshal parser added for `.sla` payload decoding
- [x] Top-level Sleigh metadata decode added: version, endianness, align, uniqbase, maxdelay, uniqmask, numsections
- [x] Encoded space metadata decode added: default space plus processor/unique/other spaces
- [x] Sourcefile decode added for persisted constructor source mappings
- [x] Symbol table boundary decode added: scopes, symbol headers, body pairing
- [x] Subtable boundary decode added: constructors plus decision tree skeleton
- [x] ConstructTpl boundary decode added: handle/varnode/op-template tree plus persisted ConstTpl forms
- [x] Pattern boundary decode added: PatternExpression tree plus decision-side DisjointPattern subtree
- [x] First executable lowering added: isolated `ConstructTplBoundary -> pkg/pcode.RawOp` emission
- [x] Unit tests added for the first core types and `.sla` container layer
- [x] Unit tests added for packed metadata decode
- [x] Unit tests added for symbol/subtable/constructor boundary decode
- [x] Project direction clarified around standalone use plus downstream MCP integration
- [x] Initial parity audit started and documented in `docs/PARITY_AUDIT.md`
- [x] Runtime parity core added: `FixedHandle`, `RuntimeContext`, `ResolveHandleTpl()`, `PropagateConstructorResult()`
- [x] Special `OpTpl` handling split so raw lowering no longer treats control directives as ordinary opcodes
- [x] `walker.go` shell added: `ParserContext`, `ParserWalker`, `ConstructState`
- [x] `obtainContext` shell added: cache miss creation plus parse-state promotion hooks
- [x] `ParserWalkerChange` shell added: root reset, operand allocation, length, and commit reservation
- [x] `builder.go` now follows walker child state for recursive `BUILD`, selecting main/named sections and falling back to `buildEmpty()` only when a named section is missing
- [x] `builder.go` now routes `LABELBUILD`, `CROSSBUILD`, and `DELAY_SLOT` through explicit builder/runtime paths
- [x] `discache.go` shell added: address-keyed `ParserContext` cache with pcode-state helpers
- [x] `lower.go` now bridges into `runtime.go` parity model for handle and const resolution
- [x] `CombinePattern` parity status rechecked against original C++ and recorded in `docs/PARITY_AUDIT.md`
- [x] `resolve.go` shell added: root reset, `loadContext`, constructor/offset/length application, operand descent, pending commit queue wiring, parser-state promotion
- [x] `decision_resolve.go` added: `SubtableSymbol::resolve()` / `DecisionNode::resolve()` shell with terminal pair matching
- [x] `resolve_handles.go` updated to follow walker-state iteration and main-template result propagation
- [x] `load_context.go` added: `LoadContext`, `ClearCommits`, `AddCommit`, `PendingCommits`, `ApplyCommits` shell
- [x] `ApplyCommits` can now resolve operand-symbol commit addresses from `ParserContext.Symbols` when operand metadata is present
- [x] `OperandSymbol` boundary metadata is now preserved: `subsym`, `off`, `base`, `minlen`, `code`, `index`, `localexp`, optional `defexp`
- [x] `patexpr.go` added: `PatternExpression::getValue()` shell for constant, start/end, next2, token, context, and basic unary-binary nodes
- [x] `OperandValue` now has a first automatic path using preserved operand metadata plus `setOutOfBandState()` when `defexp` or `defsym->getPatternExpression()` is available
- [x] `ResolveHandles()` now has a first automatic path for operand `defexp` and selected boundary symbol fixed handles
- [x] `ValueMapSymbol` and `NameSymbol` table bodies are now preserved in boundary decode
- [x] `ApplyCommits()` can resolve operand-symbol commit addresses from `OperandSymbolBoundary.Index` without a lookup hook
- [x] `symbols.go` now preserves operand-symbol metadata needed for later operand semantics: `index`, `off`, `base`, `minlen`, `code`, `subsym`, `localexp`, `defexp`
- [x] `instruction_context.go` added: `ObtainPcodeContext()` wrapper for `obtainContext(..., pcode)` followed by `applyCommits()`
- [x] `docs/RUNTIME_FLOW.md` added to freeze the current runtime execution order and current authority path
- [x] Unit tests added for decision resolution, load-context commits, pattern-expression evaluation, operand-symbol boundary decode, and pcode-context preparation
- [x] `go test ./...` passes after integrating the above shells
- [x] `translate.go` now enters translation through the runtime authority path: `ObtainPcodeContext()` -> delay-slot preparation -> `ParserWalker` -> `SleighBuilder.Build()`
- [x] `TranslateInput` now carries runtime cache, symbol table, resolve hooks, resolve-handles hooks, and commit hooks for the real translation entry
- [x] Runtime translation tests added for cached pcode context, named-section selection, and recursive `BUILD` emission through a resolved operand constructor
- [x] `TranslateSubtable()` now models the local `oneInstruction()` tail ordering: raw-cache clear -> build -> relative-label fixup -> emit
- [x] Relative intra-instruction label fixup tests added for translated branch ops
- [x] `SleighBuilder::buildEmpty()` named-section recursion semantics are now modeled instead of a no-op fallback
- [x] `DisassemblyCache` can now store emitted raw ops with deep-copy semantics for later translation/runtime use
- [x] `TranslateSubtable()` now performs the original `oneInstruction()` alignment gate before context preparation
- [x] `TranslateSubtable()` now stores emitted raw ops in `DisassemblyCache` and returns the cached owned copy
- [x] Translation tests added for unaligned instruction rejection and raw-op cache ownership
- [x] `TranslateSubtable()` now conservatively rewraps `ErrBuilderUnimplemented`-class failures into a local `UnimplError` equivalent with `oneInstruction()`-style explain text and instruction length
- [x] Translation tests added for `oneInstruction()`-style unimplemented error prefix, mnemonic/body split, and explicit operand print-gap marking
- [x] Alignment failure now follows local typed unimplemented-error semantics with instruction length `0`, matching the original `oneInstruction()` alignment failure contract
- [x] `wrapTranslateUnimplError()` no longer promotes generic errors by substring and now stays type-driven for known unimplemented paths
- [x] `DisassemblyCache` now owns staged raw-build lifecycle APIs: begin, append, add-label, resolve, emit, cancel
- [x] `SleighBuilder` now owns cache-backed raw emission through `LowerRaw`, with explicit root-tail `resolve -> emit` sequencing
- [x] `TranslateSubtable()` no longer uses the local `translatePcodeCache` stopgap and now routes raw-op ownership through the builder/cache raw-build path
- [x] Builder/translation tests added for cache-backed raw-build success, cancellation, relative-label resolution, and explicit `resolve -> emit` staging semantics
- [x] `DisassemblyCache` raw-build staging now separates internal issued-op records from owned varnode storage instead of storing caller-shaped raw-op slices directly
- [x] Raw-build ownership tests added for owned-buffer isolation and for relative-label patching against cache-owned staged data
- [x] `DisassemblyCache` raw-build staging now reuses one released state across instructions and resets resolver state while keeping backing storage when capacity is sufficient
- [x] `wrapTranslateUnimplError()` now rewrites existing typed translation errors in place, closer to original `oneInstruction()` catch/rethrow behavior
- [x] Package-wide typed `UnimplError` model introduced across key runtime/translation shells, with explain text, optional instruction length, and sentinel-compatible unwrapping
- [x] `wrapTranslateUnimplError()` now rewrites any typed `*UnimplError`, and catch formatting prints more concrete non-subtable operand text without the old Go-only gap suffix
- [x] `DisassemblyCache` staged issued ops now point directly into cache-owned varnode storage, and pool-growth rebind logic updates those references after expansion
- [x] `ObtainPcodeContext()` now best-effort prefetches the fallthrough disassembly context to derive `N2Addr` and populate `DisassemblyCache` through runtime decode path
- [x] `TranslateSubtable()` now applies typed unimplemented rewrite over a single local build/resolve/emit tail boundary, closer to original `oneInstruction()` catch scope
- [x] Operand print fallback can now print some symbol-backed operands even without a pre-materialized child state
- [x] `Resolve()` now carries flow address fields into `ParserContext`, with calladdr-style fallback surviving the full obtain/promote path
- [x] `ResolveHandles()` automatic symbol-backed path now covers `NameSymbol` and `EpsilonSymbol` fixed-handle cases without hook fallback
- [x] `ResolveHandles()` can now auto-accept pre-resolved static handles for `VarnodeSymbol` / `VarnodeListSymbol` cases without hook fallback
- [x] `symbols.go` now preserves `varnode_sym` fixed data (`space/off/size`) in boundary decode
- [x] `symbols.go` now preserves `varlist_sym` selector expression plus ordered table entry ids/null slots in boundary decode
- [x] `ResolveHandles()` can now reconstruct static `VarnodeSymbol` fixed handles directly from persisted boundary data
- [x] `ResolveHandles()` can now reconstruct `VarnodeListSymbol` fixed handles from persisted selector/table body data, with explicit unimplemented errors for null slots and out-of-range selectors
- [x] `DisassemblyCache` now has a parser-context circular reuse path closer to original `DisassemblyCache::getParserContext()`
- [x] `ObtainContext()` now uses cache-owned parser-context reuse as the authoritative entry path instead of ad hoc miss-time allocation
- [x] `ParserWalker.SetOutOfBandState()` now supports constructor-relative operand evaluation without a prebuilt child state, closer to original `OperandValue::getValue()` / `setOutOfBandState()` behavior
- [x] `OperandValue` automatic path now reports out-of-band setup failure as an explicit typed parity gap instead of silently falling back
- [x] `ResolveHandles()` now mirrors `OperandSymbol::getFixedHandle()` automatic handoff through `walker.GetFixedHandle(index)`
- [x] `DisassemblyCache.EmitRawBuildTo()` now emits directly from staged issued ops and commits one cache-owned snapshot on success instead of materializing a pre-emit helper slice first
- [x] `BuilderHooks` now exposes `RawEmitter`, and the builder tail can drive sink-style emission directly instead of relying on a builder-owned emitted-slice path
- [x] `translateBuildTail()` now injects a translation sink, chains any existing builder sink, and returns emitted raw ops from that sink without post-emit `GetRawOps()` readback
- [x] raw-build staging is now a single active reusable cache-owned state instead of unconstrained per-address staging, closer to the original single `PcodeCacher` ownership model
- [x] `translateBuildTail()` now follows the cache/sink-owned tail only: `Build()` must commit cache-owned raw ops, and translation reads that committed result without any builder-side emitted-slice path
- [x] `DisassemblyCache` now has an explicit sink-style `EmitRawBuildTo(addr, RawEmitter)` path mirroring `PcodeCacher::emit(addr, PcodeEmit*)`
- [x] builder root raw-build tail no longer keeps builder-owned emitted ops and now relies on cache/sink-owned `resolve -> emit` only
- [x] builder root raw-build tail is now sink-only even without an external emitter, using an internal no-op sink instead of falling back to a builder-side slice-return path
- [x] `lowerVarnodeTpl()` now refuses dynamic handle-backed varnodes with an explicit typed unimplemented error instead of flattening them into guessed concrete raw varnodes
- [x] `DisassemblyCache` raw-build staging now tracks varnode-pool ownership with explicit issued-op records instead of pointer-search rebinding during pool growth
- [x] `EmitRawBuildTo()` now emits cloned staged ops to the sink and commits cache-owned snapshots only after successful sink emission, so sink mutation cannot corrupt retryable staging state
- [x] `wrapTranslateUnimplError()` is now strict typed `*UnimplError` rewrite only and no longer promotes builder sentinel errors without a typed unimplemented cause
- [x] `lower.go` now performs parity-safe dynamic varnode expansion for the safe subset: dynamic inputs synthesize `LOAD` before the main op and dynamic outputs synthesize `STORE` after it
- [x] unsupported dynamic `v_offset_plus` cases are now rejected explicitly as typed unimplemented parity gaps instead of being guessed
- [x] dynamic `v_offset_plus` now follows the original low-16 split more closely: low-16 `0` is treated as a no-op subset, while non-zero low-16 stays an explicit typed parity gap
- [x] dynamic `v_offset_plus` now also accepts the constant-pointer safe subset for non-zero low-16 by folding the immediate into the pointer offset, matching the constant `INT_ADD` effect without inventing runtime temp state
- [x] non-constant-pointer dynamic `v_offset_plus` now synthesizes the `INT_ADD` side-op and routes `LOAD`/`STORE` through the runtime temp in unique space at `UniqueBase + 0x100` (`RUNTIME_BITRANGE_EA`)
- [x] upstream builder/resolve/resolve-handles sentinel errors are now normalized to typed `*UnimplError` more consistently before they reach translation catch rewrite
- [x] builder directive helper files (`builder_build.go`, `builder_cross.go`, `builder_delay.go`) now normalize sentinel unimplemented paths to typed `*UnimplError`
- [x] `obtain_context.go` and `patexpr.go` now normalize sentinel unimplemented paths to typed `*UnimplError` at clear promotion/hook boundaries
- [x] translation-entry hook/cached-state parity gaps (`load-fill`, `load-context`, delay-slot missing length) now return typed `*UnimplError` instead of generic errors
- [x] `LoweringContext` now carries `UniqueBase` and `UniqueMask`, and dynamic unique-space locations/pointers apply `uniqueoffset = (instruction.offset & UniqueMask) << 8` like original `generateLocation()` / `generatePointer()`
- [x] `TranslateInput` now supports address-scoped payload sourcing (`ByAddress` map or `Lookup` callback), so translation load-fill/load-context can supply adjacent parser contexts without requiring custom user hooks for every non-base address
- [x] `ObtainPcodeContext()` now recomputes `N2Addr` per pcode obtain path, derives fallthrough from `addr + length` before trusting cached `naddr`, and uses the same `ObtainContext(..., disassembly)` route for adjacent prefetch
- [x] `ObtainContext()` now normalizes reused parser contexts more strictly by clearing stale `N2Addr` on uninitialized reuse and resetting mismatched cached-address entries to the requested address before promotion
- [x] `DisassemblyCache` raw-build staging now tracks an explicit resolved/unresolved phase, so repeated `ResolveRawBuild()` on unchanged staging is idempotent instead of re-patching already-resolved relative references
- [x] dynamic `LOAD`/`STORE` space-selector payload now uses process-local pointer identity for the target space, closer to original `SleighBuilder::dump()` than the older space-index approximation
- [x] dynamic `v_offset_plus` lowering now falls back to the deterministic lowest-index unique space in `SpacesByIndex` when `LoweringContext.UniqueSpace` is unset
- [x] `TranslatePayloadSource` now has a first-class `Loader(addr)` route, and translation entry prefers that authoritative address-based loader before lookup/map/base-seed fallbacks
- [x] `EmitRawBuildTo()` now enforces resolve-before-emit and returns `ErrRawBuildUnresolved` for unresolved staged raw builds, matching the original `resolveRelatives()` then `emit()` discipline more closely
- [x] concrete in-memory `Backend` added for the current translation runtime: LoadImage-style instruction fetch, ContextDatabase/ContextCache-style context blob reads and writes, `allowSet`, payload-loader binding, and commit hooks
- [x] `Backend` now covers the minimal named-context variable surface: registration by bit range, default get/set, per-address get/set, conservative context-range query, and change-point clipping to the next explicit overlapping write boundary
- [x] high-level `Engine` added: `TranslateInstructionAt(addr)` now exposes a reusable one-instruction translation entry over backend loader, parser-context cache, runtime authority path, and cached fallthrough length
- [x] `Engine` can now derive the standard root subtable automatically from decoded symbol data by mirroring `sleighbase.cc` global-scope lookup for the `instruction` symbol
- [x] `NewEngineFromMetadataSymbols()` / `NewEngineFromBoundaries()` now let standalone code build an engine from decoded metadata/symbol tables/backend without explicitly threading a root subtable when the standard root exists
- [x] backend/engine tests added for payload loading, context writes, named context variables, conservative context-range queries, engine loader wiring, metadata-driven alignment, and standard root-subtable discovery
- [x] `wrapTranslateUnimplError()` now mirrors `Sleigh::oneInstruction()` more strictly by rewriting only a top-level thrown `*UnimplError`, not an arbitrarily wrapped inner cause
- [x] `EmitRawBuild()` / `FinishRawBuild()` no longer auto-run relative-label resolution and now require explicit `ResolveRawBuild()` first, matching the original `build -> resolveRelatives -> emit` tail split
- [x] `AppendBuild()` no longer silently falls through package-level empty-section recursion without an active walker state; missing named-section recursion now returns typed unimplemented
- [x] `DELAY_SLOT` / `CROSSBUILD` now keep the failing inner walker active until the recursive build returns normally, so `oneInstruction()`-style unimplemented rewrite can inspect the inner constructor state on failure
- [x] `LoweringContext` now separates active instruction semantics from sink-visible raw-op address via `RootInstruction`
- [x] engine/translation entry now propagates the root instruction address through cache-backed build/resolve/emit, so emitted raw-op `SeqNum.Address` follows the original `oneInstruction(baseaddr)` contract end-to-end
- [x] `FinishRawBuild()` removed as a Go-only compatibility alias; sink emission authority now stays with explicit `ResolveRawBuild()` -> `EmitRawBuildTo()`
- [x] backend now supports a standalone `RawLoadImage`-style raw instruction source via reader/file-backed attachment (`SetRawInstructionReader`, `OpenRawInstructionFile`, `CloseRawInstructionSource`)
- [x] raw instruction source now supports `RawLoadImage::adjustVma()`-style rebasing via `AdjustRawInstructionVMA()` with word-size scaling semantics
- [x] `EmitRawBuild()` removed; owned tests and helpers now validate sink-facing `EmitRawBuildTo()` directly
- [x] tests added for top-level-only typed unimplemented rewrite, unresolved emit rejection, named-section fallback tightening, nested delay/cross failure rewrite context, root instruction raw-op address fallback, engine/translation root-address propagation, reader/file-backed raw instruction loading, raw-image rebasing, and sink-only raw-build completion
- [x] `DisassemblyCache` raw-build staging now uses one reusable active stage object directly instead of the older map plus reusable-indirection model, closer to the original single `PcodeCacher` staging lifetime
- [x] nested delay-slot translation now has an end-to-end proof test showing that inner dynamic unique-temp bits come from the inner instruction while all emitted `SeqNum.Address` values stay pinned to the root instruction address
- [x] relative-label tracking in `DisassemblyCache` now uses direct staged `labelRefs` plus an id-indexed `labels` vector instead of the older resolver-backed helper shape, closer to original `PcodeCacher::addLabelRef()` / `addLabel()` / `resolveRelatives()`
- [x] raw-build tests now cover undefined-label failure and oversized label-id rejection in the new direct relative-label model
- [x] `wrapTranslateUnimplError()` now rewrites explain text only when a usable current walker/constructor state is actually available, while still mutating instruction length in place on the same top-level typed error object
- [x] `EngineBackendAdapter` now supports split-authority `LoadFill` / `LoadContext` hooks, so `TranslateInstructionAt()` can de-emphasize bundled `MatchInput` and prefer the original `Sleigh::resolve()`-style separate decode boundaries when both hooks are available
- [x] `translateResolveHooks()` now treats bundled `MatchInput` as per-phase compatibility fallback only: explicit `LoadFill` skips bundled instruction fallback, explicit `LoadContext` skips bundled context fallback, and shared fallback lookup is cached per address so one parser-context promotion does not fetch the same payload twice
- [x] `ParserContext.GetN2addr()` now supports lazy derivation through a bound resolver, closer to original `ParserContext::getN2addr()` semantics than the older eager-best-effort prefetch-only path
- [x] `ObtainPcodeContext()` now binds lazy `inst_next2` derivation instead of eagerly forcing adjacent disassembly during every pcode obtain, while still clearing stale `N2Addr` state on parser-context reuse
- [x] engine/instruction-context tests now cover split-authority decode hooks, fallback reuse across load phases, and lazy `inst_next2` derivation on first `GetN2addr()` access
- [x] `builder_delay.go` and `builder_cross.go` now separate infrastructure errors (plain `error`) from build errors (`*UnimplError`), matching C++ `LowlevelError` vs `UnimplError` distinction in `oneInstruction()` catch block
- [x] `builder.go` null-construct path now returns `*UnimplError("", 0)` matching `PcodeBuilder::build(nullptr)` throw semantics
- [x] `symbols.go` now preserves `FlowThruIndex` in `ConstructorBoundary`, mirroring C++ `Constructor::flowthruindex`
- [x] `walker.go` `SetConstructor()` now recomputes `FlowThruIndex` from `PrintPieces` on every constructor assignment, keeping it consistent with the C++ decode-time derivation
- [x] `translate.go` now implements `flowthruindex` recursion for `printMnemonic`/`printBody`: when a constructor has exactly one operand ref, printing delegates to the child constructor
- [x] `translate.go` now implements `VarnodeSymbol::print()` parity: outputs `getName()` directly
- [x] 8 new tests added for instruction execution parity (49d0392)
- [x] `discache.go` initial varnode pool size set to 600, matching `PcodeCacher::PcodeCacher()` default (`uint4 maxsize = 600`)
- [x] `discache.go` `allocateInstruction()` added to `rawBuildState`, mirroring `PcodeCacher::allocateInstruction()`
- [x] `discache.go` pool backing storage is retained on `reset()`, matching `PcodeCacher::clear()` which resets cursor but never frees the pool
- [x] `backend.go` `GetFileName()` / `SetFileName()` added, mirroring `LoadImage::getFileName()`
- [x] `backend.go` `GetArchType()` / `SetArchType()` added, mirroring `LoadImage::getArchType()`
- [x] `backend.go` `ContextSize()` added, mirroring `ContextDatabase::getContextSize()`
- [x] `backend.go` `SetVariableRegion()` added, mirroring `ContextDatabase::setVariableRegion()`
- [x] 11 new tests added for PcodeCacher pool and backend parity (820bfde)
- [x] `resolve_handles.go`: `runtimeContextForWalker` now passes child handles and `SpacesByIndex` to `HandleTpl::fix()` parity path; `findWalkerSpaceByIndex` now prefers `SpacesByIndex` lookup over walker-visible space scan
- [x] `walker.go`: `ParserContext` gains `SpacesByIndex` field for space lookup without walker indirection
- [x] `symbols.go`: `ContextSymbolBoundary` added with `varnode`, `low`, `high`, `flow` attributes, mirroring `ContextSymbol::decode()`
- [x] `xrefs.go`: `BuildXrefs()` implemented -- post-decode xref/userop/context registration matching `SleighBase` post-decode register pass
- [x] `patexpr.go`: `ContextSymbol` pattern access path corrected; `translate.go` `evalPatternSymbolValue` now checks both `Context` and `Pattern` sides
- [x] 12 new tests added for operand semantics and .sla runtime data parity (cc3878d)
- [x] `discache.go`: emit/resolve error messages aligned to C++ `PcodeCacher` text; `builder_build.go` same-message parity
- [x] `instruction_context.go`: `N2addr` delay-slot known gap documented; lazy derivation parity comment added
- [x] `walker.go`: `GetN2addr()` C++ counterpart comment added
- [x] `symbols.go`: `ContextOpBoundary` type added with `num`, `shift`, `mask` fields; `EpsilonSymbol` body opaque fix
- [x] `symbols_test.go`: `ContextOp` and `EpsilonSymbol` tests added; `metadata.go` audit confirmed no gaps (9f63d4a)
- [x] `packed.go`: `TYPECODE_ADDRESSSPACE` (type 5) and `TYPECODE_SPECIALSPACE` (type 6) decoding added
- [x] `metadata.go`: `requiredSpaceAttr()` helper added; `symbols.go` and `templates.go` now use it for space attribute reads
- [x] `integration_test.go`: 7-step integration test against real Ghidra 12 `6502.sla` -- all 7/7 pass; `testdata/6502-packed.sla` added (64336df)
- [x] `container.go`: XML detection and XML payload extraction added
- [x] `xml.go`: `encoding/xml`-based XML parser converts to internal `element`/`attribute` model
- [x] `metadata.go`: Sleigh v3 (XML) and v4 (packed) both accepted; `container_test.go` and `integration_test.go` extended with XML coverage
- [x] `testdata/6502.sla` (XML v3) added; XML fixture path tested end-to-end (320c3fb)

- [x] Phase 3 WU1: PcodeOp struct (32 primary + 11 secondary flags), TypeOp interface with 72-opcode registration, PcodeOpBank container (605ab92)
- [x] Phase 3 WU2: Varnode SSA struct (32+13 flags), VarnodeBank with dual sorted indices (locTree/defTree) using C++ (f-1) unsigned status trick (605ab92)
- [x] Phase 3 WU4: FlowBlock base with bidirectional edge management, BlockBasic (PcodeOp list), BlockGraph (CFG container with FindSpanningTree/CalcForwardDominator/StructureLoops) (6200824)
- [x] Phase 3 WU6: Funcdata container wrapping VarnodeBank + PcodeOpBank with Varnode/PcodeOp creation, wiring (def/descend links), and search API (6200824)
- [x] Phase 3 integration: 125 tests passing across all WU1-WU4/WU6 types

- [x] Phase 3 WU5: Heritage SSA construction -- LocationMap, TaskList, PriorityQueue, BuildADT (Bilardi-Pingali), CalcMultiequals/visitIncr, Rename (Cytron et al.), Heritage() main pipeline (02b803a)
- [x] Phase 3 complete: 6 work units, ~6,400 lines, 142 tests passing
- [x] Phase 4-5 roadmap created: docs/DECOMPILER_PIPELINE_ROADMAP.md (~22,400 lines planned)
- [x] Phase 4 complete: WU1-WU6 완료. Action/Rule framework, Type system, transformation rules, dead-code/type propagation, block structuring 경로가 구현됨
- [x] Phase 5 complete: WU7 완료. PrintC 기반 C 출력 경로와 선언 출력기가 구현됨
- [x] 현재 저장소 기준 `go test ./...` 통과

- [x] Phase D11 완료 (2026-04-04): CALL indirect (FF /2 register + memory) + SETcc (SETE/SETNE/SETL/SETGE) + MOVZX 16-to-32 golden (57 subtests), TestX86IndirectCallFunction E2E
  - `pkg/sla/x86_golden_test.go`: 7 new cases -- CALL_EAX (FF D0), CALL_mem_EAX (FF 10), SETE_AL, SETNE_AL, SETL_AL, SETGE_AL, MOVZX_EAX_AX (0F B7 r/m16) -- 총 57 subtests
  - `testdata/golden/`: CALL_EAX -> CALLIND p-code; CALL_mem_EAX -> LOAD+CALLIND; SETcc -> INT_EQUAL/INT_NOTEQUAL/INT_SLESS/INT_SLESSEQUAL+COPY to byte; MOVZX_EAX_AX -> INT_ZEXT 16->32
- [x] Phase D13 완료 (2026-04-04): CMOVcc (CMOVE/CMOVNE/CMOVGE/CMOVL/CMOVG) + BSWAP golden fixtures + TestX86BranchlessMaxFunction
  - 6 new golden subtests: CMOVE_EAX_EBX, CMOVNE_EAX_EBX, CMOVGE_EAX_EBX, CMOVL_EAX_EBX, CMOVG_EAX_EBX, BSWAP_EAX (total: 69 subtests)
  - TestX86BranchlessMaxFunction: branchless max(a,b) E2E -- CMP+CMOVL, 6+ instructions, non-empty PrintC output
  - No engine fixes required; all 6 opcodes decoded correctly by existing Sleigh engine (0F 44-4F range + 0F C8)
- [x] D12: ADC/SBB + ROR/ROL + LEAVE + CWDE golden fixtures + 3-branch clamp E2E (2026-04-04)
  - 6 new golden subtests: ADC_EAX_EBX, SBB_EAX_EBX, ROR_EAX_imm8, ROL_EAX_imm8, LEAVE, CWDE (total: 63 subtests)
  - TestX86ClampFunction: 3-branch clamp(x,lo,hi) E2E -- CMP+JGE+CMP+JLE, 4+ CFG blocks, PrintC output
  - `pkg/loader/loader_test.go`: TestX86IndirectCallFunction -- PUSH EBP + MOV EBP,ESP + MOV EAX,[EBP+8] + CALL EAX + POP EBP + RET, >= 4 instructions, non-empty PrintC
  - No engine fixes required; all 7 opcodes decoded correctly by existing Sleigh engine
- [x] Phase D10 완료 (2026-04-04): PUSH imm8/imm32 + NOT + stack locals golden (50 subtests), TestX86LocalVarFunction (local vars E2E)
  - `pkg/sla/x86_golden_test.go`: 7 new cases -- PUSH_imm8/imm32, NOT_EAX, MOV_EBP_minus4_EAX, MOV_EAX_EBP_minus4, SUB_ESP_imm8, SHL_EAX_1
  - `pkg/sla/lower.go`: fixed dynamicSpaceSelectorPayload -- use space.Index instead of raw pointer (non-deterministic ASLR value)
  - `pkg/loader/loader_test.go`: TestX86LocalVarFunction -- double_it() with SUB ESP + SHL EAX,1 + MOV [EBP-4] store/load, non-empty PrintC
- [x] Phase D9 완료 (2026-04-04): PUSH/POP regs + DEC/XCHG + Jcc (JL/JLE/JG/JB/JA) + TestX86Add3Function
  - `pkg/sla/x86_golden_test.go`: 10 new cases -- 총 43 subtests
  - PUSH_EBX/PUSH_ECX/POP_EBX: COPY+INT_SUB+STORE/LOAD 패턴, DEC_EAX: INT_SUB+flags, XCHG: 3x COPY
  - JL/JLE/JG/JB/JA_fwd: 각 Jcc flag 조합 + CBRANCH. 모든 케이스 decode gap 없음.
  - `pkg/loader/loader_test.go`: TestX86Add3Function -- PUSH EBX + 3x ADD[mem] + POP EBX, non-empty PrintC
- [x] Phase D8 완료 (2026-04-04): LEA/MOVZX/MOVSX/OR/AND/INC/CMP/JGE golden fixtures + TestX86ComplexFunction
  - `pkg/sla/x86_golden_test.go`: 8 new cases (OR_EAX_EBX, AND_EAX_EBX, INC_EAX, CMP_EAX_EBX, MOVZX_EAX_AL, MOVSX_EAX_AL, LEA_EAX_disp8, JGE_fwd) -- 총 33 subtests
  - `testdata/golden/`: OR(INT_OR+flags), AND(INT_AND+flags), INC(INT_ADD+OF), CMP(INT_SUB+flags), MOVZX(INT_ZEXT), MOVSX(INT_SEXT), LEA(INT_ADD+COPY), JGE(INT_EQUAL(SF,OF)+CBRANCH)
  - `pkg/loader/loader_test.go`: TestX86ComplexFunction -- max() CMP+JGE+conditional MOV, >= 2 CFG blocks, non-empty PrintC
- [x] Phase D7 완료 (2026-04-04): PE32 loader + TestX86PEDecompile E2E + CLI --pe flag
  - `pkg/loader/pe.go`: LoadPE32TextSection (debug/pe stdlib, PE32+ 거부 포함)
  - `pkg/loader/pe_test.go`: TestPELoader (len==13, data[0]==0x55, vma==0x401000) + TestX86PEDecompile (full pipeline)
  - `testdata/elfs/simple_add.exe`: 1024-byte minimal PE32 (add() 함수, ImageBase=0x400000, .text@0x1000)
  - `testdata/elfs/gen_pe.go`: PE32 binary generator (build tag ignore)
  - `cmd/gosleigh/main.go`: --pe flag (--elf/--binary와 상호 배타)
- [x] Phase D6 완료 (2026-04-04): IDIV/DIV/CDQ/SHL/SHR/SAR golden fixtures + E2E tests
  - `pkg/sla/x86_golden_test.go`: 6 new cases (CDQ, IDIV_ECX, DIV_ECX, SHL/SHR/SAR_EAX_imm8) -- 총 25 subtests
  - `testdata/golden/x86_CDQ.json`: INT_SEXT+SUBPIECE (Ghidra x86.sla sext(EAX)->EDX parity)
  - `testdata/golden/x86_IDIV_ECX.json`: INT_SDIV+INT_SREM signed division ops
  - `testdata/golden/x86_DIV_ECX.json`: INT_DIV+INT_REM unsigned division ops
  - `testdata/golden/x86_SHL/SHR/SAR_EAX_imm8.json`: INT_LEFT/INT_RIGHT/INT_SRIGHT (logical/arithmetic correct)
  - `pkg/loader/loader_test.go`: TestX86DivideFunction (CDQ+IDIV full pipeline) + TestX86BitshiftFunction (SHL E2E)
  - No translator fixes required; existing Sleigh engine handles all 6 opcodes
- [x] Phase D5 완료 (2026-04-04): IMUL/MUL golden fixtures + CLI --elf flag + TestX86MultiplyFunction E2E
  - `cmd/gosleigh/main.go`: --elf flag 추가 (LoadELF32TextSection 연동, --binary와 상호 배타)
  - `pkg/sla/x86_golden_test.go`: x86_IMUL_EAX_EBX (8 ops) + x86_MUL_EBX (7 ops) -- 총 19 subtests
  - `testdata/golden/x86_IMUL_EAX_EBX.json`: INT_SEXT+INT_MULT+SUBPIECE 등 8 ops
  - `testdata/golden/x86_MUL_EBX.json`: unsigned MUL semantics 7 ops
  - `pkg/loader/loader_test.go`: TestX86MultiplyFunction -- IMUL EAX,[EBP+0xC] memory operand E2E, non-empty PrintC
  - 0x0F prefix (two-byte opcode) 기존 Sleigh 엔진에서 정상 처리 확인
- [x] Phase D4 완료 (2026-04-04): if-else diamond CFG + block structuring E2E
  - `pkg/sla/resolve.go`: CRITICAL FIX -- instruction length ctx.GetLength() -> change.CalcCurrentLength() (disp8/imm 포함)
  - `pkg/bridge/bridge.go`: CRITICAL FIX -- linear scan -> BFS worklist (unconditional JMP forward target 추적)
  - `pkg/sla/x86_golden_test.go`: JE_fwd/TEST_EAX_EAX/JNS_fwd/NEG_EAX 추가 -- 총 17 subtests
  - `pkg/loader/loader_test.go`: TestX86IfElse -- abs() 함수 ({85,C0,79,04,F7,D8}), 3+ CFG blocks, non-empty PrintC
- [x] Phase D3 완료 (2026-04-04): ELF32 loader + simple_add.elf E2E
  - `pkg/loader/elf.go`: LoadELF32TextSection -- debug/elf stdlib, .text section bytes+VMA 추출
  - `testdata/elfs/simple_add.elf`: 200-byte ELF32, add() 함수 (11 bytes)
  - `pkg/loader/elf_test.go`: TestELFLoader + TestX86ELFDecompile (full pipeline, non-empty C)
- [x] Phase D2 완료 (2026-04-04): CALL instruction (0xE8) E2E
  - `testdata/golden/x86_CALL_rel32.json`: 3 ops (INT_SUB + STORE + CALL)
  - `pkg/loader/loader_test.go`: TestX86CallerFunction -- PUSH/MOV/CALL/POP/RET -> non-empty PrintC
- [x] Phase D1 완료 (2026-04-04): Heritage SSA on real loop CFG + PrintC loop output
  - `pkg/bridge/bridge.go`: RETURN/BRANCHIND hard terminator fix (collectInstructions past-end 방지)
  - `pkg/sla/x86_golden_test.go`: DEC_ECX (8 ops) + JNE_back (2 ops) 추가 -- 총 12 subtests
  - `testdata/golden/x86_DEC_ECX.json` + `x86_JNE_back.json`: golden fixture 생성
  - `pkg/loader/loader_test.go`: TestX86CountedLoop -- {B9,03,00,00,00,49,75,FD,C3} -> 3 CFG blocks, do-while PrintC 출력
- [x] Phase B6+B7 완료 (2026-04-04): x86 pspec context init + golden fixtures
  - `pkg/sla/pspec.go`: ParsePspec() -- x86.pspec `<context_set>` 파싱, SetVariableDefault 적용
  - `pkg/sla/x86_golden_test.go`: goldenEngineX86() + TestGoldenX86 (NOP/RET/PUSH_EBP)
  - `pkg/sla/translate.go`: VarnodeList operand type 지원 (+8/-2 lines)
  - `testdata/golden/x86_{NOP,RET,PUSH_EBP}.json`: golden fixture 생성
  - RET: 3 ops (LOAD/INT_ADD/RETURN), PUSH_EBP: 3 ops (COPY/INT_SUB/STORE)
  - NOP: 0 ops (Ghidra PCODE_NOP -- 정상)
- [x] WU6 (Verification / Golden Testing / E2E Integration) 완료 (2026-04-04)
  - `pkg/sla/golden_test.go`: golden test harness 구현. `GOSLEIGH_UPDATE_GOLDEN=1` 환경변수로 update mode 전환.
  - `testdata/golden/`: 6502 fixture 3종 -- BRK (0x00, 29 ops, match), NOP_EA (unimplemented gap), LDA_imm (unimplemented gap).
  - `pkg/bridge/bridge.go`: `Result.Warnings []string` 필드 추가. `collectInstructions()`에서 `*sla.UnimplError`는 Warnings 기록 후 수집 중단 (graceful), 그 외 오류는 hard-fail 유지.
  - `pkg/bridge/bridge_test.go`: `TestBuildE2EWithRealSLA` 추가 (constructor resolution gap으로 인해 skip). `TestMultiArchFixture` 추가 (추가 .sla 없어 skip).
  - `go test ./...` 통과.
  - 핵심 발견: BRK (0x00)만 정상 resolve. 나머지 6502 opcode (NOP 0xEA, LDA 0xA9, BNE 0xD0 등)는 `"unable to resolve constructor"` plain error 반환 -- decision tree resolution path의 주요 parity gap. 상세는 `docs/PARITY_AUDIT.md` Golden/Bridge Test Findings 섹션 참조.

- [x] D14: OR/AND/XOR/CMP imm8 + IMUL 3-operand + JMP indirect 완료 (2026-04-04)
  - 7개 golden fixture 추가: OR_EAX_imm8, AND_EAX_imm8, XOR_EAX_imm8, CMP_EAX_imm8, IMUL_EAX_EBX_imm8, JMP_EAX, JMP_mem_EAX
  - 총 76개 golden subtest 통과
  - `TestX86ClassifySignFunction` E2E: 3-path sign classification (zero/positive/negative) -> PrintC 출력 검증
- [x] D15: REP string ops + ENTER + switch E2E 완료 (2026-04-04)
  - 6개 golden fixture 추가: REP_MOVSB (13 ops), REP_MOVSD (13 ops), REP_STOSD (7 ops), REPNE_SCASB (17 ops), SCASB (17 ops), ENTER_8 (5 ops)
  - 총 82개 golden subtest 통과
  - `TestX86SwitchFunction` E2E: 3-case CMP+JNE chain (4-way dispatch) -> Heritage+PrintC 파이프라인 검증
  - REP-prefix string op (memcpy/memset/strlen 패턴) 및 ENTER 프롤로그 디코딩 검증
- [x] D16: SIB/reg+disp8 addressing mode golden fixtures + struct/array access E2E 완료 (2026-04-04)
  - 6개 golden fixture 추가: MOV_EAX_EBX_disp8, MOV_EBX_disp8_EAX, MOV_EAX_SIB_ECX_EAX4, LEA_EAX_SIB, MOV_EAX_SIB_disp8, MOV_EAX_EAX_EBX
  - 총 88개+ golden subtest 통과
  - `TestX86StructAccessFunction` E2E: struct field access (p->y) -> Heritage+PrintC 파이프라인 검증
- [x] D17: disp32 memory + global var access + ESI/EDI registers + linked-list E2E 완료 (2026-04-04)
  - 9개 golden fixture 추가: MOV_EAX_EBX_disp32, MOV_EBX_disp32_EAX, MOV_EAX_abs32, MOV_abs32_EAX, PUSH_ESI, POP_ESI, PUSH_EDI, POP_EDI, MOV_ESI_EAX
  - 총 97개 golden subtest 통과
  - `TestX86LinkedListFunction` E2E: linked list traversal (sum_list, back edge loop) -> Heritage+PrintC 파이프라인 검증
  - `TestX86ArrayIndexFunction` E2E: array index (arr[i], SIB scale*4) -> Heritage+PrintC 파이프라인 검증
- [x] D18: misc opcode gaps + complex multi-arg E2E 완료 (2026-04-04)
  - 5개 golden fixture 추가: MOVSX_EAX_AX (0F BF C0), MOVSX_EAX_mem (0F BE 00), MOVZX_EAX_mem (0F B6 00), TEST_EAX_imm32 (A9 FF FF FF FF), MOV_AX_EBP_disp8 (66 8B 45 08)
  - 총 102개 golden subtest 통과 (기존 97 + 신규 5)
  - decode gap 없음: 5개 opcode 모두 기존 Sleigh 엔진에서 정상 처리
    - MOVSX 16-bit reg form (0F BF): INT_SEXT AX->EAX (1 op)
    - MOVSX/MOVZX memory forms (0F BE/B6): LOAD+INT_SEXT/INT_ZEXT (memory read path)
    - TEST EAX,imm32 (A9): INT_AND + ZF/SF/PF flags (AND 결과는 임시 unique에 기록, result 버림)
    - 66h prefix MOV (operand size override): INT_ADD+LOAD+COPY (Ghidra x86.sla opsize override 경로 정상)
  - `TestX86ComplexMultiArgFunction` E2E: sum_positive() -- ESI callee-save + SIB+disp8 array access + CMP+JL conditional + DEC+JNZ loop, >= 8 instructions, >= 3 CFG blocks, non-empty PrintC 출력
- [x] D19: 66h prefix fix + new golden fixtures + nested if-else E2E 완료 (2026-04-04)
  - 66h prefix (operand size override) LOAD/COPY size=2 fix 적용
  - 6개 golden fixture 추가: JMP_rel32, PUSH_EAX, POP_EAX, PUSH_EDX, POP_EDX, JO_fwd
  - 총 108개 golden subtest 통과 (기존 102 + 신규 6)
  - `TestX86NestedIfFunction` E2E: classify2() -- nested if-else (x>0 -> y>x -> 2/1, else 0), >= 10 instructions, >= 4 CFG blocks, non-empty PrintC 출력
  - E2E 총계: 20개 테스트
- [x] D20: missing integer opcodes (JNO, XCHG mem) + FP basic decode probes + call chain E2E -- x86 32-bit integer opcode coverage complete (2026-04-04)
  - JNO (0x71), XCHG r/m32 (0x87) golden fixtures 추가
  - FP probes (FLD1/FLDZ/FSTP_m32) golden fixtures 추가 -- x87 FP 디코딩 정상 동작 확인 (skip 불필요)
  - `TestX86CallChainFunction` E2E: caller -> callee1 -> callee2 multi-CALL chain through Heritage+PrintC
  - 총 113개 golden subtest 통과 (기존 108 + 신규 5), E2E 총계: 21개 테스트
- [x] E1: cdecl calling convention + variable recovery -- named param/local output (2026-04-04)
- [x] E2: ActionDeadCode dead store eliminator -- x86 flag varnodes (ZF/CF/SF/OF/PF) eliminated from PrintC output (2026-04-04)
  - Iterative fixpoint DCE: removes ops with no-consumer outputs (INT_CARRY/SBORROW/BOOL_* chains)
  - Fixed funcdata.go OpUnsetOutput/OpDestroy bugs (VarnodeBank unlink + BlockBasic removal)
  - ActionSetCasts stub added for future cast insertion
  - `TestE2DeadCodeElimination`: SBORROW/POPCOUNT/INT_CARRY absent from classify2 output
- [x] E3: FP Heritage type annotation + PrintC float literal emission (2026-04-04)
- [x] E4: x86-64 support -- register ABI, 6 golden fixtures, 2 E2E tests (2026-04-04)
  - CspecData: IntegerRegParams() / PointerSize() / Windows grouped pentries
  - ProtoModel: RegParams/RegParamOffsets, pointer-size-aware local threshold, IsRegParam()
  - ScopeLocal: register-space varnodes classified as params (RDI/RSI/... -> param_0/1/...)
  - Engine.RegisterByName() for offset lookup
  - TestGoldenX8664: 6 x86-64 golden subtests (121 total), TestX8664SimpleFunction + TestX8664CallingConvention (29 E2E total)
  - Heritage.AnnotateFloatTypes(): marks FLOAT_* op output varnodes as float/double
  - renderFloatLiteral(): IEEE-754 bit reinterpretation (0x3f800000 -> 1f, NaN/Inf handled)
  - ScopeLocal: float type propagated from Varnode to HighVariable
  - `TestE3FloatLiteralEmit`: 10 subtests covering 0/1/neg/NaN/Inf for float32+float64
  - CSpec XML parser: `cspec.go` (Ghidra calling convention spec loader)
  - ProtoModel cdecl: EBP+8 -> param_0, EBP+12 -> param_1, EAX -> return
  - HighVariable layer: HighParam, HighLocal, HighGlobal, HighOther (variable.cc port)
  - ScopeLocal: stack frame variable name mapping (varmap.cc port)
  - FuncProto: function prototype with named parameters
  - PrintC: function signature with typed params + local variable declarations
  - `TestX86CdeclParamLocalFunction` E2E: cdecl function output contains param_0/param_1/local_0
  - 6 test files, 27 test/fuzz/benchmark functions covering all 5 new production files
- [x] E5: struct/pointer/array type recovery -- ActionInferTypes + TypeOp.PropagateType (2026-04-05)
  - `Varnode.tempType` scratch field + SetTempType/GetTempType/ClearTempType (varnode_ssa.go)
  - `TypeFactory.GetPointerTo` / `TypeFactory.GetExactType` convenience methods (typefactory.go)
  - `TypeOp.PropagateType` interface method + typeOpBase no-op default (typeop.go)
  - Concrete per-opcode PropagateType: typeOpCopy/Multiequal (pass-through), typeOpLoad (pointee forward + pointer reverse), typeOpStore (pointee/pointer bidirectional), typeOpIntAdd (pointer arithmetic), typeOpPtradd/Ptrsub, typeOpZext/Sext (sized uint/int), typeOpIntCmp (bool output), typeOpCast (size-preserving)
  - `RegisterTypeOps` updated to use concrete structs for 14 opcodes
  - `ActionInferTypes`: 7-iteration seed->propagate->writeBack convergence loop (action_infertypes.go)
  - `action_infertypes_test.go`: 4 unit tests (COPY chain, LOAD dereference, INT_ADD pointer arithmetic, convergence)
  - `TestX86StructFieldAccess` E2E: struct Point pointer type injected on param_0, struct type declaration emitted in PrintC output (pkg/loader/loader_test.go)
  - `TestX86ArrayIndexAccess` E2E: int* pointer type injected on arr param, `int *param_0` typed output
  - All existing tests continue to pass (go test ./...)

### 다음
- [x] `DecisionNode::resolve()` 결함 수정 완료: 6502 NOP(0xEA)/LDA(0xA9) 정상 동작 확인. NOP -> 0 ops, LDA -> COPY+flags. 모든 6502 golden 통과.
- [ ] Continue `Instruction Execution Parity`: remaining full catch coverage outside the current typed path, stricter same-object mutation semantics for every nested failure path, and constructor-print/catch-format parity beyond the current shell
- [ ] Continue `PcodeCacher And Builder Parity`: direct `allocateInstruction()` / `allocateVarnodes()` integration into `AppendRawBuild` path, infallible sink semantics, and full container/pool parity beyond the current `allocateInstruction` stub
- [ ] Continue `Decode Pipeline Parity`: build on the authoritative split `LoadFill` / `LoadContext` route, the per-phase bundled fallback compatibility layer, backend-backed context reads/writes, parser-context circular reuse path, lazy `inst_next2` derivation, root-instruction emission propagation, and the raw file-backed loader path, then replace remaining synthetic setup with broader real decode population of cached fields such as handles, calladdr semantics, commit-backed context state, and broader loader/database parity
- [ ] Continue `Operand Semantics Parity`: operand child-handle passing and `SpacesByIndex` lookup are now wired; extend the automatic path to cover remaining `TripleSymbol::getFixedHandle()` cases and reduce dynamic varnode-style hook fallback further
- [x] flow-symbol fixed-handle parity now has an automatic runtime path for safe `inst_dest` / `inst_ref` opaque-boundary candidates, without guessing nonexistent persisted `.sla` IDs
- [ ] Reduce the remaining Go-only sink error semantics gap in `EmitRawBuildTo()` while keeping parity-safe staging ownership
- [ ] Reduce the remaining internal container-shape gap against original `PcodeCacher` (`PcodeData` / `VarnodeData` allocation layout and pool-growth structure), even though current behavior is now closer
- [ ] Finish the remaining dynamic varnode expansion gaps: exact cross-run parity for C++ `LOAD`/`STORE` pointer-space payload handling and the explicit no-`UniqueSpace` parity gap when no unique runtime temp space exists anywhere in context
- [ ] Keep tightening `Instruction Execution Parity` by normalizing the remaining non-typed unimplemented paths still outside the current coverage
- [ ] Complete `BuildXrefs()` integration: wire the registered xref/userop/context tables into runtime resolve and pattern-evaluation paths
- [ ] Finish `symbols.go` and `metadata.go` parity audit including `ContextSymbolBoundary` and `ContextOpBoundary` runtime usage
- [ ] Reconcile Gosleigh package/module shape with standalone use plus downstream MCP integration
- [ ] Continue from translation/runtime into the broader decompiler pipeline instead of stopping at a partial translator layer
- [x] E6: symbol recovery -- SymbolTable, LoadELFSymbols, LoadDWARFFunctions, LoadPE32Exports/Imports, SetDisplayName, BuildConfig.SymbolName wiring, fixture generators, 6 unit tests + E2E (2026-04-05)
- [x] E7: AArch64 E2E pipeline -- AARCH64.pspec, goldenEngineAARCH64, TestGoldenAARCH64 (4 subtests: ADD/RET/MOV/NOP), TestAARCH64SimpleFunction loader E2E, 4 golden fixtures (2026-04-05)
- [x] E8: ActionConstantFold + dead code integration -- evaluates all-constant pure ops (INT_*/BOOL_*/POPCOUNT) to fixpoint; ActionDeadCode wired into x86 E2E pipelines; classify_sign output no longer contains POPCOUNT/CARRY/SCARRY (2026-04-05)
- [x] E9: local variable explosion fix -- collectVarnodeNames() groups non-unique varnodes by (spaceIdx,offset,size); SSA versions of same register share one local_N name; unique-space temps stay as tmp_N (2026-04-05)
- [x] E10: register name identification -- Engine.RegisterNamesByLocation() builds SLA VarnodeSymbol offset->name map; PrintC.SetRegisterNames() injects it; EAX/EBP/ZF etc. appear directly in output instead of local_N (2026-04-05)
- [x] E11: return register anchoring + flag folding -- AnchorReturnReg (EAX anchor so MOV EAX,1/-1/0 survive DCE), ActionFoldFlagConditions (ZF/SF/OF -> unique temps so flag register writes die), stripReturnIndirectRef (RETURN input[0] zeroed to break ESP/EIP epilogue chain) (2026-04-05)
- [x] E12: MIPS32 LE E2E -- mips32le.pspec, 4 golden fixtures (LW/SW/ADDIU/JR), TestGoldenMIPS32LE, TestMIPS32LESimpleFunction loader E2E (2026-04-05)
- [x] F1: merge.cc port -- Cover/CoverBlock live range tracking, Merge.MergeOp/MergeMarker, HighIntersectTest cache, MULTIEQUAL -> single HighVariable, OpInsertBefore/After for COPY insertion during TrimOpInput (2026-04-05)
- [x] F2+F3+F5: stripReturnIndirectRef (RETURN input[0] zeroed, breaks EIP chain), RuleSborrow (sborrow(V,0)->false), funcproto epilogue cleanup (2026-04-05)
- [x] F4+F7: RuleIdentityEl + ActionSeedSignedOps + INT_SUB reverse type propagation (2026-04-05)
  - RuleIdentityEl: INT_ADD/SUB/XOR/OR(x,0)->x, INT_MULT(x,1)->x, INT_MULT(x,0)->0 (C++ ruleaction.cc RuleIdentityEl::applyOp)
  - RuleSub2Add guarded to skip INT_SUB(x,0) so RuleIdentityEl can fire in-pass without multi-sweep cycle
  - Root cause: RuleSub2Add converted INT_SUB->INT_ADD+INT_MULT before IdentityEl; fix: zero-const guard
  - ActionSeedSignedOps: seeds TYPE_INT on inputs of INT_SLESS/SLESSEQUAL/SRIGHT/SDIV/SREM/SBORROW/SCARRY/2COMP (C++ typeop.cc TypeOpIntSless::propagateType)
  - ActionInferTypes extended: COPY/MULTIEQUAL reverse propagation for TYPE_INT (signed constant rendering)
  - classify_sign output: tmp_X variables now typed as `int`, `+ -0` artifact eliminated
- [x] F8: condition normalization -- BatchA second pass (2026-04-05)
  - Root cause: RuleBooleanNegate tried INT_EQUAL(SF, SBORROW_out) before RulePropagateCopy replaced SBORROW_out with const:0; since opcode didn't change, RuleBooleanNegate wasn't retried
  - Fix: run BatchA twice in the pipeline (C++ Ghidra re-runs batch action group until stabilization)
  - Effect: INT_EQUAL(const:0, INT_SLESS_result) -> BOOL_NEGATE(INT_SLESS_result) -> INT_SLESSEQUAL(0, tmp_0)
  - classify_sign condition: `0 == tmp_0 < 0` eliminated; now `0 <= tmp_0`
  - F7 also resolved: INT_SLESSEQUAL seeds TYPE_INT on its inputs, propagates to EAX -> 0xffffffff rendered as -1
- [x] F9: if-body inversion fix -- NegateCondition + collapseRegion edge ordering + renderBranchCondition (2026-04-05)
  - Bug 1: NegateCondition set BooleanFlip on first op instead of last (CBRANCH), and did not call SwapEdges. C++ parity: BlockBasic::negateCondition always uses op.back() and calls FlowBlock::negateCondition(true) which swaps edges.
  - Bug 2: collapseRegion used remove+re-append for incoming edges, which swap-deleted the original edge slot and re-appended at the end, corrupting TrueOut/FalseOut ordering. Fix: use ReplaceOutEdge (in-place) matching C++ selfIdentify -> replaceOutEdge path.
  - Bug 3: renderBranchCondition wrapped BooleanFlip with `!` prefix only. Fix: implement checkPrintNegation logic (booleanFlipToken) -- INT_EQUAL->!=, INT_NOTEQUAL->==, INT_SLESS-><=+reorder, etc. matching C++ PrintC::opCbranch negatetoken path.
  - classify_sign: `if (tmp_0 == 0) { EAX = 0; } else { if (tmp_0 != 0 && 0 <= tmp_0) { EAX = 1; } else { EAX = -1; } }` -- condition structure now correct
- [x] F10: collectSymbols catch-all params fix + RuleLessNotEqualBoolAnd (2026-04-05)
  - Bug: collectSymbols in printc.go added ALL input varnodes (EBP, ESP, etc.) as function params via catch-all fallback. Fix: input varnodes not classified by ScopeLocal are ABI-defined live-ins, not C parameters.
  - Bug: RuleLessNotEqualBoolAnd missing. C++ parity: RuleLessNotEqual fires on BOOL_AND(INT_(S)LESSEQUAL(V,W), INT_NOTEQUAL(V,W)) -> INT_(S)LESS(V,W). Added to BatchA.
  - classify_sign: `param_0, param_1, param_2` removed from signature (now correctly `void`); `tmp_0 != 0 && 0 <= tmp_0` simplified to `0 < tmp_0`
  - TestX86CdeclParamLocalFunction: param_ check updated to TODO (stack param detection requires ActionStackPtrFlow, not yet implemented)
  - Remaining issues requiring ActionStackPtrFlow: (1) param_0 in classify_sign signature, (2) ESP/EBP in local declarations, (3) tmp_0 -> param_0 naming
- [x] F11: ActionStackPtrFlow -- stack parameter detection via LOAD-to-COPY conversion (2026-04-05)
  - Added `pkg/pcode/action_stack_ptr_flow.go`: scans for frame pointer setup pattern (FP = COPY(INT_SUB(ESP_input, push_size)) or COPY(INT_ADD(SP_input, negative_delta))), then replaces each LOAD(ram, INT_ADD(FP, offset)) with COPY(stack_input_vn) at stack offset = offset + push_delta.
  - Key implementation detail: x86 Sleigh encodes PUSH as INT_SUB(ESP, unique_const) where the "4" is a unique-space temp, not a constant-space varnode. Delta is derived from the frame pointer register's size instead.
  - Creates a synthetic SpaceKindStack address space; ScopeLocal.BuildFromVarnodes then classifies stack-offset-4 as param_0, stack-offset-8 as param_1, etc.
  - Exposes StackSpace() accessor so test code can pass the space to NewProtoModelFromCspec.
  - classify_sign: signature now shows `(int param_0)` and body uses `param_0` in comparisons.
  - add_and_store: signature now shows `(unsigned int param_0, unsigned int param_1)`.
  - tmp_N fix: collectSymbols now skips unique-space varnodes with numDescend==0 (dead stores created by BatchA after ActionDeadCode ran). classify_sign output is now clean: no spurious tmp_N declarations.
  - classify_sign final output: `unsigned int classify_sign(int param_0) { int EAX; unsigned int ESP; if/else with EAX=0/1/-1; return EAX; }`
- [x] Ghidra golden infrastructure (2026-04-05)
  - JDK 21 installed at C:\Program Files\Java\jdk-21
  - C:\ghidra12 junction created (avoids Korean path issue with log4j)
  - gen_golden.py script: builds ELF32/ELF64/AARCH64 from test byte sequences, runs Ghidra 12 headless, saves output
  - testdata/ghidra_golden/ghidra_golden.json: 6 entries (classify_sign, complex_max, multiply, add3 x86-32; x64_add_ret x86-64; aarch64_add_ret AARCH64)
  - Key Ghidra parity observations: x86-32 entry has 2 ghost params (param_1/param_2=argc/argv) before real params; x86-64 no-prologue uses in_RDI/in_RSI prefix; AARCH64 cleanly detects param_1/param_2; Ghidra emits else-if chain; 0xffffffff not -1 without signed type info
- [x] printc: suppress unique-space top-level statements + else-if chain rendering (2026-04-11)
  - emitOps: unique-space varnode output statements suppressed (tmp_N = ... eliminated)
  - emitIfBlockChain: recursive else-if chain (was else { if (...) { } })
  - returnValue: skip IsAnnotation/IsInput varnodes (ABI machinery like EIP/LR)
- [x] printc: return value rendering from free varnodes (2026-04-11)
  - Root cause: anchorReturnReg wires latest-seq EAX SSA version (SUBPIECE/INT_MULT output) into RETURN; ActionDeadCode runs after and frees that varnode via MakeFree. RETURN holds stale free reference.
  - returnValue(): aligned with Ghidra C++ input[1] convention for RETURN (printc.cc:783); input[0]=return-address, input[1]=C return value. Raw p-code (no anchorReturnReg) uses input[0].
  - emitOps: suppress ops whose output is free (MakeFree'd by DeadCode) -- expression still rendered inline at RETURN site.
  - renderReturnValue(): free varnode -> findDefiningOpForFreeVarnode (scan AllOps for non-dead op at same register location, skipping COPY/phi) -> findLiveReturnVarnode fallback.
  - inferReturnType(): same free-varnode recovery for return type (multiply now shows 'unsigned int' not 'void').
  - anchorReturnReg(): fix best-selection when best.Def==nil (was not replaced by later Def!=nil candidate).
  - multiply: 'return param_0 * param_1' (was 'return local_21')
  - add3: 'return param_0 + param_1 + param_2' (correct)
  - classify_sign: correct else-if chain, correct return (was already working)
  - AArch64: 'return;' void (stale LR reference removed)
  - Known mismatch: callee-save STORE artifacts (*(local_N + -4) = local_M) require ActionPrototypeTypes for proper suppression
- [x] AArch64 E2E: Heritage varnode reuse fix + AArch64 calling convention (2026-04-11, commit 31b7898)
  - `pkg/bridge/bridge.go` resolveInput: 읽기 varnodes를 defs map에 저장하지 않음. 동일 레지스터 복수 읽기시 하나의 varnode 객체를 공유하던 버그 수정. Heritage SSA renaming이 각 read를 독립적으로 rename. C++ Ghidra SLEIGH builder와 동일하게 read마다 새 varnode 생성.
  - `pkg/pcode/protomodel.go`: WithRegParams() 메서드 추가 -- regLookup callback 없이 테스트 코드에서 레지스터 ABI 파라미터 오프셋 직접 지정 가능 (X0=16384, X1=16392).
  - `pkg/pcode/scopelocal.go` BuildFromVarnodes: 레지스터 파라미터 분류를 single-pass에서 two-pass로 변경. isinput=true (function live-in) varnode 우선 선택.
  - `pkg/pcode/printc.go` markReturnOnlyCopies: unique-space 소스 + ndesc=0 output인 COPY만 dead-store로 억제. const->register COPY (branch assignment)는 억제하지 않음.
  - `pkg/pcode/printc.go` emitLocalDeclarations: unique-space varnodes 선언 제외 (ops 억제되므로 unreferenced declaration 방지).
  - `pkg/pcode/printc.go` blank line separator: 보이는 (non-unique, non-prologue) local이 있을 때만 빈 줄 출력.
  - `pkg/loader/loader_test.go` TestAARCH64SimpleFunction: WithRegParams 호출 + golden assertions. AArch64 `unsigned long long aarch64_add_ret(unsigned long long param_0, unsigned long long param_1) { return param_0 + param_1; }` Ghidra 출력과 완전 일치.
  - 알려진 미스매치 (pre-existing): multiply `local_0 = param_0` 잉여 assignment, add3 `local_0`/`local_1` 잉여 declarations, classify_sign `0 < param_0` vs Ghidra `param_3 < 1` CFG 순서 차이. 테스트는 통과.

- [x] printc: undefined4 type rendering + uVar1 return-value naming (2026-04-11)
  - TYPE_UNKNOWN now rendered as undefined%d (undefined4/undefined8) instead of unsigned int/unsigned long long. Matches Ghidra's undefined-byte convention for untyped varnodes.
  - renameReturnOnlyLocals(): detects locals whose only non-marker consumers are RETURN ops; renames them using Ghidra's uVar1/iVar1/lVar1 prefix (ActionReturnSplit parity). Declaration type and inferred return type also forced to undefined%d for those locations when the committed type is untyped.
  - inferReturnType(): TYPE_INT/TYPE_FLOAT preserved as-is; only TYPE_UINT/TYPE_UNKNOWN slots converted to undefined%d for return-only locations.
  - BuildFromVarnodes: seeds TYPE_UINT on register-space params so AArch64/x86-64 register parameters continue rendering as unsigned int/unsigned long long.
  - classify_sign golden parity: `undefined4 uVar1;` declaration, `undefined4` return type, `uVar1 = 0/1/0xffffffff` assignments -- matches Ghidra golden exactly except processEntry wrapper (Known Mismatch).
  - Known mismatches (not yet implemented):
    - processEntry wrapper: Ghidra wraps x86 entry functions as `processEntry entry(undefined4 param_1, undefined4 param_2, ...)` with 2 ghost argc/argv params. Requires significant calling-convention changes.
    - x86 return type: multiply/add3 return `undefined4` (Ghidra shows `int` due to processEntry context).

- [x] printc: AArch64 long type + stability fixes (2026-04-11, commit 1e81d5b)
  - scopelocal: register-space params now seeded with TYPE_INT (was TYPE_UINT); AArch64 X0/X1 render as "long param_0, long param_1" matching Ghidra 12 LP64 golden.
  - printc: normalizedBaseType TYPE_INT size=8 -> "long" (was "long long"); LP64 convention: Ghidra uses "long" for 64-bit signed integer on 64-bit targets.
  - typeop: INT_ADD now propagates TYPE_INT input to output; signed-integer arithmetic preserves signedness through ActionInferTypes (C++ parity: TypeOpIntAdd::propagateType).
  - printc: removed renameReturnOnlyLocals from nil-FuncProto path; was non-deterministic due to unordered AllVarnodes() iteration without ABI context.
  - printc: fallback TYPE_UINT for unique-space return varnodes from arithmetic ops when committed type is nil/TYPE_UNKNOWN; fixes flaky undefined4 return type in TestPrintCEndToEnd.
  - AArch64 golden: `long aarch64_add_ret(long param_0, long param_1) { return param_0 + param_1; }` -- type matches Ghidra 12 golden exactly.
  - Known mismatches (not yet implemented):
    - processEntry wrapper: function name and ghost params (param_1/2 -> param_0/1 numbering shift).
    - x86 return type: multiply/add3 return `undefined4` (Ghidra shows `int` due to processEntry context).

- [x] Ghidra Golden 완전 parity: processEntry + 1-indexed params + INT_MULT type inference (2026-04-12)
  - GetParamName: 0-indexed -> 1-indexed (param_0 -> param_1). Ghidra 내부 param 번호는 항상 1-indexed.
  - PrintC.SetProcessEntry(annotation, ghostCount): 함수명 앞에 annotation prefix("processEntry") 추가, ghost params (undefined4 param_1, param_2) 선행 렌더링, real params를 ghostCount+1부터 번호 부여.
  - scopelocal: stack params에도 TYPE_INT seed 추가 (register params와 동일). x86 cdecl stack params default type = signed int.
  - typeop: typeOpIntMult 추가 -- TYPE_INT 양방향 전파 (input->output, output->input). C++ parity: TypeOpIntMult::propagateType.
  - action_infertypes: INT_MULT reverse propagation 추가 -- IMUL output TYPE_INT -> 양쪽 input으로 전파.
  - 결과: multiply `int processEntry entry(undefined4 param_1, undefined4 param_2, int param_3, int param_4)` -- Ghidra golden 완전 일치.
  - 결과: add3 `int processEntry entry(undefined4 param_1, undefined4 param_2, int param_3, int param_4, int param_5)` -- Ghidra golden 완전 일치.
  - 결과: classify_sign `undefined4 processEntry entry(undefined4 param_1, undefined4 param_2, int param_3) { undefined4 uVar1; ... }` -- Ghidra golden 완전 일치.
  - TestX86ClassifySignGoldenProcessEntry, TestX86MultiplyGoldenProcessEntry, TestX86Add3GoldenProcessEntry 추가: 정확한 signature 매칭 검증.
  - 잔여 차이: AArch64 함수명 (aarch64_add_ret vs entry) -- 테스트 설계 차이, 기능 parity에 영향 없음.
  - 잔여 차이: 포맷 (중괄호 위치, 쉼표 뒤 공백) -- C 내용 동일.

- [x] CountedLoop 렌더링 수정 + Heritage/prologueOp 억제 (2026-04-12, commit 817fd16)
  - bridge.go: instructionDefs를 명령어별로 리셋 -- 명령어 간 def 공유로 Heritage가 ECX reads=0 을 보던 버그 수정.
  - heritage.go: MULTIEQUAL output에 SetActiveHeritage() 호출 -- phi varnode가 non-free로 정확히 마킹됨.
  - printc.go markReturnOnlyCopies: inline consumer one-level lookahead -- inline op의 직접 consumer가 RETURN이 아닌 CBRANCH일 때 hasReturnOrInline=true 설정 방지. INT_ADD(ECX, -1)이 prologueOp으로 잘못 마킹되는 버그 수정.
  - printc.go markPhiReturnOnly: 새 pass -- self-loop이거나 모든 non-self consumer가 return-chain transparent인 MULTIEQUAL output을 prologueVarnode로 마킹 (ESP/EIP loop phi가 여분 local 선언으로 나타나는 문제 억제).
  - printc.go renderOpExprFrag INT_ADD: inline INT_2COMP input을 뺄셈으로 fold -- `local_0 + -1` -> `local_0 - 1`. C++ cleanup-phase Rule2Comp2Sub 동작을 렌더링 시점에 미러링.
  - TestX86CountedLoop: `do { local_0 = local_0 - 1; } while (local_0 != 0);` 정상 출력.
  - go test ./... 전체 통과.

- [x] F12: MSVC rule parity fixes -- RulePropagateCopy + RuleEqual2Zero + RuleLessEqual (2026-04-12)
  - **RulePropagateCopy** (rules_copy.go): C++ parity 두 가지 추가.
    - 상수 guard: MULTIEQUAL/INDIRECT 입력으로 상수를 전파하지 않음 (C++ ruleaction.cc:3966).
    - addr-tied guard: register/stack space varnode를 다른 위치의 MULTIEQUAL output으로 전파하지 않음 (C++ parity: Varnode::addrtied check). `isEffectivelyAddrTied()` 헬퍼 추가.
    - 효과: Classify2 empty-if-body 버그 수정 (constants was being propagated into MULTIEQUAL); AbsVal empty-else 수정.
  - **RuleEqual2Zero** (rules_bool.go): INT_ADD(a, INT_MULT(b, -1)) == 0 -> a == b 패턴 추가.
    - RuleSub2Add가 INT_SUB(a,b)를 INT_ADD(a, INT_MULT(b, 0xFFFFFFFF))로 변환한 후 RuleEqual2Zero가 이를 a == b로 정규화해야 함. Go 버전은 XOR 패턴만 처리했었음.
    - C++ parity: ruleaction.cc:5868 RuleEqual2Zero::applyOp 전체 구현.
    - INT_ADD(a, const_c) == 0 -> a == -c 패턴도 추가.
    - 효과: Classify2 `param_4 == param_3` 비교가 올바르게 렌더링됨.
  - **RuleLessEqual** (rules_misc.go): BOOL_OR 기반으로 완전 재구현.
    - 기존 구현: INT_LESSEQUAL/INT_SLESSEQUAL 기반, 상수 극단값 처리만 하던 잘못된 버전.
    - 새 구현: CPUI_BOOL_OR에서 발화, BOOL_OR(INT_SLESS(a,b), INT_EQUAL(a,b)) -> INT_SLESSEQUAL(a,b) 변환. C++ parity: ruleaction.cc:2256 RuleLessEqual::applyOp.
    - batchARuleFactories에 추가 (기존에는 batchCMiscRuleFactories에만 있었고 파이프라인에서 실행되지 않음).
    - 효과: Classify2 `param_3 <= 0` 정상 출력 (기존: `param_3 == 0 || param_3 < 0`).
  - TestMSVC_AbsVal: `if (param_3 < 0) { local_0 = -param_3; } else { local_0 = param_3; }` -- 정상.
  - TestMSVC_Classify2: `if (param_3 <= 0) { ... } else if (param_3 < param_4) { ... }` -- 논리적으로 정확. 구조적 미스매치: 조건 inversion (Ghidra는 param_4 <= param_3 선호 가능).
  - TestMSVC_CountedLoop/SumList: stack local 렌더링 미해결 -- `*(local_0 - 8) = 0` 형태. Stack Heritage 부재로 STORE-to-local이 변수 할당으로 변환되지 않음. 기능적으로 올바르나 Ghidra golden과 다름.

- [x] G1: Stack Heritage -- STORE to named local (2026-04-13)
  - **ActionStackPtrFlow** (action_stack_ptr_flow.go): STORE(ram, INT_ADD(FP,const), val) 패턴 감지 후 stack-space varnode COPY로 변환. LOAD(FP+offset)도 stack input varnode로 변환.
  - **Heritage** (heritage.go): HeritageRange()로 슬롯별 SSA Heritage 실행. MULTIEQUAL phi node 생성.
  - **MergeMarker 2회**: BatchA RulePropagateCopy가 MULTIEQUAL inputs를 unique varnode로 교체 후 2차 MergeMarker로 HighVariable 재연결.
  - **PrintC** (printc.go):
    - unique MULTIEQUAL-input op을 suppress하지 않고 MULTIEQUAL output 이름으로 emit (local_c = ...).
    - collectSymbols: unique varnode가 MULTIEQUAL sole input이면 MULTIEQUAL output(stack-space)을 locals 대표로 등록.
    - isReturnOnlyVarnode: inline consumer가 COPY->MULTIEQUAL 체인으로 이어지면 return-only 아님.
    - markPhiReturnOnly: inline consumer의 1-level lookahead에서 COPY 등 non-RETURN을 만나면 allTransparent=false.
  - **ScopeLocal** (scopelocal.go): Ghidra hex-offset 스타일 이름 (`local_c`, `local_8` 등). `localHexName()` 함수 추가.
  - **MergeMarker** (merge.go): mergeTestRequired() nil guard 추가.
  - 결과:
    - CountedLoop: `local_c = 0; while (local_8 < 5) { local_c = local_c + local_8; local_8 = local_8 + 1; } return local_c;`
    - SumList: `local_8 = 0; while (param_3 != 0) { ... }` 형태 (stack local 올바름).
  - go test ./... 전체 통과.

- [x] G2: ActionForLoops -- while-with-increment to for loop (2026-04-13)
  - collapse.go에 BlockForDo 타입 추가, ActionForLoops 액션 구현.
  - while body 마지막 op이 condition varnode에 쓰는 단순 할당이면 for increment로 올림.
  - printc.go에 BlockForDoType case + emitForBlock 렌더링 추가.
  - 결과: CountedLoop `for (local_8 = 0; local_8 < 5; local_8 = local_8 + 1)` v
  - 결과: SumList `for (; param_3 != 0; param_3 = *(param_3 + 4))` v

- [x] G3: ghost params 억제 (2026-04-13)
  - scopelocal.go BuildFromVarnodes: 실제 args가 없으면 (stack param 없으면) param list를 비워 `(void)` 출력.
  - 결과: CountedLoop `entry(void)` v

- [x] Type inference 수정 -- undefined4 vs unsigned int (2026-04-13)
  - action_infertypes.go propagateOneType: 상수 varnode는 forward 전파 생략.
    상수의 TYPE_UINT가 accumulator/counter 변수를 오염시키던 문제 해결.
  - action_seed_signed.go: INT_SLESS/SLESSEQUAL 제거. C++ parity: TypeOpIntSless::propagateType은 nullptr 반환.
    stack params는 BuildFromVarnodes에서 TYPE_INT로 초기화됨으로 충분.
  - 결과: CountedLoop `undefined4 local_c; undefined4 local_8;` v
  - 결과: Classify2 `int param_3, int param_4` v (BuildFromVarnodes에서 타입 부여)

- [x] G7: SLESSEQUAL 정규화 + CDECL int return 기본값 (2026-04-13)
  - RuleSLessEqual2Constant: INT_SLESSEQUAL(x, C) -> INT_SLESS(x, C+1) 규칙 추가 (rules_misc.go, batchARuleFactories에 등록).
  - printc.go inferReturnType: 4바이트 TYPE_UNKNOWN return을 arithmetic ancestor check 후 int로 기본값 설정.
  - hasArithmeticAncestor(): def chain을 4레벨 탐색해 연산 결과면 int, 상수 선택이면 undefined4.
  - 결과: Classify2 `if (param_3 < 1)` v, CountedLoop/SumList `int` return v
- [x] G5: AbsVal param 직접 수정 패턴 (2026-04-12)
  - isReturnOnlyVarnode: MULTIEQUAL 투과 탐지 (phi output이 RETURN만 소비하면 true).
  - renameReturnOnlyLocals: phi 입력이 param의 identity COPY면 carrier를 param으로 rename.
  - finalizeReturnCarrierRenames: renderFunctionSignature 이후 ghost offset 반영.
  - isBlockEmpty + empty else skip: identity COPY 제거 후 빈 else 분기 렌더링 억제.
  - identityOps: param-to-carrier COPY를 suppress. emitLocalDeclarations: param name 중복 선언 skip.
  - 결과: AbsVal `if (param_3 < 0) { param_3 = -param_3; } return param_3;` v (else/local 없음)
- [x] G6: uVar1 rename (Classify2/nested_if) (2026-04-12)
  - isReturnOnlyVarnode: MULTIEQUAL 투과 탐지 (phi 입력이 RETURN-feeding phi 거치면 return-only로 인식).
  - renameReturnOnlyLocals 확장: MULTIEQUAL output도 keyName 위치에 rename.
  - 결과: Classify2 `undefined4 uVar1; if (...) { uVar1 = 0; } ... return uVar1;` v

- [x] G4: pointer type inference (`int *param_3`) (2026-04-13)
  - seedLoadPointers(): ActionInferTypes.Apply 시작 전 pre-pass. LOAD op의 address input(1)에 `int *` 타입 직접 설정. C++ parity: TypeOpLoad::getInputLocal.
  - 타입 전파 cascade: param3_phi(int*) -> LOAD output(int) -> INT_ADD(int) -> local_8(int).
  - tryRenderSubscript(): renderLoad에서 LOAD[INT_ADD(ptr, const)] 패턴 감지, ptr이 pointer type이면 `ptr[index]` subscript 표기.
  - nullPtrCastStr(): renderBinary에서 pointer vs constant-0 비교 시 `(int *)0x0` cast 삽입.
  - effectiveLoadResultType() + assignCastStr(): COPY output이 pointer이고 source가 LOAD(int)이면 `(int *)` cast 삽입.
  - 결과: SumList golden 완전 일치. go test ./... all PASS.

- [x] Full golden test coverage: 6502 NOP(0xEA)/LDA(0xA9)/BRK TestGolden6502 pass (2026-04-13)

### 미시작 (우선순위 순)

- [x] H1: Ghidra format matching + auto golden assertions (2026-04-13, commit 0f6d8c4)
- [x] H1-fix: CountedLoop regression + anchorReturnReg per-RETURN selection (2026-04-13)
  - 현상: Heritage task split (gcd RuleSignForm 지원)이 phi_eax_4b_out(Block 2 loop-header)을 anchorReturnReg에 의해 RETURN input으로 wired → DeadCode가 phi 제거 불가 → EAX_vn2.NumDescend=2 → shouldInline 실패 → `local_0 = local_8 + 1; local_8 = local_0` (got) vs `local_8 = local_8 + 1` (want).
  - 수정: `anchorReturnReg` 전략을 global-best → per-RETURN 선택으로 교체. Pass 1: RETURN op와 같은 블록의 varnode 중 최신 SeqNum 선택. Pass 2: 전체 candidates 중 최신 SeqNum fallback.
  - 같은 블록 우선 이유: Block 4(exit)의 `EAX_ret=LOAD[EBP-8]`이 RETURN과 같은 블록 → 정확히 live. Loop-header phi는 다른 블록이므로 제외됨.
  - 부수 수정: Pass 1 내 "break at first same-block"을 "latest SeqNum in same block"으로 교체 -- multiply 함수에서 EAX_1(MOV)과 EAX_2(IMUL)이 모두 Block 0에 있을 때 EAX_2가 선택되어야 하기 때문.
  - 수정 파일: `pkg/pcode/funcproto.go:anchorReturnReg`
  - debug 아티팩트 제거: `cmd/gcd_debug/`, `pkg/pcode/gcd_rule_test.go`, `pkg/loader/heritage_debug_test.go`
  - 성공 기준: TestMSVC_CountedLoop, TestMSVC_SumList, TestMSVC_AbsVal, TestMSVC_Classify2, TestMSVC_Gcd_Diag, TestX86MultiplyGoldenProcessEntry 전부 PASS; go test ./... 전체 통과.
  - 현상: Gosleigh PrintC output format != Ghidra golden (4-space indent vs flat, BSD brace vs K&R+blank, ", " vs ",", `} else if` vs `}\nelse if`). TestMSVC_* tests have no assertions -- golden diff not auto-detected.
  - C++ ref: printc.cc PrintC::docFunction() (K&R function brace), printc.cc emitBlockBraces (no indent), parameterList comma format
  - 수정 대상: pkg/pcode/printc.go, pkg/pcode/printc_decl.go, pkg/pcode/emitter.go, pkg/pcode/printlanguage.go, pkg/loader/msvc_diag_test.go
  - 구현 방향: PrintC.SetGhidraFormat() -- zero indent, K&R+blank function brace, no-comma-space, `}\nelse if` style. Load testdata/ghidra_golden/ghidra_golden.json in TestMSVC_* and assert content match (whitespace-normalized). Update TestX86*GoldenProcessEntry accordingly.
  - 성공 기준: TestMSVC_CountedLoop/SumList/AbsVal/Classify2 each assert content-match against ghidra_golden.json entry

- [x] H2: Heritage CALL guard infrastructure (INDIRECT at CALL sites) (2026-04-13, commit 744b17f)
  - EffectKind/KilledByCallOffsets/UnaffectedOffsets + WithEffectOffsets (protomodel.go)
  - NewIndirectOp / NewIndirectCreation (funcdata.go)
  - WithProtoModel / guardCalls -- CALL op마다 register range별 INDIRECT 삽입 (heritage.go)
  - 파이프라인 wiring: Heritage 전에 WithEffectOffsets + WithProtoModel (msvc_diag_test.go)
  - C++ parity: heritage.cc:1443-1527 guardCalls, funcdata_op.cc:683-728 newIndirectOp/newIndirectCreation

- [x] H3: ActionAssignHigh (2026-04-13)
  - ensureHighForVarnode + assignInitialHighVariables: 각 non-free/non-constant varnode에 HighVariable 할당
  - data.SetFlag(FuncHighLevelOn) 설정
  - pkg/pcode/action_assignhigh.go 신규
  - C++ parity: coreaction.cc ActionAssignHigh::apply()

- [x] H5/H6: ActionMergeRequired + ActionMarkExplicit + ActionMarkImplied + ActionMergeCopy (2026-04-13)
  - MergeRequired: MULTIEQUAL/INDIRECT inputs/outputs를 공유 HighVariable로 병합 (merge.go)
  - MarkExplicit: high.NumInstances() > 1이면 explicit 마킹 (action_mark.go)
  - MarkImplied: Cover intersection 통과 시 implied 마킹 (action_mark.go)
  - MergeCopy: COPY output/input HighVariable 병합 -- return-carrier EAX를 param HV로 흡수 (merge.go)
  - printc.go 2개 수정: seenHV 미명명 HV 우회 + seenParamHV/seenHV 분리 + IsInput() 조건
  - 전체 golden 4개 통과: AbsVal, Classify2, CountedLoop, SumList
  - C++ parity: coreaction.cc ActionMergeRequired/MarkExplicit/MarkImplied/MergeCopy::apply()

- [x] H4: ActionNameVars (2026-04-13)
  - action_name_vars.go 신규: 미명명 register-space HV에 iVar1/uVar1 등 자동 명명
  - 두 단계 수집: bestVn 선택 (non-unique, non-input 우선), offset+createIndex 정렬 후 할당
  - gcd_diag Ghidra format 출력에서 iVar1 확인 (H4 성공 기준 충족)
  - AbsVal/Classify2 golden uVar1 유지, CountedLoop/SumList local_hex 유지 -- 모든 기존 테스트 통과
  - C++ parity: coreaction.cc ActionNameVars::apply(), database.cc ScopeInternal::assignDefaultNames()
  - 주의: guardCalls는 register space만 처리 (stack side-effect는 별도). non-leaf function golden 미추가 (H3 대상)

