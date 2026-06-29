# 프로젝트 상태

## 현재 상태 (2026-06-29 세션 종료, master `10fdf39`)

**전 패키지 그린** (loader/pcode/sla/bridge). 이번 세션: **H9 ActionSetCasts 정식 배선
완료** -- 분석-time CPUI_CAST 삽입이 bridge.Decompile에서 라이브. PTRADD 형성 블로커를
런타임 프로브로 진단/해결(ActionStartTypes 미배선 -> 배선, RulePtrArith 재발화, PrintC
PTRADD subscript 렌더, read-facing 갭 castStandardRead 보정). 전 MSVC 골든 통과.
상세는 "다음 작업" + CHANGELOG. 이전 성과:

1. **H8 gcd_x86_32 golden parity 완료** -- TestMSVC_Gcd PASS. gcd가 Ghidra golden과
   완전 일치: `while (iVar1 = param_4, iVar1 != 0) { param_4 = param_3 % iVar1; param_3 = iVar1; }`.
   근본 5수정 (RulePropagateCopy addr-tied guard / RuleMultiCollapse self-ref + OpDestroy
   dead-flag / **CoverBlock.Empty** / ActionNameVars explicit-unique + allocateCopyTrim 타입 /
   TrimJoinblockMultiequals unique-output 게이트 + printc explicit-unique 선언). 상세는 CHANGELOG.
2. **프로덕션 디컴파일 진입점 `bridge.Decompile`** 추출 (H8-debt-2 부분 완료). 골든 파이프라인이
   테스트 헬퍼가 아니라 프로덕션 함수에 단일 소스화됨.
3. **H9 CastStrategy 프리미티브 포팅+배선+검증** -- `CastStrategyC.CastStandard` +
   `IsSubpieceCast`/`IsSextCast`/`IsZextCast` (cast.go, 단위 테스트). render-time 캐스트
   판정 4종(assignCastStr / SUBPIECE / SEXT / ZEXT)을 C++ 충실 CastStrategy로 교체.

### 완료: H9 ActionSetCasts 정식 배선 (`432b30e`~`58693bc`)

분석-time CPUI_CAST 삽입이 bridge.Decompile에서 라이브, 전 골든 그린. 인프라(입력/출력
타입 + int-promotion + arithmeticOutputStandard) + 본체(Apply/castInput/castOutput) +
배선. 해결한 블로커: ActionStartTypes 미배선(typeRec 영구 false), PrintC PTRADD subscript
렌더, read-facing 갭 castStandardRead. 상세는 CHANGELOG 2026-06-29.

### 다음 작업 (우선순위)

1. **[중] H9 잔여 -- assignCastStr 전면 제거**. 현재 hybrid: 정상 op은 ActionSetCasts 실제
   CAST, NonPrinting for-loop iterate/init op만 render-time `assignCastStr`(printc.go) 잔여
   fallback. 출력은 이미 전 골든 정확이라 **출력 개선 목적 아님, 메커니즘 parity 목적**.
   - **막힌 이유 (이번 세션 2접근 실험으로 확정)**: (1) ActionSetCasts를 ForLoops 앞으로
     옮기면 삽입 CAST가 for-detection(tryMarkForLoop/findLoopVariable/testIterateForm)을
     교란 -> while+comma. (2) NonPrinting op에 castInput만 수행하면 proper for-loop은 되나
     sum_list for-iterate 캐스트는 LOAD **출력** 캐스트라 castInput으로 못 잡음(누락).
     근본: for-iterate 캐스트가 출력 캐스트 -> loop변수=op출력과 충돌.
   - **선행 필요**: ActionSetCasts를 ForLoops **앞**에 배치 + for-detector를 cast-aware로
     (findLoopVariable/testIterateForm/SetForLoop이 CAST 체인을 iterate로 인식 + for-header가
     CAST 포함 렌더). C++ 순서(ActionSetCasts -> 그 다음 printing 단계의 for-fold)와 일치시킴.
   - 수정 대상: bridge/decompile.go(순서), action_forloops.go(cast-aware), printc.go(assignCastStr 제거).
   - 성공 기준: 전 MSVC 골든 유지하며 printc.go assignCastStr 제거.

2. **[대형] H7 ActionPrototypeTypes 배선** -- **단순 배선 아님(이번 세션 재분류)**.
   ActionPrototypeTypes.Apply는 `fp.IsOutputLocked()`에서만 RETURN 반환 배선(coreaction.go:802).
   anchorReturnReg는 lock 없이 EAX->RETURN 휴리스틱. 선행: ActionOutputPrototype/ReturnRecovery
   (K1에서 구현됨)로 output 타입+lock 설정 -> ActionPrototypeTypes 배선 -> anchorReturnReg
   (paramactive.go/printc.go 12+참조) 제거. 미시작 H7 상세 참조.

3. **[대형, 대안] H8-debt-2 reconcile** -- bridge.Decompile 손정렬 subset을 프로덕션
   `BuildUniversalAction`(universalAction 충실 포팅)과 통합. **H8-debt-1** 스냅샷 판별자 원리화.

4. **H9 미포팅 잔여(저우선)**: SUBPIECE getOutputToken(findTruncation, 전용 struct)/PTRSUB
   getOutputToken(downChain)/union resolution/testStructOffset0/markExplicitUnsigned·LongSize/
   typeOrder(Equal-NotEqual·arithmeticOutputStandard 단순화 중). 현재 render-time이 커버.

세션 상세 이력: `docs/CHANGELOG.md` (2026-06-29 항목).

## 작업 방향 (2026-04-13 확정)

golden diff 맞추기 목표를 폐기. 대신: **C++ actmainloop 순서대로 각 패스를 알고리즘 레벨에서 충실히 구현**. golden test는 검증 수단이지 목표가 아님. 각 패스 구현 시 C++ 코드 먼저 읽고 이해 후 Go로 포팅.

---

### 미시작 -- actmainloop 순서 기반 foundational 패스

**NOTE**: 아래 항목들은 golden match가 아니라 C++ 알고리즘 충실 구현이 성공 기준. 각 항목 완료 후 `go test ./...` 기존 테스트 통과 여부로 regression 확인.

- [ ] H7: ActionPrototypeTypes 정식 배선 -- 함수 반환형/인자형 결정
  - 역할: 함수 프로토타입(반환형, 인자 타입)을 Heritage 전에 확정. `ActionPrototypeTypes`는
    이미 구현됨(coreaction.go:778, stub 아님)이나 골든 파이프라인(`bridge.Decompile`)이 이를
    호출하지 않고 `anchorReturnReg` 휴리스틱(paramactive.go)을 씀. gcd는 이미 `void`로 통과.
  - **2026-06-29 조사**: ActionPrototypeTypes.Apply는 `fp.IsOutputLocked()`일 때만 RETURN에
    반환 레지스터 varnode를 input으로 배선(coreaction.go:802-821). anchorReturnReg는 lock
    없이 EAX->RETURN을 휴리스틱으로 배선. 따라서 **단순 배선 불가**: ActionPrototypeTypes를
    그냥 추가하면 (a) output unlocked인 함수(대부분)는 반환 미배선 -> 회귀, (b) anchorReturnReg와
    동시 적용 시 RETURN input[1] 이중 배선. **선행 필요**: prototype-recovery 체인
    (ActionOutputPrototype/ActionReturnRecovery)이 output 타입+lock을 설정해야 ActionPrototypeTypes가
    배선 가능. 그 후 anchorReturnReg 제거. = 대형 작업(단순 배선 아님).
  - C++ 참조: `coreaction.cc ActionPrototypeTypes::apply()` + `ActionOutputPrototype` +
    `funcdata.cc Funcdata::startProcessing()`. printc.go의 anchorReturnReg 의존(RETURN
    input[1] 렌더, 12+ 참조)도 함께 제거 필요.
  - 수정 대상: `pkg/bridge/decompile.go`(프로토타입 복구 체인 + ActionPrototypeTypes 배선),
    `pkg/pcode/funcproto.go`/`paramactive.go`/`printc.go`의 anchorReturnReg 의존 제거.
  - 성공 기준: 전 골든 PASS 유지하며 anchorReturnReg 휴리스틱 제거.

- [x] H8: gcd_x86_32 golden parity **완료 (2026-06-29)**. TestMSVC_Gcd PASS.

- [ ] H8-debt-1: 스냅샷 발화 판별자를 원리적으로 교체
  - 현상: `Merge.TrimJoinblockMultiequals`가 unique-output phi에만 발화하는 휴리스틱.
    cover 교차로는 gcd(swap, temp 필요) vs SumList(self-update, for-loop)를 구분 못 함
    (둘 다 level 2). 현재는 출력 varnode의 unique-vs-addrtied로 우회.
  - C++ 참조: `block.cc BlockWhileDo::finalizePrinting` (for-loop 유효성),
    `merge.cc Merge::eliminateIntersect` (copyShadow/boundtype 필터)
  - 수정 대상: `pkg/pcode/merge.go` TrimJoinblockMultiequals 발화 조건
  - 성공 기준: loop phi 간 cyclic/swap (lost-copy) 의존성 기반 판정; gcd/SumList/
    CountedLoop 전부 PASS 유지하며 휴리스틱 주석 제거.

- [~] H8-debt-2: golden 파이프라인 프로덕션화 -- **부분 완료 (2026-06-29, `5a39f6c`)**
  - 완료: 골든 파이프라인을 `bridge.Decompile(engine, result, DecompileConfig)` 프로덕션
    함수로 추출. `runPipelineGhidra`는 bridge.Build + bridge.Decompile 호출만. 전 골든 PASS.
  - 남은 것: `bridge.Decompile`의 손정렬 action subset을 프로덕션 `BuildUniversalAction`
    (coreaction.cc ActionDatabase::universalAction 충실 포팅)과 reconcile -> 단일 정식
    actmainloop 트리로 통합. universalAction 내 미완 action들이 완성돼야 가능.
  - 참고: 진단용 `runPipeline`(비골든 변형)은 아직 손조립 + dumpSSA 유지.

- [~] H9: ActionSetCasts -- 타입 캐스트 삽입 (**대형 다중 세션 포팅**, 프리미티브 완료)
  - 역할: 타입 불일치 지점에 명시적 `CPUI_CAST` op 삽입 (현재는 render-time
    `assignCastStr` 근사 + `ActionSetCasts` no-op stub).
  - 컴포넌트:
    1. `CastStrategy::castStandard` (C 전략) -- **완료 `f545917` + 배선 `64e8c90`**
       (`pkg/pcode/cast.go` `CastStrategyC.CastStandard` + 단위 테스트). printc
       `assignCastStr`의 COPY/LOAD 캐스트 판정에 배선됨(실사용).
    2. 전 opcode의 `getInputCast`/`inputTypeLocal` (TypeOp별) -- **완료 `432b30e`**
       (typeop_cast.go + cast.go int-promotion). TypeOp 인터페이스에 `InputTypeLocal`/
       `GetInputCast` 추가, opInputMeta 테이블(per-opcode metain), 충실 오버라이드
       (Copy/Load/Store/Zext/Sext/comparison/Ptradd/Ptrsub). int-promotion 머신리
       (intPromotionType/localExtensionType/checkIntPromotionFor*) 포팅. 단위 테스트.
       남은 출력측 `getOutputToken`/`outputTypeLocal`는 castOutput과 함께 다음 체크포인트.
    3. CastStrategy 나머지:
       - `IsSubpieceCast`/`IsSextCast`/`IsZextCast` -- **완료 `7c350d3`+`3b64207`**
         (cast.go, 단위 테스트). 셋 다 PrintC 렌더링에 배선+검증됨:
         SUBPIECE offset0 정수 truncation -> `(int)x` (`TestPrintCSubpieceCast`);
         SEXT/ZEXT는 natural일 때만 cast, 아니면 SEXT()/ZEXT() (`TestPrintCZextNotCast`).
         SUBPIECE는 little-endian 가정(isSubpieceCastEndian 미구현).
       - 미구현: markExplicitUnsigned/LongSize, arithmeticOutputStandard.
    4. ActionSetCasts apply/castInput/castOutput/resolveUnion/checkPointerIssues/
       insertPtrsubZero + PTRSUB/PTRADD 재작성 + updateType/getHighTypeReadFacing/
       inheritResolution(resolution 머신리).
  - C++ 참조: `cast.cc`, `coreaction.cc ActionSetCasts::apply` (2724+), `typeop.cc`
    각 TypeOp::getInputCast.
  - 렌더링: PrintC는 이미 CPUI_CAST 처리(renderCast) -> 삽입만 하면 됨.
  - 주의: ActionSetCasts가 CAST op을 넣으면 기존 `assignCastStr` 문자열 캐스트와 **이중 캐스트**
    충돌. driver 배선 시 assignCastStr를 동시에 걷어내야 함.
  - 성공 기준: 기존 캐스트 golden (sum_list `(int *)`, complex_max `(int)`) 유지하며
    assignCastStr 의존 제거.

### 기타 미시작 (참고)
- H9 외: struct/union 타입 복구, switch statement, 6502 NOP/LDA/BNE 등 대부분 opcode
  resolution (PARITY_AUDIT.md 참조), BatchC rules 품질.

### 진단 도구
- `pkg/loader/msvc_diag_test.go` `dumpSSA`/`vnStr` (GCD_DUMP=1 env 가드, 평상시 무음) --
  SSA op 스트림 블록별 덤프. H-work 디버깅용 유지.
