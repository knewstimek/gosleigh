# 프로젝트 상태

## 현재 상태 (2026-06-29 세션 종료, master `483d3f9`)

**전 패키지 그린** (loader/pcode/sla/bridge). 이번 세션: H9 ActionSetCasts driver
인프라(입력/출력 타입 + int-promotion) + 본체(Apply/castInput/castOutput) 포팅 완료,
배선은 PTRADD 형성 블로커로 보류(경험적 입증). 상세는 위 "다음 작업 1" + CHANGELOG. 이전 성과:

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

### 다음 작업 (우선순위)

1. **[대형, 전용 세션] H9 ActionSetCasts driver** -- 분석-time `CPUI_CAST` 삽입.
   **인프라+본체 완료, 배선 블록됨 (`432b30e`/`705d5eb`/`483d3f9`)**:
   - 입력/출력 타입 인프라(getInputCast/inputTypeLocal/getOutputToken/outputTypeLocal) +
     int-promotion + arithmeticOutputStandard 포팅. ActionSetCasts.Apply/castInput/
     castOutput 본체 구현. 격리 테스트 PASS.
   - **배선 블로커 (경험적 입증, `483d3f9`)**: bridge.Decompile에 배선 시 sum_list/
     counted_loop 회귀. Gosleigh는 포인터 산술을 INT_ADD로 유지+render-time
     tryRenderSubscript로 `ptr[index]` 합성하는데, base getInputCast(INT_ADD)가 포인터
     피연산자를 `(int)`로 캐스트해 subscript 파괴. Ghidra는 PTRADD라 no-cast.
   - **선행 필요**: 최종 InferTypes 후 PTRADD 형성(RulePtrArith 재발화) -> PrintC가
     PTRADD를 subscript로 렌더 -> 그 위에 ActionSetCasts 배선 + render-time assignCastStr/
     isSubpieceCast/nullPtrCastStr 제거 + renderCast 동일 출력 검증. parity상 INT_ADD
     포인터 캐스트 억제 hack 금지.
   - 미포팅 잔여: SUBPIECE getOutputToken(findTruncation)/PTRSUB getOutputToken(downChain)/
     union resolution/testStructOffset0/markExplicit*.
2. **[대안] H8-debt-2 reconcile** -- `bridge.Decompile` 손정렬 subset을 프로덕션
   `BuildUniversalAction`과 통합 (universalAction 내 미완 action 완성 필요).
3. **[대안] H8-debt-1** 스냅샷 판별자 원리화, **H7** ActionPrototypeTypes 배선.

세션 상세 이력: `docs/CHANGELOG.md` (2026-06-29 항목).

## 작업 방향 (2026-04-13 확정)

golden diff 맞추기 목표를 폐기. 대신: **C++ actmainloop 순서대로 각 패스를 알고리즘 레벨에서 충실히 구현**. golden test는 검증 수단이지 목표가 아님. 각 패스 구현 시 C++ 코드 먼저 읽고 이해 후 Go로 포팅.

---

### 미시작 -- actmainloop 순서 기반 foundational 패스

**NOTE**: 아래 항목들은 golden match가 아니라 C++ 알고리즘 충실 구현이 성공 기준. 각 항목 완료 후 `go test ./...` 기존 테스트 통과 여부로 regression 확인.

- [ ] H7: ActionPrototypeTypes 정식 배선 -- 함수 반환형/인자형 결정
  - 역할: 함수 프로토타입(반환형, 인자 타입)을 Heritage 전에 확정. `ActionPrototypeTypes`는
    이미 구현됨(coreaction.go, stub 아님)이나 골든 파이프라인(`bridge.Decompile`)이 이를
    호출하지 않고 `anchorReturnReg` 휴리스틱(paramactive.go)을 씀. gcd는 이미 `void`로 통과.
  - C++ 참조: `coreaction.cc ActionPrototypeTypes::apply()`, `funcdata.cc Funcdata::startProcessing()`
  - 수정 대상: `pkg/bridge/decompile.go` 파이프라인에 ActionPrototypeTypes 배선,
    `pkg/pcode/funcproto.go`/`printc.go`의 anchorReturnReg 의존 제거.
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
