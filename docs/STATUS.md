# 프로젝트 상태

## 현재 상태 (2026-06-29 세션 종료, master `513903f`+)

**전 패키지 그린** (loader/pcode/sla/bridge). 이번 세션: **H9 assignCastStr 전면 제거
완료** -- render-time 캐스트 fallback을 모두 걷어내고 메커니즘 parity 달성. ActionForLoops를
ActionSetCasts **뒤**로 재배치(C++ 순서: 분석-time cast -> print-time for-fold). 재배치
블로커(SetCasts가 loop phi MULTIEQUAL에 castOutput을 걸어 출력을 High 없는 unique로 split
-> for-detection 실패)를 런타임 op 덤프로 진단, castOutput에서 marker skip으로 해결.
printc.go assignCastStr/effectiveLoadResultType 삭제(-116줄). 전 MSVC 골든 통과.
상세는 CHANGELOG 2026-06-29. 이전 성과:

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

1. **[완료] H9 잔여 -- assignCastStr 전면 제거** (2026-06-29). ActionForLoops를 ActionSetCasts
   뒤로 재배치, castOutput marker-skip으로 loop phi split 방지, printc.go assignCastStr/
   effectiveLoadResultType 삭제. 전 골든 그린. 상세 CHANGELOG.
   - **잔여 부채(저우선)**: castOutput marker-skip은 C++ `tokenct==outHighType` short-circuit
     (coreaction.cc:2546)의 등가 대체. 더 충실하려면 InferTypes가 phi 출력 high에 포인터
     타입을 전파하지 않도록(Ghidra는 unknown 유지) 하는 편이나, broad type-prop 변경이라
     보류. 현재 marker-skip은 전 골든에서 출력 정확.

2. **[대형] H7 ActionPrototypeTypes 배선** -- **consume-bit DeadCode 선행(2026-06-29 진단 확정)**.
   anchorReturnReg의 본질은 return-reg 쓰기를 DeadCode prune로부터 보존하는 것(끄면 전 non-void
   골든이 void 붕괴, 실험 측정). C++는 consume-bit 전파(gatherConsumedReturn + getActiveOutput
   + pre-live register)로 보존하나, Gosleigh DeadCode는 descendant-count 기반이라 그 분석 부재.
   선행 = consume-based ActionDeadCode 전체 포팅(다세션, 고위험). ReturnRecovery/OutputPrototype/
   PrototypeTypes 본체는 이미 구현, 배선만 남았으나 선행 없이는 무의미. 미시작 H7 상세 참조.

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
  - **2026-06-29 진단 (실험 측정)**: anchorReturnReg를 끄면(GOSL_NO_ANCHOR 실험) 전 non-void
    골든이 void로 붕괴 -- DeadCode가 return-reg(EAX) 쓰기를 prune해 계산 본체까지 소멸
    (abs_val -> `if (param_3 < 0) {}` 빈 몸체). 즉 anchorReturnReg의 본질은 **return-reg 쓰기를
    DeadCode로부터 보존**하는 것.
  - **C++ 보존 메커니즘**(coreaction.cc ActionDeadCode::apply 3936 + gatherConsumedReturn 3882):
    (1) "pre-live registers"(3960) -- register space가 아직 heritage 안된(deadRemovalAllowed
    false) 동안 register varnode 전체를 consumed로 마킹해 보존. (2) `gatherConsumedReturn`이
    `isOutputLocked() || getActiveOutput()!=NULL`이면 RETURN input을 `~0`(전체 consumed)로
    seed -> 보존. getActiveOutput()은 ActionReturnRecovery가 일찍 SetActiveOutput으로 설정
    (Gosleigh coreaction.go:1158에 이미 존재). 즉 C++는 consume-bit 전파 분석으로 return값을
    살린다.
  - **진짜 블로커 = consume-bit DeadCode 부재**: Gosleigh ActionDeadCode(action_deadcode.go)는
    descendant-count(NumDescend==0) 기반 단순 제거이지 C++의 consume-bit 분석(pushConsumed/
    propagateConsumed ~40 opcode + gatherConsumedReturn + pre-live register + markConsumedParameters
    + deadRemovalAllowed/heritage-pass 게이트 + autoLive)이 아님. **선행 = consume-based
    ActionDeadCode 서브시스템 전체 포팅** (그 자체로 다세션, 전 함수 dead-code 동작 변경 -> 고위험).
    이게 되기 전엔 anchorReturnReg가 그 역할을 대신하므로 유지. ActionReturnRecovery/
    OutputPrototype/PrototypeTypes 본체는 이미 구현(K1)되어 배선만 남았으나, 배선해도 선행
    DeadCode가 return값을 못 살려 무의미.
  - C++ 참조: `coreaction.cc ActionDeadCode::apply`(3936)/`gatherConsumedReturn`(3882)/
    `propagateConsumed`(3580)/`markConsumedParameters`(3851) + `ActionPrototypeTypes::apply` +
    `ActionReturnRecovery`/`ActionActiveReturn`. printc.go anchorReturnReg 의존(12+ 참조)도 동반 제거.
  - 수정 대상(순서): (1) `pkg/pcode/action_deadcode.go` consume-bit 포팅, (2) `decompile.go`
    ActiveReturn/ReturnRecovery/OutputPrototype/PrototypeTypes 배선, (3) anchorReturnReg/
    stripReturnIndirectRef 제거, (4) printc.go RETURN 렌더 정리.
  - 성공 기준: 전 골든 PASS 유지하며 anchorReturnReg 휴리스틱 + consume-bit DeadCode 라이브.

- [x] H8: gcd_x86_32 golden parity **완료 (2026-06-29)**. TestMSVC_Gcd PASS.

- [ ] H8-debt-1: 스냅샷 발화 판별자를 원리적으로 교체 -- **H8-debt-2와 entangled(2026-06-29 진단)**
  - 현상: `Merge.TrimJoinblockMultiequals`가 unique-output phi에만 발화하는 휴리스틱.
    출력 varnode의 unique-vs-addrtied로 우회.
  - **2026-06-29 root-cause**: Gosleigh `Merge.MergeOp`(merge.go:424)는 이미 C++ mergeOp의
    cover-trim cascade + 최후 `TrimOpOutput`(merge.go:482-518)을 충실 포팅함. 즉 스냅샷
    메커니즘(TrimOpOutput) 자체는 원리적으로 존재. **문제는 순서**: Gosleigh는 MergeMarker를
    일찍 여러 번 돌려(decompile.go) loop phi 출력을 param HV에 이미 병합 -> MergeOp가 loop
    phi에 도달할 때 cover 충돌이 이미 사라져 자연 TrimOpOutput 미발화. C++는 mergeOp가 fresh-HV
    상태의 phi에서 cover 충돌 시 trimOpOutput 호출(merge.cc:719-760). TrimJoinblockMultiequals는
    이 순서 divergence의 workaround.
  - **원리적 해법 두 갈래**: (A) MergeMarker 실행 시점을 C++ universalAction 순서로 맞춰
    MergeOp의 자연 TrimOpOutput이 loop phi에서 발화하게 함(= H8-debt-2 reconcile에 포함). (B)
    순서 유지하되 TrimJoinblockMultiequals에서 pre-merge fresh-HV cover 충돌을 재구성해 판정
    (last session이 "둘 다 level 2"로 못 깬 lost-copy 미세 검출). (A)가 정공법, H8-debt-2와 통합 권장.
  - C++ 참조: `merge.cc Merge::mergeOp`(719-772, 특히 759-760 trimOpOutput 최후 수단),
    `block.cc BlockWhileDo::finalizePrinting`(for-loop 유효성).
  - 수정 대상: `pkg/bridge/decompile.go`(MergeMarker 순서) + `pkg/pcode/merge.go`
    TrimJoinblockMultiequals 제거.
  - 성공 기준: gcd/SumList/CountedLoop 전부 PASS 유지하며 TrimJoinblockMultiequals 휴리스틱 제거.

- [~] H8-debt-2: golden 파이프라인 프로덕션화 -- **부분 완료 (2026-06-29, `5a39f6c`)**
  - 완료: 골든 파이프라인을 `bridge.Decompile(engine, result, DecompileConfig)` 프로덕션
    함수로 추출. `runPipelineGhidra`는 bridge.Build + bridge.Decompile 호출만. 전 골든 PASS.
  - 남은 것: `bridge.Decompile`의 손정렬 action subset을 프로덕션 `BuildUniversalAction`
    (coreaction.cc ActionDatabase::universalAction 충실 포팅)과 reconcile -> 단일 정식
    actmainloop 트리로 통합. universalAction 내 미완 action들이 완성돼야 가능.
  - 참고: 진단용 `runPipeline`(비골든 변형)은 아직 손조립 + dumpSSA 유지.

- [x] H9: ActionSetCasts -- 타입 캐스트 삽입 **완료 (2026-06-29)**. 분석-time CPUI_CAST
  삽입이 bridge.Decompile에서 라이브, render-time assignCastStr 완전 제거. 아래는 포팅 이력.
  - 역할: 타입 불일치 지점에 명시적 `CPUI_CAST` op 삽입.
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
  5. **for-fold 재배치 + assignCastStr 제거 -- 완료(2026-06-29)**: ActionForLoops를
     ActionSetCasts 뒤로 이동(C++ print-time for-fold 순서), castOutput marker-skip으로
     loop phi split 방지, printc.go assignCastStr/effectiveLoadResultType 삭제. 상세 CHANGELOG.
  - 성공 기준: 기존 캐스트 golden (sum_list `(int *)`, complex_max `(int)`) 유지하며
    assignCastStr 의존 제거. **충족(전 골든 그린)**.

### 기타 미시작 (참고)
- H9 외: struct/union 타입 복구, switch statement, 6502 NOP/LDA/BNE 등 대부분 opcode
  resolution (PARITY_AUDIT.md 참조), BatchC rules 품질.

### 진단 도구
- `pkg/loader/msvc_diag_test.go` `dumpSSA`/`vnStr` (GCD_DUMP=1 env 가드, 평상시 무음) --
  SSA op 스트림 블록별 덤프. H-work 디버깅용 유지.
