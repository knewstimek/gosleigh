# 프로젝트 상태

## 현재 상태 (2026-06-29 세션 종료, master `f4fcfb4`)

**전 패키지 그린** (loader/pcode/sla/bridge). 이번 세션 성과:
1. **H9 assignCastStr 전면 제거 완료** -- ActionForLoops를 ActionSetCasts 뒤로 재배치(C++
   print-time for-fold 순서), castOutput marker-skip으로 loop phi split 방지, printc.go
   assignCastStr/effectiveLoadResultType 삭제(-116줄). 전 골든 그린.
2. **H7 step1+2 완료 -- consume-bit DeadCode가 충실한 프로덕션 기본값으로 LIVE**
   (`deadcode_consume.go` + `ActionDeadCode.applyConsume`). anchorReturnReg 블로커를 실험으로
   bedrock 진단(3 부재 서브시스템), 그 중 consume-bit DeadCode를 충실 포팅+배선. 전 골든 +
   전 패키지 byte-identical. step3(anchorReturnReg 제거)은 multi-pass heritage 선행 필요.
3. **정밀 진단**: H8-debt-1(MergeMarker 순서, H8-debt-2와 entangled), H7 step3 블로커.
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

2. **[완료] H7 -- guardReturns가 유일한 return 경로, anchorReturnReg 완전 제거**.
   step1+2: consume-bit DeadCode. step3a(`34e5d6b`): guardReturns 충실 포팅(dormant, 단위테스트 4종).
   step3b(`dd1ae88`): `ApplyGuardReturnsLive`(activeoutput 설치 -> guardReturns로 RETURN에 fresh varnode
   append -> def 재마킹 -> Rename으로 dominating def 연결, placeMultiequals 미재실행=중복 phi 회피).
   step3c(`f61120f`): 14개 레거시 테스트 사이트 배선 + 전 corpus byte-identical 확인 후 기본값 전환.
   **step3 완료(2026-06-30): anchorReturnReg/ApplyActiveReturnModel/guardReturnsLiveEnabled 물리 제거**
   (-161줄). ApplyCallingConvention은 stripReturnIndirectRef만, return 값은 ApplyGuardReturnsLive 전담.
   ActionActiveReturn.Apply는 no-op 스텁(미배선, C++ call-output 본체 미포팅 명시). printc 주석 정리.
   GOSL_LEGACY_ANCHOR_RETURN fallback 폐기(blast radius 작고 전 corpus 검증). 전 패키지 그린.

3. **[대형, 대안] H8-debt-2 reconcile** -- bridge.Decompile 손정렬 subset을 프로덕션
   `BuildUniversalAction`(universalAction 충실 포팅)과 통합. consume-DeadCode가 LIVE가 되며
   universalAction 완성도 1보 전진. **H8-debt-1**(스냅샷 판별자)은 MergeMarker 순서 문제로 이와 entangled.

4. **H7 step4 / H9 미포팅 잔여(저우선)**: 실제 CalcNZMask(현 stub, consume 비트정밀도+rule 영향) /
   SUBPIECE·PTRSUB getOutputToken / union resolution / markExplicitUnsigned·LongSize. 현재 보수적 동작.

5. **정리(저우선)**: consume-DeadCode가 broader corpus에서 검증되면 `GOSL_DESCENDANT_DC` fallback +
   레거시 descendant-count 삭제 루프(action_deadcode.go) 제거.

세션 상세 이력: `docs/CHANGELOG.md` (2026-06-29 항목).

## 작업 방향 (2026-04-13 확정)

golden diff 맞추기 목표를 폐기. 대신: **C++ actmainloop 순서대로 각 패스를 알고리즘 레벨에서 충실히 구현**. golden test는 검증 수단이지 목표가 아님. 각 패스 구현 시 C++ 코드 먼저 읽고 이해 후 Go로 포팅.

---

### 미시작 -- actmainloop 순서 기반 foundational 패스

**NOTE**: 아래 항목들은 golden match가 아니라 C++ 알고리즘 충실 구현이 성공 기준. 각 항목 완료 후 `go test ./...` 기존 테스트 통과 여부로 regression 확인.

- [x] H7: return-value 복구 -- **완료 (2026-06-30, step3 전체)**. anchorReturnReg 휴리스틱을 충실한
  Heritage::guardReturns + dominance rename(ApplyGuardReturnsLive)으로 대체하고 anchorReturnReg를
  물리 제거. 아래는 진단/포팅 이력(참고). (잔여 참고: ActionPrototypeTypes 정식 배선 + ActionActiveReturn
  call-output 본체는 미포팅 -- 현재 guardReturns로 return 값 복구는 충실, 전 골든 정확.)
  - 역할: 함수 프로토타입(반환형, 인자 타입)을 Heritage 전에 확정. `ActionPrototypeTypes`는
    이미 구현됨(coreaction.go:778, stub 아님)이나 골든 파이프라인(`bridge.Decompile`)이 이를
    호출하지 않음(과거: `anchorReturnReg` 휴리스틱; 현재: ApplyGuardReturnsLive). gcd는 `void`로 통과.
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
  - **진짜 블로커 = 3개 부재 서브시스템(bedrock 진단)**: Gosleigh ActionDeadCode는 descendant-count
    기반이고, C++의 충실 경로는 다음 3개를 모두 요구함:
    1. **consume-bit DeadCode** (pushConsumed/propagateConsumed ~40 opcode + gatherConsumedReturn +
       markConsumedParameters). -- **LIVE (step 2 완료)**: `pkg/pcode/deadcode_consume.go` 충실
       포팅 + `ActionDeadCode.applyConsume`가 **프로덕션 기본 DeadCode 경로**
       (action_deadcode.go). 전 골든 + 전 패키지 그린. 모든 omission(pre-live/neverConsumed/
       >8byte/call-param)이 보수적(과보존, 절대 오삭제 X)이고 Gosleigh DeadCode는 전부
       post-heritage라 pre-live 미발화 -> 안전. descendant 경로는 GOSL_DESCENDANT_DC fallback.
       단위테스트 `TestConsumeAnalysisReturnReachable` + 골든 e2e 검증.
    2. **heritage-pass / deadcode-delay 추적** (numHeritagePasses/deadRemovalAllowed/doesDeadcode).
       pre-live register 보존(C++ 3960)에 필요. Gosleigh 부재(condexe.go/rules_ghidra_port.go에
       known mismatch 명시). **미착수**.
    3. **실제 CalcNZMask** (현재 stub, nzm 비상수 기본 ~0). consume 비트정밀도 + 많은 rule이 의존.
       구현 시 rule들이 공격적으로 바뀌어 회귀 위험 -> 보수적 ~0 유지 중. **미착수(저우선,
       consume는 ~0로 보수적 동작)**.
    (1)이 LIVE가 되며 return값 보존이 consume-DeadCode + anchorReturnReg(RETURN 배선)로 충실해짐.
    ReturnRecovery/OutputPrototype/PrototypeTypes 본체는 이미 구현(K1)되어 배선만 남았고, 이제
    (1) 위에서 step3로 배선 가능(anchorReturnReg의 SeqNum selection만 정식 ParamActive trial로 교체).
  - **남은 로드맵**: ~~step2 = consume-DeadCode 통합~~ **완료(LIVE)**. heritage-pass 추적(subsystem 2)은
    post-heritage DeadCode에선 불필요. **step3 = anchorReturnReg 제거 -> multi-pass heritage 선행
    필요(2026-06-29 재진단)**: C++ `Heritage::guardReturns`(heritage.cc:1652)는 return-reg를 RETURN에
    fresh varnode로 append하나 **`getActiveOutput()!=null`(ActionActiveReturn 선행) 조건**이고, SSA
    renaming이 dominating def에 연결. 이는 multi-pass heritage(ActiveReturn -> 후속 heritage가
    guardReturns)에 의존하는데 Gosleigh는 single-pass라 부재. anchorReturnReg(SeqNum selection +
    early wiring)가 이 전체를 근사. 충실 제거 = guardReturns + multi-pass heritage + ActiveReturn
    interplay 포팅(사이즈 큼). 현 상태: consume-DeadCode(faithful) + anchorReturnReg(guardReturns
    근사) + applyReturnRecovery(clobber prune)로 전 골든 정확. step4(저우선) = 실제 CalcNZMask.
    step4 = printc RETURN 렌더 정리. step5(저우선) = 실제 CalcNZMask로 비트정밀도.
  - C++ 참조: `coreaction.cc ActionDeadCode::apply`(3936)/`gatherConsumedReturn`(3882)/
    `propagateConsumed`(3580)/`markConsumedParameters`(3851) + `ActionPrototypeTypes::apply` +
    `ActionReturnRecovery`/`ActionActiveReturn`. printc.go anchorReturnReg 의존(12+ 참조)도 동반 제거.
  - 수정 대상(순서): (1) `pkg/pcode/action_deadcode.go` consume-bit 포팅, (2) `decompile.go`
    ActiveReturn/ReturnRecovery/OutputPrototype/PrototypeTypes 배선, (3) anchorReturnReg/
    stripReturnIndirectRef 제거, (4) printc.go RETURN 렌더 정리.
  - 성공 기준: 전 골든 PASS 유지하며 anchorReturnReg 휴리스틱 + consume-bit DeadCode 라이브.

- [x] H8: gcd_x86_32 golden parity **완료 (2026-06-29)**. TestMSVC_Gcd PASS.

- [x] H8-debt-1: TrimJoinblockMultiequals 제거 -- **완료 (2026-06-30)**. forward-snip 워크어라운드를
  충실한 C++ mergeOp trimOpOutput 메커니즘으로 대체. 전 골든 + 전 패키지 그린.
  - **해결**: `Merge.MergeOp`에서 cover 충돌(!allOK)인 loop-cond MULTIEQUAL(isLoopCondMultiequal)은
    input-trim을 건너뛰고 곧장 `TrimOpOutput` 호출(merge.cc:759-760의 실제 메커니즘) -> 긴 cover의 출력을
    COPY로 분리해 loop-head snapshot(iVar1) 생성. `TrimJoinblockMultiequals`(별도 pass + forward-snip +
    unique-output/anyPhysical/IsAddrTied 게이트)와 `hasPhysicalSource` 헬퍼 삭제, decompile.go/diag-test의
    호출 제거. FORCE_TRIMOUT 실험으로 전 corpus 검증 후 정식화.
  - **진단 이력(2개 가설 실측 반증)**: (1)"MergeMarker 순서" -- 조기 MergeMarker 제거해도 gcd 불변(반증).
    (2)"phi 출력 storage(unique vs param)" -- C++ `ConditionalExecution::getNewMulti`(condexe.cc:206)도
    `newUniqueOut` 사용, GCD_DUMP로 양쪽 다 unique 확인(반증). 확정 divergence: Gosleigh mergeOp가 cyclic
    loop-cond phi 충돌을 TrimOpInput으로 해소(trimmed=true)해 trimOpOutput 미발화 -- C++는 input-trim 소진 후
    trimOpOutput으로 떨어짐.
  - **잔여(저우선)**: `isLoopCondMultiequal` 게이트는 "input-trim이 spurious하게 해소되는 cyclic phi"의
    stand-in. 완전 원리화 = mergeOp가 게이트 없이 자연 trimOpOutput에 도달하도록 Cover/mergeTest fidelity
    수정(back-edge를 지나는 phi 출력 cover가 trim 지점과 겹치게) -- residual loop-carried Cover gap. broad
    cover 변경이라 위험, 별도 세션. 현재 게이트는 cover-충돌(!allOK) 신호 + 실제 trimOpOutput 메커니즘이라
    forward-snip 워크어라운드보다 충실.
  - C++ 참조: `merge.cc Merge::mergeOp`(719-772, 759-760 trimOpOutput), `condexe.cc getNewMulti`(206).

- [~] H8-debt-2: golden 파이프라인 프로덕션화 -- **재정의 (2026-06-30): "순서 reconcile"가 아니라
  "hollow action 본체 채우기 + Funcdata self-contain"이 본질**. 미션(#1 게이트)의 핵심 잔여.
  - **2026-06-30 측정 발견(정정)**: `BuildUniversalAction`(action.go:1159)은 C++ universalAction의
    구조적 스켈레톤(250 action/rule, 올바른 순서 + group 필터)을 갖췄고 **대부분의 action은 decompile.go가
    쓰는 것과 동일한 real impl을 공유**(InferTypes/BlockStructure/StackPtrFlow/Merge* 등 실제 Apply 보유).
    hollow은 한정적: (1) `Funcdata`가 graph/heritage-spaces를 보유 안 해 self-contained 실행 불가했음
    (-> 첫 fill로 해결), (2) 6개 stub delegate 메서드 -- `CalcNZMask`(=NonzeroMask, ~0 보수적), `Spacebase`,
    `ApplyForceGoto`, `MarkIndirectOnly`, `RemoveDoNothingBlock`, `RemoveBranch` (대부분 no-op=skip로
    당장은 acceptable, decompile.go도 이들을 별도 단계로 안 돌림).
  - **진짜 블로커 = mainloop non-convergence, root = ActionVarnodeProps + stub CalcNZMask (2026-06-30 계측)**:
    전체 트리가 gcd에서 hang. CONV_PROBE 계측으로 매 iteration progress 보고하는 action 식별:
    varnodeprops/conditionalconst/multicse/oppool1. **근본**: `ActionVarnodeProps`(coreaction)는
    `NZMask & Consumed == 0`인 varnode를 const 0으로 교체하는데, 트리 경로엔 (1) `CalcNZMask`가 stub(~0),
    (2) consume 분석 미계산 -> 모든 varnode가 Consumed==0으로 보여 매 iteration마다 live varnode를 0으로
    교체 -> 수렴 불가 + SSA 손상. decompile.go는 ActionVarnodeProps를 안 돌려서 무사했음.
  - **결론: 트리 수렴 = H7 step4(실제 CalcNZMask) + consume 분석 트리 배선에 의존**. 즉 H8-debt-2와
    H7 step4가 직결. 실제 CalcNZMask 없이는 ActionVarnodeProps/Nonzeromask 의존 액션들이 misfire.
    repeat-apply max-iteration cap도 없음(부차적). => 다음: 실제 CalcNZMask 포팅(많은 rule이 nzm 읽어
    공격적 변경=회귀 위험, 작은 단위 필수) -> 트리 재실행으로 수렴 확인.
  - **첫 fill 완료(HEAD)**: Funcdata에 graph/heritageSpaces 주입(`SetAnalysisContext`, bridge.Build이
    채움, additive 무회귀) + `OpHeritage` 실화(fd.graph/spaces로 register heritage) -> ActionHeritage가
    실제 SSA 빌드. 단위테스트 `TestUniversalActionHeritageBuildsSSA`(pre=phi 0, post>0). 프로덕션
    (decompile.go)은 여전히 외부 NewHeritage 사용 -> 무영향, 전 패키지 그린.
  - **남은 로드맵**: (1) full-pool non-convergence rule 식별/수정(oppool1을 instrument해 어느 rule이
    매 iteration progress 보고하는지) + repeat-apply 안전 cap 검토. (2) 6개 stub delegate 채우기(CalcNZMask는
    H7 step4=위험, 나머지는 작음). (3) 트리를 gcd부터 골든 통과하도록 단계적 검증(decompile.go 출력 대조).
    완성 시 decompile.go subset을 트리로 대체. 트리가 대부분 real이라 (1)이 풀리면 빠르게 진전 가능.
  - 참고: 완료(`5a39f6c`)는 골든 파이프라인을 `bridge.Decompile`로 추출(runPipelineGhidra=Build+Decompile).

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
