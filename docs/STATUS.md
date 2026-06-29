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

2. **[진행중] H7 -- consume-bit DeadCode LIVE(step1+2 완료), step3 = multi-pass heritage**.
   step1+2(2026-06-29 `42069c4`+`ef53e39`): consume-bit DeadCode 충실 포팅 + 프로덕션 기본 경로
   배선, 전 골든 그린. **step3(다음)**: anchorReturnReg(SeqNum 휴리스틱) 제거 -> C++
   Heritage::guardReturns + multi-pass heritage + ActionActiveReturn interplay 포팅 선행(사이즈 큼).
   현재 anchorReturnReg가 guardReturns 근사로 전 골든 정확. 미시작 H7 상세 참조.

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
