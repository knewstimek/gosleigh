# 프로젝트 상태

## 현재 상태 (2026-06-30 세션 종료, master `4581cf5`)

**전 패키지 그린** (loader/pcode/sla/bridge). 최종 목표 = Ghidra C++ 디컴파일러를 Go로 동일동작
포팅(실제 .sla x86/x64/ARM -> C). #1 게이트 = 손정렬 41-call `bridge.Decompile`을 충실한
`ActionDatabase.BuildUniversalAction`(250 action/rule) 트리로 대체(= H8-debt-2). 이번 세션 성과
(H8-debt-2 step1~3b-1 -- 트리가 gcd를 **의미적으로 정확하게** 출력, 남은 갭은 cosmetic 루프 회전 1개.
상세 CHANGELOG 2026-06-30):

1. **step1 -- 트리 proto/param/ScopeLocal 배선**. 트리는 FuncProto/ScopeLocal을 안 만들어
   (실행 후에도 nil) 파라미터/로컬 미명명 + 쓰레기 return이었음. `Funcdata.defaultModel`
   (Architecture::defaultfp 등가, bridge.Build이 부착) + ActionPrototypeTypes 충실화
   (setModel+ScopeLocal 생성+initActiveOutput, coreaction.cc:4626-4662). -> 시그니처 byte-match.
2. **step2 -- incremental heritage + activeparam 멱등**. heritage-once 대체(H7 step3 multi-pass도 해결):
   Heritage()가 heritage-known varnode skip(IsHeritageKnown, heritage.cc:2704-2719), OpHeritage가
   persistent Heritage 재사용 + 스택 슬롯 HeritageRange 슬롯별 1회. ApplyActiveParamModel은 input-lock 시
   early-return(oscillation 제거). -> 트리 수렴 + param_3가 루프 본체에 fold.
3. **step3a -- early stack heritage**. SSA 대조로 param_4 미fold 근본 규명(트리 ECX phi가 stack:0x8 대신
   COPY const:0 추적). OpHeritage가 첫 register heritage 직후 ActionStackPtrFlow 실행(GetPass()==1)으로
   stack을 rule pool 전에 heritage. -> param_3/param_4 모두 fold(의미적으로 정확한 gcd).
4. **step3b-1 -- 충실 ActionReturnSplit**. CFG 대조로 트리가 return을 과분리(2개)함을 규명 -- C++는
   goto-to-return 엣지만 분리(gatherReturnGotos)나 Gosleigh는 모든 in-edge 분리. goto in-edge만 분리
   (IsGotoIn)로 수정 -> 단일 return 복원. 남은 갭 = do-while -> while 루프 회전(step3b, 아래).

### 다음 작업 (우선순위) -- #1 게이트: 트리 출력을 골든 byte-identical로

1. **[대형, 최우선] H8-debt-2 step3b -- 트리 루프 회전(do-while -> while)**. step3a+3b-1까지 트리는
   수렴 + 시그니처/param_3/param_4 모두 골든 일치 + 단일 return(의미적으로 정확한 gcd). 남은 건 루프
   회전(cosmetic, 의미 동일):
   - 트리: `if (param_4) { do { iVar1 = param_3 % param_4; param_3 = param_4; param_4 = iVar1; } while (param_4); } return;`
   - 골든: `while (iVar1 = param_4, iVar1 != 0) { param_4 = param_3 % iVar1; param_3 = iVar1; } return;`
   - **근본 완전 규명 (단계별 bisect, `TestProductionStagesDiag`)**: 회전을 일으키는 패스 = **NodeJoin
     (ConditionalJoin)**. production stage 추적: `after NormalizeBranches: blocks=3 selfLoop=true` ->
     `after NodeJoin: blocks=4 selfLoop=false`. NodeJoin이 self-loop 블록을 while head+body로 분리.
   - **NodeJoin 분리의 2개 전제조건**:
     1. **조건 일치**: ConditionalJoin.findDups는 entry CBRANCH와 loop CBRANCH가 functionally-equal해야
        매칭. gcd entry=INT_EQUAL, loop=INT_NOTEQUAL(negation) -> NormalizeBranches가 loop를 flip해야
        매칭. 즉 **NormalizeBranches가 NodeJoin 전에** 실행돼야 함(실측: SKIP_NORMBRANCH 시 분리 안 함).
     2. **BlockStructure가 NodeJoin 전에 실행되면 안 됨**: 실측(BS_BEFORE_NJ)으로 BlockStructure를 먼저
        돌리면 NodeJoin 분리 실패. **근본**: BlockStructure의 collapse가 `negateCondition`(collapse.go:
        961 ruleBlockDoWhile)으로 루프 CBRANCH에 `PcodeOpBooleanFlip` 설정(block_basic.go:182, 공유 op
        이라 basic block에도 적용) -> ConditionalJoin.findDups가 BooleanFlip 있으면 **reject**
        (action_nodejoin.go:147). collapse는 clone 그래프에 작동하나 op은 공유.
   - **트리가 막히는 이유**: 트리 mainloop은 BlockStructure(action.go:1349) -> NodeJoin(1364) 순서.
     BlockStructure가 먼저 collapse해 BooleanFlip 설정 + 구조 그래프를 build-once(block_actions.go:142
     guard, C++도 동일)로 고정 -> NodeJoin이 영원히 reject -> do-while 고정. production decompile.go는
     NodeJoin -> BlockStructure 순서라 무사.
   - **열린 모순 (C++ 검증 필요, 가설 단정 금지)**: C++ universalAction도 mainloop에서 BlockStructure
     (5670) -> NodeJoin(5685) 순서 + ActionBlockStructure build-once guard 동일 + collapse가 boolean_flip
     설정. 정적 분석만으로는 C++도 막혀야 하는데 golden은 while -> 정적으로 안 풀리는 지점. 후보 가설
     (어느 것이 맞는지 C++ 코드/실행으로 확정 후 진행):
     (가) C++가 boolean_flip을 physically 적용+clear하는 rule/패스가 있어 후속 mainloop iteration에서
          NodeJoin 매칭 -> 그 rule이 Gosleigh oppool에 없거나 미발화. (나) C++가 basic block 변경(NodeJoin
          split) 시 구조 그래프를 무효화/재빌드(Gosleigh build-once는 안 함). (다) C++ collapse가 이 gcd
          루프엔 negateCondition을 안 함(orientation 차이) -> boolean_flip 미설정. (라) golden이
          universalAction 외 경로/버전에서 생성.
   - **다음 작업 (위 가설 확정 후)**: 우선 C++ blockaction.cc(ConditionalJoin::execute의 구조 무효화 여부),
     boolean_flip을 소비/clear하는 곳(C++ `flowblock.cc`/`coreaction.cc`), collapse의 negateCondition 발화
     조건을 읽어 (가)~(다) 중 무엇인지 확정. 그 다음 해당 메커니즘을 Gosleigh에 포팅. 주의:
     ConditionalJoin/BlockStructure/collapse는 production(decompile.go)도 사용 -> 전 골든 회귀 테스트 필수.
   - 진단 도구: `TestProductionStagesDiag`(TREE_DIAG=1) -- production 파이프라인 단계별 blockShape 추적
     (NodeJoin이 3->4 분리 확인). `TestTreeOutputDiag`(TREE_DIAG=1 GCD_DUMP=1) -- 트리/production SSA 대조.
   - 정렬되면 나머지 10 골든 -> decompile.go 41-call subset을 트리로 대체.
   - 성공 기준: universal 트리(SetCurrent("decompile"))가 gcd 등 전 골든을 byte-identical 출력.

2. **[대형] #2 breadth + #4 x64/ARM**: 골든 11개(거의 x86-32 + 사소한 x64/aarch64 add_ret)뿐.
   x64 실함수(register params RCX/RDX..) 성공 필요(사용자 요구). struct/union/switch/jumptable/
   미포팅 opcode(PARITY_AUDIT). 새 Ghidra 골든 생성 필요(Ghidra 12 `C:\ghidra12`,
   `testdata/ghidra_decompile.py`).

3. **정리(저우선)**: consume-DeadCode broader corpus 검증 후 `GOSL_DESCENDANT_DC` fallback +
   레거시 descendant-count 루프 제거. H9 미포팅 잔여(SUBPIECE/PTRSUB getOutputToken / union
   resolution / markExplicitUnsigned·LongSize). 트리 6개 stub delegate 중 비-CalcNZMask 채우기.

세션 상세 이력: `docs/CHANGELOG.md` (2026-06-30 항목).

## 작업 방향 (2026-04-13 확정)

golden diff 맞추기 목표를 폐기. 대신: **C++ actmainloop 순서대로 각 패스를 알고리즘 레벨에서 충실히 구현**. golden test는 검증 수단이지 목표가 아님. 각 패스 구현 시 C++ 코드 먼저 읽고 이해 후 Go로 포팅.

---

### 미시작 -- actmainloop 순서 기반 foundational 패스

**NOTE**: 아래 항목들은 golden match가 아니라 C++ 알고리즘 충실 구현이 성공 기준. 각 항목 완료 후 `go test ./...` 기존 테스트 통과 여부로 regression 확인.

- [x] H7: return-value 복구 -- **완료 (2026-06-30)**. anchorReturnReg(SeqNum 휴리스틱)를 물리 제거하고
  return 값을 충실한 Heritage::guardReturns + dominance rename(`ApplyGuardReturnsLive`)으로만 복구.
  consume-bit DeadCode(`deadcode_consume.go`, 프로덕션 기본 경로) + 실제 CalcNZMask(op.cc:548) 포팅 완료.
  step3가 의존하던 multi-pass heritage는 이번 세션 step2의 incremental heritage로 해결됨. 상세는 CHANGELOG
  2026-06-30. (잔여: ActionActiveReturn의 call-output trial 본체는 미포팅 -- 함수 자기 return은 guardReturns로
  충실, 전 골든 정확.)

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

- [~] H8-debt-2: golden 파이프라인 프로덕션화 -- **step1+2+3a+3b-1 완료 (2026-06-30): 트리 proto 배선 +
  incremental/early heritage + 충실 ReturnSplit로 트리가 수렴하고 시그니처/param_3/param_4/단일 return
  모두 골든 일치(의미적으로 정확한 gcd). 남은 갭 = do-while->while 루프 회전뿐(step3b, 위 "다음 작업"
  참조)**.
  - 구조: `BuildUniversalAction`(action.go:1159)은 C++ universalAction의 충실 스켈레톤(250 action/rule,
    올바른 순서 + group 필터)이고 대부분의 action은 decompile.go와 동일한 real impl 공유. 트리는
    self-contained 실행(Funcdata가 graph/spaces/defaultModel 보유) + 수렴 + 의미적으로 정확한 gcd 출력.
  - 잔여(루프 회전 외): 6개 stub delegate 중 `CalcNZMask`는 실제 포팅 완료(op.cc:548), 나머지 5개
    (`Spacebase`/`ApplyForceGoto`/`MarkIndirectOnly`/`RemoveDoNothingBlock`/`RemoveBranch`)는 no-op skip
    (decompile.go도 별도로 안 돌림, 당장 acceptable). repeat-apply 안전 cap 미설치(현재 수렴하므로 비차단).
  - 상세 이력(hollow 재정의 -> 첫 fill -> 수렴 -> proto 배선 -> incremental/early heritage -> ReturnSplit ->
    루프회전 root-cause)은 CHANGELOG 2026-06-30 참조.

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

### 진단 도구 (전부 env 가드, 평상시 무음/skip)
- `pkg/loader/msvc_diag_test.go` `dumpSSA`/`vnStr` (GCD_DUMP=1) -- SSA op 스트림 블록별 덤프.
- `pkg/loader/tree_output_diag_test.go` (TREE_DIAG=1):
  - `TestTreeOutputDiag` -- universal 트리를 gcd에 돌려 processEntry/ghidra 포맷 C 출력 + proto/scopelocal
    상태 + (GCD_DUMP=1 시) 트리/production SSA 나란히 덤프. production 기준 = bridge.Decompile 후
    result.Funcdata(in-place).
  - `TestProductionStagesDiag` -- production 파이프라인을 단계별로 재현하며 각 패스 후 basic-block shape
    (blocks 수 + self-loop 여부) 로그. step3b 루프회전 bisect용(NodeJoin이 3->4 분리 지점 확인).
