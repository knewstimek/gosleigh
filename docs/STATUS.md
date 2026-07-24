# 프로젝트 상태

## 최종 목표 (THE mission)

Ghidra C++ 디컴파일러 엔진을 Go로 **동일 동작(identical behavior)** 포팅. 실제 .sla(x86/x64/ARM)를
로드해 **임의 실제 함수**를 Ghidra와 같은 C 출력으로 디컴파일하는 실사용 수준. (project CLAUDE.md 프로젝트
목표 + memory `project_e2e_goal` 참조.) x64 실함수(register param RCX/RDX) 성공도 명시 목표.

### 두 경로의 현재 위치
- **Production (`bridge.Decompile`)**: H8-debt-2 완료(2026-07-03, master `eadd9c0`)로 손정렬 41-call subset을 버리고
  **universal-action 트리로 교체됨**. 유일 load-bearing 배선 = 콜러가 `bridge.Build`에 cspec(+EntryPoint)
  공급. (당시 게이트 기록 -- 현재 수치는 아래 "현재 상태"가 권위.)
- **Tree (`ActionDatabase.BuildUniversalAction`, 250 action/rule = 진짜 Ghidra 파이프라인)**: 이제 이것이
  production 경로다. bespoke `ActionStackPtrFlow`는 완전히 삭제됨(H8-debt-2 Step3, 2026-07-03, master
  `accd8a9`) -- 레거시 테스트 하네스 13개를 트리 경로로 이전한 뒤 `pkg/pcode/action_stack_ptr_flow.go`
  파일 자체를 제거. H8-debt-2(Step1+Step2+Step3) 완전 종료.

## 현재 상태 (2026-07-24 세션8, master `e3a573f` origin 푸시, 전 게이트 green 감독관 재검증)

**권위 문서 = 저장소 루트 `NEXT_SESSION_PROMPT.md`**. 요약:
- **[세션8] 자율주행 감독관 + Opus 병렬 2슬롯으로 착지 15건, x64_auto 25 -> 31/32, corpus2 8 -> 10/13.** 상세는 CHANGELOG 세션8-1~15.
  **동명 다른 룰 2건 발견**(`RuleSubRight`, `RulePushPtr`) -- 이름 충돌이 미포팅 룰을 가리고 있었다.
  룰 감사는 이름이 아니라 `getOpList`+본체로 대조할 것.
  핵심: (a) **detached op**(`f3dc442`) -- `NewOpBefore`가 op를 블록에 안 넣어 Cover/HV가 nil parent 기준으로
  계산되고 merge가 보상 trim COPY를 만들었다(C++ funcdata_op.cc:670은 `opInsertBefore`로 끝남). 이걸 고치자
  세션6/7이 반복 STOP했던 "phantom 선언 누수" 경계가 사라졌고 printc nd==1 프록시를 제거했다.
  (b) **스택을 heritage space로 등록**(`c54d295`) -- 스택이 heritage 파이프라인을 아예 안 타고 있었다
  (heritageSpaces를 번역 직후 p-code로만 수집). refinement 계열 전체 포팅. (c) **call-site 입력 trial 포팅**
  (`2f08090`, 768줄) -- caller param 5개 + 인자 4개 복구. (d) 미선언 변수 방출 버그 2건 수정(`2460b6b`/`3afb5cd`,
  둘 다 컴파일 불가능한 C를 내고 있었다).
- **[세션6 후속5] char 리터럴 렌더 착지(`53fce49`)**: `renderConstant`(printc.go)에 char-print 분기 추가
  (size-1 signed int -> `'\0'`, C++ type.cc:3642 cacheCoreTypes 재현, val<0x80 좁은 게이트). strlen_style
  strict MATCH -> **x64_auto 23->24/32**. 전 게이트 무회귀.
- **[세션6 후속4] (B) print-inline 일부 착지(`4759d8e`)**: `shouldInline`이 nd>1 implied 식 term-dup 인라인
  (printc.go) + `ActionNameVars` explicit-only 네이밍(action_name_vars.go). flag는 이미 C++ 일치(실측), 순수
  렌더+네이밍. **sum_via_pp(corpus2) + sum_pp_walk(x64_auto) MATCH -> corpus2 8/13, x64_auto 23/32**. 전 게이트
  무회귀. 잔여 = umulhi 줄바꿈(PrettyEmitter)/swap_via_temp LOAD cover/nd==1 full-faithful = STOP 경계.
- **[세션6 후속3] for-loop 인식 착지(`60e01f0`)**: `findLoopVariable`(action_forloops.go)가 CPUI_CAST 투과.
  근본 = 액션 순서 차이(C++은 finalTransform을 ActionSetCasts 전 실행, Gosleigh는 후 -> 삽입 CAST가 depth-4 예산
  소진). strlen_style Ghidra for 구조 일치(잔차 char 리터럴 `!= '\0'` = STOP 경계). x64_auto MATCH 22 유지. 전 게이트 무회귀.
- **[세션6] A2 param-recovery undercount 착지(`991be09`)**: 충실 `ParamListStandard`/`ParamEntry`/`fillinMap`
  포팅(신규 paramlist.go) + fixateproto `recoverMissingStackParams`로 helper_sum 스택 param_5 복구(ssadump
  실측, golden 시그니처 일치). 전 게이트 무회귀.
- **[세션6 후속] dead-negate 제거(`ed0bbea`)**: helper_sum body `tmp_0` 근본 = cleanup 룰 왕복이 만든 orphan
  INT_2COMP(C++ 미생성). `Rule2Comp2Sub`가 rewrite 후 orphan 2COMP 파괴(ruleaction.cc:7254). corpus2 6->7,
  x64_auto 20->21(longlong_combo 동반).
- **[세션6 후속2] multi_return_early 착지(`f569034`)**: `BlockIf` 조건헤드가 `BlockList`일 때 PrintC
  이미터가 선행 guarded-return 누락 + 최내곽 오렌더. ActionReturnSplit·collapse는 정확했고(decomp_dbg
  실측) 순수 emitter 버그. `emitConditionLead`/`renderCondition`에 BlockList 케이스 추가(emitBlockLs
  no_branch/only_branch 미러, printc.cc:2913). **x64_auto 21->22/32**(multi_return_early MATCH). 상세 CHANGELOG
  세션6 후속2. 아래 게이트 수치는 이 값으로 갱신됨.
- 게이트: tree **10/10**, x64 corpus **8/8**, **op_switch byte-MATCH**, breadth **3/3**,
  corpus2 **10/13**(+gate +umulhi), x64_auto **31/32**(+bit_rotate_left +swap_via_temp +while_countdown
  +popcount_loop +sign_extend_boundary +reverse_bytes_inplace +array_init_then_sum), production 전부 PASS,
  `go test ./...` green, `go vet` clean. **잔여: x64_auto switch_dense 1건 / corpus2 add_pt·caller·faverage 3건.**
- 세션5 착지(상세 CHANGELOG 세션5): **GenGoldens bodyHex 손상 버그**(dead-code island 누락으로 분기 변위
  파괴 -- 전 코퍼스 감사로 x64_auto 2건만 손상 확정, 붕괴형 mismatch는 입력 무결성부터) + 엔진 9건
  (cover 인덱스=블록위치, LoopBody 포인터 안정성, InfLoop do/while(true), RuleCollectTerms 포팅,
  RuleShift2Mult 컨텍스트 게이트, RuleDoubleShift 완전 포팅, PTRADD 렌더 스케일 제거, heritage BuildADT
  faithful 포팅(clamp3 완결), **param-recovery overcount 수정(phantom R8 param 제거 -- ActionInputPrototype
  input-only trial + deadcode 후 발화)**). (세션5가 지목했던 param-recovery undercount는 세션6에 A2 스택
  param + dead-negate로 착지 완료 -- 현재 다음 작업은 위 [최신] 블록/NEXT_SESSION 참조.)
- **툴 2종 착지(핸드오프 우선 제작 툴 완성)**: `tools/goldengap/`(원커맨드 골든 생성+갭 자동분류,
  `testdata/x64_auto/` 32함수 discovery 코퍼스) + `tools/ssadiff/`(C++ 코어 decomp_dbg <-> Gosleigh
  최종 SSA를 op 단위 나란히 비교, savefile 템플릿 생성 포함).
- 세션4 착지(11건: dispatch 포인터 타이핑->breadth 3/3, ActionReturnSplit, 파서-컨텍스트 pin 등)는
  CHANGELOG 2026-07-17 세션4 참조.


## 다음 작업 (우선순위)

> **[최신] 2026-07-24 세션8 (master `e3a573f` origin 푸시): 착지 8건, **corpus2 8/13, x64_auto 29/32**.
> 남은 미스매치와 근본(전부 실측 확인됨):
> - **array_init_then_sum**: 상류 3단이 막혀 있다 -- (1) `Funcdata.Spacebase()`가 `UpdateType(ptr)`만 해서
>   spacebase 포인터 타입이 InferTypes에 덮임(C++ funcdata.cc:264는 `updateType(ptr,**true,true**)`),
>   (2) `propagateAddPointer`에 `CPUI_INT_ADD` 케이스 부재(C++ typeop.cc:1291-1313) -> RulePtrArith 미진입 ->
>   PTRSUB/PTRADD 미생성, (3) ActionSetCasts가 CAST(ptr->int)로 체인 절단. **증명됨**: 골든과 같은 심볼
>   (`aiStack_48`, `int[18]`)을 손으로 주입해도 출력 바이트 무변화 -> **상류 없이 varmap/ScopeLocal 작업은 무력**.
>   `local_423` 미선언 방출도 여기에 종속(printc.go:4223 `local_%d(CreateIndex)` 폴백).
> - **umulhi**: printc 표현식 렌더 flat-string -> 그룹토큰스트림 재아키텍처(단독 대형세션).
> - **gate**: De Morgan 조건형 + then/else 스왑. **reverse_bytes_inplace**: for 헤더 comma 식 하나만 남음.
> - **caller/add_pt**: 구조는 복구됐으나 strict MATCH는 별건에 게이팅(caller=하네스 한계로 **불가**,
>   add_pt=SUBPIECE/CONCAT44 렌더 + uStackX 네이밍). **switch_dense**: imagebase/reloc.
> - **faverage**: FP 서브시스템 통째 갭.
> 권위 있는 다음-작업은 저장소 루트 `NEXT_SESSION_PROMPT.md` + CHANGELOG 2026-07-24 세션8-1~17 참조.
> 갭 지도 = `testdata/x64_auto/GAPMAP.md` + `testdata/x64_corpus2/README.md`.**

## 잔여 부채 (2026-07-17 세션5 실측 검증 -- 다음 작업의 권위는 루트 NEXT_SESSION_PROMPT.md)

이전의 미시작 (a)/(a-2)/(b) 섹션과 2026-07-02/03 완료 서사는 stale이라 삭제했다(이력은 CHANGELOG).
stale였던 이유 = 마일스톤 완료 후 해당 미시작 섹션을 지우지 않음: (a) dispatch는 세션4 breadth 3/3으로,
(a-2) 단축타입명/uVar1은 세션2/3으로, (b) process 3갭은 세션2 x64 corpus 8/8로 이미 완료였다.
아래는 코드/게이트로 재확인한 장기 부채만:

- **[세션8에 (B) print-inline 클러스터 전부 해소]** (이 불릿은 세션6/7 서술이 대거 stale이라 정정):
  (1) "nd==1 flag-faithful화 시 phantom 누출 = heritage/merge marker 영역"이라던 진단은 **반증됐다** -- 진짜 근본은
  detached op(`NewOpBefore`가 블록 삽입 누락)였고, 고치자 `shouldInline` nd==1이 `isImplied()`를 존중해도 누출이
  없어졌다(`f3dc442`, CHANGELOG 세션8-2). (2) umulhi 줄바꿈은 "그룹토큰스트림 재아키텍처 별도 대형세션"이 아니라,
  ExprFragment가 자식만 버리고 있어 **점진 해결**됐다(`ee6dde2`, MATCH). (3) swap_via_temp의 "markImpliedCheckCover
  merge 딥존" 진단은 맞았고 `365aa20`으로 착지(+ detached op로 렌더 완결) -> **MATCH**.
- **[세션6] A2 param-recovery 하이브리드 잔존**: 새 `ParamListStandard.fillinMap`은 스택 갭에만 additive
  소비, 레지스터/로컬은 여전히 옛 `ApplyActiveParamModel`(IsParamOffset 휴리스틱). 완전 대체(updateInputTypes
  store 재빌드 + unref varnode 실체화)는 A2 잔여 슬라이스.

- **isLoopCondMultiequal band-aid**(merge.go, H8-debt-1 잔여): 세션5 cover fix 이후 dowhile_count는 트림
  자체가 불필요해졌으나 gcd는 여전히 forceOutputTrim 경로로 통과(무회귀 확인). 원리화는 broad/위험, 별도 세션.
- **heritage guardStores/guardLoads 미포팅**(heritage.go ~1077 주석): clamp3와 무관함이 세션5에 확인됐지만
  LOAD/STORE 많은 함수에서 발화할 수 있는 부채로 잔존.
- **SeqNum.Order != 블록 실행 위치(전역)**: cover 소비자만 세션5에 국소 해결(`97084fa`). 다른 Order 소비자
  (double.go, funcdata.go, rules_misc.go, merge.go 정렬)는 여전히 stale decode order -- 측정된 실패는 없음.
  완전 포팅은 Order를 opTree 맵 키에서 분리해야 함(별도 세션).
- **pre-structure SSA 정합**(deadcode/MarkImplied 타이밍): TEMP 클러스터는 세션8에 대부분 해소됨(detached op
  `f3dc442` + printc group-token `ee6dde2` + free-varnode 스킵 `3afb5cd`). 잔여 known-gap = BlockBasic::isComplex
  leaf faithful 포팅(40d00a3 스텁, 6게이트 회귀 이력).
- **PathMeld.meld/internalIntersect/checkUnrolledGuard 스텁**: 현 코퍼스는 단일 path/guard라 미도달.
  다중 guard switch 코퍼스 추가 시 필요.
- **consume-DeadCode 정리**: `GOSL_DESCENDANT_DC` fallback(action_deadcode.go:70) + 레거시
  descendant-count 루프 잔존 -- broader corpus 검증 후 제거.
- **goldengap 툴 개선 후보**: GAPMAP.md는 전체 자동생성(수동 섹션 없음)이라 '덮어씀' 우려는 stale(옛 주의
  삭제). 실제 한계 = TYPECAST/TEMP 토큰수 휴리스틱이 블록소실/미인라인 근본을 못 짚음(multi_return_early는
  세션6에 emitter 버그로 판명돼 이미 MATCH -- 예시도 stale).
- struct/union 타입 복구, reloc/FP(corpus2 P5-P8 / faverage), PARITY_AUDIT 미포팅 opcode 잔여. (스택 파라미터는
  세션8 A2 스택 param `991be09`+heritage refinement `c54d295`로, CONCAT44 렌더는 `6521fd2`로 해소.)
- **[세션8 신규 최대 부채] 동명 다른 룰 잔여 9건**: 룰 감사(`b0d1476`)가 Go 룰 이름은 같은데 C++과 다른 룰
  12건을 확인, 3건 포팅(`31539bc`/`0fa8787`). 잔여 9건(RuleShiftPiece/RuleZextCommute/RuleDoubleSub 등)은
  전부 actprop에 등록돼 실행 중 -- NEXT_SESSION_PROMPT 표. **룰 감사는 이름이 아니라 getOpList+본체로 대조.**


## 완료 마일스톤 (상세는 CHANGELOG)
- **H7** return-value 복구(production): anchorReturnReg 물리 제거, guardReturns + dominance rename
  (`ApplyGuardReturnsLive`)가 유일 경로. consume-bit DeadCode + 실제 CalcNZMask 포팅. (완료 2026-06-30)
- **H8** gcd_x86_32 golden parity(production). (완료 2026-06-29)
- **H8-debt-1** TrimJoinblockMultiequals 제거 -> 충실 mergeOp trimOpOutput(merge.cc:759-760). (완료 2026-06-30)
- **H8-debt-2** 트리 프로덕션화: step1(proto 배선)+step2(incremental heritage)+step3a(early stack heritage)+
  step3b-1(충실 ReturnSplit)+step3b(루프 회전, gcd byte-identical)+step4(AncestorRealistic + return-value 복구,
  1/5->3/5)+step5(누산기 BuildFromVarnodes high 재사용 + ActionForLoops 배선 + detached dead COPY 정리,
  3/5->5/5 byte-identical)+step6(De Morgan flip + **RuleRangeMeld CircleRange 포팅 = x86-32 8/8, 전체 8/10**)+
  step7(**cspec 구동 arch-aware default ProtoModel -> aarch64 register-param 복구 = 전체 9/10**)+
  step8(**x64 processEntry in_RDI: entry-point void proto + irregular input 네이밍 = 전체 10/10 byte-identical**)+
  step9(**production 경로(bridge.Decompile)를 트리로 교체 = 미션 #1 게이트 달성, master `eadd9c0`, 2026-07-03**)+
  step10(**bespoke `ActionStackPtrFlow` 완전 삭제 -- 레거시 하네스 13개 트리 이전, master `accd8a9`,
  2026-07-03**). **완료(본체+Step3, H8-debt-2 완전 종료)**.
- **H9** ActionSetCasts: 분석-time CPUI_CAST 삽입 라이브, render-time assignCastStr 제거. (완료 2026-06-29)
- 기타 미착수 잔여는 위 "잔여 부채" 참고.

## 작업 방향 (2026-04-13 확정)
golden diff 맞추기 자체를 목표로 삼지 않음. **C++ actmainloop 순서대로 각 패스를 알고리즘 레벨에서 충실히
구현**하고 golden test는 검증 수단으로 사용. 각 패스 구현 전 C++ 코드 먼저 읽고 이해 후 Go 포팅. 트리/
production 모두 같은 action impl을 공유하므로 트리 수정 시 production 회귀(전 골든) 필수 확인.

## 진단 도구 (전부 env 가드, 평상시 skip)
- `msvc_diag_test.go` `dumpSSA`/`vnStr` (GCD_DUMP=1) -- SSA op 스트림 블록별 덤프.
- `tree_output_diag_test.go` (TREE_DIAG=1): `TestTreeOutputDiag`(트리 gcd C 출력 + proto/scopelocal,
  GCD_DUMP=1 시 트리/production SSA 대조). (`TestProductionStagesDiag`는 은퇴한 손정렬 파이프라인 복제였다
  -- H8-debt-2 Step3(master `accd8a9`)에서 삭제됨.)
- `tree_goldens_diag_test.go` (TREE_DIAG=1): `TestTreeGoldensDiag` -- 트리를 5개 x86-32 골든에 돌려
  match/mismatch + diff 보고(전수 매치는 TestTreeFullGoldenMap 10/10이 권위).
- 회귀 가드(일반 스위트): `TestUniversalActionTreeGcdGolden`(트리 gcd byte-identical),
  `TestUniversalActionTreeConverges`(트리 수렴), `TestMSVC*`(production 골든).
