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

## 현재 상태 (2026-07-23 세션6, master `53fce49`, origin 푸시, 전 게이트 green 감독관 재검증)

**권위 문서 = 저장소 루트 `NEXT_SESSION_PROMPT.md`**. 요약:
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
  corpus2 **8/13**(+sum_via_pp), x64_auto **24/32**(+sum_pp_walk +strlen_style), production 전부 PASS, `go test ./...` green.
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

> **[최신] 2026-07-23 세션7 (master `48a747b` origin 동기화): for-loop 인식(`60e01f0`) + (B) print-inline
> 일부(`4759d8e`) + char 리터럴(`53fce49`) 착지. **corpus2 8/13, x64_auto 24/32**. 다음 후보(전부 대형/딥존) =
> **umulhi**(printc 표현식렌더를 flat-string -> 그룹토큰스트림 재아키텍처, Oppen코어 prettyprint.go는 완성이나
> PrintC가 굵은 불투명 토큰만 넘겨 RHS 내부 연산자에서 못 접음 -- 코어렌더 영향 단독세션) / swap_via_temp
> (markImpliedCheckCover LOAD/STORE alias cover, merge 딥존) / A2 잔여(IsParamOffset 완전대체). 권위 있는
> 다음-작업/현재상태는 저장소 루트 `NEXT_SESSION_PROMPT.md` + CHANGELOG 2026-07-23 세션6 후속3~5 참조.
> 갭 지도 = `testdata/x64_auto/GAPMAP.md` + `testdata/x64_corpus2/README.md`.**

## 잔여 부채 (2026-07-17 세션5 실측 검증 -- 다음 작업의 권위는 루트 NEXT_SESSION_PROMPT.md)

이전의 미시작 (a)/(a-2)/(b) 섹션과 2026-07-02/03 완료 서사는 stale이라 삭제했다(이력은 CHANGELOG).
stale였던 이유 = 마일스톤 완료 후 해당 미시작 섹션을 지우지 않음: (a) dispatch는 세션4 breadth 3/3으로,
(a-2) 단축타입명/uVar1은 세션2/3으로, (b) process 3갭은 세션2 x64 corpus 8/8로 이미 완료였다.
아래는 코드/게이트로 재확인한 장기 부채만:

- **[세션6->세션7 부분 착지 `4759d8e`] (B) print-inline**: `shouldInline`이 nd>1 implied 식을 term-dup 인라인하도록
  수정 + `ActionNameVars` explicit-only 네이밍 -> sum_via_pp/sum_pp_walk MATCH. flag는 이미 C++ 일치였고(실측)
  순수 렌더+네이밍 갭이었다. **잔여**: (1) nd==1 경로는 원본 보존(전면 flag-faithful화 시 loop-carried
  PTRADD/CAST가 phi로 explicit 마킹돼 phantom 선언 누출 = heritage/merge marker 영역), (2) umulhi는 내용
  byte-identical이나 **줄바꿈만 MISMATCH** = printc 표현식렌더 flat-string -> 그룹토큰스트림 재아키텍처(별도
  대형세션, 아래 [최신] 참조), (3) swap_via_temp는 `*param_1` LOAD가 impl 오분류 = markImpliedCheckCover
  LOAD/STORE alias cover 갭(merge 딥존).
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
- **pre-structure SSA 정합**(deadcode/MarkImplied 타이밍): TEMP 클러스터 + BlockBasic::isComplex leaf
  known-gap의 공통 선행 -- NEXT_SESSION_PROMPT (B).
- **PathMeld.meld/internalIntersect/checkUnrolledGuard 스텁**: 현 코퍼스는 단일 path/guard라 미도달.
  다중 guard switch 코퍼스 추가 시 필요.
- **consume-DeadCode 정리**: `GOSL_DESCENDANT_DC` fallback(action_deadcode.go:70) + 레거시
  descendant-count 루프 잔존 -- broader corpus 검증 후 제거.
- **goldengap 툴 개선 후보**: GAPMAP.md는 전체 자동생성(수동 섹션 없음)이라 '덮어씀' 우려는 stale(옛 주의
  삭제). 실제 한계 = TYPECAST/TEMP 토큰수 휴리스틱이 블록소실/미인라인 근본을 못 짚음(multi_return_early는
  세션6에 emitter 버그로 판명돼 이미 MATCH -- 예시도 stale).
- struct/union 타입 복구, 스택 파라미터/CONCAT44/reloc/FP(corpus2 P5-P8), PARITY_AUDIT 미포팅 opcode 잔여.


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
