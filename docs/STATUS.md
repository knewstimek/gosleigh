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

## 현재 상태 (2026-07-23 세션6, master `991be09`, origin 푸시, 전 게이트 green 감독관 재검증)

**권위 문서 = 저장소 루트 `NEXT_SESSION_PROMPT.md`**. 요약:
- **[세션6] A2 param-recovery undercount 착지(`991be09`)**: 충실 `ParamListStandard`/`ParamEntry`/`fillinMap`
  포팅(신규 paramlist.go) + fixateproto `recoverMissingStackParams`로 helper_sum 스택 param_5 복구(ssadump
  실측, golden 시그니처 일치). 전 게이트 무회귀. corpus2는 6/13 유지 -- body `tmp_0`는 param 무관 별개 갭
  (dead INT_2COMP = IMUL 플래그 잔재가 consume-deadcode 통과). **다음 최우선 = dead-negate 제거(제거 시
  helper_sum MATCH, 6->7)**. 상세 CHANGELOG 세션6. 아래 세션5 게이트 수치는 유효(A2는 시그니처만 개선).
- 게이트: tree **10/10**, x64 corpus **8/8**, **op_switch byte-MATCH**, breadth **3/3**,
  corpus2 **6/13**(+find_pair/clamp3), x64_auto **20/32**(15->20: dowhile_count/nested_if_ladder_grade/
  param_reuse_accum/char_arith_promote/bit_mask_shift_combo), production 전부 PASS, `go test ./...` green.
- 세션5 착지(상세 CHANGELOG 세션5): **GenGoldens bodyHex 손상 버그**(dead-code island 누락으로 분기 변위
  파괴 -- 전 코퍼스 감사로 x64_auto 2건만 손상 확정, 붕괴형 mismatch는 입력 무결성부터) + 엔진 9건
  (cover 인덱스=블록위치, LoopBody 포인터 안정성, InfLoop do/while(true), RuleCollectTerms 포팅,
  RuleShift2Mult 컨텍스트 게이트, RuleDoubleShift 완전 포팅, PTRADD 렌더 스케일 제거, heritage BuildADT
  faithful 포팅(clamp3 완결), **param-recovery overcount 수정(phantom R8 param 제거 -- ActionInputPrototype
  input-only trial + deadcode 후 발화)**). 다음 최우선 = param-recovery undercount(helper_sum 스택 param/
  add_pt struct = resolveModel/deriveInputMap 포팅) -- NEXT_SESSION_PROMPT (A2).
- **툴 2종 착지(핸드오프 우선 제작 툴 완성)**: `tools/goldengap/`(원커맨드 골든 생성+갭 자동분류,
  `testdata/x64_auto/` 32함수 discovery 코퍼스) + `tools/ssadiff/`(C++ 코어 decomp_dbg <-> Gosleigh
  최종 SSA를 op 단위 나란히 비교, savefile 템플릿 생성 포함).
- 세션4 착지(11건: dispatch 포인터 타이핑->breadth 3/3, ActionReturnSplit, 파서-컨텍스트 pin 등)는
  CHANGELOG 2026-07-17 세션4 참조.


## 다음 작업 (우선순위)

> **[최신] 2026-07-23 세션6 (엔진 tip `991be09` origin 동기화): A2 param-recovery undercount 착지 -- 충실
> ParamListStandard 포팅으로 helper_sum 스택 param_5 복구. corpus2 6/13 유지, x64_auto 20/32. 다음 최우선
> = dead-negate 제거(helper_sum body tmp_0의 근본 = dead INT_2COMP/IMUL 플래그가 consume-deadcode 통과;
> 제거 시 helper_sum MATCH 6->7, 단 다수 함수 회귀 위험이라 read-only 진단 먼저). 권위 있는 다음-작업/
> 현재상태는 저장소 루트 `NEXT_SESSION_PROMPT.md` + CHANGELOG 2026-07-23 세션6 참조. 갭 지도 =
> `testdata/x64_auto/GAPMAP.md` + `testdata/x64_corpus2/README.md`.**

## 잔여 부채 (2026-07-17 세션5 실측 검증 -- 다음 작업의 권위는 루트 NEXT_SESSION_PROMPT.md)

이전의 미시작 (a)/(a-2)/(b) 섹션과 2026-07-02/03 완료 서사는 stale이라 삭제했다(이력은 CHANGELOG).
stale였던 이유 = 마일스톤 완료 후 해당 미시작 섹션을 지우지 않음: (a) dispatch는 세션4 breadth 3/3으로,
(a-2) 단축타입명/uVar1은 세션2/3으로, (b) process 3갭은 세션2 x64 corpus 8/8로 이미 완료였다.
아래는 코드/게이트로 재확인한 장기 부채만:

- **[세션6] dead INT_2COMP (IMUL 플래그 잔재) consume-deadcode 통과**: helper_sum body `tmp_0`의 근본.
  `u = -(R9D*s0x28)`가 use 없이 살아남아 곱셈을 2-use로 만들어 인라인 차단. decomp_dbg상 C++ 코어는 미생성.
  제거 시 helper_sum golden MATCH(corpus2 6->7). **다음 세션 최우선.** IMUL SLEIGH 번역/consume-deadcode
  영역이라 다수 함수 회귀 위험 -> read-only 진단 먼저.
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
- **goldengap 툴 개선 후보**: report가 GAPMAP.md 수동 섹션을 덮어씀 + TYPECAST 휴리스틱이 블록 소실을
  오분류(multi_return_early 사례, 세션5 확인).
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
