# 프로젝트 상태

## 최종 목표 (THE mission)

Ghidra C++ 디컴파일러 엔진을 Go로 **동일 동작(identical behavior)** 포팅. 실제 .sla(x86/x64/ARM)를
로드해 **임의 실제 함수**를 Ghidra와 같은 C 출력으로 디컴파일하는 실사용 수준. (project CLAUDE.md 프로젝트
목표 + memory `project_e2e_goal` 참조.) x64 실함수(register param RCX/RDX) 성공도 명시 목표.

### 두 경로의 현재 위치
- **Production (`bridge.Decompile`, 41-call 손정렬 subset)**: x86-32 골든 11개 전부 그린. 단 작은 튜닝
  함수 코퍼스일 뿐 -- 실제 임의 함수(struct/union/switch/jumptable/미포팅 opcode)는 미완.
- **Tree (`ActionDatabase.BuildUniversalAction`, 250 action/rule = 진짜 Ghidra 파이프라인)**: 이게 미션의
  본체. #1 게이트 = 트리를 프로덕션 경로로 만들어 41-call subset을 대체(= H8-debt-2). **현재 트리 x86-32
  골든 3/5 byte-identical(gcd/abs_val/classify2).**

## 현재 상태 (2026-06-30 세션 진행, 전 패키지 그린)

**트리 전체 골든 맵 7/10 byte-identical** (`TestTreeFullGoldenMap`). x86-32 7/8(gcd/abs_val/classify2/
counted_loop/sum_list/multiply/add3 MATCH; classify_sign은 의미상 정확하나 RuleRangeMeld 미구현으로 byte 차이;
complex_max 바이트 미보유). x64_add_ret/aarch64_add_ret MISMATCH(register-param 트리 미배선 -- 아래 갭 지도).
이번 세션 4개 충실 수정으로 x86-32 3/5 -> 7/8 + register-param 갭 지도 작성:
- **루프 누산기 dead-temp 근본 해소**(scopelocal.go BuildFromVarnodes): 이전 세션의 "loop-snapshot/trimOpOutput
  누산기 미통합" 가설은 **오진**이었음. 실제 근본 = merge 이후 ActionInputPrototype(coreaction.go:986)이
  BuildFromVarnodes를 호출 -> local 루프가 새 high를 만들어 stack varnode만 훔쳐 병합된 register(누산기/카운터)를
  orphan(uVar2)으로 남김. C++ ActionInputPrototype::apply는 high를 재생성하지 않음. 수정 = 새 high 생성 대신
  **기존 병합 high 재사용 + SetName**(claimedHigh 가드로 over-merge 폴백). counted_loop 두 루프변수 write-back 복구.
- **트리 ActionForLoops 배선**(action.go FinalStructure 직후): C++은 for-fold를 print 시점에 하므로 universalAction에
  없음. Gosleigh는 ActionForLoops(production이 마지막에 호출하는 것과 동일)로 모델링 -> 트리 터미널 액션으로 추가.
  `while`->`for` 성립.
- **detached dead COPY 정리**(rules_copy.go RulePropagateCopy): sum_list 포인터-iterate(`param_3=(int*)param_3[1]`)의
  주소 PTRADD/COPY가 AddTreeState.buildTree에서 detached-alive로 생성됨(인라인 표현식). copy-prop이 LOAD을 PTRADD로
  bypass해 COPY가 dead 되나, 트리 oppool 이후 dead-code 미실행으로 잔존 -> PTRADD 2-use -> explicit uVar3 선언 +
  for-fold 거부. 수정 = propagation이 detached COPY를 dead로 만들면 즉시 OpDestroy(C++ dead-code 등가, detached
  한정으로 gcd snapshot 무회귀). 상세 CHANGELOG 2026-06-30.
- **De Morgan connective flip 버그 수정**(rules: prefer_complement.go getBooleanFlipOpcode): 분기 반전 시
  `getBooleanFlipOpcode`가 BOOL_AND/BOOL_OR를 미처리(ok=false) -> opFlipInPlaceExecute가 AND<->OR swap 코드에
  도달 전 skip -> operand만 뒤집히고 connective는 AND 유지 = De Morgan 위반(classify_sign이 `(p==0)&&(p<0)`
  모순 렌더). `(CPUI_MAX,true)` sentinel 추가로 swap 살림(C++ opFlipInPlaceExecute parity). classify_sign이
  의미상 정확(`(p==0)||(p<0)`)해짐. **모든 BOOL_AND/BOOL_OR 분기 조건에 영향하는 correctness 수정.**

회귀 가드: `TestUniversalActionTreeGcdGolden` + production `TestMSVC*` + 전 패키지 그린.

---

## 다음 작업 (우선순위)

### 1. [최우선] 미션 #1 게이트 완료 -- production 경로(bridge.Decompile)를 universal-action 트리로 교체

#1 게이트의 실제 교체 작업: `bridge.Decompile`(decompile.go)의 손정렬 41-call subset을
`db.BuildUniversalAction(nil) + SetCurrent("decompile").Perform(fd)` 경로로 대체. production은 여전히 41-call
손정렬, 트리는 별도 경로로 공존.

#### 트리 전체 골든 갭 지도 (2026-06-30, `TestTreeFullGoldenMap` TREE_MAP=1, 10 testable)
**7/10 byte-identical.** 트리가 모든 골든에 동일 출력하는지의 전체 지도:
- **x86-32 (8/9 가용, 7 MATCH)**: gcd/abs_val/classify2/counted_loop/sum_list/multiply/add3 = MATCH. classify_sign
  = MISMATCH(아래 상세, RuleRangeMeld). complex_max = 바이트 미보유(instruction-overlap 골든) -> 미테스트.
- **x64_add_ret = MISMATCH (register-param 갭)**: GOT `undefined8 ... { return local_31 + local_30; }` vs WANT
  `long ... { long in_RDI; long in_RSI; return in_RDI + in_RSI; }`. 두 갭: (a) **입력 레지스터(RDI/RSI)가
  `in_RDI`/`in_RSI`가 아닌 `local_31`/`local_30`(스택 로컬)로 오분류** -- 트리가 register 입력을 input-register로
  네이밍 안 함, (b) **반환타입 `undefined8` vs `long`** -- signed-long 추론 안 됨. 본문 계산 자체는 됨.
- **aarch64_add_ret = MISMATCH (완전 붕괴)**: GOT `void entry(void) { return; }` vs WANT
  `long entry(long param_1,long param_2) { return param_1 + param_2; }`. 레지스터 파라미터(X0/X1) + 반환값
  복구가 트리에서 **전혀 안 됨** -> 본문이 dead-code로 전소. (production 부분 파이프라인 테스트는 시그니처 복구됨
  -> 트리 전용 미배선.)
- **핵심 결론**: 트리는 x86-32(스택 기반 param/local)엔 견고하나, **register-param 아키텍처(x64 SysV RDI/RSI,
  ARM X0/X1)의 (1) 레지스터-파라미터 복구, (2) input-register 네이밍(in_RDI), (3) signed-long 타입 추론이 트리
  파이프라인에 미배선**. 이게 미션 명시 목표(x64 register param 실함수)의 직접 블로커. production decompile.go는
  ApplyCallingConvention + ScopeLocal RegParam 경로로 일부 처리하나 트리의 ActionDefaultParams/PrototypeTypes/
  RestructureVarnode 경로엔 register-param 인식이 빠짐(또는 stackparam 전용). 단 이 골든들도 tiny -- 실제 x64/ARM
  함수는 훨씬 큰 갭.
- **다음 우선순위 (갭 지도 기반)**:
  1. classify_sign: RuleRangeMeld 포팅(아래).
  2. x64/ARM register-param: 트리에 register-param 복구 배선(scopelocal.go BuildFromVarnodes는 RegParamOffsets
     경로가 이미 있음 -- 트리 proto model이 RegParamOffsets를 안 채우거나 ActionDefaultParams가 register trial을
     안 도는지 규명). aarch64 void 붕괴부터(가장 큰 갭).
  3. 둘 다 정렬되면 production 골든 전체 그린 확인 후 decompile.go subset 제거.
- **x86-32 classify_sign 상세** (위 7/10 중 유일 x86 잔여):
  - **classify_sign MISMATCH (잔여 = RuleRangeMeld 미구현)**: golden `else if (param_3 < 1)`. 두 단계로 규명됨:
    - **(수정완료) De Morgan connective flip 버그**: raw jg = `BOOL_AND(BOOL_NEGATE(ZF), INT_EQUAL(OF,SF))`.
      분기 반전 시 `getBooleanFlipOpcode`가 BOOL_AND/BOOL_OR를 미처리(ok=false)해 opFlipInPlaceExecute가 swap
      코드 도달 전 skip -> operand만 뒤집히고 connective는 AND 유지 -> `(p==0)&&(p<0)`(모순) 렌더. 수정:
      `getBooleanFlipOpcode`에 BOOL_AND/BOOL_OR -> (CPUI_MAX, true) 추가(prefer_complement.go, C++
      opFlipInPlaceExecute parity). 이제 `(p==0)||(p<0)`(=p<=0, 의미상 정확) 렌더. 전 패키지 그린.
    - **(잔여) BOOL_OR comparison-merge 미구현**: 트리 잔여 `BOOL_OR(INT_EQUAL(p,0), INT_SLESS(p,0))`를
      golden은 `INT_SLESS(p,1)`(= `p<=0` 단일 비교)로 collapse. 이 동일-변수 비교 병합은 `RuleRangeMeld`
      (rules_ghidra_port.go:858)가 담당하나 **newKnownMismatchBatchRule stub(미구현)** -- "CircleRange
      pullBack/intersect/union 미포팅". 트리는 BOOL_OR 잔존, golden은 단일 비교. 다음 = RuleRangeMeld 포팅
      (CircleRange interval, ruleaction.cc:1341 RuleRangeMeld + circlerange.cc) 또는 동일-변수-동일-상수
      2-비교 병합 targeted subset. production은 다른 순서로 단일 비교를 일찍 형성해 BOOL_OR 미형성(회피).
  - **complex_max**: 바이트 미보유 + instruction-overlap 경고 골든(`/* WARNING: ...overlaps */`), 별도 처리.
- **작업 순서**:
  1. classify_sign De Morgan/flag-collapse 갭 수정(트리 8/8 -> production 골든 전체 검증).
  2. 11개 production 골든 전부 트리로 검증(아직 일부만). mismatch 골든별 규명.
  3. 전부 통과하면 `bridge.Decompile`을 트리 호출로 교체(또는 옵션 플래그). `TestMSVC*`가 트리 경로로 그린이면
     41-call subset 제거.
- **성공 기준**: production `TestMSVC*` 전부 트리 경로로 그린 + 41-call subset(decompile.go) 제거.
- **주의**: 트리에 액션 추가/flags 변경 시 `TestTreeGoldensDiag`를 `-timeout 60s`로 감싸 hang 조기 검출.
  copy-prop/merge/MarkExplicit 등 공유 코드 수정 시 production `TestMSVC*` 전수 회귀 필수.
- **진단 도구**: `tree_accum_diag_test.go`(ACCUM_DIAG=1, ACCUM_CASE=<name>, PROD_DUMP=1) -- 트리 SSA + alive-ops
  (detached 표시) + high 그룹 + production 대조 덤프. 누산기/포인터-iterate류 갭 재현에 사용.

### 2. [대형] breadth + x64/ARM 실함수

골든 11개(거의 x86-32 + 사소한 x64/aarch64 add_ret)뿐. x64 실함수(register params RCX/RDX..) 성공 필요
(사용자 명시 요구). struct/union/switch/jumptable/미포팅 opcode(`docs/PARITY_AUDIT.md`). 새 Ghidra 골든
생성(Ghidra 12 `C:\ghidra12`, `testdata/ghidra_decompile.py`). **전략 옵션**: #1(트리 perfection)이 골든마다
깊은 rabbit hole이면, 실제 임의 함수에 production을 돌려 real-world 갭을 먼저 넓게 발굴하는 것이 미션
딜리버리에 더 가까울 수 있음 -- 다음 세션에서 판단.

### 3. [저우선] 정리
- consume-DeadCode broader corpus 검증 후 `GOSL_DESCENDANT_DC` fallback + 레거시 descendant-count 루프 제거.
- H9 미포팅 잔여: SUBPIECE/PTRSUB `getOutputToken` / union resolution / markExplicitUnsigned·LongSize.
- 트리 5개 stub delegate(`Spacebase`/`ApplyForceGoto`/`MarkIndirectOnly`/`RemoveDoNothingBlock`/
  `RemoveBranch`) 중 비-CalcNZMask 채우기(현재 no-op skip, 당장 비차단).
- H8-debt-1 잔여: `isLoopCondMultiequal` 게이트 원리화(Cover/mergeTest fidelity, broad/위험, 별도 세션).

---

## 완료 마일스톤 (상세는 CHANGELOG)
- **H7** return-value 복구(production): anchorReturnReg 물리 제거, guardReturns + dominance rename
  (`ApplyGuardReturnsLive`)가 유일 경로. consume-bit DeadCode + 실제 CalcNZMask 포팅. (완료 2026-06-30)
- **H8** gcd_x86_32 golden parity(production). (완료 2026-06-29)
- **H8-debt-1** TrimJoinblockMultiequals 제거 -> 충실 mergeOp trimOpOutput(merge.cc:759-760). (완료 2026-06-30)
- **H8-debt-2** 트리 프로덕션화: step1(proto 배선)+step2(incremental heritage)+step3a(early stack heritage)+
  step3b-1(충실 ReturnSplit)+step3b(루프 회전, gcd byte-identical)+step4(AncestorRealistic + return-value 복구,
  1/5->3/5)+**step5(누산기 BuildFromVarnodes high 재사용 + ActionForLoops 배선 + detached dead COPY 정리,
  3/5->5/5 byte-identical)**. 다음 = 위 "다음 작업 1"(production 경로를 트리로 교체). (진행 중)
- **H9** ActionSetCasts: 분석-time CPUI_CAST 삽입 라이브, render-time assignCastStr 제거. (완료 2026-06-29)
- 기타 미시작: struct/union 타입 복구, switch statement, 대부분 opcode resolution(PARITY_AUDIT), BatchC 품질.

## 작업 방향 (2026-04-13 확정)
golden diff 맞추기 자체를 목표로 삼지 않음. **C++ actmainloop 순서대로 각 패스를 알고리즘 레벨에서 충실히
구현**하고 golden test는 검증 수단으로 사용. 각 패스 구현 전 C++ 코드 먼저 읽고 이해 후 Go 포팅. 트리/
production 모두 같은 action impl을 공유하므로 트리 수정 시 production 회귀(전 골든) 필수 확인.

## 진단 도구 (전부 env 가드, 평상시 skip)
- `msvc_diag_test.go` `dumpSSA`/`vnStr` (GCD_DUMP=1) -- SSA op 스트림 블록별 덤프.
- `tree_output_diag_test.go` (TREE_DIAG=1): `TestTreeOutputDiag`(트리 gcd C 출력 + proto/scopelocal,
  GCD_DUMP=1 시 트리/production SSA 대조), `TestProductionStagesDiag`(production 단계별 blockShape).
- `tree_goldens_diag_test.go` (TREE_DIAG=1): `TestTreeGoldensDiag` -- 트리를 5개 x86-32 골든에 돌려
  match/mismatch + diff 보고(현재 3/5: gcd/abs_val/classify2).
- 회귀 가드(일반 스위트): `TestUniversalActionTreeGcdGolden`(트리 gcd byte-identical),
  `TestUniversalActionTreeConverges`(트리 수렴), `TestMSVC*`(production 골든).
