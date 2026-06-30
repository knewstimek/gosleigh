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

**트리 x86-32 골든 4/5 byte-identical (gcd/abs_val/classify2/counted_loop).** 이번 세션에 counted_loop의
루프 본문 dead-temp 블로커를 충실히 해소하고 트리에 ActionForLoops를 배선해 for-fold를 살림. sum_list만 잔여.
- **루프 누산기 dead-temp 근본 해소**(scopelocal.go BuildFromVarnodes): 이전 세션의 "loop-snapshot/trimOpOutput
  누산기 미통합" 가설은 **오진**이었음. 실제 근본 = merge 이후 ActionInputPrototype(coreaction.go:986)이
  BuildFromVarnodes를 호출 -> local 루프가 새 high를 만들어 stack varnode만 훔쳐 병합된 register(누산기/카운터)를
  orphan(uVar2)으로 남김. C++ ActionInputPrototype::apply는 high를 재생성하지 않음. 수정 = 새 high 생성 대신
  **기존 병합 high 재사용 + SetName**(claimedHigh 가드로 over-merge 폴백). counted_loop 두 루프변수 write-back 복구.
  상세 CHANGELOG 2026-06-30.
- **트리 ActionForLoops 배선**(action.go FinalStructure 직후): C++은 for-fold를 print 시점에 하므로 universalAction에
  없음. Gosleigh는 ActionForLoops(production이 마지막에 호출하는 것과 동일)로 모델링 -> 트리 터미널 액션으로 추가.
  counted_loop `while`->`for` 성립.

회귀 가드: `TestUniversalActionTreeGcdGolden` + production `TestMSVC*` + 전 패키지 그린.

---

## 다음 작업 (우선순위)

### 1. [최우선] 트리 sum_list -- 포인터-iterate PTRADD 체인 explicit 마킹 + for-fold

트리 골든 **4/5**(gcd/abs_val/classify2/counted_loop). sum_list 1개만 잔여. counted_loop의 누산기 dead-temp는
이번 세션에 해소됨(BuildFromVarnodes 병합-high 재사용 + ActionForLoops 배선, 상세 CHANGELOG 2026-06-30).
- **현상 (sum_list, TREE_DIAG)**: 본문 write-back은 정상(`local_8 = local_8 + *param_3`, `param_3 = (int *)
  param_3[1]`). 차이는 (1) `while`(golden은 `for`), (2) stray `int *uVar3;` phantom 선언(본문 미사용).
- **정밀 규명 (ACCUM_CASE=sum_list + PROD_DUMP 계측, tree_accum_diag_test.go)**: iterate 주소 계산 체인이
  트리/production에서 다르게 wiring됨.
  - production: `PTRADD(param_3,1,4)`(detached) -> `COPY 0x6600`(detached, unnamed) -> `LOAD 0x6600`(blk3) ->
    `CAST`(NONPRINT) -> param_3. PTRADD/COPY 모두 **single-use chain = implied/unnamed**.
  - tree: copy-prop이 LOAD 주소를 COPY 출력(0x6600) 대신 **PTRADD 출력(0x87325)으로 직접 당김** -> PTRADD
    출력이 2-use(LOAD + 이제 dead가 된 COPY) -> **MarkExplicit이 explicit 표시 + NameVars가 uVar3 명명**. dead
    COPY는 detached라 DeadCode가 안 지움(detached op 미처리).
  - **for-fold 거부 지점**: `testIterateForm`(action_forloops.go:181) DFS가 iterate(CAST)->LOAD->PTRADD 출력
    uVar3에서 truncate. uVar3가 explicit+multi-use(NumDescend>1)라 walk 중단(action_forloops.go:257) ->
    loopDef(param_3 phi) high에 도달 못 함 -> false -> while 유지. production은 PTRADD가 implied라 DFS가
    param_3까지 도달.
- **근본**: copy-prop이 LOAD 주소를 PTRADD로 bypass해 PTRADD 출력 use-count를 2로 만들고(=explicit), 죽은
  COPY가 detached라 정리 안 됨. golden(Ghidra)은 PTRADD를 inline(`param_3[1]`)하므로 트리의 explicit 마킹이
  오답. 후보 수정: (a) RulePropagateCopy가 LOAD 주소 COPY를 bypass하지 않게(또는 bypass 후 dead COPY 제거),
  (b) detached dead COPY를 use-count/MarkExplicit에서 제외, (c) production처럼 RulePtrArith late 순서. (a)/(b)는
  gcd 회귀 위험 있는 copy-prop/MarkExplicit 공유 영역 -- 작은 단위 검증 필수.
- **진단 재현**: `ACCUM_DIAG=1 ACCUM_CASE=sum_list PROD_DUMP=1 go test ./pkg/loader -run TestTreeAccumDiag -v`
  (tree_accum_diag_test.go: SSA + alive-ops(detached 표시) + high 그룹 + production 대조 덤프).
- **수정 대상 Go 파일**: `pkg/pcode/ruleaction*.go`(RulePropagateCopy), `pkg/pcode/coreaction.go`(MarkExplicit
  use-count), `pkg/pcode/action_forloops.go`(testIterateForm).
- **성공 기준**: `TestTreeGoldensDiag` 5/5 byte-identical. 정렬되면 decompile.go 41-call subset을 트리로
  교체(미션 #1 게이트 완료).

**주의(step4 교훈)**: 트리에 액션 추가/flags 변경 시 `TestTreeGoldensDiag`를 `-timeout 60s`로 감싸 hang 조기
검출. copy-prop/MarkExplicit 수정 시 production `TestMSVC*` 전체 회귀 필수(공유 코드).

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
  step3b-1(충실 ReturnSplit)+step3b(루프 회전, gcd byte-identical)+**step4(AncestorRealistic + return-value
  복구, 골든 1/5->3/5)**. 다음 = 위 "다음 작업 1"(누산기 phi + for-fold). (진행 중)
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
