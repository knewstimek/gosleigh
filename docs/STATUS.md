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

## 현재 상태 (2026-06-30 세션 종료, master `75b98b7`, 전 패키지 그린)

**H8-debt-2 step4 완료 -- AncestorRealistic 포팅 + 트리 return-value 복구로 골든 1/5 -> 3/5.** 값 반환
함수가 트리에서 void + dead-code로 렌더되던 공통 블로커 해소(상세 CHANGELOG 2026-06-30 step4).
- **AncestorRealistic 충실 포팅**(`ancestor_realistic.go`, C++ funcdata_varnode.cc:2016-2256): 반환
  varnode 조상이 realistic한지 backward stack-DFS로 판정(solid movement vs unaffected/killedbycall/
  bare-input). gcd param_3(bare input)=void, abs_val -param_3(solid NEG)=int.
- **트리 guardReturns 배선**(`action_guardreturns.go` ActionGuardReturns, once-per-func): production의
  ApplyGuardReturnsLive(격리 heritage 패스)를 트리 mainloop 안 ActionReturnRecovery 직전에 1회 호출.
  RETURN에 반환 레지스터를 엮어 본문 살림.
- **ActionReturnRecovery 게이트 + once-per-func**: markActive를 AncestorRealistic.execute AND
  ancestorOpUse 둘 다 통과로 제한(coreaction.go:1207). flags=0이면 active return 시 매 pass 재빌드로
  mainloop hang -> once-per-func(guardReturns 직후 1회 빌드 = C++ fullyChecked 수렴 재현).
- **propagateConstant nil-parent 가드**(condexe.go): guardReturns 트랜지언트의 detached op skip.

step3b(gcd 루프 회전) 완료분은 그대로 유효. 회귀 가드: `TestUniversalActionTreeGcdGolden` +
production `TestMSVC*` 전부 그린. production은 ActionDirectWrite 미실행이라 게이트 미적용(트리 전용).

---

## 다음 작업 (우선순위)

### 1. [최우선, 대형] 트리 counted_loop/sum_list -- 스택 로컬 누산기 phi 병합 + for-loop fold

트리 골든 2/5 잔여. **반환값은 이미 복구됨**(int, `return local_c`/`return local_8`). 남은 갭은
return-value가 아니라 루프 본체 렌더링:
- **현상 (counted_loop, TREE_DIAG GOT vs golden)**:
  - GOT: `while (local_8 < 5) { uVar2 = local_c + local_8; uVar1 = local_8 + 1; }` -- 본문 갱신이 dead
    temp(uVar1/uVar2)로 새고 루프 변수 local_c/local_8에 write-back 안됨(루프-carried 스택 로컬 phi
    back-edge 미병합). 또한 `while`(golden은 `for`).
  - WANT: `for (local_8 = 0; local_8 < 5; local_8 = local_8 + 1) { local_c = local_c + local_8; }`.
- **현상 (sum_list)**: 유사 for-fold 미인식 + 변수 하나가 `return`으로 오명명(naming 충돌).
- **핵심 단서**: counted_loop_x86_32/sum_list_x86_32 **둘 다 production 골든**이고 production은 통과
  (msvc_diag_test.go:294 등, for 루프 정상). 즉 production 경로는 스택-로컬 누산기를 올바로 병합 +
  for-fold함. 트리만 못함.
- **SSA 레벨 규명 (이번 세션 실측, counted_loop 트리 vs production SSA 대조)**: **op 구조는 byte-identical**.
  같은 블록/같은 MULTIEQUAL/같은 INT_ADD. 차이는 **순수 HighVariable 병합(naming)** 하나뿐:
  - 트리 block3: `register:0x4[4]#uVar2 = INT_ADD stack:0xfffffff4#local_cT stack:0xfffffff8#local_8T`
    block4: `register:0x0[4]#uVar1 = INT_ADD stack:0xfffffff8#local_8T const:0x1` -- 루프 본문 결과가
    **별도 HighVariable(uVar1/uVar2)** -> printer가 `uVar2 = local_c + local_8`(dead, write-back X).
  - production block3: `register:0x4[4]#local_c = INT_ADD ...` block4: `register:0x0[4]#local_8 = INT_ADD ...`
    -- 루프 본문 레지스터 결과가 **스택 로컬과 같은 HighVariable(local_c/local_8)** -> `local_c = local_c +
    local_8`(write-back) + for-fold 인식.
  - 즉 **루프 back-edge 레지스터 정의(register:0x4/0x0)를 스택 로컬 HighVariable(local_c/local_8,
    stack:0xfffffff4/0xfffffff8)로 병합하는 merge를 트리가 빠뜨림**. 트리에 merge 액션은 전부 존재
    (action.go:1423-1435 MergeRequired/MergeCopy/DominantCopy/MergeAdjacent/MergeType 등)하므로, 누락이
    아니라 **트리에서 그 merge의 cover/mergeTest가 실패하거나 once-per-func/flags 오등록으로 한 번만
    돌고 마는 류**(step3b 패턴) 의심. 어느 merge 액션이 production에서 register<->stack을 잇는지
    (MergeMarker/MergeAdjacent/mergeAddrTied 후보) 먼저 격리할 것.
- **진단 도구**: `GCD_DUMP=1 TREE_DIAG=1`로 SSA 대조. counted_loop용 임시 테스트는 이번 세션에 제거됨 --
  필요시 buildGcd 패턴 + counted_loop 바이트(tree_goldens_diag_test.go:64)로 재작성(트리: BuildUniversalAction
  +SetCurrent("decompile").Perform, production: bridge.Decompile, 둘 다 dumpSSA). `TestProductionStagesDiag`
  (production 단계별), 트리 출력은 `TestTreeGoldensDiag`.
- **수정 대상 Go 파일**: `pkg/pcode/merge.go`(mergeMarker/mergeAdjacent/mergeTest/cover) + 트리 파이프라인
  merge 액션 flags/등록(`pkg/pcode/action.go:1423-1435`). ForLoops(for-fold)는 병합이 풀리면 자동 따라올
  가능성 높음(production은 같은 SSA로 for-fold 성공) -- 병합 먼저.
- **성공 기준**: `TestTreeGoldensDiag` 5/5 byte-identical. 정렬되면 decompile.go 41-call subset을 트리로
  교체(미션 #1 게이트 완료).

**주의(step4 교훈)**: 트리에 반환값/누산기를 엮으면 once-per-func vs flags=0 오등록으로 mainloop hang이
재발하기 쉬움. 새 액션 추가/flags 변경 시 `TestTreeGoldensDiag`를 `-timeout 60s`로 감싸 hang 조기 검출.

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
