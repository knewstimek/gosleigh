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
  골든 1/5 byte-identical(gcd만).**

## 현재 상태 (2026-06-30 세션 종료, master `da76e07`, 전 패키지 그린)

**H8-debt-2 step3b 완료 -- universal 트리가 gcd를 golden과 byte-identical 출력.** do-while->while 루프
회전을 막던 5개 C++ parity 버그를 잡음(상세 CHANGELOG 2026-06-30 step3b COMPLETE). 근본 패턴 = "C++
flags=0 액션을 once-per-func로 오등록 + 동명 임포스터 rule + BlockCopy edge-forward 누락" 클러스터. 전부
production-safe(트리 전용; production은 .Apply 직접 호출로 액션 프레임워크 밖).
1. `RuleCondNegate` 임포스터 -> 충실 포팅(CBRANCH+boolean_flip -> BOOL_NEGATE+clear).
2. `ActionNodeJoin`/`ActionNormalizeBranches` once-per-func -> flags=0(매 mainloop pass 재실행).
3. **`BlockBasic.NegateCondition`이 소스 기본블록 edge 미swap** (핵심) -> C++ BlockCopy::negateCondition
   (block.hh:534)처럼 srcDelegate edge도 swap. collapse가 entry를 loop와 정렬 -> NodeJoin join -> while.
4. 트리 풀이 잘못된 `RulePushMulti`(arithmetic 트리거) -> 충실 `RulePushMultiME`(MULTIEQUAL). 조건 인라인.
5. `ActionInferTypes` once-per-func -> flags=0. 스냅샷 타입(undefined4 uVar1 -> int iVar1).

회귀 가드 `TestUniversalActionTreeGcdGolden`(일반 스위트). 진단 `TestTreeGoldensDiag`(TREE_DIAG=1).

---

## 다음 작업 (우선순위)

### 1. [최우선, 대형] 트리 return-value 복구 -- 나머지 골든의 공통 블로커

트리 x86-32 골든 4/5 실패의 **공통 근본**. 값 반환 함수(abs_val/counted_loop/sum_list/classify2,
전부 EBP-프레임 + 스택 로컬)가 트리에서 `void` + 값 계산 dead-code 제거로 렌더.

**규명된 메커니즘 (이번 세션 실측 확정)**:
- 트리 `Heritage.Heritage`(heritage.go:728~)가 guardCalls만 호출하고 **guardReturns 미호출**(C++
  Heritage::heritage -> guard()는 guardCalls+guardReturns 둘 다, heritage.cc).
- **naive하게 guardReturns만 추가하면 실패**(실험으로 확인 후 되돌림): (a) gcd가 `int ... return param_3;`로
  깨짐(void여야 함) + iVar1 스냅샷도 깨짐, (b) sum_list가 ActionConditionalConst.propagateConstant에서 nil
  deref. 이유 둘:
  1. **void/실제 판정이 틀림**: 트리는 ActionReturnRecovery(coreaction.go:1183)를 가지나 void/실제 판정을
     간이 `ancestorOpUseReturn`(funcproto.go:591, onlyReturnUse 기반)으로 함. C++는 **AncestorRealistic**
     (funcdata_varnode.cc, ~200줄 stack-DFS 백워드 dataflow + "solid movement" 휴리스틱). gcd의 param_3는
     루프 통과 파라미터(solid movement 없음)라 Ghidra가 void로 판정하나, 간이 판정은 "사용된 반환"으로 오판.
     **선행 의존 플래그 미구현**: `isUnaffected`/`isDirectWrite`/`isKilledByCall`/`isIncidentalCopy`/
     `isIndirectCreation`/`isReturnAddress` (Mark/Persist는 있음).
  2. **격리 필요**: guardReturns를 main heritage 루프에 넣으면 루프 스냅샷(trimOpOutput)까지 망가짐.
     production은 별도 heritage 패스 `ApplyGuardReturnsLive`(paramactive.go:826, BuildADT + 재마킹 + Rename,
     return 범위만)로 격리해 우회.
- 함수 자기 반환 담당 액션: **ActionReturnRecovery**(C++ coreaction.cc:1909, mainloop) +
  **ActionOutputPrototype**(5747, post-mainloop). ActionActiveReturn(1774)은 CALL 출력(다른 함수 반환)이라
  무관.

**진입점(다음 세션)**: C++ `funcdata_varnode.cc AncestorRealistic::execute/enterNode/uponPop`(2016-2260) +
`funcdata.hh:656` State 정의 먼저 읽기 -> 선행 Varnode 플래그 구현(+이를 설정하는 ActionDirectWrite 등
확인) -> `ancestorOpUseReturn`을 AncestorRealistic 충실 포팅으로 교체(production도 사용 = 회귀 위험 큼,
전 골든 회귀 필수) -> 트리에 격리 guardReturns 통합 -> `TestTreeGoldensDiag`로 한 골든씩 검증.
**성공 기준**: `TestTreeGoldensDiag` 5/5 byte-identical.

전략 메모: return-value 외 잔여 트리 갭(실측) = for-loop fold 미인식(counted_loop while->for), 스택
로컬 누산기. 한 골든씩 production 경로(작동)와 대조해 step3b처럼 flags/임포스터/edge-forward 류 우선 의심.
정렬되면 decompile.go 41-call subset을 트리로 교체(미션 #1 게이트 완료).

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
  step3b-1(충실 ReturnSplit)+**step3b(루프 회전, gcd byte-identical)**. 다음 = 위 "다음 작업 1". (진행 중)
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
  match/mismatch + diff 보고(현재 1/5).
- 회귀 가드(일반 스위트): `TestUniversalActionTreeGcdGolden`(트리 gcd byte-identical),
  `TestUniversalActionTreeConverges`(트리 수렴), `TestMSVC*`(production 골든).
