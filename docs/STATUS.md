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
- **완전 규명 (이번 세션, SETHIGH/MergeOp/BYTYPE 계측으로 액션 단위 추적)**: op 구조는 트리/production
  byte-identical. 차이는 **HighVariable 병합/네이밍** 하나. 루프 본문 레지스터 결과(register:0x4=누산기,
  register:0x0=카운터)가 트리에서 스택 로컬(local_c/local_8)과 분리돼 dead temp(uVar1/uVar2)로 렌더.
  3중 체인으로 규명:
  1. **(수정완료, master f66a2b5)** `ActionOutputPrototype`가 `hv.AddInstance(firstRet)`로 반환 varnode를
     병합 High에서 훔침 -> C++ updateOutputTypes는 타입만 갱신(coreaction.cc:4776). 제거함.
  2. **(미적용, cover 수정 후 재적용)** `ScopeLocal.BuildFromVarnodes`(scopelocal.go local 루프)가
     `NewHighVariable("local_c")` + AddInstance로 스택 varnode를 **새 High로 훔침** -> register는 같은 병합
     High에 있으나 g.varnodes(offset별 스택 SSA)에 없어 누락. 수정안 = 새 High 생성 대신 그룹 varnode의
     **기존 병합 High 재사용 + SetName**(register 따라옴). **단 #3 cover 수정 없이 적용하면 corruption**
     (아래 #3의 over-merge된 High를 재사용해 local_c/local_8 합쳐짐).
  3. **(미수정, H8-debt-1 cover-fidelity = parked)** `mergeByDatatype`(ActionMergeType)가 register:0x0과
     register:0x4(루프 back-edge 너머 simultaneously-live)를 **over-merge** -> `HighIntersectTest`의 cover
     intersection이 이 두 레지스터의 live range 겹침을 **미검출**(loop-carried Cover gap). 이전엔
     BuildFromVarnodes의 offset별 재분리가 이 over-merge를 가렸음(#2 수정이 노출). **(수정완료, f66a2b5)**
     스택 심볼 addrtied 부여(scopelocal_ext.go RestructureVarnode)로 스택 로컬은 addrtied 가드로 보호되나,
     **레지스터는 merge 그룹 내에서 생성돼 심볼 sync를 안 거쳐 addrtied 미적용** -> 레지스터 over-merge 잔존.
- **추가 규명 (SSA-버전 레벨, SETHIGH/BYTYPE action-tagged 계측)**: 문제는 **루프 본문 register:0x4(INT_ADD
  출력)가 여러 SSA 버전으로 존재**한다는 것. 한 버전은 local_c phi 입력으로 MergeMarker가 stack:fff4(local_c)와
  병합(정상), 다른 버전(snapshot)은 출력에 `uVar2 = local_c + local_8`로 렌더(= gcd iVar1 snapshot과 같은
  H8-debt-1 loop-snapshot 머신이 counted_loop에선 write-back으로 통합 안 됨). 직접 블로커 2개:
  1. **BuildFromVarnodes 훔침(#2)**: 병합된 register:0x4가 inputprototype의 BuildFromVarnodes가 stack:fff4를
     훔쳐 orphan -> uVar2. (#2 reuse가 직접 수정이나 #3-blob 노출.)
  2. **mergeByDatatype over-merge**: ActionMergeType(production은 미실행, 트리만 = C++ universalAction과 일치)가
     stack:fff4/fff8 + 레지스터들을 한 blob으로 병합. addrtied 가드가 막아야 하나 **stack varnode가 addrtied
     아님**. 근본: `syncVarnodeFlags`(funcdata.go:586)는 C++ "addrtied can be cleared but not set" 의미로
     **addrtied를 set 못 함** -- C++은 varnode 생성 시 상속, Gosleigh의 merge-그룹 COPY는 미상속. #3(심볼
     addrtied 부여)도 sync가 set 못 해 varnode에 전파 안 됨(실측 -- ActionMappedLocalSync 재실행 실험도 실패).
- **이번 세션 추가 수정 (전부 충실 C++ parity, green, master `d265c2a`)**:
  - **setVarnodeProperties 포팅**(44f6e80): NewVarnode/NewVarnodeOut가 생성 시 local-scope SymbolEntry
    flags(addrtied)를 stamp. + RestructureVarnode가 기존 stack varnode를 re-stamp. -> 두 스택 로컬
    (stack:fff4/fff8)이 addrtied가 돼 mergeByDatatype blob에서 빠짐(stack over-merge 해결, 실측).
  - **moveIntersectTests 충실 포팅**(d265c2a): 병합 survivor의 stale `false` 캐시 무효화(C++ variable.cc:
    1091). cover 정확 계산 시 stale-false로 인한 over-merge 방지(잠재 선행수정).
  - OutputPrototype AddInstance 제거 + 스택 심볼 addrtied(f66a2b5).
- **남은 단 하나의 블로커 (정밀 규명, 최심층)**: 루프 본문 누산기 INT_ADD 출력 `register:0x4`가 스택
  로컬 `local_c`와 **통합 안 됨**. SSA: `local_cT = MULTIEQUAL register:0x4#uVar2 unique#uVar2`(phi 출력
  =local_c, 입력=uVar2 별도) -> printer가 `uVar2 = local_c + local_8`(dead). MergeMarker가 phi 입력
  register:0x4를 출력 stack:fff4와 병합했다가(mergerequired SETHIGH 확인) 다른 register:0x4 SSA 버전이
  uVar2로 남음 = **gcd iVar1과 같은 loop-snapshot(trimOpOutput) 머신이 누산기 케이스에서 snapshot 버전을
  로컬과 통합 못 함**. 여러 register:0x4 SSA 버전 중 어느 게 phi 입력/snapshot인지 + MergeOp의 phi-trim이
  왜 입력을 trim하는지가 핵심.
- **다음 세션 진입점**: `merge.go MergeOp`(phi 입력/출력 trim 결정, Phase 2 cover) + `trimOpOutput`(snapshot
  생성, gcd는 loop-cond phi만 처리 -- 누산기 non-cond phi로 확장). gcd 회귀 주의(loop-snapshot 공유). 정렬
  후 #2(BuildFromVarnodes 재사용) 재적용 -> counted_loop 5/5 기대.
- **진단 재현**: buildGcd 패턴 + counted_loop 바이트(tree_goldens_diag_test.go:64). MERGE_DBG 계측(SETHIGH
  action-tagged + ISECT/CACHE-HIT + cover-block dump, 이번 세션 제거됨)으로 register:0x4의 여러 SSA 버전
  High 이동 추적. dumpSSA(GCD_DUMP=1)로 phi 구조 확인.
- **수정 대상 Go 파일**: `pkg/pcode/highvariable.go`(Cover.Rebuild/getCover), `pkg/pcode/merge.go`
  (computeHighIntersection/highBlockIntersection), `pkg/pcode/scopelocal.go`(#2 BuildFromVarnodes 재사용).
  ForLoops(for-fold)는 병합 풀리면 자동 따라올 가능성(production은 같은 SSA로 for-fold 성공).
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
