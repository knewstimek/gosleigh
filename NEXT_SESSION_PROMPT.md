# 다음 세션 프롬프트 (2026-07-02 작성, master `5bf90f9`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다.** 이번 세션에서
문서의 "Fix A/B"(스택 인식을 heritage 이전으로 이동 / def-use walk 패치)가 **오진**으로 판명돼 폐기됐다 --
Ghidra의 실제 메커니즘을 다시 읽어 맞춘 것이 정답이었다.

## 현재 상태 (master `5bf90f9`, 커밋 5개 **미푸시**, 전 패키지 그린)
- 트리 전체 골든 맵 **10/10** byte-identical(`TestTreeFullGoldenMap`, TREE_MAP=1).
- x64 breadth corpus **6/8** MATCH(`TestX64CorpusGoldenMap`, X64_CORPUS=1): add4/poly4/max3/sum_to_n/sum_array/classify.
- production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*` 전부 pass. `go test ./...` 클린
  (pkg/loader symbols_test 3건 missing-.exe 사전실패는 무시 -- untracked fixture).

## 이번 세션 완료 (건드리지 말 것, 충실+검증완료)
**grid_score/process 스택프레임 복구 = DONE.** bespoke가 raw pointer 쓰레기(`(int*)(lVar1-24)`)로 실패하던
두 함수의 스택 프레임을 Ghidra 충실 spacebase 경로로 완전 복구(감독관이 실제 출력으로 검증).
- 근본: Ghidra `Funcdata::spacebase`(funcdata.cc:230-269)가 모든 RSP 계열 varnode(input/sub-result/phi)에
  spacebase 마킹 -> 이미 충실 포팅돼 있던 `RuleLoadVarnode`/`RuleStoreVarnode`가 `[rsp+k]`를 스택 varnode로
  변환. `sub rsp,N` 오프셋 누적 = RuleSub2Add+RuleCollapseConstants+RuleAddMultCollapse(ruleaction.cc:4113-4182).
  x86-32 EBP도 같은 경로(RulePropagateCopy가 `MOV EBP,ESP`를 인라인 -> `[EBP+k]`=`[ESP_input+k]`).
- 커밋: `602dde8`(flag-gated) -> `c87debe`(플립: 트리 기본값, 플래그 제거) -> `721cac8`(docs) ->
  `425acb1`(markExplicitUnsigned: grid_score `& 1U`, cast.cc:38-71 충실 포팅, H9 leftover 해소) -> `5bf90f9`(docs).
- **구조 분리**: 충실 경로는 universal-action 트리 기본값. production `bridge.Decompile`(41-call subset)은
  ActionSpacebase/RuleLoadVarnode를 안 돌리므로 bespoke `ActionStackPtrFlow`를 그대로 유지. bespoke 완전
  은퇴는 트리가 production 경로가 될 때(H8-debt-2).

## 다음 작업 (아래 3개 중 택1, 전부 비스택 -- 사용자 steer)

### 옵션 1 [권장, 두 문제 동시 해결 가능] grid_score decl-order = process 타입누수의 공통 근본
- **현상**: grid_score 유일 잔여 diff = 선언 순서(golden은 `int iVar1;`를 스택 로컬보다 먼저; 우리는 스택 로컬
  먼저). 정렬 규칙 자체는 충실(SymbolEntry addr=(space idx,offset); printc.cc:2650 / CompareLocDef
  varnode_bank.go:57).
- **진짜 근본(grid7 확정)**: `pkg/bridge/bridge.go registerSpaceByIndex`가 stack space Index=maxIdx+1로
  잡는데 maxIdx가 const space(index 65535)까지 스캔 -> `65535+1` **uint16 overflow -> stack index 0**(최저)
  -> 스택 로컬이 전부 앞으로 정렬. Ghidra는 stack space가 高 index.
- **얽힘(고위험, 이게 본체)**: overflow만 고쳐 stack index를 높이면 grid_score 순서는 맞으나 counted_loop가
  `undefined4->int`(타입+순서), sum_to_n/sum_array 깨짐(X64 4/8, tree 9/10). stack space의 loc_tree 위치가
  `RestructureVarnode`/`ActionInferTypes` 심볼 스냅샷 타이밍(이 세션 초반 TYPE-LEAK 기계)과 order-dependent.
  이 type-snapshot loc_tree-order 의존성이 **process의 diamond 타입누수(undefined4) 근본과 동일**로 추정 ->
  한 번 풀면 둘 다 해결 가능성.
- **수정 대상 Go**: `bridge.go registerSpaceByIndex`(overflow: const space 제외) + `scopelocal.go`/`rangehint.go`
  의 RestructureVarnode/mapStateStackTypes loc_tree-order 의존성(상단 TYPE-LEAK 진단 섹션 참조).
- **성공 기준**: `X64_CORPUS=1 TestX64CorpusGoldenMap` grid_score MATCH(6/8->7/8) + `TREE_MAP=1` 10/10 무회귀
  (counted_loop/sum_to_n/sum_array 무회귀가 관건) + production 무회귀.
- **주의**: print-time "레지스터 임시를 스택 앞에 재정렬"은 heuristic이라 금지. fresh worktree + 전 매트릭스 가드.

### 옵션 2 process 나머지 기능 (큰 별개, correctness)
- 포인터-파라미터 배열 deref 누락: golden `iVar1 = *(int*)(param_1+(longlong)local_14*4)`(param_1[i], heap)를
  우리는 통째 누락 -> iVar1 미초기화 read(실제 correctness 갭). RulePtrArith/포인터-파라미터 배열 인덱스 복구.
- 64비트 signed division 반환 타입: golden `ulonglong ...(longlong)local_c/(longlong)local_10 & 0xffffffff`.
- 단축평가 `&&` + comma 연산자 조건 구조화(golden) vs 우리 if/else-if/else.
- 성공 기준: `X64_CORPUS` process MATCH(6/8->증가). 각 항목 C++ 원본 대응 미조사 -> 조사부터.

### 옵션 3 [미션 #1 게이트] H8-debt-2: tree를 production 경로로
- 트리 스택복구가 이제 충실+우수하므로 `bridge.Decompile`의 41-call subset을 `db.BuildUniversalAction+Perform`
  으로 교체 시도. 성공 시 bespoke `ActionStackPtrFlow` 완전 은퇴 가능. production cspec/EntryPoint 배선을
  트리와 맞춰야 함(decompile.go 자체 cdecl 모델). 큰 별도 작업.

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (6/8 유지/증가)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam'`
- `go test ./...` (symbols_test 3건 missing-.exe 무시)

## 방법론 (이번 세션 검증됨)
- 팀 모델: 어려운 근본 규명은 fable, 구현/진단은 Opus 서브에이전트(worktree 격리), 각 fix의 C++ 근거를
  감독관이 직접 스팟체크하고 게이트 전 승인. green이어도 unfaithful이면 기각. 고위험 변경은 worktree +
  env 플래그 A/B 토글 -> parity 확인 후 플립 -> 플래그 제거 순.

## 참고 문서
- `docs/STATUS.md`(미시작 전문), `docs/CHANGELOG.md`(2026-07-02 항목), 메모리 `project_gosleigh`.
- C++: funcdata.cc(spacebase:230-269), ruleaction.cc(RuleLoadVarnode:4193-4361, RuleAddMultCollapse:4113-4182,
  correctSpacebase:4193-4204), cast.cc(markExplicitUnsigned:38-71), variable.cc(getNameRepresentative:456-511),
  varmap.cc(gatherVarnodes/RangeHint), printc.cc(emitScopeVarDecls:2650, push_integer:1425).
- Go 스택 경로: pkg/pcode/funcdata.go(Spacebase), pkg/address/space.go(spacebase infra), pkg/bridge/bridge.go
  (buildFaithfulStackSpace/bindLoadStoreSpaces/registerSpaceByIndex), pkg/pcode/rules_loadstore.go,
  rules_arith.go(RuleAddMultCollapse), action_name_vars.go(getNameRepresentative), cast.go(markExplicitUnsigned).
