# 다음 세션 프롬프트 (2026-07-03 작성, master `8d007b5`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다.** 이번 세션에서
문서의 "Fix A/B"(스택 인식을 heritage 이전으로 이동 / def-use walk 패치)가 **오진**으로 판명돼 폐기됐다 --
Ghidra의 실제 메커니즘을 다시 읽어 맞춘 것이 정답이었다.

## 현재 상태 (master `8d007b5`, 전 패키지 그린)
- 트리 전체 골든 맵 **10/10** byte-identical(`TestTreeFullGoldenMap`, TREE_MAP=1).
- x64 breadth corpus **7/8** MATCH(`TestX64CorpusGoldenMap`, X64_CORPUS=1): add4/poly4/max3/sum_to_n/sum_array/classify/grid_score. process만 잔여.
- production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*` 전부 pass. `go test ./...` 클린
  (pkg/loader symbols_test 3건 missing-.exe 사전실패는 무시 -- untracked fixture).

## 이번 세션 완료 (건드리지 말 것, 충실+검증완료)
**grid_score 선언순서 = DONE (x64 corpus 6/8 -> 7/8).** 이전 세션이 세운 "얽힘" 가설(stack space index 변경이
RestructureVarnode/ActionInferTypes 타입-스냅샷 타이밍과 얽혀있다)은 ACTTRACE 실측으로 **반증**됐다 -- stack idx
0 vs high에서 counted_loop의 counted-action 트레이스가 바이트 동일(pass 수/스냅샷 타이밍 불변, 타입 추론은
typeOrder 단조하강 fixpoint라 순서 무관). 진짜 근본은 printc 선언-대표(representative) 선택이 loc_tree 순서에
의존하던 포팅 버그였다.
- 근본: `pkg/pcode/printc.go collectSymbols`가 named HighVariable 선언 대표를 loc_tree first-wins로 골라,
  stack space index가 바뀌면 rep가 stack/register 인스턴스 사이로 뒤집히며 선언 순서 + 타입 소스가 같이
  이동했다. Ghidra는 대표를 `HighVariable::getNameRepresentative`(variable.cc:492, compareName
  variable.cc:456)로 골라 인스턴스 순서 무관, 선언은 scope 심볼맵 주소순 방출(`emitScopeVarDecls`
  printc.cc:2650).
- 수정 2건(master `8d007b5`): (1) `pkg/bridge/bridge.go registerSpaceByIndex`가 maxIdx 스캔에서 const
  space(Index=0xFFFF)를 포함해 `maxIdx+1`이 uint16 overflow -> stack index 0으로 떨어지던 문제 -- const
  space를 maxIdx 스캔에서 제외(Ghidra는 const index 0 고정 translate.cc:362, spacebase는 로드시 실공간 위
  append architecture.cc:563). (2) `pkg/pcode/printc.go collectSymbols` + 신규 `pkg/pcode/
  action_name_vars.go highNameRepresentativeLive`로 선언 대표를 live-제한 `getNameRepresentative`로 재선택
  (live 제한 이유: `HighVariable::remove` variable.cc:515 미포팅 -- 상세는 CHANGELOG 2026-07-03).
- 검증(감독관 실행): `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1 TestX64CorpusGoldenMap` 7/8,
  production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*` 전부 PASS, `go test ./...` 클린.
- **process는 별개 근본 확정** -- grid_score와 "공통 근본" 추정은 반증됐다. 아래 옵션 2 참고.

## 다음 작업 (아래 2개 중 택1, 전부 비스택 -- 사용자 steer)

### 옵션 1 [권장] process 나머지 기능 (큰 별개, correctness)
- grid_score와 "공통 근본" 추정은 반증됨(이번 세션 ACTTRACE 실측) -- process는 별개 근본 4건, 각각 독립.
- (1) undefined4 diamond 타입누수: 근본 = `ActionDoNothing`/`RemoveDoNothingBlock` 미포팅
  (coreaction.cc:3473-3497, funcdata_block.cc:327; Go 스텁 coreaction.go:592/funcdata.go:614).
- (2) 포인터-파라미터 배열 deref 누락: golden `iVar1 = *(int*)(param_1+(longlong)local_14*4)`(param_1[i], heap)를
  우리는 통째 누락 -> iVar1 미초기화 read(실제 correctness 갭). RulePtrArith/포인터-파라미터 배열 인덱스 복구.
- (3) 64비트 signed division 반환 타입: golden `ulonglong ...(longlong)local_c/(longlong)local_10 & 0xffffffff`.
- (4) 단축평가 `&&` + comma 연산자 조건 구조화(golden) vs 우리 if/else-if/else.
- 성공 기준: `X64_CORPUS=1 TestX64CorpusGoldenMap` process MATCH(7/8->8/8). (1)은 C++ 대응 확인됨, (2)(3)(4)는
  C++ 원본 대응 함수 미조사 -> 조사부터.

### 옵션 2 [미션 #1 게이트] H8-debt-2: tree를 production 경로로
- 트리 스택복구가 이제 충실+우수하므로 `bridge.Decompile`의 41-call subset을 `db.BuildUniversalAction+Perform`
  으로 교체 시도. 성공 시 bespoke `ActionStackPtrFlow` 완전 은퇴 가능. production cspec/EntryPoint 배선을
  트리와 맞춰야 함(decompile.go 자체 cdecl 모델). 큰 별도 작업.

## known-gap (별도, 낮은 우선순위)
- const space가 여전히 0xFFFF(Ghidra는 const이 loc_tree 맨 앞 index 0, 우리는 맨 뒤) -- 현 corpus 무해(실측),
  const=0 이관은 별도 세션.
- `HighVariable::remove`(variable.cc:515) 미포팅 = 인스턴스 수명 갭의 근본. `printc.go collectSymbols`의
  live-제한(highNameRepresentativeLive)이 국소 보정이고, 완전 해소는 remove 포팅(후속 과제).

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (7/8 유지/증가)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam'`
- `go test ./...` (symbols_test 3건 missing-.exe 무시)

## 방법론 (이번 세션 검증됨)
- 팀 모델: 어려운 근본 규명은 fable, 구현/진단은 Opus 서브에이전트(worktree 격리), 각 fix의 C++ 근거를
  감독관이 직접 스팟체크하고 게이트 전 승인. green이어도 unfaithful이면 기각. 고위험 변경은 worktree +
  env 플래그 A/B 토글 -> parity 확인 후 플립 -> 플래그 제거 순.

## 참고 문서
- `docs/STATUS.md`(미시작 전문), `docs/CHANGELOG.md`(2026-07-03 항목), 메모리 `project_gosleigh`.
- C++: funcdata.cc(spacebase:230-269), ruleaction.cc(RuleLoadVarnode:4193-4361, RuleAddMultCollapse:4113-4182,
  correctSpacebase:4193-4204), cast.cc(markExplicitUnsigned:38-71), variable.cc(getNameRepresentative:492,
  compareName:456, remove:515), translate.cc(const space index 0:362), architecture.cc(addSpacebase:563),
  varmap.cc(gatherVarnodes/RangeHint), printc.cc(emitScopeVarDecls:2650, push_integer:1425),
  coreaction.cc(ActionDoNothing:3473-3497), funcdata_block.cc(RemoveDoNothingBlock:327).
- Go 스택 경로: pkg/pcode/funcdata.go(Spacebase), pkg/address/space.go(spacebase infra), pkg/bridge/bridge.go
  (buildFaithfulStackSpace/bindLoadStoreSpaces/registerSpaceByIndex), pkg/pcode/rules_loadstore.go,
  rules_arith.go(RuleAddMultCollapse), pkg/pcode/action_name_vars.go(getNameRepresentative/
  highNameRepresentativeLive), cast.go(markExplicitUnsigned), pkg/pcode/printc.go(collectSymbols).
