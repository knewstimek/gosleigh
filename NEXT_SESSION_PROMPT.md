# 다음 세션 프롬프트 (2026-07-03 작성, master `c4d85ea`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다.**

## 현재 상태 (master `c4d85ea`, 전 패키지 그린)
- 트리 전체 골든 맵 **10/10** byte-identical(`TestTreeFullGoldenMap`, TREE_MAP=1).
- x64 breadth corpus **7/8** MATCH(`TestX64CorpusGoldenMap`, X64_CORPUS=1): add4/poly4/max3/sum_to_n/
  sum_array/classify/grid_score. process만 잔여(아래 참고).
- production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*` 전부 pass. `go test ./...` 클린
  (pkg/loader symbols_test 3건 missing-.exe 사전실패는 무시 -- untracked fixture).

## 이번 세션 완료 (건드리지 말 것, 충실+검증완료)
직전 세션(grid_score 선언순서, master `8d007b5`)에 이어진 세션. process의 4개 근본 후보 중 2건을 닫고,
남은 3건의 진짜 근본을 재규명해 확정했다.

**1) gap1 완료 -- 포인터-파라미터 배열 deref (master `7a7b203`)**
- 현상: golden `iVar1 = *(int *)(param_1 + (longlong)local_14 * 4);` 누락 -> iVar1 미초기화 read.
- 근본: `pkg/pcode/printc.go` emitOps가 unique-space 출력을 무조건 억제(continue), 예외는 named MULTIEQUAL
  단독 consumer뿐이었음(Gosleigh 근사). Ghidra `PrintC::emitBlockBasic`(printc.cc:2836)는 `isImplied()`로만
  억제, unique space 여부로 억제하지 않음 -- explicit def는 unique space라도 emit된다.
- 수정: 억제 가드에 `out.IsExplicit() && out.NumDescend()>0` 예외 추가. `NumDescend()>0`은 충실 프록시
  -- `ActionMarkExplicit`(coreaction.cc:3244)는 `ActionDeadCode` 이후 실행(coreaction.cc:3252, beginDef(0)가
  no-descendant dead op을 print 전에 제거)이라 실제 explicit def는 print 시점에 항상 live descendant를 가짐.
- KNOWN-GAP: 이 가드가 없으면 우리 faithful-stack ActionDeadCode를 통과해 잔존하는 `sub rsp,0x18` 프레임
  COPY(unique, explicit, NumDescend==0)가 `uVarN = 0x18;`로 샌다 -- 그 잔존 COPY 자체는 Ghidra처럼
  ActionDeadCode가 제거해야 하나 후속 과제, 그때까지 NumDescend>0가 대리.
- 게이트: tree 10/10, x64 corpus 7/8(deref 라인 정확 렌더), production green.

**2) ActionDoNothing/RemoveDoNothingBlock 충실 포팅 (master `c4d85ea`)**
- 이전에 no-op 스텁이던 `ActionDoNothing.Apply`(coreaction.go:594)/`Funcdata.RemoveDoNothingBlock`
  (funcdata.go:713)을 C++ 그대로 포팅. 신규 `pkg/pcode/funcdata_donothing.go`: pushMultiequals
  (funcdata_block.cc:84), opZeroMulti(:177), descendantsOutside(:233), blockRemoveInternal(:254, MULTIEQUAL
  pushdown + edge rewire 포함 -- 불충분한 BlockGraph.SpliceBlock 경로 아님), RemoveDoNothingBlock(:327).
  `pkg/pcode/block_basic.go`에 HasOnlyMarkers(block.cc:2578)/IsDoNothing(:2596)/UnblockedMulti(:2534)
  술어(switch-target/BRANCHIND 가드 포함). `ActionDoNothing.Apply`(coreaction.cc:3473): 블록 스캔 ->
  isDoNothing && unblockedMulti(0) -> removeDoNothingBlock, count++(self-loop do-nothing 블록은 플래그만).
- **A/B 결과(결정적, "do-nothing 제거가 gap3/gap4 공통 근본"이라는 이전 세션 가설(gap34-invest)을 반증)**:
  액션이 실제 발화(classify/grid_score/process(2회)에서 do-nothing 블록 제거)하지만 grid_score/max3/
  classify/sum_array 골든은 undefined4 MATCH 유지(do-nothing 제거 단독으로 int-flip 안 됨), process도 변화
  없음(&& 미렌더, undefined 유지). 커밋은 유지 -- 충실 포팅 + 무회귀 + H8-debt-2 선행 인프라이기 때문.
- 미구현(주석 명시): jump-table 제거, blockRemoveInternal의 unreachable-path descend2Undef -- 현재
  do-nothing 호출 경로에서 도달 안 함.
- 게이트: tree 10/10, x64 corpus 7/8, production 전부 PASS.

**3) 판정: process 잔여 3갭(gap2/gap3/gap4) = deep-debt, H8-debt-2와 분리 불가**
gap34-v2 재규명(실제 MSVC 디스어셈블 + Ghidra golden ground-truth 대조)으로 확정. process 트리 출력은
코스메틱이 아니라 의미적으로 붕괴돼 있다 -- count++가 범위 밖 가드 안(정답은 범위 안)에 있고, 범위 안
v(local_18)는 미초기화, 로드 대입문 드롭(gap1로 그 중 하나는 닫힘).
- **gap2(64비트 signed division 반환 렌더링)**: 진짜 근본(구현 시도는 미커밋, gcd 회귀로 기각) = 과축소
  주체 `RuleSubCommute`(rules_ext.go:225). Go의 `RuleSubvarZext`(return narrowing)가 ZEXT를 RuleSubCommute의
  overlap 체크 전에 제거해 순서 이탈. 충실 SEXT 가드 포팅 시 gcd 회귀(packed .sla가 dividend를 INT_OR로
  인코딩하는데 Ghidra는 INT_SEXT로 처리 -- RuleOrSextForm 미정규화). return-recovery/type-snapshot 타이밍과
  얽혀 있음.
- **gap3(단축평가 `&&` 조건 구조화)**: 진짜 근본은 RuleBlockOr/comma가 아니다(RuleBlockOr는 발화하나 이미
  붕괴된 그래프 위에서 오극성으로 발화, condexe는 process에서 애초 미발화). 실체 = 비대칭 clamp의
  단일-스토어 블록(v=hi)이 sibling count 블록으로 오폴딩(블록구조화 collapse 또는 RuleStoreVarnode heritage
  결함).
- **gap4(undefined 타입 누수)**: 진짜 근본은 스냅샷 타이밍이 아니다. MSVC eax 스크래치 임시가 스택-로컬로
  미접힘(Merge/copyprop parity 갭).
- **결론**: 3갭 전부 return-recovery/type-snapshot/merge/structuring 파이프라인 재작업으로 수렴한다 --
  H8-debt-2와 분리할 수 없다. process는 코퍼스 중 유일하게 3-way clamp + count + 64비트 나눗셈 +
  early-return이 eax를 공유하는 특이 케이스다.
- 검증(감독관 실행): `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1 TestX64CorpusGoldenMap` 7/8,
  production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*` 전부 PASS, `go test ./...` 클린.

## 다음 작업 (H8-debt-2, 단일 우선순위)
process의 잔여 3갭이 return-recovery/type-snapshot/merge/structuring 파이프라인으로 수렴한다는 게 이번
세션 결론이라, process를 별도 옵션으로 더 이상 취급하지 않는다(deep-debt로 재분류, 독립 세션으로 시도하지
말 것). 다음 세션은 미션 #1 게이트인 H8-debt-2 하나에 집중한다.

- **현상**: production `bridge.Decompile`(decompile.go)이 여전히 41-call 손정렬 subset. 트리
  (`db.BuildUniversalAction+Perform`)는 이제 tree 10/10 + x64 corpus 7/8로 production보다 우수하지만 아직
  production 경로로 승격되지 않았다. bespoke `ActionStackPtrFlow`도 트리와 이중 유지 중.
- **작업**: `bridge.Decompile`의 41-call subset을 `db.BuildUniversalAction(nil) + SetCurrent("decompile").
  Perform(fd)` 경로로 교체(또는 옵션 플래그 공존 후 전환). production cspec/EntryPoint 배선을 트리 테스트
  (runTreeCase)와 맞춰야 함(decompile.go가 자체 cdecl 모델 사용). 11개 production 골든(`TestMSVC*`)을 트리
  경로로 검증하고 mismatch 골든별 규명. 성공 시 bespoke ActionStackPtrFlow 완전 은퇴 가능. `ActionDoNothing`
  (master `c4d85ea`)은 이 작업의 선행 인프라.
- **process 3갭과의 관계**: gap2/gap3/gap4는 이 작업(특히 return-recovery/merge/structuring 재작업) 과정에서
  함께 조사/해소될 가능성이 높은 경로다 -- 별도 세션으로 독립 시도하지 말 것(gap2 SEXT 가드 시도가 gcd
  회귀로 기각된 전례 있음).
- **C++ 참조**: `coreaction.cc`(ActionReturnRecovery, ActionDoNothing:3473-3497), `funcdata_block.cc`
  (RemoveDoNothingBlock:327), `merge.cc`(HighVariable 병합), block 구조화 rule군(`ruleaction.cc` 계열,
  RuleBlockOr/RuleSubCommute/RuleSubvarZext -- Go 측 rules_ext.go:225 대응).
- **수정 대상 Go 파일**: `pkg/bridge/bridge.go`(Decompile), `pkg/pcode/decompile.go`, `pkg/pcode/action.go`
  (universalAction 배선), 필요 시 `pkg/pcode/rules_ext.go`(RuleSubCommute/RuleSubvarZext 순서), `merge.go`,
  구조화 rule(`rules_*.go`, `block_*.go`).
- **성공 기준**: production `TestMSVC*` 전부 트리 경로로 그린 + 41-call subset(decompile.go) 제거. 부수
  성과로 `X64_CORPUS=1 TestX64CorpusGoldenMap` process MATCH(7/8 -> 8/8)를 목표로 삼되, 이번 작업 범위 안에서
  필수 요건은 아니다(전체 파이프라인 정합이 먼저).

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
- A/B 실측이 가설을 반증할 수 있다 -- 포팅 자체가 충실하면 유지하고, 반증된 가설만 따로 폐기한다. green이어도
  unfaithful이면 기각. 고위험 변경은 worktree + env 플래그 A/B 토글 -> parity 확인 후 플립 -> 플래그 제거 순.

## 참고 문서
- `docs/STATUS.md`(미시작 전문), `docs/CHANGELOG.md`(2026-07-03 항목), 메모리 `project_gosleigh`.
- C++: printc.cc(emitBlockBasic:2836, emitScopeVarDecls:2650), coreaction.cc(ActionMarkExplicit:3244,
  baseExplicit:3009, ActionDeadCode beginDef:3252, ActionDoNothing:3473-3497), funcdata_block.cc
  (pushMultiequals:84, opZeroMulti:177, descendantsOutside:233, blockRemoveInternal:254,
  RemoveDoNothingBlock:327), block.cc(removeFromFlow:1545, UnblockedMulti:2534, HasOnlyMarkers:2578,
  IsDoNothing:2596), variable.cc(getNameRepresentative:492, compareName:456, remove:515).
- Go: `pkg/pcode/printc.go`(emitOps, collectSymbols), `pkg/pcode/coreaction.go`(ActionDoNothing),
  `pkg/pcode/funcdata_donothing.go`(신규), `pkg/pcode/block_basic.go`(신규 술어), `pkg/pcode/rules_ext.go`
  (RuleSubCommute:225).
