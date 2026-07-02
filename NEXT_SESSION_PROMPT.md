# 다음 세션 프롬프트 (2026-07-03 작성, master `eadd9c0`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다.**

## 현재 상태 (master `eadd9c0`, 전 패키지 그린)
- **미션 #1 게이트 달성**: production `bridge.Decompile`이 41-call 손정렬 subset을 버리고 universal-action
  트리 경로로 교체됨. production과 트리가 이제 같은 경로를 공유한다.
- 트리 전체 골든 맵 **10/10** byte-identical(`TestTreeFullGoldenMap`, TREE_MAP=1).
- x64 breadth corpus **7/8** MATCH(`TestX64CorpusGoldenMap`, X64_CORPUS=1): add4/poly4/max3/sum_to_n/
  sum_array/classify/grid_score. process만 잔여 -- 별개 deep-debt로 확정(아래 참고, H8-debt-2로 자동 해소
  안 됨을 이번 세션에 실측 확인).
- production `TestMSVC_{CountedLoop,SumList,AbsVal,Classify2,Gcd}` 5/5 byte-identical, `TestAARCH64`/
  `TestX8664`/`TestX64RegParam` 전부 pass. `go test ./...` 클린(pkg/loader symbols_test 3건 missing-.exe
  사전실패는 무시 -- untracked fixture).

## 이번 세션 완료 (건드리지 말 것, 충실+검증완료)
직전 세션(process gap1 + ActionDoNothing, master `c4d85ea`)에 이어진 세션. 미션 #1 게이트("트리를 production
경로로")를 달성했다.

**H8-debt-2 완료 -- production을 universal-action 트리로 (master `eadd9c0`)**
- **근본**: 트리와 41-call subset은 액션 목록이 아니라 단 하나의 배선(setup wiring) 차이만 있었다. production
  콜러가 `bridge.Result`를 cspec 없이(CspecData=nil) 만들어 cspec-less cdecl + 하드코딩 EAX 반환 + bespoke
  `ActionStackPtrFlow`를 강제하고 있었다. 트리는 cspec `<stackpointer>`가 있어야 faithful ActionSpacebase +
  RuleLoadVarnode/RuleStoreVarnode 경로가 실제 StackSpace를 갖는다.
- **구현**: Step1(하네스 cspec/EntryPoint 배선 -- `msvc_diag_test.go` `runPipelineGhidra`에 CspecPath
  x86gcc.cspec + EntryPoint 추가) + Step2(`Decompile` 본문을 `db.BuildUniversalAction(nil)+
  BuildDefaultGroups()+SetCurrent("decompile").Perform(fd)`로 교체, ApplyCallingConvention/bespoke
  ActionStackPtrFlow/수동 Heritage/DeadCode/Merge/InferTypes 손정렬 41-call 전부 제거).
- **게이트(감독관 독립 검증)**: `TestMSVC_{CountedLoop,SumList,AbsVal,Classify2,Gcd}` 5/5 byte-identical +
  `TestAARCH64`/`TestX8664`/`TestX64RegParam` PASS + tree 10/10 + x64 corpus 7/8(무회귀) + `go test ./...` 클린.
- **Step3(bespoke `ActionStackPtrFlow` 파일 삭제) = 후속, 아래 다음 작업 (b) 참고**: `action_stack_ptr_flow.go`가
  legacy 하네스 ~15개(`loader_test.go` 직접-heritage 테스트, 비-Ghidra `runPipeline`, diag 테스트)에서 아직
  직접 호출된다. production 경로에선 이미 은퇴했으나 파일 삭제는 그 하네스들을 트리로 이전한 뒤에나 가능하다.
- **정정(중요, 직전 세션 기록 오류)**: 직전 세션 기록은 "H8-debt-2가 merge/structuring/snapshot parity를
  정면으로 다루므로 process 3갭이 그 과정에서 해소될 경로"라고 예측했다. 실측 결과 그렇지 않았다 -- x64
  corpus는 애초에 트리 경로(`BuildUniversalAction+Perform`)로 돌고 있었으므로 process는 이미 트리 위에서
  발현 중이었고, 이번 배선교체(production을 트리로)는 process와 무관하다(x64 corpus 여전히 7/8, process
  변화 없음). process 3갭은 H8-debt-2 완료 후에도 트리 액션 내부의 별개 deep-debt로 남는다.

## 다음 작업 (우선순위)
H8-debt-2 본체(미션 #1 게이트)는 끝났다. 남은 작업 셋을 우선순위 순으로 진행한다.

### (a) [최우선] process 잔여 3갭 -- deep-debt, 별도 세션
gap2/gap3/gap4는 return-recovery/type-snapshot/merge/structuring 파이프라인 재작업으로 수렴하는 트리 액션
내부 부채다. **H8-debt-2 완료로는 자동 해소되지 않는다(위 정정 참고, 실측 확인)**. 독립 세션으로 gap2/gap3/
gap4를 개별 시도하지 말 것(gap2 SEXT 가드 시도가 gcd 회귀로 기각된 전례 있음) -- 파이프라인 재작업으로
묶어서 접근.
- **gap2(64비트 signed division 반환 렌더링)**: golden `ulonglong ...(longlong)local_c/(longlong)local_10 &
  0xffffffff`. 진짜 근본(구현 시도는 미커밋, gcd 회귀로 기각) = 과축소 주체 `RuleSubCommute`
  (rules_ext.go:225). Go의 `RuleSubvarZext`(return narrowing)가 ZEXT를 RuleSubCommute의 overlap 체크 전에
  제거해 순서가 이탈한다. 충실 SEXT 가드 포팅 시 gcd가 회귀함(packed .sla가 dividend를 INT_OR로 인코딩하는데
  Ghidra는 INT_SEXT로 처리 -- `RuleOrSextForm` 미정규화).
- **gap3(단축평가 `&&` 조건 구조화)**: 진짜 근본은 RuleBlockOr/comma가 아니다(RuleBlockOr는 발화하나 이미
  붕괴된 그래프 위에서 오극성으로 발화, condexe는 process에서 애초 미발화). 실체 = 비대칭 clamp의
  단일-스토어 블록(v=hi)이 sibling count 블록으로 오폴딩(블록구조화 collapse 또는 RuleStoreVarnode heritage
  결함).
- **gap4(undefined 타입 누수)**: 진짜 근본은 스냅샷 타이밍이 아니다. MSVC eax 스크래치 임시가 스택-로컬로
  미접힘(Merge/copyprop parity 갭).
- **C++ 참조**: `coreaction.cc`(ActionReturnRecovery), `merge.cc`(HighVariable 병합), block 구조화 rule군
  (`ruleaction.cc` 계열, RuleBlockOr/RuleSubCommute/RuleSubvarZext -- Go 측 rules_ext.go:225 대응).
- **수정 대상 Go 파일**: `pkg/pcode/rules_ext.go`(RuleSubCommute/RuleSubvarZext 순서), `pkg/pcode/
  coreaction.go`(ActionReturnRecovery), `pkg/pcode/merge.go`, 구조화 rule(`pkg/pcode/rules_*.go`,
  `block_*.go`).
- **성공 기준**: `X64_CORPUS=1 TestX64CorpusGoldenMap`에서 process MATCH(7/8 -> 8/8) + `TREE_MAP=1
  TestTreeFullGoldenMap` 10/10 무회귀 + production `TestMSVC*` 무회귀.

### (b) H8-debt-2 Step3 -- bespoke `ActionStackPtrFlow` 파일 삭제 (레거시 하네스 트리 이전)
- **현상**: `pkg/pcode/action_stack_ptr_flow.go`는 production에서는 은퇴했으나(master `eadd9c0`) legacy
  테스트 하네스 ~15개(`loader_test.go`의 직접-heritage 테스트, 비-Ghidra `runPipeline` 경로, diag 테스트)에서
  여전히 직접 호출된다.
- **작업**: 각 하네스를 트리 경로(`db.BuildUniversalAction(nil)+BuildDefaultGroups()+
  SetCurrent("decompile").Perform(fd)`, cspec+EntryPoint 배선 필수)로 이전. 하네스마다 cspec 유무/
  EntryPoint 여부가 달라 개별 검토 필요(트리는 cspec `<stackpointer>` 없이는 스택 로컬 미복구).
- **완료 후**: `action_stack_ptr_flow.go` + 관련 stub 삭제, 저장소 전체 grep으로 잔존 참조 0건 확인.
- **성공 기준**: `action_stack_ptr_flow.go` 참조 파일 0개, `go test ./...` 클린, tree 10/10 + x64 corpus 7/8
  무회귀.

### (c) [대형] breadth -- 실 x64/struct/switch 함수 + 새 골든
골든 11개(거의 x86-32 + 사소한 x64/aarch64 add_ret)뿐. x64 실함수(register params RCX/RDX..) 성공 필요
(사용자 명시 요구). struct/union/switch/jumptable/미포팅 opcode(`docs/PARITY_AUDIT.md`). 새 Ghidra 골든
생성(Ghidra 12 `C:\ghidra12`, `testdata/ghidra_decompile.py`).
- x64 breadth corpus(`testdata/x64_corpus/`)는 8개 실함수(add4/poly4/max3/sum_to_n/sum_array/classify/
  grid_score/process) 갭 맵이 `TestX64CorpusGoldenMap`(X64_CORPUS=1)로 이미 존재. 다음 확장은 struct/union/
  switch/jumptable을 쓰는 신규 샘플 함수 추가 + 대응 Ghidra 골든 생성.

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
- 이번 세션은 예측("H8-debt-2가 process를 해소할 것")이 실측으로 반증된 사례이기도 하다 -- 완료 보고 전에
  실제 골든 카운트(process 여전히 MISMATCH)로 재확인할 것. 배선/경로 교체 작업은 "같은 서브시스템을 건드린다"
  와 "그 서브시스템 내부 버그를 고친다"를 구분해서 예측할 것.

## 참고 문서
- `docs/STATUS.md`(미시작 전문 + 다음 작업 우선순위 1/2/3), `docs/CHANGELOG.md`(2026-07-03 "H8-debt-2 완료"
  항목), 메모리 `project_gosleigh`.
- C++: `coreaction.cc`(ActionDatabase::universalAction, ActionReturnRecovery, ActionDoNothing:3473-3497),
  `funcdata_block.cc`(RemoveDoNothingBlock:327), `merge.cc`(HighVariable 병합).
- Go: `pkg/bridge/decompile.go`(Decompile, 트리 배선), `pkg/bridge/bridge.go`(Build, cspec/EntryPoint 계약),
  `pkg/pcode/action_stack_ptr_flow.go`(Step3 삭제 대상), `pkg/pcode/rules_ext.go`(RuleSubCommute:225).
