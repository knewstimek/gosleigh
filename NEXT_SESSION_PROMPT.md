# 다음 세션 프롬프트 (2026-07-02 작성)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. **x64 실함수(register param RCX/RDX) 성공이 명시 목표.**

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다** -- 이번 세션
RulePtrFlow 사례가 그 예(green이었지만 오역이라 dormant로 재수정). "green golden != 충실."

## 현재 상태 (master `59d11ad`, PUSHED, 전 패키지 그린)
- **트리 전체 골든 맵 10/10 byte-identical** (`TestTreeFullGoldenMap`, TREE_MAP=1).
- **x64 breadth corpus 6/8 MATCH** (`TestX64CorpusGoldenMap`, X64_CORPUS=1): add4/poly4/max3/sum_to_n/sum_array/classify.
  남은 2 = **grid_score, process** (둘 다 스택프레임 미복구).
- production `TestMSVC*` 무변경(faithful ActionInferTypes는 tree 전용, bridge/production은 legacy 격리).

## 2026-07-02 완료 (이번 세션, 13 커밋 -- 건드리지 말 것, 충실+무회귀)
1. **TYPE-LEAK 충실 포팅**(7커밋): `int local_N` vs golden `undefined4 local_N` 근본 규명 + 포팅 -> max3 MATCH.
   - 근본 = **심볼 스냅샷 타이밍**(전파 strength 아님, 그 가설은 반증됨): 로컬 선언 타입 = 마지막
     `ActionRestructureVarnode`의 committed varnode 타입 스냅샷. `ActionInferTypes`가 count 미보고
     (coreaction.cc:5422)라 순수 타입 커밋으로는 restructure 추가 pass 없음. no-diamond(counted_loop/max3/
     sum_to_n)는 fullloop iter-2가 1 pass 수렴 -> 마지막 restructure가 pre-typeprop TYPE_UNKNOWN 스냅샷 ->
     undefined4. diamond(else 분기, process)는 `ActionDoNothing`이 marker-only 블록 제거(count+1) -> iter-2
     2 pass -> pass2 restructure가 커밋 후 int -> int.
   - fixes: TypeOrder(datatype.go) / faithful ActionInferTypes tree 전용(action_infertypes.go, production은
     action_infertypes_legacy.go) / **ActionDeadCode flags=0**(uint-flood 근본: in-loop DeadCode 매 pass
     재실행으로 orphan `RAX=ZEXT(EAX)` 제거, coreaction.hh:560) / RangeHint symbol 타입(rangehint.go) /
     decl-from-symbol(printc.go) / **RulePtrFlow dormant**(오역 수정: hasTruncations 게이트로 non-truncated
     아키텍처에서 미발화, ruleaction.cc:9068).
2. **sum_array 데이터모델/printc**(3커밋): x64 6/8.
   - 데이터모델: cspec `<data_organization><long_size>` -> ProtoModel.LongSize -> printc normalizedBaseType.
     8바이트 signed = LLP64(Win x64) "longlong" / LP64 "long". (TypeFactory::sizeOfLong parity.)
   - printc 잔차: 8바이트 상수 LL 접미사 제거(`4LL`->`4`, push_integer isLongPrint parity) + cast==unary
     precedence(`*((int*)x)`->`*(int*)x`, dereference/typecast OpToken 둘 다 62, printc.cc:34-35).

## 다음 작업 [최우선] -- grid_score/process 스택프레임 복구 (x64 6/8 -> 증가)

### 진단 완료 (2026-07-02, GOSLEIGH_SPF_DEBUG 계측)
- **현상**: grid_score/process가 `stackOffsets=[]`(스택 로컬 전면 미복구) -> `uVar2=(int*)(uVar3-0x18)` +
  `uVar2[N]` 쓰레기. golden은 스택 로컬 + 정상 파라미터.
- **근본**: seed(RSP) 탐지는 성공. 실패는 `stackAddrOffset()`가 in-loop 접근 `INT_ADD(const, register:0x20/8W)`
  의 rsp base를 못 잡음. 두 원인: (1) 중첩루프 rsp phi cycle(상호참조 MULTIEQUAL -> buildStackOffsetMap
  action_stack_ptr_flow.go:550-575의 "모든 non-self 입력 매핑+동일offset" 규칙이 cycle에서 영구 미해결),
  (2) free rsp read(주소 INT_ADD의 rsp 입력이 def 없는 free varnode, def-use walk 도달 불가). grid_score/
  process 같은 근본.
- **C++ 대비 갭**: Ghidra는 RSP를 spacebase(pspec `<stackpointer>`)로 선언, 스택 접근 인식을 **heritage
  이전** raw p-code(`INT_ADD(RSP_input,const)`, phi/free 없음)에서 수행. `ActionStackPtrFlow::apply`
  (coreaction.cc:482)는 clog/extrapop 정리만. 우리는 bespoke def-use 전파를 **heritage 이후 1회**
  (action.go:1361 actstackstall) 실행 -> 파편화된 rsp라 단순 CFG만 커버. 코드 주석도 인지
  (action_stack_ptr_flow.go:222-224, heritage.go:936-937).

### 수정안 (docs/STATUS.md `### 미시작`에 전문)
- **A (정석 parity, 고위험)**: 스택 접근 인식을 heritage 이전으로 이동. raw INT_ADD(RSP_input,const) 변환 후
  stack space heritage(StackSlots/HeritageRange 기존). SP 무변화라 base가 전부 RSP_input const-chain ->
  전파 자명. 단 SSA 없는 SP 값추적 필요 + **파이프라인 순서 변경 = x86-32 EBP 회귀 위험 큼**.
- **B (타겟, 부분)**: buildStackOffsetMap phi-cycle 강화. process free-read는 이걸로 못 풀어 결국 A 성격 필요.
- **권장 진행**: A를 fresh 세션에서 **worktree 격리 + 전 매트릭스 가드**로. TREE_MAP 10/10(x86-32 EBP 무회귀)
  최우선.

### 대상 파일 / 성공 기준
- Go: `pkg/pcode/action_stack_ptr_flow.go`(buildStackOffsetMap/stackAddrOffset), `pkg/pcode/action.go`(파이프
  라인 순서 :1179 heritage / :1361 actstackstall), heritage/StackSlots 경로.
- C++: coreaction.cc ActionStackPtrFlow(:482), heritage/spacebase 경로, pspec `<stackpointer>`.
- 성공 기준: `X64_CORPUS=1 TestX64CorpusGoldenMap`에서 grid_score/process 스택 로컬 복구(6/8 증가) +
  `TREE_MAP=1 TestTreeFullGoldenMap` 10/10 유지. process는 스택 외 나눗셈 렌더 + 8바이트 ulonglong return
  잔차 별도(스택 복구 후 재평가). step5 `ActionDoNothing`(현재 no-op 스텁 coreaction.go:594)은 스택 복구 후.

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (6/8 유지/증가)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam'`
- `go test ./...` (pkg/loader의 symbols_test 3건 missing-.exe 사전실패는 무시 -- untracked fixture)

## 참고 문서
- `docs/STATUS.md`(스택프레임 미시작 전문), `docs/CHANGELOG.md`(2026-07-02 두 항목), 메모리 `project_gosleigh`.
- C++: coreaction.cc(ActionInferTypes:5385/ActionDeadCode:3473/ActionStackPtrFlow:482), varmap.cc(gatherVarnodes
  :1124/isReadActive:1088), ruleaction.cc(RulePtrFlow:9058/RulePtrArith:6662), printc.cc(push_integer:1354/
  OpToken:34), heritage.cc.

## 방법론 (이번 세션 검증됨)
- 팀 모델: 심층 C++ 규명 + 실측(변형 corpus / SSA ACTTRACE / decomp_dbg) + 구현을 서브에이전트로 나누되,
  감독관이 **각 fix의 C++ 근거를 직접 스팟체크**하고 게이트 전 승인. green이어도 unfaithful이면 기각.
- 서브에이전트는 Opus 권장(sonnet 품질 낮음). 529 과부하 시 감독관이 인계 가능.
- 디버그 asset: TracerScout가 빌드한 `decomp_dbg.exe`(CPUI_DEBUG=TYPEPROP+OPACTION_DEBUG)가 scratchpad에
  있었으나 세션 워크트리 정리로 사라졌을 수 있음 -- 필요시 재빌드(cpp/ 복사 + `-DCPUI_DEBUG` + BFD 4파일 제외).
