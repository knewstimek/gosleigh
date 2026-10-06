# GOAL: 실바이너리 parity (realexe)

**목표**: 실제 링크된 PE의 임의 함수를 Ghidra와 동일한 C로. 진척 지표 = `gosleigh.realexe.measure`(200 층화 샘플)의
일치 수 + 토큰 유사도(sim). 매 단계 `gosleigh.gates`(`py -3 tools/gates.py`) 무회귀 + 게이트 골든 출력 바이트 동일.

| 커밋 | 내용 | 일치 | sim |
|---|---|---|---|
| `60b3835` | 기준선 | 10 | - |
| `e31d2b1` | 스택 포인터 흐름 + call 스택 인자 사슬 | 10 | 0.417 |
| `320acb4` | 호스트 심볼(callee 이름) + merged 모델(thiscall/fastcall) | 14 | 0.485 |
| `f98453d` | callee 프로토타입(extrapop/callee_pop), 반환 판정 | 14 | 0.506 |
| `873ee2e` | 플래그 그룹 버그(incidental_copy), 미사용 call 출력 제거 | 17 | 0.522 |
| `1aa498b` | 호스트 이름/로컬, flow override(꼬리 호출 CALL_RETURN) | 100 | 0.840 |
| `e9cbade` | ram heritage + 전역 심볼(호스트 savefile), RestrictLocal, mergeIndirect | 103 | 0.846 |
| `c87b817` | 헤더 주석(FID), C++ 이름 번호, noreturn halt, 문자열 리터럴, 크래시/행 수정 | 110 | 0.881 |
| `5ee1024` | callee/외부 잠긴 프로토타입, typedef, callfixup 인젝션, RulePiecePathology, deadcode 공간 게이트, unaff_ | 123 | 0.903 |
| `d2f1c0f` | 스텁 규칙 8종 포팅(EarlyRemoval 등), isComplex, 호출/캐스트/선언 줄바꿈 구조, SetCasts 블록 순서, LaneDivide | 137 | - |
| `be538b3` | 결정성(AllOps SeqNum 순), 상수 단일 reader, guardCalls 모델, 레이블/goto 본문, 부분 전역 심볼, bool 반환 | 139 | - |
| `929028e` | downChain, BlockSwitch/MultiGoto, DeterminedBranch, 다중 루트 지배자, removeUnreachableBlocks, 규칙 감사(SLess2Zero 등 8종 원본화) | 143 | - |
| `37a144b` | 캐스트가 HighVariable 타입 사용, arithmeticOutputStandard, getExactPiece, baseExplicit 원본화, PIECE 토큰, 프로토타입 출력형 | 147 | - |
| `07bedd0` | TraceDAG 원본화, 액션 변경 신호=count, cover의 implied 추적, heritage 단일 rename, mergeByDatatype, CMOV 블록 분할, 루프 조건 우회로 제거 | 160 | - |
| `f241da2` | 반환값 복원 수명 원본화(guardReturns/ReturnRecovery), finalTransform/isMoveable, dominant copy, AliasChecker, guardStores, 이름 번호 순서, CALLOTHER 이름 | 164 | - |

## 도구 (`tools/realexe/`)
- `realexe.py analyze|sample|measure|capture`, `gaps.py`(불일치 유형 집계), `difffn.py`(인덱스별 diff).
- **`capture`가 핵심**: `GenCapture.java`가 Ghidra 디버그 savefile을 만들고, `tools/decomp_dbg.exe`가 그 실바이너리
  맥락 그대로 C++ 코어를 돌린다(골든을 재현함). 갭 원인은 이걸로 실측한다.
- decomp_dbg는 readonly 데이터를 상수로 접어 Java 골든과 다를 수 있다. 캡처 사본에서 `readonly="true"`를
  `false`로 바꾸면 골든과 같아진다(전역 문자열/테이블 함수).

## 원칙 (이번 작업에서 확인)
Gosleigh의 여러 층이 소형 골든 맞춤 재구현이었다. 실바이너리 갭의 근본은 대부분 (a) C++ 고리 누락(스텁/부분포팅)
또는 (b) **코어가 Java(호스트)에서 받는 정보의 부재**다. (b)는 `pcode.HostScope`/`bridge.BuildConfig`로 공급한다 --
이름 변환(IllegalCharCppTransformer), callee extrapop(purge+stackshift), flow override, 함수 로컬(localdb)은 하네스가
Ghidra API로 Java와 같은 값을 덤프한다.

## 남은 갭 (실측, 빈도 순 -- 갱신은 `gaps.py` + `capture`)

| # | 갭 | 근거 | 비고 |
|---|---|---|---|
| R | Go 규칙이 C++와 다른 변환을 하는 경우가 남음. `tools/ruleaudit.py`(Go apply 길이 vs C++ applyOp 길이)로 상위부터 대조: expandload, conditionalmove, structoffset0, andpiece, highorderand, switchsingle, andcompare 등 | ruleaction.cc | 규칙 하나씩 원본화 |
| T | 타입 추론 차이: 반환형, 지역 타입(uint vs int) | typeop.cc propagateType, ActionInferTypes | 사례 다수 |
| N | 변수 번호(iVar1 vs iVar2) 어긋남 -- merge/이름 순서 | merge.cc, ActionNameVars | 5건 이상 |
| G | 전역 겹침: normalizeWriteSize PIECE 출력이 ram 변수로 남아 `(uint)CONCAT12`가 두 문장으로 갈라짐, coverVarnodes 미포팅 | heritage.cc normalizeWriteSize | [166][184][188][189] |
| D | 선언이 심볼이 아니라 남은 varnode 기반이라 clearDeadVarnodes 원본화 불가 | printc.cc emitScopeVarDecls | 원본화 시 decl +8 |
| S | 출력에 `struct X { }` 정의가 찍힘(Ghidra는 함수 출력에 타입 정의 없음) | printc.cc docFunction | [142][177][196] |
| P | 현재 함수의 잠긴 호스트 프로토타입: 반환형/레지스터 파라미터 타입/스택 파라미터 이름은 적용(ApplyHostSelfPrototype). 남음: C++처럼 입력 잠금으로 두고 잠긴 저장소에서 입력 varnode 생성(ActionPrototypeTypes locked-input, ActionInputPrototype updateInputNoTypes) -- 지금은 파라미터를 추정한 뒤 덮어써서 크기가 다른 읽기(1바이트)와 일부 이름이 어긋남 | fspec.cc, coreaction.cc ActionPrototypeTypes/ActionInputPrototype | [124][128][129][170][174][183] |
| - | known mismatch: RulePieceStructure 스텁, TypePointerRel(downChain 구조체 내부), BlockBasic 커버 시작 주소, forceOutputNum(멀티고토 self edge), DivTermAdd 128비트, guardCallOverlappingInput, LoadGuard(ValueSet), clearDeadVarnodes 스택/destroy, cseElimination 블록 끝 주소 | ruleaction.cc, heritage.cc | |
