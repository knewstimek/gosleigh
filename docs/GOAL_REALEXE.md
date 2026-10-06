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
| `5505fee` | 점프테이블 실패 경고 문구, lookForFuncParamNames, 현재 함수 잠긴 프로토타입(부분), RuleShiftSub 원본화 | 165 | - |
| `85c1531` | 규칙 원본화 20여 종(ExpandLoad, ConditionalMove+cloneExpression, SwitchSingle 등), opInsertAfter의 MULTIEQUAL 건너뛰기, totalReplaceConstant의 marker COPY, 파라미터형=High 타입, 반환 운반자 개명 등 printc 휴리스틱 ~900줄 제거 | 175 | - |
| `c6ab701` | 상수 공간 정렬, 선언/캐스트=High 타입, extraout_, isComplex(원본 블록), MultiCollapse 기능동등, BoolNegate/ExpandLoad 원본화, tryCallPull+호출인자 consume, 외부 간접호출 재시작(override), 포인터 typedef | 180 | - |
| `ead2d24` | checkCallDoubleUse/getTrialForInputVarnode/clearActiveInput 원본화, isPossibleAlias, 쉼표 조건 토큰 구조, 조건 리프 레이블, RuleDivOpt/isCollapsible/isZeroExtended 원본화, PTRSUB 오프셋=필드 시작(hasMatchingSubType) | 189 | - |
| `bc60903` | unique 공간 heritage+rename 자리표시자, likelytrash 연결, deadcode의 addrforce 해제/INDIRECT 삭제, testUntiedCallIntersection, 캡처 protoeval 수정 | 191 | - |
| `d58370b` | PTRSUB 출력(opPtrsub), VariableGroup(groupWith/확장 커버/partialCopyShadow), RulePieceStructure+groupPartials, PIECE 타입 전파, 구조체 typedef | 194 | - |
| `fdc48ac` | TypePartialStruct, 명령어 내부 상대 분기(findRelTarget), SplitDatatype 원본화, 큰 base=undefined1[N], TypePointerRel(ephemeral), propagateConsumed/NZMask 확장정밀도, SUBPIECE 필드 출력, 출력 그룹/for/while 줄바꿈, op time=C++ 흐름 순서, 동적 심볼 충돌 | 196 | - |
| `0287d6d` | markUnaliased의 notmapped 구멍, ActionMultiCse 원본화, scopeBreak 인덱스 비교, HighVariable 인스턴스 주소 정렬 | 198 | - |
| `HEAD` | LoadGuard+ValueSetSolver, AddTreeState 출력 무타입, propagateSpacebaseRef, finalizeDatatype, CBRANCH bool 입력, STORE guard 붕괴 판정, 출력 ParamList(join EDX:EAX), 루트 action reset(typerecovery on/start 분리), 블록 내 위치 순서, ActionDeadCode neverConsumed, BlockBasic cover/getEntryAddr | 200 | 1.000 |

## 도구 (`tools/realexe/`)
- `realexe.py analyze|sample|measure|capture`, `gaps.py`(불일치 유형 집계), `difffn.py`(인덱스별 diff).
- **`capture`가 핵심**: `GenCapture.java`가 Ghidra 디버그 savefile을 만들고, `tools/decomp_dbg.exe`가 그 실바이너리
  맥락 그대로 C++ 코어를 돌린다(골든을 재현함). 갭 원인은 이걸로 실측한다.
- GenCapture는 `setOptions` 없이 openProgram이 프로그램 옵션을 쓰게 한다(protoeval=cspec 병합 모델). 예전 캡처의
  `<protoeval>default</protoeval>`은 thiscall 골든을 재현 못하므로 병합 모델 이름으로 바꿔 쓴다.
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
| R | Go 규칙이 C++와 다른 변환을 하는 경우가 남음. `tools/ruleaudit.py`로 상위부터 대조. 남은 상위: subcommute(부분), sless2zero, segment/transformcpool(인프라 의존) | ruleaction.cc | 규칙 하나씩 원본화 |
| T | 타입 추론 차이: 반환형, 지역 타입(uint vs int) | typeop.cc propagateType, ActionInferTypes | 사례 다수 |
| G | 전역 겹침: normalizeWriteSize PIECE 출력이 ram 변수로 남아 `(uint)CONCAT12`가 두 문장으로 갈라짐, coverVarnodes 미포팅 | heritage.cc normalizeWriteSize | [166][184][188][189] |
| D | 선언이 심볼이 아니라 남은 varnode 기반이라 clearDeadVarnodes 원본화 불가 | printc.cc emitScopeVarDecls | 원본화 시 decl +8 |
| S | 출력에 `struct X { }` 정의가 찍힘(Ghidra는 함수 출력에 타입 정의 없음) | printc.cc docFunction | [142][177][196] |
| P | 현재 함수의 잠긴 호스트 프로토타입: 반환형/레지스터 파라미터 타입/스택 파라미터 이름은 적용(ApplyHostSelfPrototype). 남음: C++처럼 입력 잠금으로 두고 잠긴 저장소에서 입력 varnode 생성(ActionPrototypeTypes locked-input, ActionInputPrototype updateInputNoTypes) -- 지금은 파라미터를 추정한 뒤 덮어써서 크기가 다른 읽기(1바이트)와 일부 이름이 어긋남 | fspec.cc, coreaction.cc ActionPrototypeTypes/ActionInputPrototype | [174][183] |
| - | known mismatch: 스페이스베이스 내부 오프셋 TypePointerRel(inferPropagateAddIn2Out within!=0), VariablePiece 교차 캐시(매번 재계산), forceOutputNum(멀티고토 self edge), DivTermAdd 128비트, guardCallOverlappingInput, clearDeadVarnodes 스택/destroy, cseElimination 블록 끝 주소, Heritage::processJoins(자유 join varnode), ParamListStandardOut model rules(fillinMap 비-fallback), 함수 자체 출력의 join 반환(guardReturns는 단일 반환 레지스터) | ruleaction.cc, heritage.cc | |
