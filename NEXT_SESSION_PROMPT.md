# 다음 세션 프롬프트 (2026-07-01 후반 작성)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. **x64 실함수(register param RCX/RDX/RDI/RSI) 성공이 명시 목표.**

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. parity 안 맞으면 known mismatch로 명시하고 넘어간다 (휴리스틱으로 때우지 말 것 --
이게 printc.go가 누더기가 된 원인).

## 현재 상태 (master 39ae4b2, 전 패키지 그린; 단 6 커밋 origin 미푸시일 수 있음 -- 확인할 것)
- **트리 전체 골든 맵 10/10 byte-identical** (`TestTreeFullGoldenMap`, TREE_MAP=1): x86-32 8/8 + x64_add_ret +
  aarch64_add_ret.
- **x64 breadth corpus 4/8 MATCH** (`testdata/x64_corpus/`, `TestX64CorpusGoldenMap` X64_CORPUS=1):
  add4 + poly4 + sum_to_n + classify. 남은 4 = max3, sum_array, grid_score, process.

## 2026-07-01 후반 완료 (이번 세션, 7 커밋 -- 건드리지 말 것, 충실+무회귀)
1. **sum_to_n flip** (`2321533`): 세 충실 수정.
   - `Funcdata.OpInsertEnd` flow-break 분기 (funcdata.go) -- C++ `opInsertEnd`(funcdata_op.cc:435): 블록이
     branch terminator로 끝나면 그 앞에 삽입. 단순 append였던 걸 고침. addrtied merge COPY가 CBRANCH 뒤로
     가던 버그.
   - `emitBlockIf` no_branch 선행 statement (printc.go emitIfBlockChain) -- C++ `emitBlockIf`(printc.cc:3026):
     condition 블록을 no_branch로 먼저 emit. plain-if 경로에만 추가(else-if 미적용).
   - `RuleLessNotEqualBoolAnd`을 트리 actprop에 추가 (action.go) -- =C++ RuleLessNotEqual(ruleaction.cc:2310,
     `V<=W && V!=W => V<W`). production batchA에만 있어 트리 누락 -> 변수-대-변수 signed JG/JLE flag가
     `BOOL_AND(NOTEQUAL,SLESSEQUAL)`로 남던 것 collapse.
2. **classify flip** (`c9094fc`): 상수 radix `mostNaturalBase`(printlanguage.cc:735) + push_integer(printc.cc:1395)
   충실 포팅. renderConstant fallback `<10?dec:hex` -> `<=10?dec` + `mostNaturalBase`. `100` vs `0x64`.
3. **네이밍 해저드 제거** (`7fecf7b`): rules_misc.go의 misnamed `RuleLessNotEqual`은 사실 C++ `RuleBooleanNegate`
   (ruleaction.cc:2957)의 중복이었다. 삭제 + batchC를 NewRuleBooleanNegate로 + actprop 중복 등록 제거.

## 다음 작업 [최우선] -- 남은 4개의 공통 블로커: TYPE-LEAK (근본 실측 확정)

### 확정된 진단 (Ghidra 12 DumpHigh.java 실측, 2026-07-01)
증상: `int local_N` vs golden `undefined4 local_N` (max3/sum_array, + grid_score/process 일부).
- **Ghidra는 로컬 선언을 HighSymbol 타입으로** 한다 (`PrintC::emitVarDecl` printc.cc:2634, `sym->getType()`).
  max3/sum_to_n/sum_array의 스택 로컬 Symbol 타입 = **undefined4** (HighVariable 타입은 int인데도).
  process는 Symbol 타입 = int. **우리는 누수된 varnode int으로 선언** (printc.go emitLocalDeclarations:1127
  `vn.TypeDefFacing()`).
- **오답 제거**: copyTrim/read-snip 가설 틀림 -- Ghidra 비교는 addrtied 스택을 직접 읽는다.
- **단순 규칙 아님**: sum_array local_18(`*(int*)(p+(longlong)local_18*4)` 인덱스)=undefined4 vs process
  local_14(동일 인덱스 사용)=int. 같은 사용 다른 Symbol. 즉 committed `Varnode::getType()`(HV 타입과 별개)이
  함수별로 갈리고(전파 strength), 이게 `MapState::gatherVarnodes`(varmap.cc:1124)+`RangeHint::merge/preferred`
  (varmap.cc:30-157)로 Symbol 타입이 된다.

### 다음 단계 (이 순서로)
1. **Ghidra를 TYPEPROP_DEBUG로 빌드/실행해 committed varnode 타입 전파 스텝 추적** (코드+HighFunction 덤프로는
   한계 도달; sum_array vs process가 동일 구조인데 갈리는 이유를 step-trace로 확인). Ghidra 12 = C:\ghidra12.
   DumpHigh.java는 삭제됨 -- testdata/x64_corpus/GenGoldens.java 패턴으로 재작성(HighFunction.getPcodeOps +
   LocalSymbolMap.getSymbols, vn.getHigh().getDataType() vs HighSymbol.getDataType()).
2. 그 결과로 (a) committed 타입 전파를 Ghidra와 일치시키거나(action_infertypes.go getLocalType/propagateOneType/
   writeBack 충실 포팅) (b) ScopeLocal에 RangeHint 기반 symbol 타입 빌드(scopelocal.go, 현재 FLOAT만 세팅
   line 345) + emitVarDecl을 symbol 타입에서.
3. **주의**: 반쪽만(선언 소스만) 바꾸면 sum_list(golden `int local_8`)/counted_loop 깨진다. 반드시 worktree
   격리 + 전 매트릭스(max3/sum_to_n/sum_array/process/sum_list/counted_loop + 10/10) 가드.

### 부수 블로커 (TYPE-LEAK과 독립, 단독으론 flip 안 됨)
- **데이터모델 long/longlong** (sum_array/process/grid_score 시그니처): `long param_1` vs golden `longlong`.
  Win x64 LLP64(long=4, longlong=8). normalizedBaseType(printc.go:1177)이 8바이트 INT를 "long"으로 하드코딩.
  cspec `<data_organization><long_size=4/><long_long_size=8/>`는 파싱되나(cspec.go) printc까지 threading 안 됨.
  aarch64/Linux x64(LP64)는 "long" 유지. cspec->funcdata->printc 배선 필요.
- **SEXT-as-cast + 여분 괄호** (sum_array): `(longlong)local_18` vs `SEXT(local_18)`(캐스트명은 데이터모델 의존) +
  `*(int *)x` vs `*((int *)x)`(printc deref-cast precedence, contained).
- **스택 프레임 미복구** (grid_score/process): 중첩 루프 + 다수 local의 RSP 프레임을 gap2a가 못 잡아
  `uVar2=(int*)(uVar3-0x18)` 쓰레기로 오복구. 별도 deep. process는 나눗셈 렌더도.

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (4/8 유지/증가)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64SimpleFunction|TestX8664|TestX64RegParamOrder'`
- `go test ./...` (전 패키지)
- heritage/printc/subvar/deadcode/infertypes는 공유 코드 -> x86-32 회귀 매우 조심, 작은 단위로.

## 후속 (미션 #1 본체, corpus 후)
11개 production `TestMSVC*`를 트리 경로로 검증 -> `bridge.Decompile`의 41-call 손정렬 subset 제거.

## 참고 문서
- `docs/STATUS.md` (#2 갭 분석 + 이번 세션 type-leak 실측 상세), CHANGELOG, 메모리 `project_gosleigh`/
  `reference_x64_corpus`. C++: `ghidra-ref/.../cpp/` printc.cc(emitVarDecl/push_integer), varmap.cc(MapState/
  RangeHint), coreaction.cc(ActionInferTypes), varnode.cc(getLocalType).
