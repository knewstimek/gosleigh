# GOAL: 실바이너리 parity (realexe)

**목표**: 실제 링크된 PE의 임의 함수를 Ghidra와 동일한 C로 디컴파일. 진척 지표는 장난감 코퍼스(x64_auto)가 아니라
`tools/realexe` 층화 샘플(카탈로그 `gosleigh.realexe.measure`)의 일치 수 + 토큰 유사도(sim). 기존 게이트
(`gosleigh.gates` = `py -3 tools/gates.py`)는 매 단계 무회귀 + 골든 출력 바이트 동일 확인.

| 시점 | 커밋 | 일치 | sim |
|---|---|---|---|
| 기준선 | `60b3835` | 10/200 | (미측정) |
| 스택 포인터 흐름 | `e467f63` | 10/200 | 0.411 |
| call 스택 인자 사슬 | `e31d2b1` | 10/200 | 0.417 |

일치 수는 함수당 모든 갭이 풀려야 오르므로 sim으로 단계 효과를 본다.

## 남은 근본 갭 (실측, 영향 순)

Go 엔진의 상당 층이 C++ 구조가 아닌 소형 골든 맞춤 재구현이다. 실바이너리는 그 층을 통째로 C++ 구조로 교체해야 맞는다.

| # | 층 | 현상 (200 샘플) | C++ 근거 | 상태 |
|---|---|---|---|---|
| P | 함수 프로토타입 층: FuncProto/ProtoStore/ProtoParameter, ActionInputPrototype(updateInputTypes), ProtoModelMerged/resolveModel, 이름있는 모델 집합 | `__thiscall` 46 + `__fastcall` 33 전부 불일치, ECX 입력이 `local_N`으로 샘 | fspec.cc FuncProto 3778~, 2700-2930, coreaction.cc 4718 | 미착수 |
| H | 호스트 심볼 층: 코어가 Java(ScopeGhidra)에서 받는 함수/데이터 심볼. Gosleigh엔 공급 인터페이스 자체가 없음 | call 대상 `local_N`(Ghidra `FUN_`/FID명), `DAT_` 29, `vftable` 21, `ExceptionList` 16 | ghidra_arch/ScopeGhidra, printc.cc opCall/genericFunctionName | 미착수 |
| N | 변수 명명 층: PrintC 자체 폴백(`local_%d(createIndex)`) 대신 Symbol + ScopeInternal::buildVariableName(`in_`/`unaff_`/`extraout_`) | `unaff_` 8, `extraout_` 2 등 | database.cc 2440-2500 | 미착수 |
| R7 | p-code 0개 명령어에서 bridge 실패(`has no raw ops`) | 4% | - | 미조사 |
| - | 부분 포팅 잔여: markNotMapped, guardCallOverlappingInput, tryOutput*Guard, store/load LoadGuard(ValueSet), heritage 전체 구조 | 개별 함수 | heritage.cc, varmap.cc | known mismatch 명시됨 |

H는 하네스 쪽 덤프(GenSample이 프로그램 심볼표 출력) + 엔진 쪽 공급 인터페이스(Funcdata host scope)로 구성한다.
C++ 코어 단독(콘솔)은 이름 없는 call 대상을 `func_0x...`로 찍는다 -- `FUN_`은 Java 쪽 이름이다.
