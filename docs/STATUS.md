# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-07)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1 (x86-32) | 200/200 | 골든 재생성(프로그램 옵션, readonly on) |
| realexe private-sample seed2 (보지 않은 표본) | 196/200 | 일반화 지표 |
| realexe private-sample (x64 UE4) | 192/200, sim 0.996 | ENGINE-ERR 0, TIMEOUT 0 |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, corpus2 10/13, x64_auto 108/109 |

측정: `realexe.py measure --work local/realexe/<name>` (표본 200, 위치 기준 짝짓기).
캡처 부가파일은 `realexe.py capture`가 함께 만든다(기존 캡처는 `realexe.py names`).

## 알려진 큰 미포팅 (known mismatch)

| 항목 | 위치 | 영향 |
|---|---|---|
| 잠긴 프로토타입의 function_parameter 심볼 | scopelocal*.go | 호스트 스택 인자가 있으면 ScopeLocal을 늦게 만들지 않음 |
| heritage 쓰기 정규화 순서 / Go 고유 subtask 분할 | heritage.go `refinedSubTaskSize` | guard 전 쓰기 정규화 시 seed1/2 퇴행 |
| ActionActiveParam 위치 + 입력 프로토타입 조기 잠금 | action.go, paramactive.go | C++ 위치로 옮기면 seed2 [180] 퇴행 |
| guardReturns를 heritage 밖에서 1회만 | coreaction.go ActionReturnRecovery | 출력 trial 수가 C++과 다름(actcmp로 확인) |
| TypePartialUnion, Go typedef의 원형 링크 | unionresolve.go, typefactory.go | 부분 유니온, isOpIdentical |
| 지역 스코프 자체 이름의 isNameUsed | printlanguage.go | `::` 한정은 호스트 질의만 반영 |
| 호출 주변 스택 조각 INDIRECT의 mergeIndirect COPY | merge.go | private-sample [194] |
| TypePartialUnion 부분 읽기, INDIRECT 기반 스택 힌트 | unionresolve.go, varmap_restructure.go | private-sample [173] |
| 8바이트 long/longlong 코어 타입 슬롯 | typefactory.go `coreBaseName` | 이름별 인터닝 유지 |
| heritage 조각(R8D) 생성 순서 -> 이름 대표/동적 심볼 | heritage.go | private-sample [193] |
| merge 커버 교차로 C++만 넣는 trim COPY | merge.go | seed2 [192] 문장 순서 |

## 도구

- C++ 정답 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `load function @addr`).
  `trace propagation on`(TYPEPROP), `trace address`+`trace enable`(규칙별 op 전후).
- Go↔C++ 비교: `actcmp.py`(action 변경 수), `rulecmp.py`(규칙 적용 수), C++ `print map`/`print high NAME`.
- Go 추적: `SSA_DUMP_AFTER`, `SSA_DUMP_TYPES`, `RULE_TRACE=1|2`(action 포함), `INFER_TRACE`.
