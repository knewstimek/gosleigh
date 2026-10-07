# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-07)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1 (x86-32) | 200/200 | 골든 재생성(프로그램 옵션, readonly on) |
| realexe private-sample seed2 (보지 않은 표본) | 200/200 | 일반화 지표 |
| realexe private-sample (x64 UE4) | 192/200, sim 0.996 | ENGINE-ERR 0, TIMEOUT 0 |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, corpus2 10/13, x64_auto 108/109 |
| x64 코퍼스 C++ 코어 대조 `rawcmp.py` | corpus 8/8, corpus2 13/13, x64_auto 109/109 | 같은 바이트를 C++ 하네스로 |

측정: `realexe.py measure --work local/realexe/<name>` (표본 200, 위치 기준 짝짓기).

x64 게이트의 남은 불일치는 골든 JSON에 없는 환경 정보 때문이다: corpus2 `caller`(재배치된
호출 대상 이름), `faverage`(전역 심볼 이름), `add_pt`(Java Program DB 스택 변수 이름),
x64_auto `switch_dense`(전체 이미지의 `__ImageBase`). 같은 바이트의 C++ 코어 출력과는 일치한다.

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

## 도구

- C++ 정답 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `load function @addr`).
  `trace propagation on`(TYPEPROP), `trace address`+`trace enable`(규칙별 op 전후).
- Go↔C++ 비교: `actcmp.py`(action 변경 수), `rulecmp.py`(규칙 적용 수), C++ `print map`/`print high NAME`.
- 캡처 없는 x64 코퍼스: `rawcmp.py testdata/<corpus>/x64_goldens.json [name]`(바이트를 private-sample 캡처에 이식).
- Go 추적: `SSA_DUMP_AFTER`, `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`(action 포함), `INFER_TRACE`.
