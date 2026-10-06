# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-07)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1 (x86-32) | 199/200 | 골든 재생성(프로그램 옵션, readonly on) |
| realexe private-sample seed2 (보지 않은 표본) | 183/200 | 일반화 지표 |
| realexe private-sample (x64 UE4) | 128/200, sim 0.961 | ENGINE-ERR 0 |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, corpus2 10/13, x64_auto 108/109 |

측정: `realexe.py measure --work local/realexe/<name>` (표본 200, 위치 기준 짝짓기).

## private-sample 잔여 분류 (C++ 하네스 대조, `scratchpad harness_cmp.py` 방식)

| 분류 | 수 | 다음 행동 |
|---|---|---|
| 하네스=골든, Go만 다름 | 23 | Go 버그. 하네스 `print raw`로 국소화 후 원본 포팅 |
| Go=하네스, 골든만 다름 | 7 | 캡처/라이브 차이(`::` 이름충돌, bool ZEXT 등) |
| 셋 다 다름 | 42 | 캡처 한계 + Go 차이 혼재 |

## 알려진 큰 미포팅 (known mismatch)

| 항목 | 위치 | 영향 |
|---|---|---|
| 호스트 union / ScoreUnionFields | hostdata.go | 유니온 필드 선택 |
| 입력 프로토타입 조기 잠금 | paramactive.go `ApplyActiveParamModel` | C++은 ActionInputPrototype에서만 유도. 현재 사후 보정 |
| heritage 쓰기 정규화 순서 | heritage.go | 읽기만 guard 전 정규화 |
| Scope::isNameUsed | printlanguage.go | `::name` 한정 (캡처에 기록 없음) |
| Funcdata::replaceVolatile | coreaction.go | volatile 접근 |

## 도구

- `tools/decomp_dbg.exe` + `local/realexe/*/captures/<entry>.xml`: C++ 정답 실측(`print raw/C`, `break start`).
- 캡처 부가파일 `<entry>.typeorder`: Enum 경고의 질의 순서(GenCapture).
- Go 추적: `SSA_DUMP_AFTER`, `SSA_DUMP_TYPES`, `RULE_TRACE=1|2`, `INFER_TRACE`, `GOLDENGAP_STALL`.
