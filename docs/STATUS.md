# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-07)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1 (x86-32) | 200/200 | 골든 재생성(프로그램 옵션, readonly on) |
| realexe private-sample seed2 (보지 않은 표본) | 188/200 | 일반화 지표 |
| realexe private-sample (x64 UE4) | 143/200, sim 0.980 | ENGINE-ERR 0 |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, corpus2 10/13, x64_auto 108/109 |

측정: `realexe.py measure --work local/realexe/<name>` (표본 200, 위치 기준 짝짓기).

## 알려진 큰 미포팅 (known mismatch)

| 항목 | 위치 | 영향 |
|---|---|---|
| 잠긴 프로토타입의 function_parameter 심볼 | scopelocal*.go | 호스트 스택 인자가 있으면 ScopeLocal을 늦게 만들지 않음 |
| heritage 쓰기 정규화 순서 / Go 고유 subtask 분할 | heritage.go `refinedSubTaskSize` | guard 전 쓰기 정규화 시 seed1/2 퇴행 |
| 호스트 union / ScoreUnionFields | hostdata.go | 유니온 필드 선택 |
| 입력 프로토타입 조기 잠금 | paramactive.go `ApplyActiveParamModel` | C++은 ActionInputPrototype에서만 유도 |
| Scope::isNameUsed | printlanguage.go | `::name` 한정 (캡처에 기록 없음) |
| cspec size_alignment_map 미해석 | typefactory.go | x86 맵과 기본 맵이 같아 현재 무해 |

## 도구

- `tools/decomp_dbg.exe` + `local/realexe/*/captures/<entry>.xml`: C++ 정답 실측(`print raw/C`, `break start`).
- 계측/추적 하네스: ghidra-ref 사본을 scratchpad에 두고 `tools/build_decomp_dbg.py` 방식으로 빌드.
  `/DOPACTION_DEBUG`로 빌드하면 `trace address`(인자 없이 = 함수 전체) + `trace enable`로
  규칙 적용 순서(DEBUG n: rule) 출력. 일부 TU만 재컴파일하면 수 초.
- 캡처 부가파일 `<entry>.typeorder`: Enum 경고의 질의 순서(GenCapture).
- Go 추적: `SSA_DUMP_AFTER`, `SSA_DUMP_TYPES`, `RULE_TRACE=1|2`, `INFER_TRACE`, `GOLDENGAP_STALL`.
