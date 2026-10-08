# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-08)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1..25 (x86-32) | 25개 모두 200/200 | |
| realexe private-sample seed1..24 (x64 UE4) | 24개 중 23개 200/200 | s21 [188] 남음 (캡처 한계) |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, breadth 3/3, corpus 8/8, corpus2 10/13, x64_auto 108/109 |

측정: `realexe.py measure --work local/realexe/<name>` (메모리가 빠듯하면 `REALEXE_WORKERS=8`).
골든 코어는 ghidra-ref HEAD 빌드(local/ghidra12_head, `GHIDRA_HEADLESS=<사본>/support/analyzeHeadless.bat
realexe.py sample`).

## 알려진 불일치 (known mismatch)

| 항목 | 위치 | 원인(조사 메모: repoplane topic) |
|---|---|---|
| 캡처에 없는 라이브 응답 | GenCapture / goldengap capture | private-sample [188] 두 번째 vtable CALLIND 인자. Go == C++ 하네스(같은 캡처), 라이브 골든만 다르고 Enum 경고 순서도 다름 (`gosleigh/realexe/private-sample-callind-args-live-only`) |

## 다음 후보

- 표본 생성은 seed 번호를 계속 올린다(private-sample 26, private-sample 25).
- 위 표 항목: 라이브 Ghidra가 그 함수에서 지연 질의한 타입/호출 정보를 캡처가 기록하도록 GenCapture 확장.

## 도구

- C++ 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `pre:trace address` + `pre:trace enable`,
  `pre:trace propagation on`, `pre:break start <action>`, `print map`/`print tree block`/`print high X`).
  계측은 src TU를 백업 후 getenv 게이트 fprintf, `ONLY=<tu> build.py`, 끝나면 복원.
- Go 추적: `SSA_DUMP_AFTER=<action>`(부분 문자열 일치), `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`,
  `INFER_TRACE`, `COLLAPSE_TRACE`.
