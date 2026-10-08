# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-08)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1..27 (x86-32) | 27개 모두 200/200 | |
| realexe private-sample seed1..26 (x64 UE4) | 26개 중 25개 200/200 | s21 [188]은 골든 비결정성(아래) |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, breadth 3/3, corpus 8/8, corpus2 10/13, x64_auto 108/109 |

측정: `realexe.py measure --work local/realexe/<name>` (메모리가 빠듯하면 `REALEXE_WORKERS=8`).
골든 코어는 ghidra-ref HEAD 빌드(local/ghidra12_head, `GHIDRA_HEADLESS=<사본>/support/analyzeHeadless.bat
realexe.py sample`).

## 알려진 불일치 (known mismatch)

(없음)

## 골든 비결정성 (포팅 불일치 아님)

- private-sample [188] 두 번째 vtable CALLIND 인자: C++ `ParamTrial::operator<`(fspec.cc:1902)가 같은 group의
  ParamEntry를 **포인터 주소**로 비교한다(XMM0 vs RCX). 같은 x86 decompile.exe도 실행마다 결과가 달랐고,
  private-sample [169]는 반대 순서를 요구한다. Go는 생성 순서(하네스와 동일)를 유지한다.
  근거와 재현 방법은 repoplane `gosleigh/realexe/private-sample-callind-args-live-only`.

## 미이식

| 항목 | C++ | Go 위치 |
|---|---|---|
| multistage 점프테이블 재시작 | jumptable.cc JumpTable::matchModel (insertMultistageJump + setRestartPending) | jumptable.go MatchModel (지금은 경고만) |

## 다음 후보

- 표본 생성은 seed 번호를 계속 올린다(private-sample 28, private-sample 27).

## 도구

- C++ 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `pre:trace address` + `pre:trace enable`,
  `pre:trace propagation on`, `pre:break start <action>`, `print map`/`print tree block`/`print high X`).
  계측은 src TU를 백업 후 getenv 게이트 fprintf, `ONLY=<tu> build.py`, 끝나면 복원.
- 라이브 계측: ghidra-ref를 x86로 빌드한 decompile.exe를 ghidra12_head에 잠깐 넣고 headless로 단일 함수를
  돌린 뒤 원본으로 되돌린다(stderr가 안 보이므로 env로 지정한 파일에 기록).
- Go 추적: `SSA_DUMP_AFTER=<action>`(부분 문자열 일치), `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`,
  `INFER_TRACE`, `COLLAPSE_TRACE`.
