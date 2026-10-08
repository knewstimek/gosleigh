# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-08)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1..22 (x86-32) | 22개 중 19개 200/200 | s15 [173], s21 [181], s22 [199] 남음 |
| realexe private-sample seed1..21 (x64 UE4) | 21개 중 19개 200/200 | s19 [188] [191], s21 [188] [190] 남음 |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, breadth 3/3, corpus 8/8, corpus2 10/13, x64_auto 108/109 |

측정: `realexe.py measure --work local/realexe/<name>`. 골든 코어는 ghidra-ref HEAD 빌드
(local/ghidra12_head, `GHIDRA_HEADLESS=<사본>/support/analyzeHeadless.bat realexe.py sample`).

## 알려진 불일치 (known mismatch)

| 항목 | 위치 | 원인(조사 메모: repoplane topic) |
|---|---|---|
| goto 선택 | collapse.go selectGoto/TraceDAG | private-sample [173], s22 [199] no-return 블록 (`gosleigh/realexe/private-sample-goto-selection`) |
| 스택 trial 수명 | heritage.go guardCalls, ActiveParam | 푸시된 쿠키 s0xffbc가 일찍 사라짐 (`.../private-sample-pushed-cookie-trial`) |
| 타입 전파 시점 | action_infertypes.go | private-sample [188] GUID 범위 병합, private-sample [199] PTRADD 기준 포인터 (`.../private-sample-guid-vs-split-locals`) |
| 재시작 후 전파 미수렴 | bridge 재시작 | private-sample [191] "not settling" 경고 (`.../private-sample-restart-infer-not-settling`) |
| heritage PIECE 재사용 | heritage.go normalize | private-sample [190] SUBPIECE 주소/순서 |
| 간접 호출 인자 | ActiveParam(CALLIND) | private-sample [188] 인자 없는 vtable 호출 |
| 모델 rule 일부 미포팅 | modelrules.go | x86-64 gcc/swift join_dual_class, goto_stack |
| checkPointerIssues 주소공간 경고 | action_deadcode.go | Go Pointer에 공간 없음 |

## 다음 후보

- 위 표의 항목 하나씩: 각 메모의 "next" 단계부터. 표본 생성은 seed 번호를 계속 올린다(private-sample 23, private-sample 22).

## 도구

- C++ 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `pre:trace address` + `pre:trace enable`,
  `pre:trace propagation on`, `pre:break start <action>`, `print map`/`print tree block`, env `RSDBG=1`
  restructure 추적). 계측은 src TU를 백업 후 getenv 게이트 fprintf, `ONLY=<tu> build.py`, 끝나면 복원.
- Go 추적: `SSA_DUMP_AFTER=<action>`(부분 문자열 일치), `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`,
  `INFER_TRACE`.
