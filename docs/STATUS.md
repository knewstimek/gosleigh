# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-08)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1..50 (x86-32) | 50개 모두 200/200 | |
| realexe private-sample seed1..49 (x64 UE4) | 49개 중 47개 200/200 | s6 [169], s29 [168]은 골든 비결정성(아래) |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, breadth 3/3, corpus 8/8, corpus2 10/13, x64_auto 108/109 |

측정: `realexe.py measure --work local/realexe/<name>` (메모리가 빠듯하면 `REALEXE_WORKERS=8`).
골든 코어는 ghidra-ref HEAD 빌드(local/ghidra12_head, `GHIDRA_HEADLESS=<사본>/support/analyzeHeadless.bat
realexe.py sample`).

## 알려진 불일치 (known mismatch)

(없음)

## 미이식

(없음)

## 골든 비결정성 (포팅 불일치 아님)

C++ `ParamTrial::operator<`(fspec.cc:1902)는 같은 group의 ParamEntry를 **포인터 주소**로 비교한다
(x64 XMM0 vs RCX). std::list 노드는 대개 생성 순서대로 주소가 커지지만 보장되지 않는다(하네스에서
XMM1 < XMM0, R9 < R8인 실행을 확인). Go는 cspec 문서 순서(`paramEntry.pos`)로 비교한다.
이 순서에 걸리는 CALLIND 인자 복구는 decompile.exe 프로세스마다 결과가 달라진다(하네스도 실행마다 다름).

| 표본 | 함수 | 골든 쪽 결과 |
|---|---|---|
| private-sample [169] / private-sample [168] | FStaticStateResource | 두 vtable 호출 인자가 표본마다 다름 |

근거와 재현 방법: repoplane `gosleigh/realexe/private-sample-callind-args-live-only`.
upstream 수정 PR: NationalSecurityAgency/ghidra#9750 (entry 위치 번호로 비교). 병합되면 Go 쪽 비교를
upstream과 다시 대조한다(repoplane `gosleigh/upstream/ghidra-pr-9750-paramtrial-order`).

## 다음 후보

- 표본 생성은 seed 번호를 계속 올린다(private-sample 51, private-sample 50).

## 도구

- C++ 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `pre:trace address` + `pre:trace enable`,
  `pre:trace propagation on`, `pre:break start <action>`, `print map`/`print tree block`/`print high X`).
  계측은 src TU를 백업 후 getenv 게이트 fprintf, `ONLY=<tu> build.py`, 끝나면 복원.
- 라이브 계측: ghidra-ref를 x86로 빌드한 decompile.exe를 ghidra12_head에 잠깐 넣고 headless로 단일 함수를
  돌린 뒤 원본으로 되돌린다(stderr가 안 보이므로 env로 지정한 파일에 기록).
- Go 추적: `SSA_DUMP_AFTER=<action>`(부분 문자열 일치), `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`,
  `INFER_TRACE`, `COLLAPSE_TRACE`.
