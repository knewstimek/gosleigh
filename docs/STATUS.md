# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-07)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1/2/3 (x86-32) | 200/200/200 | 전부 HEAD 코어 골든(12.0.4판은 golden_12.0.4) |
| realexe private-sample seed1 (x64 UE4) | 200/200 | HEAD 코어 골든 |
| realexe private-sample seed2 | 200/200 | |
| realexe private-sample seed4 (새 표본) | 198/200 | [110] 변수 번호 순서, [195] ST0 반환 복구 |
| realexe private-sample seed3 (새 표본) | 199/200 | [194] 스택 입력 변수 타입(int vs longlong) |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, corpus2 10/13, x64_auto 108/109 |
| x64 코퍼스 C++ 코어 대조 `rawcmp.py` | corpus 8/8, corpus2 13/13, x64_auto 109/109 | 같은 바이트를 C++ 하네스로 |

측정: `realexe.py measure --work local/realexe/<name>`. 게이트 잔여 불일치는 골든 JSON에 없는 환경
정보(재배치 호출 이름, 전역/스택 심볼 이름, `__ImageBase`)이며 C++ 코어 출력과는 일치한다.

골든 코어는 ghidra-ref HEAD(12.2 DEV)여야 한다: `tools/cppharness/build_native.py`로 만든 decompile.exe를
local/ghidra12_head에 넣고 `GHIDRA_HEADLESS=<그 사본>/support/analyzeHeadless.bat realexe.py sample`.
shift count >= 64 같은 C++ UB는 이 빌드 동작을 따른다(pcodeop.go INT_RIGHT nzmask).

## 알려진 불일치 (known mismatch)

| 항목 | 위치 | 영향 |
|---|---|---|
| heritage 쓰기 정규화 순서 | heritage.go guard 앞 normalizeRange | guard 전 쓰기 정규화 시 x86 퇴행(repoplane memo) |
| guardReturns를 heritage 밖에서 1회만 | coreaction.go ActionReturnRecovery | 출력 trial 수 차이 |
| 지역 스코프 이름의 isNameUsed | printlanguage.go | `::` 한정은 호스트 질의만 |
| 8바이트 long/longlong 코어 슬롯 | typefactory.go `coreBaseName` | 이름별 인터닝 |
| Go typedef의 원형 링크 | typefactory.go | isOpIdentical |
| 모델 `<rule>` 미포팅 | paramlist.go assignMap | 함수 타입은 fallback 배정만 |

## 도구

- C++ 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `pre:break start <action>`).
  계측: src TU를 scratchpad에 백업, fprintf 삽입, `ONLY=<tu> build.py`, 끝나면 복원.
  Go 쪽에 같은 형식 트레이스를 넣고 나란히 비교(pretty printer 토큰, collapse 규칙, guardCalls 등).
- Go↔C++ 비교: `actcmp.py`, `rulecmp.py`(규칙 적용 수), C++ `print tree block`/`print map`.
- 캡처 없는 x64 코퍼스: `rawcmp.py testdata/<corpus>/x64_goldens.json [name]`.
- : GenCapture가 getFNTypes 기록(C++ decode 아님)을 빼고 쓴다. 옛 캡처는 재캡처 필요할 수 있음.
- `.typeorder`: GenCapture가 getFNTypes 기록(C++ decode 아님)을 빼고 쓴다. 옛 캡처는 재캡처가 필요할 수 있다.
- Go 추적: `SSA_DUMP_AFTER`, `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`, `INFER_TRACE`.
