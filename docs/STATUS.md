# 프로젝트 상태

목표: Ghidra C++ 디컴파일러를 Go로 동일 동작 포팅(CLAUDE.md). 이력은 `git log`/`docs/CHANGELOG.md`.

## 현재 수치 (2026-10-08)

| 측정 | 결과 | 비고 |
|---|---|---|
| realexe private-sample seed1/2/3/4 (x86-32) | 200/200/200/200 | 전부 HEAD 코어 골든(12.0.4판은 golden_12.0.4) |
| realexe private-sample seed1/2/3 (x64 UE4) | 200/200/200 | HEAD 코어 골든 |
| 게이트 `tools/gates.py` | 전부 유지 | tree 10/10, breadth 3/3, corpus 8/8, corpus2 10/13, x64_auto 108/109 |
| x64 코퍼스 C++ 코어 대조 `rawcmp.py` | corpus 8/8, corpus2 13/13, x64_auto 109/109 | 같은 바이트를 C++ 하네스로 |

측정: `realexe.py measure --work local/realexe/<name>`. 게이트 잔여 불일치는 골든 JSON에 없는 환경
정보(재배치 호출 이름, 전역/스택 심볼 이름, `__ImageBase`)이며 C++ 코어 출력과는 일치한다.

골든 코어는 ghidra-ref HEAD(12.2 DEV)여야 한다: `tools/cppharness/build_native.py`로 만든 decompile.exe를
local/ghidra12_head에 넣고 `GHIDRA_HEADLESS=<그 사본>/support/analyzeHeadless.bat realexe.py sample`.
shift count >= 64 같은 C++ UB는 이 빌드 동작을 따른다(pcodeop.go INT_RIGHT nzmask).

## 알려진 불일치 (known mismatch)

| 항목 | 위치 | 영향 |
|---|---|---|
| 모델 rule 일부 미포팅 | modelrules.go `SetModelRules` | x86-64 gcc/swift의 join_dual_class, goto_stack, qualifier 규칙은 버림(win/x86gcc 규칙은 포팅) |
| 프로토타입 저장소 배정은 기본 모델만 rule 보유 | bridge.go `SetModelRules` | 이름 있는 다른 prototype의 rule 미적용 |
| collapseConstantSymbol 미포팅 | rules_ghidra_port.go RuleCollapseConstants | equate 상수 접기 시 심볼 전달 없음 |

## 다음 후보

- 새 표본(seed5 이상)으로 미확인 실패 수집: `realexe.py sample --work <w> --n 200 --seed N` 후 측정.
- x86-64 gcc 모델 rule(MultiSlotDualAssign, GotoStack): modelrules.cc 해당 클래스, 대상 Go 파일
  modelrules.go, 성공 기준은 SysV 바이너리 골든(현재 코퍼스 없음).

## 도구

- C++ 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `pre:trace address A B` + `pre:trace enable`로
  주소 범위의 규칙별 변화, `pre:break start <action>`).
  계측: src TU를 scratchpad에 백업, getenv 게이트 fprintf 삽입, `ONLY=<tu> build.py`, 끝나면 복원.
  Go 쪽에 같은 형식 트레이스를 넣고 나란히 비교.
- Go↔C++ 비교: `actcmp.py`, `rulecmp.py`(규칙 적용 수), C++ `print tree block`/`print map`.
- 캡처 없는 x64 코퍼스: `rawcmp.py testdata/<corpus>/x64_goldens.json [name]`.
- `.typeorder`: GenCapture가 getFNTypes 기록(C++ decode 아님)을 빼고 쓴다. 옛 캡처는 재캡처가 필요할 수 있다.
- Go 추적: `SSA_DUMP_AFTER`, `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`, `INFER_TRACE`.
