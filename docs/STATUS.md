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

## 검증 범위와 한계

- realexe 골든은 Ghidra 헤드리스가 준 호스트 정보(함수 경계, 심볼, 타입, 프로토타입: work의 `captures/`,
  `symbols.json`)를 받은 상태의 코어 출력 비교다. 실행 파일만 넣어서는 이 수준이 나오지 않는다.
- 표본은 MSVC PE 두 개(x86-32, x64)이고 4KB 이하 함수만 뽑는다(`realexe.py sample --max-bytes 4096`).
  GCC/Clang, ELF, ARM, 큰 함수, 속도/메모리는 미측정.
- CLI(`cmd/gosleigh`)는 개발용이다. 실사용은 downstream 호스트가 `pkg/decomp`(진입점: `Load` ->
  `Program.Decompile`)와 `pkg/specs`(x86/x64 sla+pspec+cspec embed)로 붙인다. `cmd/goldengap`이 이
  경로로 돌기 때문에 위 realexe/게이트 수치가 곧 공개 API의 수치다.
- 엔진은 취소가 안 되고 일부 실함수에서 메모리가 무한히 늘 수 있다(goldengap `-mem-limit-mb`가 있는
  이유). 상주 호스트는 별도 프로세스에 시간/메모리 상한을 걸고 돌려야 한다.

### 미시작

순서: (downstream) 호스트 어댑터/PDB -> 측정 모드로 어댑터 품질 측정. GCC/ELF 이하는 병행 가능.

| 항목 | 현상 | 참조 | 수정 대상 | 성공 기준 |
|---|---|---|---|---|
| 호스트 어댑터 | Ghidra capture 없이는 호스트 정보가 비어 이름/타입/프로토타입이 빠진다 | C++ 호스트 쪽: `ghidra_arch.cc`, `database_ghidra.cc`(ScopeGhidra), `typegrp_ghidra.cc`, `loadimage_ghidra.cc` | `pcode.HostScope`(funccallspec.go:63), `decomp.Function`을 채우는 downstream 어댑터 | 같은 work를 Ghidra 호스트 정보 대신 어댑터로 돌린 출력의 골든 일치율을 재는 측정 모드 추가 후 수치화 |
| PDB 타입/프로토타입 | downstream은 PE의 RSDS(PDB 경로/GUID)만 읽는다 | Ghidra PDB 파서는 Java(ghidra-ref 미포함)라 parity 대상 아님. MSF/DBI/TPI 포맷 | downstream 호스트 | PDB를 적용한 Ghidra 골든 work에서 일치율 |
| GCC/ELF 표본 | 미측정 | `tools/realexe/realexe.py sample` | `tools/realexe`(현재 PE 전용: `pe_machine`/`ARCH_SPECS`) | GCC로 빌드한 ELF work 200/200 |
| 큰 함수 | 4KB 초과 함수 미측정 | `realexe.py sample --max-bytes` | 측정만 | `--max-bytes` 상향 work 200/200 |
| 게이트 잔여 | corpus2 10/13, x64_auto 108/109 | `testdata/x64_auto/GAPMAP.md`, corpus2 진단 테스트 출력 | `pkg/pcode` | `X64 CORPUS2 MAP` 13/13, x64_auto 109/109 |
| ARM 등 | 실바이너리 미검증(sla 골든 테스트만) | `pkg/sla/aarch64_golden_test.go` | `tools/realexe`(아키텍처 매핑) | ARM 바이너리 work 200/200 |
| seed 연장 | private-sample 51, private-sample 50부터 | `realexe.py sample --seed N` 후 `measure` | 측정만 | 새 work 200/200 |

## 도구

- C++ 하네스: `tools/cppharness` (`hx.py WORK IDX "print C"`, `pre:trace address` + `pre:trace enable`,
  `pre:trace propagation on`, `pre:break start <action>`, `print map`/`print tree block`/`print high X`).
  계측은 src TU를 백업 후 getenv 게이트 fprintf, `ONLY=<tu> build.py`, 끝나면 복원.
- 라이브 계측: ghidra-ref를 x86로 빌드한 decompile.exe를 ghidra12_head에 잠깐 넣고 headless로 단일 함수를
  돌린 뒤 원본으로 되돌린다(stderr가 안 보이므로 env로 지정한 파일에 기록).
- Go 추적: `SSA_DUMP_AFTER=<action>`(부분 문자열 일치), `SSA_DUMP_TYPES`, `SSA_DUMP_TREE`, `RULE_TRACE=1|2`,
  `INFER_TRACE`, `COLLAPSE_TRACE`.
