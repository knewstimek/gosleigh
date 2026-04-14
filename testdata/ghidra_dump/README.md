# Ghidra SSA Dump Infrastructure

Ghidra headless를 사용해 특정 함수의 post-merge SSA 상태(HighFunction)를
JSON으로 덤프하는 유틸리티. Gosleigh와 C++ Ghidra 출력을 사이드바이사이드
비교해 parity gap을 특정할 때 사용.

## 파일

- `GhidraGcdDump.java` -- Ghidra GhidraScript. HighFunction의 모든 BasicBlock,
  PcodeOpAST, Varnode, HighVariable 정보를 JSON으로 출력.
- `gcd_x86_32.bin` -- 24바이트 MSVC /O1 x86-32 gcd 함수 (frameless,
  ESP-relative params, CDQ+IDIV). `msvc_diag_test.go:TestMSVC_Gcd`와 동일.
- `gcd_x86_32_ssa.json` -- 위 스크립트로 생성한 Ghidra 12.0.4 기준 SSA 덤프.
  H8 근본 원인 특정에 사용 (2026-04-14).

## 사용법

```bash
# 덤프 재생성 (Ghidra 12 + JDK 21 필요)
mkdir -p /tmp/ghidra_proj
analyzeHeadless /tmp/ghidra_proj gcd_dump \
  -import testdata/ghidra_dump/gcd_x86_32.bin \
  -loader BinaryLoader -processor "x86:LE:32:default" -loader-baseAddr 0x0 \
  -scriptPath testdata/ghidra_dump \
  -postScript GhidraGcdDump.java testdata/ghidra_dump/gcd_x86_32_ssa.json 0x0
```

## 주요 발견 (2026-04-14 H8)

덤프로 확인한 Ghidra의 gcd SSA 구조:
- Block 1 (loop head)에 `Merge::snipReads`가 삽입한 합성 COPY가 존재:
  `COPY phi_param_2 → unique(iVar1)` (seq 94, 원 MULTIEQUAL 직후)
- Body는 `iVar1`을 SREM의 divisor 및 param_1 피드백 소스로 사용
- Gosleigh에는 이 COPY가 없음. `pkg/pcode/merge.go`의 `processCopyTrims`와
  `markInternalCopies`가 스텁이고, `mergeAddrTied` / `unifyAddress` /
  `eliminateIntersect` / `snipReads` / `allocateCopyTrim` 전체 파이프라인
  (`merge.cc` 라인 403-700) 미포팅 상태
- H8 근본 원인: 이 파이프라인 누락으로 iVar1 materialization 불가
