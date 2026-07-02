# x86-64 breadth 확장 corpus (struct / 2D array / jumptable switch)

기존 `testdata/x64_corpus`에 없던 실전 패턴으로 Ghidra 골든을 만들어 트리 갭을
매핑하는 디스커버리 자산. 기존 corpus는 건드리지 않는다(7/8 baseline 무회귀).

## 파이프라인 (x64_corpus와 동일, 별도 골든)

```
py -3 testdata/x64_breadth/build.py        # breadth.c -> breadth.obj (MSVC x64 /Od /GS-)
py -3 testdata/x64_breadth/run_ghidra.py   # obj -> Ghidra 12 헤드리스 -> x64_breadth_goldens.json
X64_BREADTH=1 go test ./pkg/loader/ -run TestX64BreadthGoldenMap -v   # 트리 갭 맵
```

- `GenGoldens.java`는 `../x64_corpus`의 것을 그대로 재사용(제네릭 덤퍼).
- `breadth.obj`는 gitignore(`*.obj`). 바이트는 골든 JSON에 들어간다.
- 하네스 `TestX64BreadthGoldenMap`은 `x64_corpus_diag_test.go`의 헬퍼
  (`x64CorpusEntry`/`normGhidraC`/`hexToBytes`)를 공유한다.

## 함수 (3개)

- `dist_sq(struct Point *)` -- 포인터를 통한 struct 필드 접근(offset 0, 8).
- `sum2d(long *, rows, cols)` -- 중첩/2D 배열 인덱싱(`m[i*cols+j]`).
- `dispatch(long)` -- dense switch(0..7), MSVC /Od에서 jump table로 lowering.

## 측정된 갭 맵 (2/3 MATCH)

- **dist_sq MATCH**: 트리가 multi-offset 포인터 deref를 Ghidra와 동일 복구
  (`*param_1 * *param_1 + param_1[1] * param_1[1]`). Ghidra도 debug info 없이
  struct 타입을 복원하지 않고 `int *` + `param_1[1]`로 두므로, struct **타입**
  복구(ActionInferTypes/RuleStructOffset0)는 이 입력으로 검증되지 않는다.
- **sum2d MATCH**: 2D 주소 산술
  `*(int *)(param_1 + (longlong)(local_18 * param_3 + local_14) * 4)` 완전 일치.
- **dispatch MISMATCH (핵심 갭)**: jump table이 `.rdata`에 `&__ImageBase`
  상대 오프셋으로 있어 relocation을 요구한다. 단일 .text 블롭에는 image base와
  reloc/.rdata가 없어 **Ghidra 자신도** 복구 실패(`WARNING: Could not emulate
  address calculation` + `Treating indirect jump as call`) -> BRANCHIND를
  CALLIND로 강등하고 artificial return을 붙인다(flow.cc `truncateIndirectJump`,
  fail_normal). 트리는 이 폴백이 없어 raw `goto *(...)` + `goto label_missing`가
  printC까지 생존한다.

### dispatch 갭의 근본 분류

1. **jumptable 복구 미구동**: `JumpTable`/`JumpModel` 머신러리는 `jumptable.go`에
   포팅됨(CHANGELOG K3/A8 scaffold)이나 decompile 파이프라인에서 호출되지 않는다.
   `AddJumpTable`/`RecoverAddresses`/`SwitchOver` 호출자가 `RecoverMultistage`
   내부뿐. C++ 대응: `Funcdata::recoverJumpTables` 드라이버.
2. **truncateIndirectJump 폴백 미포팅**: 복구 실패한 BRANCHIND -> CALLIND +
   artificial return 전환이 Go에 없다. C++: `FlowInfo::truncateIndirectJump`
   (flow.cc:727, `setBadJumpTable(true)`). 이것이 `void`/`goto *` vs
   `undefined8`/`uVar1 = (*(code*)(...))()` + `return` 차이의 직접 원인.
3. **`goto label_missing`**: range guard의 default(범위 밖) 타깃 블록이 링크되지
   않음. jumptable/switch 정규화 + artificialHalt 재구조화가 없어서 발생. #1/#2
   에서 파생.
4. **`&__ImageBase` 부재 / 상수 base 차이**: 단일 .text 하네스가 image base +
   .rdata + reloc을 갖지 않음. 트리의 테이블 base가 raw 상수(`13952`/`0x1150`)로,
   Ghidra의 `&__ImageBase` + `0x5b40`과 다르다. loader/harness 계층 갭(별개).

### 신규/기지

- struct/2D deref MATCH = 기존 능력 확인(신규 갭 아님).
- jumptable 복구 미구동 + truncateIndirectJump 폴백 부재 = **신규 매핑**.
  `docs/PARITY_AUDIT.md`(SLEIGH 계층)와 `docs/STATUS.md`에 항목 없음. jumptable은
  CHANGELOG에 scaffold로만 기록됨(파이프라인 미연결). 대규모 구현 대상이라 이번엔
  매핑까지.
