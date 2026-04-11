# Ghidra Golden vs Gosleigh Output Diff

최종 갱신: 2026-04-11 (commit 1e81d5b)
갱신 방법: `go test ./pkg/loader/... -v -run "TestX86ClassifySign|TestX86Multiply|TestX86Add3|TestX86Complex$|TestAARCH64Simple"` 실행 후 수동 기록

---

## 요약: 공통 문제 패턴

| 문제 | 함수 | 수정 레이어 | 상태 |
|------|------|------------|------|
| `return EIP` (잘못된 리턴 레지스터) | multiply, add3, aarch64 | ActionStackPtrFlow / proto | **완료** |
| CF/OF/SF/ZF/PF 플래그 로컬 선언 | multiply, add3, aarch64 | ActionFoldFlagConditions 미적용 | **완료** |
| unique_* 변수 미제거 | multiply, add3, aarch64 | dead-store 제거 범위 | **완료** |
| SUBPIECE/CARRY/SCARRY/POPCOUNT 그대로 | multiply, add3 | Rule 적용 미흡 | **완료** |
| ESP/EBP/EBX callee-saved 로컬 선언 | multiply, add3, classify_sign | ActionPrototypeTypes 미구현 | **완료** |
| EAX -> uVar1 rename 없음 | classify_sign | ActionReturnSplit 미구현 | **완료** |
| else-if 대신 중첩 if | classify_sign | PrintC 블록 출력 | **완료** |
| undefined4 대신 unsigned int | 전체 | TypeFactory 기본 타입 표현 | **완료** |
| AArch64 unsigned long long 대신 long | aarch64 | TYPE_INT seeding + LP64 표현 | **완료** |
| ghost params (param_1, param_2) 없음 | 전체 x86-32 | ABI/cspec | 미구현 (Known Mismatch) |
| processEntry 함수명 | 전체 x86-32 | ABI/cspec | 미구현 (Known Mismatch) |
| x86 리턴 타입 int | multiply, add3 | processEntry context 타입 | 미구현 (Known Mismatch) |

---

## classify_sign (x86-32)

### Ghidra 실측
```c
undefined4 processEntry entry(undefined4 param_1,undefined4 param_2,int param_3)
{
  undefined4 uVar1;

  if (param_3 == 0) {
    uVar1 = 0;
  }
  else if (param_3 < 1) {
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

### Gosleigh 현재 출력 (2026-04-11 fd269f7)
```c
undefined4 classify_sign(int param_0) {
    undefined4 uVar1;

    if (param_0 == 0) {
        uVar1 = 0;
    } else if (param_0 < 1) {
        uVar1 = 0xffffffff;
    } else {
        uVar1 = 1;
    }
    return uVar1;
}
```

### 차이 (잔여)
- 함수명: `classify_sign` vs `processEntry entry` (Known Mismatch)
- ghost params 없음 (param_1, param_2=argc/argv) (Known Mismatch)
- 파라미터 이름: `param_0` vs `param_3` (ghost params 없어서 번호 차이)

### 완료된 항목
- [x] 타입: `undefined4 uVar1` -- 완료
- [x] 리턴 타입: `undefined4` -- 완료
- [x] 반환 변수 이름: `uVar1` (ActionReturnSplit parity) -- 완료
- [x] else-if 체인 -- 완료
- [x] 상수: `0xffffffff` -- 완료
- [x] callee-saved 레지스터 (ESP 등) 로컬 제거 -- 완료

---

## multiply (x86-32)

### Ghidra 실측
```c
int processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  return param_3 * param_4;
}
```

### Gosleigh 현재 출력 (2026-04-11 fd269f7)
```c
undefined4 multiply(undefined4 param_0, undefined4 param_1) {
    return param_0 * param_1;
}
```

### 차이 (잔여)
- 함수명: `multiply` vs `processEntry entry` (Known Mismatch)
- ghost params 없음 (param_1, param_2=argc/argv) (Known Mismatch)
- 리턴 타입: `undefined4` vs `int` (processEntry context 타입, Known Mismatch)
- 파라미터 타입: `undefined4` vs `int` (processEntry context, Known Mismatch)

### 완료된 항목
- [x] 파라미터 타입: `undefined4` -- 완료
- [x] SUBPIECE+IMUL -> 단순 곱셈 -- 완료
- [x] CF/OF 플래그 제거 -- 완료
- [x] unique_* 변수 제거 -- 완료
- [x] return EIP 제거 -- 완료
- [x] callee-saved 레지스터 제거 -- 완료

---

## add3 (x86-32)

### Ghidra 실측
```c
int processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)
{
  return param_3 + param_4 + param_5;
}
```

### Gosleigh 현재 출력 (2026-04-11 fd269f7)
```c
undefined4 add3(undefined4 param_0, undefined4 param_1, undefined4 param_2) {
    return param_0 + param_1 + param_2;
}
```

### 차이 (잔여)
- 함수명: `add3` vs `processEntry entry` (Known Mismatch)
- ghost params 없음 (Known Mismatch)
- 리턴/파라미터 타입: `undefined4` vs `int` (processEntry context, Known Mismatch)

### 완료된 항목
- [x] 파라미터 타입: `undefined4` -- 완료
- [x] CARRY/SCARRY/POPCOUNT 제거 -- 완료
- [x] SF/ZF/PF 플래그 제거 -- 완료
- [x] return EIP 제거 -- 완료
- [x] callee-saved 레지스터 제거 -- 완료

---

## aarch64_add_ret (AArch64)

### Ghidra 실측
```c
long entry(long param_1,long param_2)

{
  return param_1 + param_2;
}
```

### Gosleigh 현재 출력 (2026-04-11 1e81d5b)
```c
long aarch64_add_ret(long param_0, long param_1) {
    return param_0 + param_1;
}
```

### 차이 (잔여)
- 함수명: `aarch64_add_ret` vs `entry` (processEntry Known Mismatch)
- 파라미터 번호: `param_0/1` vs `param_1/2` (processEntry ghost params 없어서 번호 차이)

### 완료된 항목
- [x] 플래그 변수 제거 -- 완료
- [x] return 값 정상 -- 완료
- [x] 파라미터 수 정상 -- 완료
- [x] unique_* 제거 -- 완료
- [x] 리턴 타입: `long` (LP64 TYPE_INT 64-bit) -- 완료 (1e81d5b)
- [x] 파라미터 타입: `long` (TYPE_INT, LP64 convention) -- 완료 (1e81d5b)

---

## 우선순위 수정 목록 (현재 잔여)

1. **[높음] processEntry wrapper** -- x86-32 entry 함수에 `processEntry entry(undefined4 param_1, undefined4 param_2, ...)` ghost params 추가. ABI/cspec 변경 필요.
2. **[낮음] x86 리턴 타입 int** -- processEntry wrapper 구현 후 자동으로 해결될 가능성 높음.
