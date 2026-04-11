# Ghidra Golden vs Gosleigh Output Diff

최종 갱신: 2026-04-12 (commit after processEntry + type inference)
갱신 방법: `go test ./pkg/loader/... -v -run "TestX86ClassifySignGolden|TestX86MultiplyGolden|TestX86Add3Golden|TestAARCH64Simple"` 실행 후 수동 기록

---

## 요약: 공통 문제 패턴

| 문제 | 함수 | 수정 레이어 | 상태 |
|------|------|------------|------|
| `return EIP` (잘못된 리턴 레지스터) | multiply, add3, aarch64 | ActionStackPtrFlow / proto | **완료** |
| CF/OF/SF/ZF/PF 플래그 로컬 선언 | multiply, add3, aarch64 | ActionFoldFlagConditions | **완료** |
| unique_* 변수 미제거 | multiply, add3, aarch64 | dead-store 제거 범위 | **완료** |
| SUBPIECE/CARRY/SCARRY/POPCOUNT 그대로 | multiply, add3 | Rule 적용 | **완료** |
| ESP/EBP/EBX callee-saved 로컬 선언 | multiply, add3, classify_sign | ActionPrototypeTypes parity | **완료** |
| EAX -> uVar1 rename 없음 | classify_sign | ActionReturnSplit parity | **완료** |
| else-if 대신 중첩 if | classify_sign | PrintC 블록 출력 | **완료** |
| undefined4 대신 unsigned int | 전체 | TypeFactory 기본 타입 표현 | **완료** |
| AArch64 unsigned long long 대신 long | aarch64 | TYPE_INT seeding + LP64 | **완료** |
| 0-indexed params (param_0) | 전체 | GetParamName 1-indexed 변경 | **완료** |
| ghost params 없음 | 전체 x86-32 | SetProcessEntry + 렌더링 | **완료** |
| processEntry 함수명 prefix 없음 | 전체 x86-32 | SetProcessEntry annotation | **완료** |
| x86 리턴/파라미터 타입 int | multiply, add3 | 스택 param TYPE_INT seed + INT_MULT 전파 | **완료** |

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

### Gosleigh 출력 (ProcessEntry 모드)
```c
undefined4 processEntry entry(undefined4 param_1, undefined4 param_2, int param_3) {
    undefined4 uVar1;

    if (param_3 == 0) {
        uVar1 = 0;
    } else if (param_3 < 1) {
        uVar1 = 0xffffffff;
    } else {
        uVar1 = 1;
    }
    return uVar1;
}
```

### 차이 (잔여)
- 없음 (내용 완전 일치, 포맷 차이만: 중괄호 위치, 들여쓰기, 쉼표 뒤 공백)

---

## multiply (x86-32)

### Ghidra 실측
```c
int processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  return param_3 * param_4;
}
```

### Gosleigh 출력 (ProcessEntry 모드)
```c
int processEntry entry(undefined4 param_1, undefined4 param_2, int param_3, int param_4) {
    return param_3 * param_4;
}
```

### 차이 (잔여)
- 없음 (내용 완전 일치, 포맷 차이만)

---

## add3 (x86-32)

### Ghidra 실측
```c
int processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)
{
  return param_3 + param_4 + param_5;
}
```

### Gosleigh 출력 (ProcessEntry 모드)
```c
int processEntry entry(undefined4 param_1, undefined4 param_2, int param_3, int param_4, int param_5) {
    return param_3 + param_4 + param_5;
}
```

### 차이 (잔여)
- 없음 (내용 완전 일치, 포맷 차이만)

---

## aarch64_add_ret (AArch64)

### Ghidra 실측
```c
long entry(long param_1,long param_2)

{
  return param_1 + param_2;
}
```

### Gosleigh 출력
```c
long aarch64_add_ret(long param_1, long param_2) {
    return param_1 + param_2;
}
```

### 차이 (잔여)
- 함수명: `aarch64_add_ret` vs `entry` -- 테스트 설계 차이 (Ghidra는 entrypoint를 `entry`로 명명, 우리는 명시적 이름 사용)

---

## 우선순위 수정 목록 (현재 잔여)

1. **[낮음] AArch64 함수명** -- 테스트에서 `Name: "entry"`로 변경하면 해결. 의미 있는 이름 유지를 위해 보류.
2. **[낮음] 포맷 차이** -- 중괄호 위치, 쉼표 뒤 공백 등 Ghidra 스타일 vs 표준 C 스타일. 기능 parity에 영향 없음.
