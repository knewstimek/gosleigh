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

---

## MSVC 테스트 함수 (2026-04-12)

이 함수들은 MSVC x86-32로 컴파일된 바이너리에서 추출한 실제 기계어 패턴을 사용한다.
Ghidra 실측 golden은 아직 없음; 논리적 정확성 및 rule parity를 기준으로 평가.

### AbsVal (MSVC x86-32)

```c
// Gosleigh 출력
int processEntry entry(undefined4 param_1, undefined4 param_2, int param_3) {
    int local_0;

    if (param_3 < 0) {
        local_0 = -param_3;
    } else {
        local_0 = param_3;
    }
    return local_0;
}
```

상태: **정상** -- MSVC `NEG + conditional branch` 패턴 정확히 변환됨. RulePropagateCopy addr-tied guard 수정으로 else-body 공백 문제 해결.

---

### Classify2 (MSVC x86-32)

```c
// Gosleigh 출력
unsigned int processEntry entry(undefined4 param_1, undefined4 param_2, int param_3, int param_4) {
    unsigned int local_0;

    if (param_3 <= 0) {
        local_0 = 0;
    } else if (param_3 < param_4) {
        local_0 = 2;
    } else {
        local_0 = 1;
    }
    return local_0;
}
```

상태: **대부분 정상** -- 논리적으로 정확. 잔여 구조적 차이:
- `param_3 < param_4`가 `param_4 <= param_3`의 inversion으로 표현됨 (ActionPreferComplement 또는 블록 구조 순서에 따라 달라짐). 두 표현 모두 동치.
- Ghidra는 원본 JLE 방향을 따라 `param_4 <= param_3` 형태를 선호할 가능성 있음.

---

### CountedLoop (MSVC x86-32, PUSH EBP 프롤로그 + stack locals)

```c
// Gosleigh 출력 (현재)
undefined4 processEntry entry(undefined4 param_1, undefined4 param_2) {
    undefined4 local_0;

    local_0 = local_178 - 4;
    local_0 = local_0 - 8;
    *(local_0 - 8) = 0;
    *(local_0 - 4) = 0;
    while (*(local_0 - 4) < 5) {
        *(local_0 - 8) = *(local_0 - 8) + *(local_0 - 4);
        *(local_0 - 4) = *(local_0 - 4) + 1;
    }
    return *(local_0 - 8);
}
```

```c
// 예상 Ghidra 출력
int processEntry entry(undefined4 param_1, undefined4 param_2) {
    int local_8;
    int local_4;

    local_8 = 0;
    local_4 = 0;
    while (local_4 < 5) {
        local_8 = local_8 + local_4;
        local_4 = local_4 + 1;
    }
    return local_8;
}
```

상태: **미해결** -- Stack Heritage 미구현. ActionStackPtrFlow가 LOAD만 변환(COPY(stack_input_vn))하고 STORE는 미변환. `STORE(ram, INT_ADD(FP, const), val)` -> stack local 변수 할당 변환 필요. 루프 내 stack local의 SSA phi node 생성도 필요.

---

### SumList (MSVC x86-32, PUSH ECX 프롤로그 + stack locals)

```c
// Gosleigh 출력 (현재)
undefined4 processEntry entry(undefined4 param_1, undefined4 param_2, int param_3) {
    undefined4 local_0;

    local_0 = local_142 - 4;
    local_0 = local_0 - 4;
    *(local_0 - 4) = 0;
    while (param_3 != 0) {
        *(local_0 - 4) = *(local_0 - 4) + *param_3;
        *(local_0 + 8) = *(param_3 + 4);
    }
    return *(local_0 - 4);
}
```

상태: **미해결** -- CountedLoop와 동일한 Stack Heritage 이슈. PUSH ECX를 스택 프레임 설정 패턴으로 인식하지 못함 (PUSH EBP + MOV EBP, ESP 대신 PUSH ECX로 1개 local 할당).

---

## 우선순위 수정 목록 (현재 잔여)

1. **[높음] Stack Heritage**: STORE(ram, INT_ADD(FP,const), val) -> stack local 변수 할당. CountedLoop/SumList 개선에 필수. ActionStackPtrFlow 확장 또는 별도 Heritage mini-pass.
2. **[중간] Classify2 조건 방향**: param_3 < param_4 vs param_4 <= param_3 -- ActionPreferComplement 또는 블록 구조 순서 조정.
3. **[낮음] AArch64 함수명** -- 테스트에서 `Name: "entry"`로 변경하면 해결. 의미 있는 이름 유지를 위해 보류.
4. **[낮음] 포맷 차이** -- 중괄호 위치, 쉼표 뒤 공백 등 Ghidra 스타일 vs 표준 C 스타일. 기능 parity에 영향 없음.
