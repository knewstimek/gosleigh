# Ghidra Golden vs Gosleigh Output Diff

최종 갱신: 2026-04-11 (commit bbef55a)
갱신 방법: `go test ./pkg/loader/... -v -run "TestX86ClassifySign|TestX86Multiply|TestX86Add3|TestX86Complex$|TestAARCH64Simple"` 실행 후 수동 기록

---

## 요약: 공통 문제 패턴

| 문제 | 함수 | 수정 레이어 |
|------|------|------------|
| `return EIP` (잘못된 리턴 레지스터) | multiply, add3, aarch64 | ActionStackPtrFlow / proto |
| CF/OF/SF/ZF/PF 플래그 로컬 선언 | multiply, add3, aarch64 | ActionFoldFlagConditions 미적용 |
| unique_* 변수 미제거 | multiply, add3, aarch64 | dead-store 제거 범위 |
| SUBPIECE/CARRY/SCARRY/POPCOUNT 그대로 | multiply, add3 | Rule 적용 미흡 |
| ESP/EBP/EBX callee-saved 로컬 선언 | multiply, add3, classify_sign | ActionPrototypeTypes 미구현 |
| EAX -> uVar1 rename 없음 | classify_sign | ActionReturnSplit 미구현 |
| else-if 대신 중첩 if | classify_sign | PrintC 블록 출력 |
| undefined4 대신 unsigned int | 전체 | TypeFactory 기본 타입 표현 |
| ghost params (param_1, param_2) 없음 | 전체 x86-32 | ABI/cspec |

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

### Gosleigh 현재 출력
```c
unsigned int classify_sign(int param_0) {
    int EAX;
    unsigned int ESP;

    if (param_0 == 0) {
        EAX = 0;
    } else {
        if (0 < param_0) {
            EAX = 1;
        } else {
            EAX = -1;
        }
    }
    return EAX;
}
```

### 차이
- 타입: `unsigned int` vs `undefined4`
- 함수명: `classify_sign` vs `processEntry entry`
- ghost params 없음 (param_1, param_2=argc/argv)
- 반환 변수: `EAX` vs `uVar1` (ActionReturnSplit 미구현)
- `unsigned int ESP` 로컬 선언 (ActionPrototypeTypes 미구현)
- `else if` 대신 중첩 `else { if ... }`
- 상수: `-1` vs `0xffffffff` (조건: Ghidra는 `param_3 < 1`, Gosleigh는 `0 < param_0`)

---

## multiply (x86-32)

### Ghidra 실측
```c
int processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  return param_3 * param_4;
}
```

### Gosleigh 현재 출력
```c
unsigned int multiply(unsigned int param_0, unsigned int param_1) {
    unsigned int tmp_0;
    unsigned long long tmp_1;
    unsigned int EAX;
    unsigned int ESP;
    unsigned int EBP;
    unsigned char CF;
    unsigned char OF;
    unsigned int EIP;

    unique_41500_4 = param_1;
    ESP = param_0 + -4;
    unique_87304_4 = 4;
    *ESP = param_1;
    EBP = ESP;
    tmp_0 = *(ESP + 8);
    EAX = tmp_0;
    tmp_1 = (unsigned long long)tmp_0 * (unsigned long long)*(ESP + 0xc);
    EAX = SUBPIECE(tmp_1, 0);
    unique_79500_4 = SUBPIECE(tmp_1, 4);
    CF = (unsigned long long)EAX != tmp_1;
    OF = CF;
    unique_87300_4 = 0;
    ESP = ESP + 4;
    EBP = *ESP;
    EIP = *ESP;
    ESP = ESP + 4;
    return EIP;
}
```

### 차이
- 파라미터 수: 2 vs 4 (ghost params + 실제 params 미분리)
- ActionStackPtrFlow 미적용 (PUSH/POP 패턴이 multiply에선 작동 안 함)
- SUBPIECE(a*b, 0) -> `a * b` 단순화 미구현
- CF/OF 플래그 로컬 선언 및 연산 그대로 노출
- unique_* 변수 미제거
- `return EIP` (완전히 틀린 리턴 -- EIP는 리턴 주소)

---

## add3 (x86-32)

### Ghidra 실측
```c
int processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)
{
  return param_3 + param_4 + param_5;
}
```

### Gosleigh 현재 출력
```c
unsigned int add3(unsigned int param_0, unsigned int param_1, unsigned int param_2) {
    // CF, OF, SF, ZF, PF, EAX, EBX, ESP, EBP, EIP 모두 로컬
    // CARRY/SCARRY/POPCOUNT 연산 그대로
    // return EIP  <- 틀림
}
```

### 차이
- multiply와 동일한 구조적 문제
- 추가로 CARRY/SCARRY/POPCOUNT 연산 그대로 (flags folding 전혀 안 됨)
- SF/ZF/PF 플래그까지 추가로 노출

---

## aarch64_add_ret (AArch64)

### Ghidra 실측
```c
long processEntry entry(void)
{
  long in_RSI;
  long in_RDI;

  return in_RDI + in_RSI;
}
```
(주: 이건 x64_add_ret -- aarch64 golden은 별도)

### Gosleigh 현재 출력 (aarch64_add_ret)
```c
unsigned long long aarch64_add_ret(unsigned long long param_0, unsigned long long param_1, unsigned long long param_2) {
    unsigned long long tmp_0;
    unsigned long long pc;
    unsigned char tmpCY; unsigned char tmpOV; unsigned char tmpNG; unsigned char tmpZR;
    unsigned long long x0;

    unique_23f00_8 = param_1;
    tmpCY = CARRY(param_0, param_1);
    tmpOV = SCARRY(register_4000_8, param_1);
    tmp_0 = register_4000_8 + param_1;
    tmpNG = tmp_0 < 0; tmpZR = tmp_0 == 0;
    x0 = tmp_0;
    pc = param_2;
    return param_2;
}
```

### 차이
- `return param_2` (pc = param_2 후 return -- 틀림, param_0 + param_1을 반환해야 함)
- tmpCY/tmpOV/tmpNG/tmpZR 플래그 그대로 노출
- register_4000_8 이름 (AArch64 레지스터 이름 미매핑)
- unique_* 미제거

---

## 우선순위 수정 목록

1. **[긴급] ActionStackPtrFlow 범용화** -- classify_sign에만 적용, multiply/add3/aarch64는 미적용. 스택 프레임 감지가 PUSH EBP/MOV EBP,ESP 패턴 이외에는 동작 안 함.
2. **[긴급] 플래그 folding 범용화** -- ActionFoldFlagConditions가 classify_sign에는 작동, multiply/add3에는 미작동. 왜?
3. **[높음] SUBPIECE+IMUL -> 단순 곱셈** -- RuleSubpieceOfInt 계열 미구현
4. **[높음] unique_* dead-store 제거 범위** -- printc의 numDescend==0 체크가 classify_sign에만 특화
5. **[중간] ActionPrototypeTypes** -- callee-saved 레지스터 (ESP, EBP, EBX) 제거
6. **[중간] ActionReturnSplit** -- EAX/x0 -> uVar1/iVar1 rename
7. **[낮음] undefined4 타입 표현, ghost params, else-if 체인**
