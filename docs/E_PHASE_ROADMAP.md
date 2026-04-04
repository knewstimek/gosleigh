# E-Phase Roadmap: Decompiler Output Quality

x86 translation layer (D-phase) 완료 후, 실사용 품질의 C 출력을 위한 분석 레이어 포팅.

## 현재 출력 vs 목표 출력

현재 PrintC 출력 예시:
```c
void func(void) {
    *(ulong *)(ESP + 0xfffffff4) = EAX;
    EAX = *(ulong *)(EBP + 8);
    if (EAX <= 0) goto lab_1;
}
```

E-phase 완료 후 목표:
```c
int classify2(int x, int y) {
    if (x > 0) {
        if (y > x) return 2;
        return 1;
    }
    return 0;
}
```

## E1: 호출 규약 + 변수 복원 [DONE 2026-04-04]

**핵심 deliverable**: 함수 파라미터와 로컬 변수에 이름 붙이기.
- C++ 참조: `fspec.cc` (ProtoModel/FuncProto/ParamEntry/cdecl), `variable.cc` (HighVariable/HighParam/HighLocal), `varmap.cc` (ScopeLocal/MapState/AliasChecker), `cover.cc` (Cover/LocationRange), `merge.cc` (Merge)
- 구현:
  - cdecl ProtoModel: EBP+8 -> param1, EBP+12 -> param2, EAX -> return
  - HighVariable 계층 (HighParam, HighLocal, HighGlobal stubs)
  - ScopeLocal: 스택 프레임 변수 이름 맵핑
  - Cover + Merge: SSA phi-node 병합, 변수 liveness
  - PrintC 연동: 함수 선언 파라미터 출력, 로컬 변수 선언
- E2E: classify2 출력에 `int x, int y` 파라미터 명시

## E2: Dead Code 제거 + Cast 삽입 + CoreAction 오케스트레이션

**핵심 deliverable**: 깔끔한 C 출력 (플래그 변수 제거, 타입 캐스트).
- C++ 참조: `coreaction.cc` (ActionDeadCode, ActionSetCasts, ActionNormalizeSetup, ActionPrototypeTypes), `cast.cc` (CastStrategy/CastStrategyC)
- 구현:
  - ActionDeadCode: 사용되지 않는 CF/ZF/SF/OF 플래그 varnode 제거
  - ActionSetCasts: 타입 불일치 (int)(ptr) 캐스트 자동 삽입
  - coreaction 전체 오케스트레이션 파이프라인 완성
- E2E: 플래그 dead assign 없는 깔끔한 C 출력

## E3: FP 타입 추론 레이어

**핵심 deliverable**: float/double 변수 C 출력.
- x87 FP decode는 D20에서 완료 (FLD1/FLDZ/FSTP p-code 정상 동작 확인)
- C++ 참조: Heritage float type annotation, `rules_float.go` (기 구현), PrintC float emit
- 구현:
  - Heritage에서 FLOAT_* opcode varnode를 float 타입으로 마킹
  - PrintC: `float` / `double` 타입 선언 + 리터럴 출력 (`1.0f`, `0.0`)
  - RuleFloatCast / RuleIgnoreNan 등 기 구현된 float rules 연동
- E2E: float 파라미터를 갖는 함수 디컴파일

## E4: x86-64 지원

**핵심 deliverable**: 64-bit x86 코드 디컴파일.
- x86-64.sla 로드 + 64bit 레지스터 (RAX/RBX/RSI/RDI/R8-R15)
- System V AMD64 ABI: RDI/RSI/RDX/RCX/R8/R9 -> param1~6
- 64-bit golden fixtures 셋 + E2E
- Windows x64 ABI 옵션 (RCX/RDX/R8/R9)

## E5: Type System 강화 (struct/pointer/array)

**핵심 deliverable**: 복합 타입 복원.
- C++ 참조: `type.cc` (TypePointer/TypeArray/TypeStruct 강화), `typegrp.cc` (TypeFactory)
- struct field 접근 패턴 인식 (`EAX+4` -> `ptr->next`)
- 배열 인덱스 패턴 (`EDX+EAX*4` -> `arr[i]`)
- PrintC: `struct Node { int val; struct Node *next; }` 자동 생성

## E6: 심볼 복원 (DWARF + PE import)

**핵심 deliverable**: 함수명/변수명 복원.
- DWARF debug info 파싱 → 함수명, 변수명, 타입
- PE import table → API 함수명 (MessageBoxA, CreateFileW 등)
- ELF symbol table → 함수명

## 우선순위 및 의존성

```
E1 (호출 규약 + 변수) -> E2 (dead code + cast) -> E3 (FP layer)
                                                 -> E4 (x86-64)
E2 + E4 완료 후 -> E5 (struct/array type)
E5 완료 후 -> E6 (symbol recovery)
```

## 완료 기준 (E-phase 전체)

- 파라미터명/로컬변수명 포함한 읽기 쉬운 C 출력
- 플래그 dead code 없음
- float/double 타입 출력
- x86-64 기초 지원
- 기본 struct/pointer 타입 출력
- API 함수명 복원 (PE import)
