# Decompiler Pipeline Roadmap (Phase 4-5)

## 목적

Phase 3 (P-code Engine / SSA)에서 생성된 SSA 그래프를 분석/변환하여
최종적으로 C 코드를 출력하는 전체 디컴파일 파이프라인을 구축한다.

## Phase 3과의 연결점

```
Phase 3: Funcdata + Heritage -> SSA-form PcodeOp/Varnode graph
    |
    v
Phase 4: Action/Rule fixpoint loop -> Type inference -> Block structuring
    |
    v
Phase 5: PrintC -> C source output
```

## 핵심 C++ 클래스와 Go 대응 계획

| C++ 클래스 | 파일 | 책임 | 규모 |
|-----------|------|------|------|
| Action/ActionGroup | action.hh/cc | 변환 패스 실행 엔진 | ~327줄 |
| Rule (130개 서브클래스) | ruleaction.hh/cc | 패턴 매칭 기반 SSA 변환 규칙 | ~1,609줄 (hh) |
| Datatype/TypeFactory | type.hh/cc | 타입 시스템 + 타입 팩토리 | ~1,039줄 |
| CollapseStructure | blockaction.hh/cc | CFG -> 구조화 블록 변환 | ~361줄 |
| PrintC | printc.hh/cc | C 코드 출력기 | ~377줄 |

합계 (hh만): ~3,713줄. 구현부 포함 시 훨씬 큼.

## 작업 단위

### WU1. Action/Rule Framework (~1,400 Go줄)

- Action 기본 클래스: apply(), flag/breakpoint, group membership
- ActionGroup: 순차 실행, rule_repeatapply
- ActionRestartGroup: restartPending 시 재실행
- ActionPool: Rule 매칭 + fixpoint 루프
- ActionDatabase: 루트 Action 레지스트리
- Rule 기본 클래스: getOpcode() + applyOp()
- 의존성: Phase 3 (Funcdata, PcodeOp)

### WU2. Type System (~3,700 Go줄)

- Datatype 계층: Base, Char, Void, Pointer, PointerRel, Array, Enum, Struct, Union, Code, Spacebase
- TypeField, TypeBitField
- TypeFactory: intern pool, 타입 생성/검색
- metatype 체계: TYPE_VOID, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR, TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_UNKNOWN
- 의존성: 없음 (Phase 3 타입과 독립)

### WU3. Core Rules -- Batch A: 산술/비트/불리언 (~4,000 Go줄)

- ~50개 Rule: 산술 단순화, 비트 연산, 불리언 정규화, 비교 연산, 확장/절단
- fixpoint 루프에서 가장 자주 발화하는 규칙들
- 의존성: WU1

### WU4. Pointer/Memory Rules -- Batch B (~3,500 Go줄)

- AddTreeState: 포인터 산술 트리 워커
- ~25개 Rule: RulePtrArith, RulePushPtr, RulePtrFlow, RulePtrsubUndo 등
- LOAD/STORE varnode propagation
- 의존성: WU1, WU2

### WU5. Remaining Rules -- Batch C: 나눗셈/부동소수점/기타 (~3,000 Go줄)

- ~55개 Rule: 나눗셈/모듈로 강도 축소, float 규칙, switch, cpool, segment
- 점진적 추가 가능
- 의존성: WU1, WU2

### WU6. Block Structuring (~2,400 Go줄)

- CollapseStructure: 반복적 구조 규칙 적용 (if/while/do/switch)
- LoopBody: 루프 멤버십/중첩 추적
- TraceDAG: switch-case 인식
- FloatingEdge: 비구조적 goto 에지
- ConditionalJoin: 분할된 조건식 병합
- ActionBlock* Actions
- 의존성: WU1, Phase 3 BlockGraph

### WU7. C Printer (PrintC) (~3,600 Go줄)

- ~50개 opcode emit 핸들러
- ~11개 block emit 메서드
- 타입/변수 선언 출력
- 서식 옵션 (brace style, NULL printing, cast suppression)
- 의존성: WU2, WU6, WU3-5 (올바른 표현식 형태 필요)

## 의존 관계 및 병렬화

```
WU1 (Action/Rule)  ||  WU2 (Type System)     -- 병렬 가능
       |                     |
       v                     |
WU3 (Core Rules)  ||  WU6 (Block Structuring) -- 병렬 가능
       |                     |
       v                     v
WU4 (Pointer Rules) <-- WU2  |
       |                     |
WU5 (Div/Float Rules)        |
       |                     |
       +----------+----------+
                  |
                  v
           WU7 (PrintC)
```

## 권장 실행 순서

1. WU1 + WU2 병렬
2. WU3 + WU6 병렬 (WU1 완료 후)
3. WU4 + WU5 병렬 (WU1, WU2 완료 후)
4. WU7 (전부 완료 후)

## 규모 추정

| 작업 | Go 예상 줄 수 |
|------|-------------|
| 1. Action/Rule Framework | 1,400 |
| 2. Type System | 3,700 |
| 3. Core Rules (Batch A) | 4,000 |
| 4. Pointer Rules (Batch B) | 3,500 |
| 5. Remaining Rules (Batch C) | 3,000 |
| 6. Block Structuring | 2,400 |
| 7. C Printer | 3,600 |
| 합계 | ~22,400 |

## 우선순위

### 필수 (출력을 위해 반드시 필요)

- WU1: 모든 변환의 실행 엔진
- WU2: 포인터 규칙과 프린터에 필수
- WU3: 가장 자주 발화하는 규칙, 없으면 출력이 지저분함
- WU6: if/while/switch 구조 없이는 goto 덩어리
- WU7: C 텍스트 출력 자체

### 지연 가능 (품질 향상, 기본 출력엔 불필요)

- WU4: 포인터 복구 -- 임시로 raw offset 산술로 대체 가능
- WU5: 나눗셈 이디엄/float -- 대부분 함수에서 불필요
- WU7 세부 서식 옵션 -- 기본값으로 stub 가능

## 주의사항

- 130개 Rule이 가장 큰 볼륨이다. 각 Rule은 독립적이므로 병렬 구현 가능.
- Action fixpoint 루프가 수렴하려면 Rule 간 상호작용을 정확히 맞춰야 한다.
- CollapseStructure는 반복적 패턴 매칭으로, 비환원 그래프 처리가 가장 어렵다.
- PrintC는 모든 opcode/block 타입에 대한 핸들러가 필요하므로 볼륨이 크다.
- Phase 3의 Heritage가 올바른 SSA를 생성해야 Phase 4가 동작한다.
