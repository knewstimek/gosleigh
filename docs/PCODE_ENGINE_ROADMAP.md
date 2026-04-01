# P-code Engine Roadmap (Phase 3)

## 목적

이 문서는 Phase 2 (Sleigh Runtime) 이후, P-code Engine을 구축하기 위한 로드맵이다.
Phase 2에서 생성된 raw p-code (PcodeOpRaw/VarnodeData)를 SSA 기반 데이터/제어 흐름 그래프로 변환하는 것이 목표다.

이 문서는 decompiler 전체 완성 (Phase 4-5)을 다루지 않는다.

## Phase 2와의 연결점

```
Phase 2: PcodeEmit -> RawOp (opcode, VarnodeData inputs/output)
    |
    v
Phase 3: Funcdata.createOp() -> PcodeOp + Varnode -> Heritage -> SSA
    |
    v
Phase 4+: Action/Rule -> Type inference -> Control flow structuring
```

## 핵심 C++ 클래스와 Go 대응 계획

| C++ 클래스 | 파일 | 책임 | 규모 |
|-----------|------|------|------|
| PcodeOp | op.hh/cc | P-code 연산 노드 (입/출력 Varnode 관리) | ~1,575줄 |
| TypeOp | typeop.hh | 연산의 타입 정보 및 동작 정의 | 별도 |
| Varnode | varnode.hh/cc | SSA 데이터 노드 (위치, 크기, def-use) | ~2,484줄 |
| VarnodeBank | varnode.hh/cc | Varnode 컨테이너 (위치/정의 기준 검색) | 동일 |
| PcodeOpBank | op.hh/cc | PcodeOp 컨테이너 (다중 정렬) | 동일 |
| FlowBlock | block.hh/cc | 제어 흐름 블록 기반 클래스 | ~4,636줄 |
| BlockBasic | block.hh/cc | 기본 블록 (PcodeOp 리스트) | 동일 |
| BlockGraph | block.hh/cc | 블록 그래프 (구조화 계층) | 동일 |
| Heritage | heritage.hh/cc | SSA 구성 (Phi-node, rename) | ~3,214줄 |
| Funcdata | funcdata.hh/cc | 함수 컨테이너 (최상위 API) | ~1,850줄 |

합계: ~13,759줄

## 작업 단위

### 1. PcodeOp & TypeOp 기본 구조 -- 완료 (605ab92)

- PcodeOp: 32 primary + 11 secondary flags, SetOpcode behavioral flag clearing
- TypeOp: interface + 72-opcode registration factory
- PcodeOpBank: SeqNum-indexed map + alive/dead lists
- 29 tests passing

### 2. Varnode & VarnodeBank -- 완료 (605ab92)

- Varnode: 32+13 flags, def-use links, overlap/containment
- VarnodeBank: dual sorted indices (locTree/defTree), C++ (f-1) status trick
- 46 tests passing

### 3. PcodeOpBank & 기본 쿼리 -- 완료 (작업 1에 포함)

- PcodeOpBank: Create/FindOp/Target/MarkAlive/MarkDead/Destroy
- 작업 1과 함께 구현됨

### 4. FlowBlock & BlockBasic -- 완료 (6200824)

- FlowBlock: bidirectional edge management, block/edge flags
- BlockBasic: PcodeOp list with insert/remove/NegateCondition
- BlockGraph: CFG container, FindSpanningTree, CalcForwardDominator, StructureLoops
- 구조화 블록 타입 (BlockIf, BlockWhile 등)은 Phase 4에서 확장 예정
- 31 tests passing

### 5. Heritage (SSA 구성)

- Phi-node 배치 (placeMultiequals)
- 변수 이름 변경 알고리즘 (rename)
- LocationMap: 주소 범위 추적
- 메모리 별칭 분석 (LoadGuard, StoreGuard)
- 의존성: 작업 2, 4
- 가장 복잡한 단위

### 6. Funcdata (함수 컨테이너) -- skeleton 완료 (6200824)

- VarnodeBank + PcodeOpBank 통합
- Varnode/PcodeOp creation, wiring (def/descend), search API
- Heritage/BlockGraph 통합은 WU5 완료 후 확장
- 19 tests passing
- 의존성: 작업 1-5 모두 (Heritage 연동은 미완)

## 의존 관계 및 병렬화

```
작업 1 (PcodeOp)  ||  작업 2 (Varnode)    -- 병렬 가능
        |                  |
        v                  |
작업 3 (PcodeOpBank)       |
        |                  |
        +--------+---------+
                 |
                 v
        작업 4 (FlowBlock)
                 |
                 v
        작업 5 (Heritage)
                 |
                 v
        작업 6 (Funcdata)
```

## 권장 실행 순서

1. 작업 1 + 작업 2 병렬
2. 작업 3 (작업 1 완료 후)
3. 작업 4 (작업 1, 2, 3 완료 후)
4. 작업 5 (작업 2, 4 완료 후)
5. 작업 6 (작업 1-5 완료 후)

## 규모 추정

| 작업 | Go 예상 줄 수 |
|------|-------------|
| 1. PcodeOp/TypeOp | 1,200-1,400 |
| 2. Varnode/VarnodeBank | 1,800-2,200 |
| 3. PcodeOpBank | 400-500 |
| 4. FlowBlock/BlockBasic | 3,500-4,000 |
| 5. Heritage | 2,500-3,000 |
| 6. Funcdata | 1,000-1,300 |
| 합계 | ~13,500 |

## 주의사항

- Heritage 알고리즘이 가장 복잡하다 (SSA 논문 기반 Phi-node 배치 + rename).
- 에지 관리에서 양방향 링크 동기화를 틀리면 그래프 전체가 망가진다.
- Phase 2의 PcodeEmit 인터페이스와 호환성을 유지해야 한다.
- 원본 C++ parity 원칙은 Phase 3에서도 동일하게 적용한다.
