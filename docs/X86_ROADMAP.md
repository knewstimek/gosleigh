# x86 실사용 디컴파일러 로드맵

## 현재 상태 (2026-04-04)

- 6502 BRK: E2E(바이트 -> C 코드) 동작 (30 p-code ops)
- 6502 NOP/LDA: resolve 성공, p-code 생성됨. LDA imm8 offset 버그 수정 완료 (2026-04-04)
- Phase 4-5(rules, block structuring, PrintC) 구현 있으나 실제 데이터 E2E 검증 없음
- CLI/ELF loader 미구현
- x86.sla 확보 완료 -- testdata/sla/ (47개 파일, 6.1MB: x86/x86-64/ARM/AARCH64/MIPS/68k)
- x86.sla 로드 성공 (4 spaces, 1630 UserOps, 43 ContextFields)
- x86 translate 결과: 모든 opcode 0 ops 반환 (에러 없음). context 초기화 문제 추정

## 실행 순서 (의존 관계 반영)

### Phase A: Sleigh Runtime 완성 (x86 진입 전제)

1. ~~DecisionNode::resolve() parity fix~~ -- 완료 (2026-04-04)
2. ~~TokenField offset 버그~~ -- 완료 (2026-04-04)
3. ~~BuildXrefs() runtime 연결 + CALLOTHER wiring~~ -- 완료 (2026-04-04)
4. ~~context variable write path + dynamic varnode~~ -- 완료 (2026-04-04)

### Phase B: x86 진입

5. ~~x86.sla 확보~~ -- 완료 (testdata/sla/, 2026-04-04)
6. x86 context 초기화 -- .pspec에서 기본 context 값 읽어 backend에 설정 (addrsize/opsize 등)
7. x86 golden fixture + 검증 -- 단순 opcode (NOP, MOV, PUSH, RET 등)
8. x86에서 발견되는 추가 gap 수정 (반복)

### Phase C: E2E 인프라

9. ELF LoadImage 구현 -- code section 추출, entry point
10. CLI 진입점 -- cmd/gosleigh/main.go
11. x86 단순 함수 (no loop) E2E: ELF -> C 출력 검증

### Phase D: 실사용 수준

12. Heritage SSA on real CFG 검증 -- 루프/switch
13. Rules 미완성 보완 -- div/switch/float
14. block structuring E2E 검증
15. assembly printer (optional)
16. DWARF/symtab 활용 (optional)

## 의존 관계

```
B6 -> B7 -> B8 (반복) -> C1 -> C2 -> C3 -> D1 -> D2 -> D3
```

## 크기 추정

- Phase A: ~~완료~~
- Phase B: gorchera job 3~5개 (x86 복잡도에 따라 반복)
- Phase C: gorchera job 2개
- Phase D: gorchera job 3~5개
- 전체: gorchera job 10~15개

## 핵심 원칙

- x86.sla 로드 후 실제로 터지는 지점에서 gap을 발견하는 것이 가장 효율적.
- 추측으로 gap을 메우지 않는다. 실제 실행 -> 실패 지점 -> C++ 참조 -> 수정 사이클.
- Phase B3은 반복 작업: x86 opcode 하나씩 추가하며 터지는 곳을 고치는 루프.
