# Gosleigh Architecture

## 프로젝트 목표

Gosleigh는 Ghidra/Sleigh의 완성형 Go 구현이다.
원본 C++ 소스: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/` (~186K lines)

최종 목표는 SLEIGH decode -> p-code 생성 -> decompiler pipeline까지 이어지는 전체 경로다.
standalone 라이브러리/도구와 downstream MCP 통합 모두 가능한 구조를 유지한다.

## 참조 자료

### Ghidra C++ Decompiler Core Modules

| Module | Key Files | Role |
|--------|-----------|------|
| Sleigh Runtime | sleigh.cc/hh, sleighbase.cc/hh | Instruction decoding engine |
| Sleigh Compiler | slgh_compile.cc/hh, slghparse.cc/hh | .slaspec -> .sla compiler |
| Architecture | architecture.cc/hh, sleigh_arch.cc/hh | Architecture abstraction layer |
| P-code | opcodes.cc/hh, pcoderaw.cc/hh, translate.cc/hh | Intermediate representation |
| Varnode/Op | varnode.cc/hh, op.cc/hh | SSA data flow nodes |
| Function/Block | funcdata.cc/hh, block.cc/hh, blockaction.cc/hh | Function & control flow |
| Type System | type.cc/hh, typeop.cc/hh, typegrp.cc/hh | Type inference & propagation |
| Actions | action.cc/hh, ruleaction.cc/hh | Decompilation transformation rules |
| Output | printc.cc/hh, printjava.cc/hh | C/Java code emission |

### 외부 참고

- `lifting-bits/sleigh` - C++ standalone CMake build of Sleigh
- `black-binary/sleigh` - Rust port of Sleigh disassembler
- `rizinorg/rz-ghidra` - Rizin integration of Ghidra decompiler
- `toor-de-force/ghidra-decompiler-standalone` - Standalone decompiler fork

### Ghidra 문서

- Sleigh spec: `ghidra-ref/Ghidra/Features/Decompiler/src/main/doc/sleigh.xml`
- Processor specs: `ghidra-ref/Ghidra/Processors/` (x86, ARM, MIPS, etc.)

## 포팅 단계

### Phase 1: Core Types & Foundations -- 완료

- Address, AddrSpace, VarnodeData, OpCode
- .sla container, packed marshal parser
- 기본 테스트

### Phase 2: Sleigh Runtime -- 완료

- .sla 전체 decode (metadata, symbols, patterns, templates, decision tree)
- Instruction decoding (constructor resolve, handle resolution)
- P-code emission (builder, cache, sink-style emit)
- Runtime context (obtain, commit, delay slot)
- Backend (LoadImage, ContextDatabase, Engine)
- XML v3 (Ghidra 10.x) + packed v4 (Ghidra 11+/12) 지원
- 상세 진행 상태: `docs/STATUS.md`, `docs/SLEIGH_RUNTIME_ROADMAP.md`

### Phase 3: P-code Engine -- 진행 중

- PcodeOp + TypeOp: 완료 (WU1)
- Varnode + VarnodeBank: 완료 (WU2)
- PcodeOpBank: 완료 (WU1에 포함, WU3)
- FlowBlock + BlockBasic + BlockGraph: 완료 (WU4)
- Funcdata container: 완료 (WU6)
- Heritage (SSA construction): 완료 (WU5) -- guard 인프라는 Phase 4로 연기
- 상세 로드맵: `docs/PCODE_ENGINE_ROADMAP.md`

### Phase 4: Decompilation Pipeline -- 미착수

- Action/Rule framework
- Type inference & propagation
- Control flow structuring (if/while/for recovery)

### Phase 5: Code Emission -- 미착수

- C-like output printer
- AST generation

## 기술 결정

- 라이선스: Apache 2.0 (Ghidra와 동일)
- 언어: Go
- 외부 의존성: 코어 패키지는 stdlib only
- standalone CLI는 개발/테스트용 harness
- MCP 통합은 외부 호스트 adapter를 통해 이루어질 수 있음
