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

### Phase 3: P-code Engine -- 완료

- PcodeOp + TypeOp: 완료 (WU1)
- Varnode + VarnodeBank: 완료 (WU2)
- PcodeOpBank: 완료 (WU1에 포함, WU3)
- FlowBlock + BlockBasic + BlockGraph: 완료 (WU4)
- Funcdata container: 완료 (WU6)
- Heritage (SSA construction): 완료 (WU5) -- guard 인프라는 Phase 4로 연기
- 상세 로드맵: `docs/PCODE_ENGINE_ROADMAP.md`

### Phase 4: Decompilation Pipeline -- 완료

- Action/Rule framework
- Type system / type propagation substrate
- Transformation rules
- Control flow structuring (if/while/switch/goto recovery)

### Phase 5: Code Emission -- 완료

- PrintC 기반 C 출력 경로
- 선언 렌더링과 구조화 블록 직렬화

## Phase 4-5 구현 구조

Phase 4-5 구현의 중심은 `pkg/pcode/` 아래에 모여 있다. 현재 저장소는 별도 AST 계층을 먼저 만든 뒤 출력하는 방식보다, `Funcdata`/`BlockGraph`/`Datatype`를 직접 구조화하고 곧바로 PrintC로 직렬화하는 경로를 택하고 있다.

### Action/Rule framework

- `action.go`는 함수 단위 패스 실행 프레임워크를 제공한다. `ActionBase`가 공통 상태, 통계, breakpoint/warning 토글을 들고, `ActionGroup`은 중첩 패스를 순차 실행하며, `ActionRestartGroup`은 `Funcdata`가 재시작을 요청할 때 같은 그룹을 다시 돈다.
- `action.go`의 `ActionPool`은 p-code를 순서대로 훑으면서 opcode별 rule 목록을 적용한다. rule이 opcode를 바꾸면 같은 op를 다시 스캔하고, 새 op가 삽입되면 정렬된 op 목록을 다시 동기화한다.
- `action.go`의 `ActionDatabase`는 root action과 그룹 목록을 분리해 둔다. `universal` 트리를 기준으로 group 이름 집합을 켜고 끄며 파생 root를 다시 clone하는 구조라서, 배치 조합을 문서화하기 쉽다.
- `rule.go`는 per-op 변환 계약을 정의한다. `RuleBase`는 enable/disable, breakpoint, warning, test/apply 카운터를 공통으로 들고, concrete rule은 `GetOpList()`와 `ApplyOp()`만 구현하면 `ActionPool`에 꽂을 수 있다.

### Type system

- `datatype.go`는 Ghidra식 `metatype`/`subMetatype` 값을 유지하면서 `Base`, `Void`, `Pointer`, `Array`, `Struct`, `Union`, `Enum`, `Code`를 정의한다. 포인터 대상, 배열 원소, 복합 필드, 함수 시그니처가 모두 이 계층으로 연결된다.
- `datatype.go`의 각 타입은 크기, 정렬, 표시 이름, core/enum/incomplete/resolution 플래그를 함께 들고 다닌다. 구조체/유니온 필드 레이아웃과 함수 타입 파라미터도 같은 표면으로 노출된다.
- `typefactory.go`는 구조적으로 같은 타입을 canonical instance로 intern한다. `GetPointer()`, `GetStruct()`, `GetUnion()`, `GetEnum()`, `GetCode()`가 동일한 서명을 공유하는 타입을 재사용하므로, 규칙 적용과 출력 단계가 같은 타입 객체를 안정적으로 참조한다.
- `typefactory.go`의 shared factory는 타입 전파와 PrintC 출력에서 공통으로 쓰인다. 선언 출력 전에 타입을 정규화할 때도 이 factory를 다시 거쳐 포인터, 배열, 함수 타입을 재조립한다.

### Transformation rules

- `rules_arith.go`는 공통 `batchRule` helper를 정의하고 산술 정규화 규칙을 담는다. `RuleTrivialArith`, `RuleAddUnsigned`, `RuleSub2Add`, `RuleShift2Mult`, `RuleAddMultCollapse` 같은 규칙이 상수/산술 형태를 정리한다.
- `rules_bitwise.go`는 마스크와 비트 연산 패턴을 정리한다. `RuleOrMask`, `RuleAndMask`, `RuleShiftBitops`, `RuleAndZext`, `RuleXorCollapse` 등이 여기에 있다.
- `rules_bool.go`는 비교와 조건식의 불리언 정규화를 맡는다. `RuleEquality`, `RuleBoolNegate`, `RuleBooleanDedup`, `RuleLogic2Bool`, `RuleEqual2Zero` 류의 규칙이 포함된다.
- `rules_ext.go`는 `PIECE`/`SUBPIECE`와 `INT_ZEXT`/`INT_SEXT` 주변의 확장 규칙을 모은다. `RulePiece2Zext`, `RuleZextEliminate`, `RuleConcatZext`, `RuleSubZext` 등이 대표적이다.
- `rules_copy.go`는 copy propagation과 멀티이퀄 collapse를 묶는다. `RulePropagateCopy`, `RuleConcatCommute`, `RuleSubCancel`, `RuleMultiCollapse`를 포함하고, `BatchARules()`/`AddBatchARules()`/`NewBatchAActionPool()`로 대형 배치를 조립한다.
- `rules_pointer.go`는 `PTRADD`/`PTRSUB`, 구조체 오프셋, 세그먼트 포인터 흐름을 다룬다. `RulePtrArith`, `RuleStructOffset0`, `RulePtrFlow`, `RulePtraddConstantIndex`, `RulePtrsubCollapse`가 이 파일에 있다.
- `rules_loadstore.go`는 `LOAD`/`STORE`를 더 읽기 쉬운 varnode/주소 형태로 정리한다. `RuleLoadVarnode`, `RuleLoadConstAddr`, `RuleLoadSpacebase`, `RuleStoreConstAddr`, `RuleStoreStackMark`가 대표적이다.
- `rules_divmod.go`는 signed/unsigned division과 modulo 패턴을 batch C로 모은다. `RulePositiveDiv`, `RuleDivOpt`, `RuleDivChain`, `RuleModOpt`, `RuleSignMod2Opt` 등이 들어 있다.
- `rules_float.go`는 부동소수점 cast와 부호/NaN 정리를 담당한다. `RuleFloatCast`, `RuleIgnoreNan`, `RuleUnsigned2Float`, `RuleFloatSign`, `RuleFloatSignCleanup`이 구현돼 있다.
- `rules_misc.go`는 switch, constant pool, shift/compare, conditional move, 함수 포인터 인코딩 같은 남은 패턴을 batch C로 묶는다. `BatchCMiscRules()`와 `AddBatchCMiscRules()`가 이 묶음을 `ActionPool`에 등록한다.

### Block structuring

- `block_actions.go`는 구조화 단계의 action entry point다. `ActionBlockStructure`가 basic CFG를 clone한 뒤 `CollapseStructure`를 돌리고, `ActionFinalStructure`는 block order와 출력 전 후처리 훅을 호출한다.
- `collapse.go`는 핵심 구조화 엔진이다. `CollapseStructure`가 loop labeling, likely goto 선택, condition collapse를 순서대로 적용하면서 `newBlockIf`, `newBlockIfElse`, `newBlockWhileDo`, `newBlockSwitch`, `newBlockGoto` 계열 structured block을 만든다.
- `loopbody.go`는 루프 본문 후보를 계산한다. 헤드/테일/exit block을 추적하고, containment와 exit edge를 판정해 while/do-while/무한루프 구조화를 위한 입력을 준비한다.
- `tracedag.go`는 DAG 추적으로 likely goto 후보를 뽑는다. 루트 집합에서 loop DAG edge만 따라가며 strongly connected component를 찾고, 내부 edge 하나를 floating edge 후보로 밀어 넣는다.
- 이 단계의 결과는 `Funcdata.GetStructure()`가 돌려주는 structured `BlockGraph`에 저장된다. PrintC는 basic block이 아니라 이 structure graph를 우선 소비한다.

### PrintC output

- `emitter.go`는 가장 낮은 출력 계층이다. `TokenEmitter`와 `TextEmitter`가 공백, 줄바꿈, 들여쓰기를 일관되게 관리해 상위 레이어가 토큰 단위로 출력할 수 있게 한다.
- `printlanguage.go`는 언어 독립 출력 helper다. block open/close, statement 종료, label 출력, 식 precedence/associativity 처리를 담당하는 `ExprFragment`와 helper API를 제공한다.
- `printc.go`는 `Funcdata`를 실제 C 비슷한 코드로 바꾸는 메인 엔진이다. 파라미터/로컬 심볼을 수집하고, `CPUI_RETURN`에서 반환 타입을 추론하고, named type definition을 먼저 출력한 뒤 structured block을 순회하며 문장과 식을 만든다.
- `printc.go`는 구조화된 `BlockGraph`를 우선 사용하고, 없으면 basic block graph로 fallback한다. 즉 block structuring 단계와 code emission 단계가 직접 연결돼 있다.
- `printc_decl.go`는 선언 전용 렌더러다. 포인터, 배열, 함수 포인터 선언자와 `struct`/`union`/`enum` 정의를 문자열로 만들며, `CDeclString()`, `CFuncSignatureString()`, `CTypeDefinitionString()` 같은 API를 노출한다.

## 기술 결정

- 라이선스: Apache 2.0 (Ghidra와 동일)
- 언어: Go
- 외부 의존성: 코어 패키지는 stdlib only
- standalone CLI는 개발/테스트용 harness
- MCP 통합은 외부 호스트 adapter를 통해 이루어질 수 있음
