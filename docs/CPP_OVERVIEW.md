# C++ Overview

## 문서 성격

이 문서는 작업 보조용 요약이다.

- 원본 기준은 항상 `ghidra-ref/` C++ 소스다
- 이 문서와 원본이 충돌하면 원본을 따른다
- 여기 적힌 범위와 판단은 현재 작업 단계 기준이며, 이후 바뀔 수 있다

## 목적

이 문서는 Ghidra decompiler C++ 전체를 설명하려는 문서가 아니다.

목표는 첫 Go 포팅 범위에서 반드시 알아야 하는 책임 분리와 진입점을 빠르게 찾게 하는 것이다.

함께 봐야 하는 문서:

- `docs/INDEX.md`
- `docs/CPP_FLOW.md`
- `docs/CPP_TYPES.md`
- `docs/CPP_PORT_SCOPE.md`

## 이번에 보는 핵심 축

첫 포팅 범위에서 중요한 축은 아래 여덟 가지다.

1. `Translate`
2. `Sleigh`
3. `SleighBase`
4. `.sla` format
5. `ParserContext` / `ParserWalker`
6. `SleighSymbol` / `SymbolTable`
7. `PcodeEmit` / `PcodeBuilder`
8. `Address` / `AddrSpace` / `VarnodeData` / `OpCode`

## 각 축의 역할

### `Translate`

정의 위치:

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/translate.hh`

역할:

- 번역기 전체 인터페이스를 정의한다
- `oneInstruction()`와 `printAssembly()` 같은 핵심 API를 잡는다
- 주소 공간, 레지스터 조회, userop 이름 조회 같은 추상 인터페이스를 제공한다
- endianness, alignment, unique space base 같은 공통 번역기 상태를 가진다

핵심 포인트:

- Go에서는 `Translate`에 해당하는 추상 경계를 너무 빨리 넓히지 않는 편이 좋다
- 첫 단계에서는 `Sleigh`가 실제 구현이고, `Translate`는 그 바깥 계약으로 보는 편이 맞다

### `Sleigh`

정의 위치:

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.hh`
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.cc`

역할:

- 실제 instruction decode와 p-code 생성을 수행하는 엔진이다
- `LoadImage`에서 바이트를 읽고
- `ContextDatabase`와 캐시를 사용해 parse context를 만든 뒤
- constructor tree를 해석해서
- p-code를 emitter로 밀어 넣는다

핵심 포인트:

- 첫 Go 구현의 실제 중심은 `Sleigh` 쪽이다
- 특히 `resolve()`, `resolveHandles()`, `oneInstruction()` 흐름을 먼저 이해해야 한다

### `SleighBase`

정의 위치:

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/sleighbase.hh`
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/sleighbase.cc`

역할:

- `Translate`와 `Sleigh` 사이의 공통 기반층이다
- `.sla` 디코드, 심볼 테이블, 레지스터 xref, userop 목록, context field 재등록을 담당한다
- 주소 공간 집합과 SLEIGH 심볼 집합을 실제 번역기 객체에 묶는다

핵심 포인트:

- Go에서 `.sla` reader를 만들 때 이 레이어의 책임 분리가 중요하다
- 순수 실행 경로인 `Sleigh`와, 사전 로딩/메타데이터 계층인 `SleighBase`를 섞으면 구조가 쉽게 꼬인다

### `.sla` format

정의 위치:

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/slaformat.hh`
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/slaformat.cc`

역할:

- `.sla` 파일의 헤더, 버전, element/attribute id 집합, 압축 인코드/디코드 경계를 제공한다
- `SleighBase::decode()`가 이 포맷 정의를 사용해 실제 translator 상태를 복원한다

핵심 포인트:

- `.sla`는 단순 raw binary 덤프가 아니라 자체 헤더와 압축된 marshal stream을 가진다
- Go 쪽 `.sla` reader는 먼저 헤더 검증과 decompress/marshal 계층부터 분리하는 편이 안전하다

### `ParserContext` / `ParserWalker`

정의 위치:

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/context.hh`

역할:

- instruction 하나에 대한 parse tree와 상태를 들고 있는 객체가 `ParserContext`다
- 그 parse tree를 현재 위치 기준으로 순회하는 객체가 `ParserWalker`다
- `Sleigh::resolve()`는 `ParserWalkerChange`를 사용해 tree를 만들고
- `SleighBuilder`는 `ParserWalker`를 사용해 같은 tree를 다시 따라가며 p-code를 만든다

핵심 포인트:

- Go에서도 parse result와 tree walker를 분리하는 편이 좋다
- decode와 emission이 같은 tree를 다른 단계에서 사용한다는 점이 중요하다

### `SleighSymbol` / `SymbolTable`

정의 위치:

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/slghsymbol.hh`

역할:

- SLEIGH 언어의 심볼 계층 전체를 잡는다
- address space, token, userop, value, varnode, context, operand, subtable 같은 개념이 여기에 들어간다
- `.sla` decode 후 `SleighBase`가 이 심볼 테이블을 바탕으로 register xref와 context 등록을 다시 만든다

핵심 포인트:

- 포팅 대상의 본질은 단순 instruction decoder가 아니라, SLEIGH 언어 런타임이다
- 그래서 `.sla` reader 단계부터 symbol 계층을 완전히 무시할 수는 없다

### `PcodeEmit` / `PcodeBuilder`

정의 위치:

- `translate.hh`의 `PcodeEmit`
- `semantics.hh`의 `PcodeBuilder`

역할:

- `PcodeEmit`은 외부 애플리케이션으로 p-code를 내보내는 추상 sink다
- `PcodeBuilder`는 SLEIGH 템플릿에서 실제 p-code를 조립하는 내부 빌더다

핵심 포인트:

- Go에서도 둘을 분리하는 편이 좋다
- 내부 생성기와 외부 소비자 인터페이스를 섞으면 나중에 테스트가 어려워진다

### `Address` / `AddrSpace` / `VarnodeData`

정의 위치:

- `address.hh`
- `space.hh`
- `pcoderaw.hh`

역할:

- `Address`는 주소 공간과 오프셋의 쌍이다
- `AddrSpace`는 저장 영역의 성격과 규칙을 나타낸다
- `VarnodeData`는 주소 공간, 오프셋, 크기만 가지는 최소 저장 위치 표현이다
- special spaces로 `constant`, `unique`, `join`, `iop`, `fspec`, `stack` 같은 내부 공간이 존재한다

핵심 포인트:

- `Varnode`보다 `VarnodeData`가 먼저다
- 첫 포팅 단계에서는 SSA 분석용 `Varnode`보다 raw 위치 표현이 훨씬 중요하다

### `OpCode` / raw p-code

정의 위치:

- `opcodes.hh`
- `pcoderaw.hh`
- `op.hh`

역할:

- `OpCode`는 p-code 명령 종류 enum이다
- `PcodeOpRaw`는 가장 얇은 raw p-code 표현이다
- `PcodeOp`는 이후 SSA, 블록, 분석용 속성이 붙은 무거운 표현이다

핵심 포인트:

- 첫 포팅은 `PcodeOp` 전체를 옮길 필요가 없다
- 먼저 `OpCode`와 raw emission에 필요한 최소 데이터 구조부터 옮기는 편이 맞다
- 다만 `op.hh`를 읽어 보면 나중에 왜 raw 표현과 analysis 표현을 분리해야 하는지 바로 드러난다

## 첫 포팅 관점에서 중요한 판단

- 첫 구현의 중심은 `decompiler` 전체가 아니라 `Sleigh runtime`이다
- `Varnode`와 `PcodeOp`의 분석용 기능은 초기에 과하다
- 먼저 필요한 것은 `Address`, `AddrSpace`, `VarnodeData`, `OpCode`, parse context, symbol/runtime 경계, 그리고 decode/emission 경로다

## 먼저 읽어야 할 파일

- `sleigh.hh`
- `sleigh.cc`
- `translate.hh`
- `semantics.hh`
- `sleighbase.hh`
- `sleighbase.cc`
- `context.hh`
- `slghsymbol.hh`
- `address.hh`
- `space.hh`
- `pcoderaw.hh`
- `opcodes.hh`
- `slaformat.hh`
- `slaformat.cc`

그 다음 순서:

- `op.hh`
- `varnode.hh`
