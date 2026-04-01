# C++ Types

## 문서 성격

이 문서는 작업 보조용 타입 정리다.

- 원본 기준은 항상 `ghidra-ref/` C++ 소스다
- 이 문서와 원본이 충돌하면 원본을 따른다
- 여기 적힌 타입 분류와 우선순위는 현재 포팅 단계 기준이다

## 목적

첫 포팅 범위에서 중요한 타입의 정의 위치와 책임을 고정한다.

여기서 다루는 타입은 "지금 바로 Go 공통 타입 설계에 영향을 주는 것"만 포함한다.

## `Address`

정의:

- `address.hh:59`

핵심 필드:

- `AddrSpace *base`
- `uintb offset`

책임:

- 주소 공간과 오프셋의 쌍을 표현한다
- invalid address를 표현할 수 있다
- 비교, 순서, 가감산, encode/decode를 제공한다

포팅 판단:

- Go에서도 값 타입으로 두는 편이 자연스럽다
- 분석용 속성을 붙이지 말고 최대한 얇게 유지해야 한다

## `AddrSpace`

정의:

- `space.hh:52` 부근 본 정의

책임:

- 저장 공간의 종류와 성질을 표현한다
- endianness, word size, logical/physical 성격, index 등 공간 자체의 규칙을 가진다
- register space, ram space, unique space, join space 같은 다양한 공간의 기반이 된다

포팅 판단:

- Go에서는 먼저 공통 메타데이터 구조와 enum 성격의 분류를 설계하는 편이 좋다
- C++의 전체 상속 구조를 바로 그대로 옮길 필요는 없다

관련 special spaces:

- `constant`: p-code 상수 표현
- `unique`: temporary register 표현
- `join`: 분리된 물리 위치를 하나의 논리 값처럼 다루는 공간
- `iop`, `fspec`: 내부 포인터 인코딩용 공간
- `stack`: spacebase 기반 가상 공간

포팅 판단 추가:

- 첫 단계에서는 special space 전체 구현보다 식별과 기본 메타데이터가 더 중요하다
- 특히 `constant`와 `unique`는 초기에 반드시 설계에 포함되어야 한다

## `VarnodeData`

정의:

- `pcoderaw.hh:35`

핵심 필드:

- `AddrSpace *space`
- `uintb offset`
- `uint4 size`

책임:

- 저장 위치를 표현하는 최소 컨테이너다
- SSA 링크, 타입 전파, def-use 그래프 같은 무거운 정보는 없다
- raw p-code emission과 register lookup에서 바로 쓸 수 있다

포팅 판단:

- 첫 Go 포팅에서 `Varnode`보다 `VarnodeData`가 먼저 와야 한다
- 사실상 `Address + size`지만, C++ 기준으로는 별도 타입으로 유지하는 의미가 있다

## `ParserContext`

정의:

- `context.hh:95`

책임:

- instruction 하나의 parse state를 저장한다
- instruction bytes, context bytes, parse tree, length, next address, delay slot, parser state를 가진다

포팅 판단:

- Go에서도 decode 결과를 보관하는 별도 타입이 필요하다
- 이 타입은 emission 버퍼와는 다른 계층이다

## `ParserWalker`

정의:

- `context.hh:162` 부근 본 정의

책임:

- `ParserContext` 안의 constructor tree를 현재 위치 기준으로 순회한다
- operand push/pop, current constructor, current handle, instruction/context bit 조회를 담당한다

포팅 판단:

- tree와 walker를 분리하지 않으면 `resolve`와 `build` 두 단계를 깔끔하게 나누기 어렵다

## `OpCode`

정의:

- `opcodes.hh:37`

책임:

- p-code 명령 종류 전체를 enum으로 정의한다
- branching, load/store, integer, boolean, float, internal ops 범주를 포함한다

포팅 판단:

- Go에서는 enum 상수 집합으로 먼저 옮기고
- 이름 변환과 문자열화는 뒤따라가면 된다
- 순번 값은 가능하면 원본과 맞추는 편이 비교와 fixture에 유리하다

## `PcodeEmit`

정의:

- `translate.hh:94`

핵심 메서드:

- `dump(const Address&, OpCode, VarnodeData*, VarnodeData*, int4)`

책임:

- instruction 하나에서 나온 p-code op들을 외부 애플리케이션으로 전달한다

포팅 판단:

- Go에서는 인터페이스로 두는 것이 자연스럽다
- 다만 slice 기반 입력으로 바꾸면 C++의 포인터 배열보다 다루기 편하다

## `SleighSymbol` / `SymbolTable`

정의:

- `slghsymbol.hh`

책임:

- SLEIGH 언어의 심볼 계층과 스코프를 표현한다
- operand, varnode, context, subtable, userop 등 대부분의 decode 요소가 여기서 나온다

포팅 판단:

- 초반에 전체 구현은 과하지만, symbol kind 분류는 reader 설계에 반영해야 한다
- 첫 `.sla` loader는 최소한 decode에 필요한 symbol 종류를 잃지 않아야 한다

## `PcodeCacher`

정의:

- `sleigh.hh:58`
- `sleigh.cc:21`

책임:

- instruction 단위로 raw p-code와 varnode 데이터를 임시 저장한다
- label reference를 모아 두었다가 relative branch offset으로 고친다
- 마지막에 emitter 호출로 넘긴다

포팅 판단:

- builder가 바로 emitter를 부르지 않고, 한 단계 모으는 구조를 유지하는 편이 좋다
- Go에서도 instruction 단위 buffer 객체가 있으면 구현이 단순해진다

## `PcodeBuilder`

정의:

- `semantics.hh:195`

책임:

- SLEIGH template를 실제 p-code op로 조립하는 내부 빌더 추상층이다

포팅 판단:

- 외부 emitter와 분리된 내부 builder 계층을 유지하는 편이 좋다

## `PcodeOpRaw`

정의:

- `pcoderaw.hh:110`

책임:

- opcode, seqnum, output, inputs만 가진 얇은 raw p-code 표현이다

포팅 판단:

- 첫 포팅에서 `PcodeOp` 전체를 가져오기 전에 중간 산출물로 참고할 가치가 있다
- 하지만 Go 설계상 반드시 이름까지 그대로 따라갈 필요는 없다

## `SleighBase`

정의:

- `sleighbase.hh:60`

책임:

- `.sla` decode
- symbol table 보관
- register xref 구축
- userop/context 정보 재구성

포팅 판단:

- Go에서는 runtime translator와 `.sla` model/loader 계층의 경계가 여기에서 갈린다
- 초반에는 타입 하나로 시작해도 되지만, 책임은 문서상 분리해두는 편이 좋다

## `PcodeOp`

정의:

- `op.hh:63`

책임:

- SSA, 블록, 분석 플래그, 부모/입출력 연결 등을 모두 품은 무거운 연산 노드다

포팅 판단:

- 첫 단계에서 직접 포팅 대상이 아니다
- 지금은 `OpCode`와 raw emission에 필요한 최소 shape만 가져가면 충분하다
- 다만 `op.hh`를 읽어 보면 이후 analysis용 구조가 얼마나 커지는지 알 수 있으므로, 초반에 raw 모델과 분리해야 한다는 근거가 된다

## `Varnode`

정의:

- `varnode.hh:73`

책임:

- SSA 노드
- def-use 링크
- 타입/심볼/커버리지/분석 상태

포팅 판단:

- 첫 포팅 범위에서는 제외하는 편이 맞다
- 이 타입은 decompiler 분석 단계와 강하게 엮여 있다
- `varnode.hh`는 나중에 왜 raw `VarnodeData`를 먼저 고정해야 하는지 보여주는 반례에 가깝다
