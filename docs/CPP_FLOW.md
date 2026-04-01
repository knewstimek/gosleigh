# C++ Flow

## 문서 성격

이 문서는 작업 보조용 흐름 요약이다.

- 원본 기준은 항상 `ghidra-ref/` C++ 소스다
- 이 문서와 원본이 충돌하면 원본을 따른다
- 중요한 구현 결정 전에는 관련 C++ 원본 파일을 다시 확인한다

## 목적

이 문서는 첫 포팅 범위에서 가장 중요한 실행 흐름인 `Sleigh -> Translate -> PcodeEmit`를 고정한다.

전체 제어 흐름을 다 적는 것이 아니라, `oneInstruction()` 기준으로 실제 어떤 단계가 지나가는지만 정리한다.

## 핵심 진입점

핵심 인터페이스 정의:

- `translate.hh:419` 근처 `Translate::oneInstruction(PcodeEmit&, const Address&)`

실제 구현 진입점:

- `sleigh.cc:741` `Sleigh::oneInstruction(PcodeEmit&, const Address&)`

## 큰 흐름

`Sleigh::oneInstruction()`는 대략 아래 순서로 움직인다.

1. instruction address alignment를 검사한다
2. `obtainContext(baseaddr, ParserContext::pcode)`로 parse context를 확보한다
3. context commit을 적용한다
4. instruction length와 delay slot을 계산한다
5. `ParserWalker`를 만든다
6. `SleighBuilder`로 constructor template를 p-code로 빌드한다
7. relative reference를 정리한다
8. `pcode_cache.emit(baseaddr, &emit)`로 외부 `PcodeEmit`에 전달한다
9. 최종 instruction length를 반환한다

## 세부 흐름

### 1. `obtainContext()`

위치:

- `sleigh.cc:590`

역할:

- 주소별 `ParserContext`를 캐시에서 가져온다
- 현재 parse state가 부족하면 추가 해석을 진행한다

동작:

- state가 `uninitialized`면 `resolve()` 호출
- 요청 state가 `pcode`면 `resolveHandles()`까지 호출

즉:

- `resolve()`는 constructor tree를 확정하는 단계
- `resolveHandles()`는 p-code 생성을 위한 operand handle을 확정하는 단계

### 2. `resolve()`

위치:

- `sleigh.cc:609`

역할:

- instruction bytes를 읽고 constructor tree를 만든다

주요 동작:

- `loader->loadFill()`로 instruction bytes를 채운다
- root constructor를 resolve한다
- operand별로 하위 constructor를 따라 내려간다
- context 적용
- minimum length 계산
- delay slot 정보 기록
- instruction 다음 주소를 설정
- parser state를 `disassembly`로 올린다

핵심 해석:

- 이 단계가 끝나면 "이 instruction이 어떤 constructor 조합으로 해석되는가"가 정해진다
- 아직 p-code용 handle 계산은 끝나지 않았다
- 즉 decode의 핵심 산출물은 단순 opcode가 아니라 `constructor tree`다

### 3. `resolveHandles()`

위치:

- `sleigh.cc:664`

역할:

- constructor tree를 따라 operand handle을 실제 값으로 고정한다

주요 동작:

- operand symbol을 순회한다
- subtable이면 더 내려간다
- 고정 심볼이면 `getFixedHandle()`로 handle 채움
- 표현식이면 상수 공간의 값으로 handle 채움
- constructor result handle이 있으면 부모로 fix한다
- parser state를 `pcode`로 올린다

핵심 해석:

- 이 단계가 끝나야 p-code template를 실제 operand 값으로 인스턴스화할 수 있다

### 3.5 `ParserContext`와 `ParserWalker`

역할:

- `ParserContext`는 instruction별 parse tree, instruction bytes, context bytes, next address, delay slot 등을 담는다
- `ParserWalker`는 현재 constructor/operand 위치를 기준으로 tree를 순회한다
- `ParserWalkerChange`는 tree를 만들면서 수정하는 변형이다

핵심 해석:

- `resolve()`와 `build()`는 서로 다른 일을 하지만 같은 parse state를 공유한다
- Go에서 이 경계를 잘못 잡으면 decode와 p-code emission이 뒤엉킨다

### 4. delay slot 처리

위치:

- `sleigh.cc:757`

역할:

- 현재 instruction이 delay slot을 요구하면 뒤 instruction들을 추가로 읽어 total fall-through 길이를 계산한다

포팅 관점:

- 첫 Go 포팅에서 이 로직은 빼먹기 쉬운 부분이다
- decode만 옮기고 길이 계산을 단순화하면 branch 계열에서 곧 깨질 가능성이 높다

### 5. `SleighBuilder`와 p-code 생성

위치:

- `sleigh.cc:769`

주요 코드:

- `ParserWalker walker(pos);`
- `SleighBuilder builder(...)`
- `builder.build(walker.getConstructor()->getTempl(), -1);`
- `pcode_cache.resolveRelatives();`
- `pcode_cache.emit(baseaddr, &emit);`

역할:

- constructor template를 실제 p-code op 시퀀스로 만든다
- 그 결과를 cache에 쌓았다가 emitter로 내보낸다

핵심 해석:

- Go 포팅에서도 내부 빌드 단계와 외부 emit 단계를 분리해야 한다
- 바로 `emit.dump()`만 호출하는 식으로 합치면 relative fixup과 테스트가 불편해진다

### 6. `PcodeCacher`

정의 위치:

- `sleigh.hh:58`
- `sleigh.cc:21`

역할:

- 한 instruction에서 생성된 `PcodeData`와 `VarnodeData`를 임시 풀에 모은다
- intra-instruction label 참조를 나중에 relative offset으로 backpatch한다
- 최종적으로 `emit.dump()` 호출로 외부 emitter에 넘긴다

핵심 해석:

- raw emission 직전에 별도 캐시 단계가 한 번 더 있다
- Go에서도 이 단계가 있으면 relative branch fixup과 테스트가 단순해진다

### 7. `SleighBuilder`

정의 위치:

- `sleigh.hh:131`
- `sleigh.cc:330`

역할:

- `PcodeBuilder` 구현체로서 template를 실제 p-code 데이터로 만든다
- `constant space`, `unique space`, `DisassemblyCache`, `PcodeCacher`를 함께 사용한다
- `delaySlot()`과 `appendCrossBuild()`로 다른 instruction의 p-code 조각까지 짜 넣을 수 있다

핵심 해석:

- 이 객체는 단순 opcode 변환기가 아니다
- parse tree, space 정책, temporary unique allocation, relative label 생성까지 담당한다

### 8. `unique space`와 `constant space`

핵심 위치:

- `translate.hh:496` `getUniqueSpace()`
- `translate.hh:522` `getConstantSpace()`
- `translate.hh:611` `getUniqueStart()`
- `sleigh.cc:152` 이후 `SleighBuilder::generateLocation()`

역할:

- `constant space`는 p-code 내부 상수값을 주소처럼 인코딩하는 특수 공간이다
- `unique space`는 translation/runtime temporary를 위한 전용 공간이다

포팅 관점:

- 이 둘은 실제 메모리 공간이 아니라 p-code 모델의 일부다
- Go 설계에서 초반부터 일반 공간과 같은 인터페이스 위에 올리되, 의미는 분리해서 문서화해야 한다

### 9. `.sla` 로딩이 실행 흐름에 들어오기 전 단계

실행 전에 먼저 일어나는 일:

1. `.sla` header 검증
2. 압축 해제 및 marshal stream ingest
3. `SleighBase::decode()`로 translator 메타데이터 복원
4. address spaces 복원
5. symbol table 복원
6. register xref와 userop/context 정보 재구성
7. root `instruction` subtable 연결

핵심 해석:

- runtime decode는 `.sla` 로딩이 끝난 translator 상태를 전제로 한다
- 그래서 Go 구현도 `.sla loader`와 `instruction translation`을 같은 package에 두더라도 개념적으로는 분리해야 한다

### 10. symbol 계층이 왜 필요한가

핵심 위치:

- `slghsymbol.hh`

역할:

- operand resolve, context field 등록, userop 이름, register xref, subtable 진입이 모두 symbol 계층에 걸려 있다

핵심 해석:

- `.sla reader`를 만들 때 symbol을 너무 늦게 생각하면 다시 뜯어고치게 된다
- 첫 구현이 full symbol API까지 필요하지는 않지만, 적어도 decode에 필요한 symbol 종류 분류는 초기에 모델에 반영해야 한다

## 이 흐름에서 당장 필요한 파일

- `sleigh.hh`
- `sleigh.cc`
- `translate.hh`
- `semantics.hh`
- `sleighbase.hh`
- `sleighbase.cc`
- `slaformat.hh`
- `slaformat.cc`

## 다음 문서

- 타입 책임: `docs/CPP_TYPES.md`
- 포팅 범위 파일 목록: `docs/CPP_PORT_SCOPE.md`
