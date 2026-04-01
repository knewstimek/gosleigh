# C++ Port Scope

> **역사적 문서**: 이 문서는 프로젝트 초기의 포팅 범위 결정 기록이다. 아래 "결정 필요" 항목들은 이미 코드로 결정되었고, "체크리스트"도 모두 완료되었다. 현재 포팅 범위와 parity 상태는 `docs/PARITY_AUDIT.md`와 `docs/SLEIGH_RUNTIME_ROADMAP.md`를 본다.

## 문서 성격

이 문서는 현재 작업 단계에서의 임시 포팅 범위를 적은 것이다.

- 원본 기준은 항상 `ghidra-ref/` C++ 소스다
- 여기 적힌 포함/제외 범위는 고정 규칙이 아니다
- 이후 구현이나 검증 결과에 따라 범위는 바뀔 수 있다

## 목적

이 문서는 "지금 당장 첫 Go 구현에 포함할 C++ 참조 범위"를 고정한다.

범위를 넓게 잡으면 구현보다 독해 비용이 더 커진다. 따라서 첫 범위는 의도적으로 좁게 유지한다.

## 포함

### 반드시 읽을 파일

- `sleigh.hh`
- `sleigh.cc`
- `translate.hh`
- `semantics.hh`
- `address.hh`
- `space.hh`
- `pcoderaw.hh`
- `opcodes.hh`
- `sleighbase.hh`
- `sleighbase.cc`
- `slaformat.hh`
- `slaformat.cc`
- `context.hh`
- `slghsymbol.hh`

### 곧이어 읽을 파일

- `op.hh`
- `varnode.hh`

## 이번 단계에서 직접 구현 대상으로 보는 것

- `Translate` 인터페이스 관점
- `Sleigh::oneInstruction()` 흐름
- `Address`
- `AddrSpace`
- `VarnodeData`
- `OpCode`
- raw p-code emission 경계
- `.sla` header/decode 경계
- `constant space`와 `unique space` 의미
- parse tree와 symbol runtime의 최소 구조

## 이번 단계에서 직접 구현 대상으로 보지 않는 것

- full `Varnode`
- full `PcodeOp`
- SSA 변환
- basic block 구성
- type propagation
- action/rule framework
- C output printer

## 왜 이 범위인가

- 첫 usable milestone은 decode와 p-code emission이다
- `Varnode`와 `PcodeOp`의 무거운 분석 기능은 여기에 필요하지 않다
- `.sla` reader를 시작하기 전에 공통 타입과 emission 경계를 먼저 고정해야 한다

## 바로 다음 문서화 작업

아직 결정이 필요한 부분:

- `op.hh`와 `varnode.hh`의 개념을 Go 초기 타입에 얼마나 노출할지
- 첫 Go 타입 설계에서 `PcodeOpRaw`를 별도 타입으로 둘지, 더 얇은 표현으로 재구성할지
- symbol decode 모델을 full fidelity로 갈지, first-slice 최소 모델로 갈지

## 구현 시작 전 체크리스트

- `docs/CPP_FLOW.md`에 `oneInstruction()` 흐름이 정리되어 있는가
- `docs/CPP_TYPES.md`에 핵심 타입 책임이 정리되어 있는가
- 첫 Go 타입이 `Varnode`가 아니라 `VarnodeData` 기준으로 잡혀 있는가
- `PcodeEmit`와 내부 빌드 단계를 분리해서 설계하고 있는가
