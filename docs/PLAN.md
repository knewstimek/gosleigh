# Gosleigh Plan

> **역사적 문서**: 이 문서는 프로젝트 초기 계획이다. 아래 작업 순서(1-5)는 모두 완료되었고, 현재 진행 상태는 `docs/STATUS.md`와 `docs/SLEIGH_RUNTIME_ROADMAP.md`가 권위 문서다. 설계 의도와 의존성 정책은 여전히 참고 가치가 있어 보존한다.

## 목표

이 프로젝트의 목표는 Ghidra/Sleigh의 완성형 Go 구현이다.
원본 C++ 구현이 존재하는 구간에서는 parity 확보가 최상위 원칙이며, 추정이나 근사 구현으로 대체하면 안 된다.
여기서 말하는 완성형은 `.sla` 로딩, instruction decode, p-code generation, 이후 decompiler pipeline까지 이어지는 전체 경로를 뜻한다.

이 저장소는 MVP, prototype, translator demo를 만드는 곳이 아니다.
작은 구현 단위는 모두 최종 완성본으로 가기 위한 검증 슬라이스일 뿐이며, 그것 자체가 제품 목표가 아니다.

우선순위는 다음과 같다.

- Ghidra C++ 구현의 실제 책임 분리를 정확히 이해한다
- Go 쪽 공통 타입과 경계를 흔들리지 않게 정한다
- `.sla`부터 constructor, semantics, p-code, decompiler 단계까지 이어지는 전체 경로를 단계적으로 고정한다
- 최종적으로 standalone 사용과 downstream MCP 통합 둘 다 가능한 완성형 구조를 만든다

현재 `Sleigh runtime/.sla translation path`만 따로 100%까지 올리는 상세 로드맵은 `docs/SLEIGH_RUNTIME_ROADMAP.md`를 기준으로 본다.

즉, 지금 하는 작은 단위 작업은 모두 최종 구현을 위한 중간 검증일 뿐이며, 문서와 코드 어느 쪽에서도 이를 최종 목표처럼 표현하면 안 된다.

## 통합 전제

다운스트림 호스트에는 이미 자체 디스어셈블러가 있을 수 있다.

따라서 Gosleigh의 우선순위는 아래와 같다.

- 새 범용 디스어셈블러를 만드는 것: 우선순위 낮음
- SLEIGH 기반 instruction translation runtime을 만드는 것: 우선순위 높음
- p-code와 관련 메타데이터를 MCP 도구로 노출하는 것: 우선순위 높음

현재 기준으로 Gosleigh는 호스트의 기존 disassembler를 대체하기보다, 그 위에 없는 계층을 채우는 쪽이 맞다.

## 지금 가장 먼저 할 일

구현에 바로 들어가기 전에 아래 문서화를 먼저 끝낸다.

1. `Sleigh -> Translate -> PcodeEmit` 호출 흐름 정리
2. `Address`, `AddrSpace`, `VarnodeData`, `PcodeOp`, `OpCode` 소유 파일과 책임 정리
3. 첫 포팅 범위에 포함할 C++ 파일 목록 확정
4. Go 패키지 경계 초안 정리

이 네 가지가 정리되기 전에는 `.sla` reader 구현에 들어가지 않는다.

## 작업 순서

### 1. C++ 기준 맥락 정리

목적:

- 포팅 대상을 넓게 보지 말고, 첫 구현에 필요한 최소 단위로 고정한다

해야 할 일:

- `sleigh.hh/.cc`
- `translate.hh/.cc`
- `semantics.hh`
- `address.hh/.cc`
- `space.hh/.cc`
- `pcoderaw.hh/.cc`
- `opcodes.hh/.cc`
- `op.hh/.cc`
- `varnode.hh/.cc`

산출물:

- 호출 흐름 문서
- 타입 책임 문서
- 첫 포팅 범위 파일 목록

완료 기준:

- 다음 작업자가 봐도 "어디서부터 Go로 옮겨야 하는지" 바로 판단할 수 있다

### 2. Go 프로젝트 뼈대 만들기

목적:

- 이후 타입 정의와 테스트를 바로 얹을 수 있는 최소 구조를 만든다

해야 할 일:

- `go mod init`
- 최소 패키지 디렉터리 생성
- 빈 엔트리포인트 또는 스모크 테스트 추가
- 단, CLI는 최종 제품이 아니라 개발용 harness로 간주

산출물:

- `go.mod`
- 초기 디렉터리 구조

완료 기준:

- `go test ./...`가 최소 형태로 돌아간다

### 3. 공통 타입 먼저 고정

목적:

- 이후 `.sla` reader와 decode 경로가 임시 표현을 만들지 않게 한다

해야 할 일:

- `Address`
- `AddrSpace`
- `VarnodeData`
- `OpCode`
- 필요하면 `PcodeOp` 최소 형태

산출물:

- Go 타입 정의
- 단위 테스트

완료 기준:

- `.sla` reader와 p-code emission이 이 타입들 위에서 설계 가능하다

### 4. `.sla` reader`

목적:

- 실제 Sleigh 산출물을 Go 내부 모델로 읽어들인다

해야 할 일:

- `slaformat.*` 기준 포맷 확인
- 바이너리 레코드 구조 정리
- 주소 공간, 심볼, 생성자, 컨텍스트 관련 최소 로딩 구현

산출물:

- `.sla` 로더
- 테스트용 fixture

완료 기준:

- 실제 `.sla` 파일 하나를 읽어서 내부 구조로 보관할 수 있다

### 5. decode -> p-code 경로 열기

목적:

- 실제 instruction decode와 constructor resolution, semantics execution을 연결해 완성형 runtime의 중심 경로를 연다

해야 할 일:

- instruction decode
- constructor tree walk
- p-code emit 인터페이스
- 실제 명령어 비교 테스트를 점진적으로 넓혀 최종 decompiler 경로의 기반 검증으로 사용

산출물:

- decode API
- p-code emission API
- 비교 테스트

완료 기준:

- 작은 instruction corpus에 대해 안정적으로 같은 p-code가 나온다

## 작업 방식

승인 피로를 줄이기 위한 기본 원칙:

- 파일 읽기/수정/검색은 가능하면 shell보다 agent-tool을 우선 사용한다
- shell은 `gofmt`, `go test`, `go mod`처럼 실제 실행이 필요한 경우에만 쓴다
- 반복되는 shell 승인이 필요해지면 넓은 권한 대신 좁은 prefix 승인 규칙을 선호한다
- standalone harness와 downstream host adapter는 분리하되, 코어 패키지는 host-agnostic하게 유지한다

## 의존성 정책

코어 패키지는 가능한 한 Go 표준 라이브러리만 사용한다.

원칙:

- `pkg/address`, `pkg/pcode`, `pkg/sla`, `pkg/sleigh`는 초기에 stdlib-only로 유지한다
- 외부 의존성은 테스트나 좁은 개발 도구에만 허용한다
- 로깅, CLI, DI, 바이너리 파싱 프레임워크는 초기에 넣지 않는다
- 의존성을 추가할 때는 stdlib로 부족한 이유를 문서로 남긴다

현재 기준:

- 프로덕션 런타임 외부 의존성: 가능하면 0개
- 테스트 의존성: 실제 필요가 생길 때만 검토

## 초기 패키지 초안

초기 구조는 아래처럼 시작하되, 나쁜 경계가 보이면 초반에 바로 바꾼다.

- `cmd/gosleigh/`
- `pkg/address/`
- `pkg/pcode/`
- `pkg/sla/`
- `pkg/sleigh/`
- `internal/refmap/`

주의:

- `cmd/gosleigh/`는 개발용 harness로만 본다
- 최종 MCP 통합은 외부 호스트 쪽 adapter를 통해 이루어질 수 있다

## 첫 구현 전에 꼭 정리할 문서

이 문서들이 먼저 있어야 한다.

- `docs/INDEX.md`: 인덱스 경로, 조회 방식, 시작 심볼
- `docs/CPP_OVERVIEW.md`: 첫 포팅 범위의 전체 맥락
- `docs/CPP_FLOW.md`: `Sleigh -> Translate -> PcodeEmit` 흐름
- `docs/CPP_TYPES.md`: 핵심 타입 책임과 정의 위치
- `docs/CPP_PORT_SCOPE.md`: 지금 포함/제외할 C++ 파일 범위
- `docs/STATUS.md`: 현재 완료/다음 작업
- `docs/RUNTIME_FLOW.md`: 현재 권위 runtime 실행 순서
- `docs/SLA_BOUNDARIES.md`: `.sla` top-level, symbol table, constructor, decision 경계

## 지금 추천하는 실제 시작점

가장 효율적인 시작점은 `코드 작성`이 아니라 `C++ 문맥 고정`이다.

바로 다음 작업은 이것이 맞다.

1. `docs/CPP_OVERVIEW.md` 작성
2. `docs/CPP_FLOW.md`에 `Sleigh -> Translate -> PcodeEmit` 흐름 고정
3. `docs/CPP_TYPES.md`에 핵심 타입의 정의 위치와 책임 고정
4. `docs/CPP_PORT_SCOPE.md`에 첫 포팅 파일 목록 확정

그 다음에야 `go mod init`과 타입 구현으로 넘어간다.
