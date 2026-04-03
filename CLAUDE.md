# Gosleigh

Ghidra decompiler/Sleigh runtime을 Go로 다시 구현하는 프로젝트. standalone 사용과 downstream MCP 통합을 모두 고려한다.

## 참고 문서

- 현재 진행 상태: `docs/STATUS.md`
- Sleigh runtime 로드맵: `docs/SLEIGH_RUNTIME_ROADMAP.md`
- P-code engine 로드맵: `docs/PCODE_ENGINE_ROADMAP.md`
- Decompiler pipeline 로드맵: `docs/DECOMPILER_PIPELINE_ROADMAP.md`
- runtime 실행 경로: `docs/RUNTIME_FLOW.md`
- parity 감사: `docs/PARITY_AUDIT.md`
- .sla 바운더리: `docs/SLA_BOUNDARIES.md`
- 아키텍처: `docs/ARCHITECTURE.md`
- C++ 참조 가이드 (읽기 순서): `docs/CPP_OVERVIEW.md` -> `CPP_FLOW.md` -> `CPP_TYPES.md` -> `CPP_PORT_SCOPE.md`
- 인덱싱: `docs/INDEX.md`
- 원본 C++ 소스: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/`
- Sleigh 문서: `ghidra-ref/Ghidra/Features/Decompiler/src/main/doc/sleigh.xml`

## 원본 C++ parity

- 원본 Ghidra C++와의 parity가 최우선이다. 속도, 편의, 새로운 설계, 로컬 단순화보다 우선한다.
- `ghidra-ref/`에 이미 정의된 동작을 추정, 근사, 재해석하지 않는다. 원본 C++를 다시 읽고 그대로 맞춘다.
- 중요한 설계나 구현 결정 전에 관련 원본 C++ 파일을 다시 확인한다.
- parity가 아직 안 맞으면 `known mismatch` 또는 `unimplemented`로 명시하고 넘어간다.
- `docs/CPP_*.md`는 작업 노트일 뿐이다. 문서와 원본 C++가 충돌하면 원본 C++가 이긴다.
- 문서에 적힌 C++ 포팅 범위는 임시 slice일 뿐, 영구 경계가 아니다.

## 작업 방식

- 오케스트레이터는 프로덕션 코드를 직접 구현하지 않는다. 구현 작업은 서브에이전트 소관이다.
- 오케스트레이터는 조율, 범위 분리, 진행상황 회수, 충돌 확인, 문서화, 리뷰, 통합 판단, 최종 검증만 맡는다.
- 구현 작업에는 소넷이나 mini 모델을 사용한다. 예외는 좁은 읽기 전용 탐색뿐이며, 이유를 명시한다.
- placeholder/noop/빈 입력 UI를 만들지 않는다. 이런 UI가 뜨면 실패로 간주한다.
- 사용자 입력 없이 멈추는 인터랙티브 단계나 broad tool 호출을 만들지 않는다.

## 코드 규칙

- 라이선스: Apache 2.0
- 들여쓰기: 탭 (Go 표준)
- 코드와 출력에는 비ASCII 문자를 넣지 않는다.
- 코드 주석은 영어로 작성한다. 의도와 invariant를 설명하며, 문법 설명은 하지 않는다.
- parity에 민감한 코드에는 대응되는 원본 Ghidra C++ class/function을 짧게 적는다.
- 의도 전달이 필요한 코드에는 반드시 주석을 남긴다. 특히 C++ 원본과 구조가 달라진 이유, 의도적 생략, 우회 경로 등은 다음 작업자가 왜 이렇게 했는지 알 수 있어야 한다.
- C++를 Go로 옮길 때는 직역보다 Go다운 구조를 우선한다.
- 코어 런타임 패키지는 표준 라이브러리 우선이다. 서드파티는 반복 복잡도를 확실히 줄일 때만 넣는다.

## 문서 규칙

- 프로젝트 문서는 한국어로 작성한다. (코드/출력의 비ASCII 금지 규칙과 별개다.)
- 저장소 문서에는 private downstream 대상 이름을 적지 않는다.
- 중간 슬라이스를 MVP나 최종 목표처럼 표현하지 않는다.
- 마일스톤을 끝내면 `docs/STATUS.md`를 갱신한다.
- runtime 실행 경로가 바뀌면 같은 라운드에 `docs/RUNTIME_FLOW.md`와 `docs/PARITY_AUDIT.md`도 갱신한다.
- 여러 파일에 걸친 실행 순서와 authority path는 문서에, 세부 C++ 대응 관계는 코드 주석에 남긴다.

## ghidra-ref

- `ghidra-ref/`는 읽기 전용 참조다. 절대 수정하지 않는다.
- C++ codegraph 인덱스: `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/.codegraph.db`
- `ghidra-ref/`를 다시 동기화하면 인덱스를 다시 만든다.

## 프로젝트 목표

- Gosleigh의 목표는 완성형, 실사용 가능한 Go 기반 Sleigh runtime과 decompiler 경로다.
- 현재 우선순위는 SLEIGH 기반 translation/runtime이며, 이것도 전체 디컴파일 경로의 일부다.
- 기존 host의 disassembler를 바로 대체한다고 가정하지 않는다.
