# 다음 세션 프롬프트 (2026-07-01 작성)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. **x64 실함수(register param RCX/RDX/RDI/RSI) 성공이 명시 목표.**

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다.

## 갭1(반환 크기) 결과 -- 2026-07-01 완료, 갭3으로 이관 (먼저 읽을 것)
이전 핸드오프의 충실 경로(ActionReturnRecovery/deriveOutputMap/assumedOutputExtension)는 **오진**이었음.
deriveOutputMap->fillinMap은 출력 trial 폭을 안 좁히고, assumedOutputExtension은 funcLinkOutput의 CALL-output
전용. x64 반환 narrowing의 실제 메커니즘 = **consume(NZMask) + subvariable flow**, 두 곳 충실 포팅 완료:
- `pkg/pcode/coreaction.go` `ActionReturnRecovery.Apply` 끝에 **`fp.ClearActiveOutput()`**(C++ coreaction.cc:1951).
  ActiveOutput이 남으면 `gatherConsumedReturn`이 전체 소비 반환 -> ZEXT 영구 잔존. 클리어해야 NZMask로 4바이트.
- `pkg/pcode/subvarflow.go` `tryReturnPull` stub -> subflow.cc:238 충실 포팅(returnsTraversed 전파 +
  addTerminalPatchSameOp).
**결과: corpus add4/poly4 반환 타입 `unsigned long long`->`int`. 전 회귀 그린(10/10 트리 + production).**
**아직 MATCH 아님** -- 남은 블로커는 갭3(아래). 두 수정은 유지할 것(충실 + 무회귀, git status로 확인).

## 현재 상태 (master af43fdb, 전 패키지 그린, 전부 푸시됨)
- **트리 전체 골든 맵 10/10 byte-identical** (`TestTreeFullGoldenMap`, TREE_MAP=1): x86-32 8/8 + x64_add_ret +
  aarch64_add_ret. 이게 미션 #1 게이트(트리=프로덕션 경로)의 핵심 검증.
- **x64 Windows ABI register-param 복구는 작동**: add4/poly4가 RCX/RDX/R8/R9 -> param_1..4 정확.
- **갭2a(RSP 스택 프레임) 완료**(commit 2d9133b): x64 `sub rsp,N` 프레임을 SP 오프셋 맵 전파로 추적.
  action_stack_ptr_flow.go buildStackOffsetMap + encodeStackSlotOffset(ptrSize). max3/sum_to_n이 `uVar7[10]`
  쓰레기 -> 3 params + local_18/local_14 복구로 개선. x86-32(EBP) 무회귀.
- **x64 breadth corpus 파이프라인**(`testdata/x64_corpus/`): MSVC `cl /c /Od` -> COFF obj -> Ghidra 12 헤드리스
  Java postScript -> `x64_goldens.json`(8 실함수). 갭 맵 `TestX64CorpusGoldenMap`(X64_CORPUS=1). 재생성:
  `py -3 testdata/x64_corpus/build.py && py -3 testdata/x64_corpus/run_ghidra.py`.

## 다음 작업 [최우선] -- 갭3: 내부 ZEXT 프로모션 체인 미붕괴 (add4/poly4 MATCH의 마지막 관문)

### 현상 (갭1 수정 후)
add4 반환 타입은 `int`로 정확하나 본문이 여전히 캐스트 도배 + dead 잔존:
- GOT: `int add4(...) { unsigned long long uVar3; uVar3 = (unsigned long long)(unsigned int)iVar2; return (int)((unsigned long long)(unsigned int)(... p1 + ... p2) + p3) + p4); }`
- WANT: `int add4(...) { return param_1 + param_2 + param_3 + param_4; }`

### 근본 (이번 세션 정밀 규명 완료 -- 핵심)
- **raw p-code는 정상**: `add eax,x` = 4바이트 `EAX[4] = INT_ADD(EAX[4], x[4])` + `RAX[8] = ZEXT(EAX[4])`
  (상위 클리어). 중간 RAX ZEXT는 전부 dead(아무도 8바이트 RAX를 안 읽음, 최종 반환만 읽음)여야 함.
- **범인 = `refinedSubTaskSize`(heritage.go:630)**: task 시작 offset의 **max** varnode 크기를 반환. offset 0에
  EAX(4)+RAX(8) 오버랩 시 maxSz=8=size -> **분할 안 함** -> EAX(4) read가 [0,8) 8바이트 phi에 rename되어
  8바이트로 넓혀짐(`iVar1[4]=INT_ADD(uVar6[8]=ZEXT, ...)` 혼합 크기) -> 중간 ZEXT live화.
- **그래서 `RuleSubvarZext.DoTrace`가 중간 ZEXT에서 pullcount=0 실패**(반환 ZEXT trim은 outer만 벗김; 내부 add가
  8바이트 RAX 읽음). traceForward/Backward 자체는 정상(계측 확인).
- **C++ 정답**: `Heritage::refinement`(heritage.cc, buildRefinement)이 **모든 varnode 경계(0,4,8)에서 분할** ->
  [0,4)+[4,8). EAX read는 size 4 유지(미넓힘), RAX(8) ZEXT write만 `normalizeWriteSize`로 PIECE 분할(상위
  [4,8)는 dead). clean IR이면 중간 ZEXT가 dead -> deadcode 제거, 최종 ZEXT만 tryReturnPull로 trim -> WANT.

### 수정 대상 (다음 세션 -- 코어 heritage, 고위험)
- **`Heritage::refinement` 충실 포팅**: heritage.go의 `refinedSubTaskSize` simplified 분할(max varnode 크기)을
  C++ buildRefinement(모든 varnode start+size 경계 마킹 -> 경계마다 split)로 교체.
- **`normalizeReadSize`(heritage.cc:382) 포팅**: range size보다 작은 read varnode를 `SUBPIECE(big[size], overlap)`로
  재정의. (현재 미포팅 -- heritage.go Guard가 안 부름.)
- **`normalizeWriteSize`(heritage.cc:416) 포팅**: range size보다 작은 write를 PIECE로 빈 조각 채워 size 맞춤.
- heritage.go 728-758 task 루프 + Guard(846)에 read/write normalize 배선. 현재 주석이 "no PIECE/SUBPIECE physical
  splits"로 생략 명시 -- 그걸 되살리는 작업.
- **회귀 필수(전 아키텍처 영향)**: x86-32은 sub-register(AX/AL) 함수에서 영향 가능 -> 10/10 트리 + 전 production
  `TestMSVC*` 반드시. 작은 단위 + 매 단계 전 스위트.

### 진단 도구 (재작성 필요 -- 이번 세션 임시 test는 정리함)
corpus 함수를 트리로 빌드 후 alive-op stream을 nzm+con 포함 덤프(add4부터). `INT_ADD`가 8바이트 RAX 피연산자를
읽으면 widening 발생 확인. 수정 후 4바이트 add + dead 중간 ZEXT 제거 확인.

### 성공 기준
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v`: **add4/poly4가 MATCH로 flip**.
- **회귀(필수)**: `TREE_MAP=1 ... TestTreeFullGoldenMap` 10/10 + production `TestMSVC*` +
  `TestAARCH64SimpleFunction`/`TestX8664`/`TestX64RegParamOrder` 그린. heritage 수정은 전 아키텍처 영향 ->
  x86-32 매우 조심, 작은 단위로 + 매번 전 스위트.

## 후속 갭
- **갭1은 완료**(위 상단). 두 수정(coreaction.go ClearActiveOutput + subvarflow.go tryReturnPull) 유지.
- **갭2b 루프 home-slot 통합**: Win x64 reg param의 home slot([rsp+8..]) read가 루프 back-edge 횡단 시 param_1로
  통합 안 되고 uVar1로 남음(sum_to_n). max3(비루프)는 통합됨. 별도.
- 그 다음: 11개 production `TestMSVC*`를 트리 경로로 검증 후 `bridge.Decompile` 41-call subset 제거(미션 #1 본체).

## 참고 문서
- `docs/STATUS.md` #2(갭 분석), CHANGELOG 2026-06-30~07-01, 메모리 `reference_x64_corpus`(파이프라인+갭),
  `project_gosleigh`(전체 상태). C++ 읽기: `ghidra-ref/.../cpp/coreaction.cc`, `fspec.cc`, `heritage.cc`.
