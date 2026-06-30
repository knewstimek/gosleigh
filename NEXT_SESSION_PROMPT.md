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

## 다음 작업 [최우선] -- 갭3 잔여: param_1 naming (add4/poly4 MATCH의 마지막 관문)

### 갭3 프로모션 체인은 해결됨 (2026-07-01, normalizeRead/WriteSize 포팅)
근본은 heritage rename의 **offset-only key**(`renameRecurse` `makeAddressKey(inp.Addr())`)였음: EAX(0,4)와
RAX(0,8)가 같은 키로 충돌 -> EAX read가 RAX(8) ZEXT def를 집어 8바이트로 넓혀짐 -> 중간 ZEXT live화. C++는
`normalizeReadSize`(SUBPIECE)/`normalizeWriteSize`(PIECE)로 range 내 varnode를 균일 크기로 만들어 충돌을 없앰.
포팅 완료(heritage.go: normalizeReadSize/normalizeWriteSize/normalizeRange + Collect WriteMask 필터 + task 루프
배선). **결과: add4/poly4 깨끗한 4바이트 산술**(`return iVar2 + param_2 + ...`, 프로모션 캐스트 소멸). 전 회귀 그린.

### 현상 (남은 미스매치)
- GOT(add4): `int add4(int param_2,int param_3,int param_4) { unsigned long long uVar1; uVar1 = ...; return uVar2 + param_2 + param_3 + param_4; }`
- WANT: `int add4(int param_1,...) { return param_1 + param_2 + param_3 + param_4; }`
- 차이: (a) **param_1 손실** -- RCX는 본문에서 read+write(accumulator)라 subvar가 RCX(8)->ECX(4) input으로
  trim하며 param_1 이름 상실(`uVar2`로 렌더). param_2/3/4(RDX/R8/R9)는 read-only라 정상 유지. (b) dead
  `uVar1=ZEXT(..)` + self-COPY 잔존(최종 deadcode 부재).

### 수정 대상 (다음 세션)
- **subvar의 param-input trim 차단**: subvarflow.go `setReplacement`가 `vn.IsInput() && (mask&1) && bitsize>=8`
  이면 input을 trim 허용 -> param storage(RCX)를 ECX로 trim. Ghidra는 param을 full-width 유지(SUBPIECE(param)이
  param으로 렌더). param이 lock/recover된 input은 trim 거부하거나, param naming이 sub-register offset 매칭하도록.
  C++ subflow.cc setReplacement의 input/typelock 가드와 대조.
- **dead temp 정리**: normalize가 만든 PIECE/SUBPIECE 잔재(uVar1 ZEXT, self-COPY) -> 최종 deadcode 패스 확인.
- (선택) refineInput / refinement boundary-split도 C++엔 있으나 현 corpus엔 불필요. CALL-def write의
  newIndirectCreation 경로도 미포팅(현재 skip) -- call 있는 함수에서 필요해지면 포팅.

### 진단 도구 (재작성 필요 -- 임시 test는 정리함)
corpus를 트리로 빌드 후 alive-op stream 덤프(add4). param_1=reg0x8(RCX) input이 `uVar2`(ECX 4바이트)인지 확인.
subvar input-trim 차단 후 `param_1` 복구 + dead temp 제거 확인.

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
