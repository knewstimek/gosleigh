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

### 근본 (이번 세션 진단 완료)
- **raw p-code는 정상**: `add eax,x` = 4바이트 `EAX[4] = INT_ADD(EAX[4], x[4])` + `RAX[8] = ZEXT(EAX[4])`
  (상위 클리어). 중간 RAX ZEXT는 전부 dead(아무도 8바이트 RAX를 안 읽음, 최종 반환만 읽음)여야 함.
- **그런데 최종 IR은 add가 8바이트 RAX를 읽음**: `iVar1[4] = INT_ADD(uVar6[8]=ZEXT, param_3[4])` 식 혼합 크기.
  즉 heritage normalization/copy-prop이 `add eax`의 EAX(4) read를 RAX(8)=ZEXT로 **넓힘** -> 중간 ZEXT가 live화.
- **그래서 `RuleSubvarZext.DoTrace`가 중간 ZEXT에서 `pullcount=0`으로 실패**(체인이 RETURN/terminal 미도달 --
  4바이트 add 출력이 terminal로 끊김). traceForward/Backward 자체는 실패 안 함(계측 확인). clean IR(미widening)
  이면 중간 ZEXT가 dead라 deadcode가 제거하고 최종 ZEXT만 tryReturnPull로 trim -> WANT 형태.

### 조사 대상 (다음 세션)
- **heritage가 sub-register read를 8바이트로 넓히는 지점**: `pkg/pcode/heritage.go` `normalizeReadSize` /
  disjoint cover 계산. register offset 0 범위가 RAX(8) write(ZEXT) 때문에 8바이트로 잡혀 EAX(4) read가 RAX(8)로
  정규화되는지 확인. C++ `Heritage::guard`/`normalizeReadSize`(heritage.cc:1156~)와 대조.
- 또는 copy propagation이 EAX read를 RAX=ZEXT def로 포워딩하는지(rules_copy.go).
- **subvar/typeop은 근본 아님** -- subvar는 widening의 결과를 못 푸는 것일 뿐. widening을 막거나 Ghidra와
  동일하게 만드는 게 핵심.

### 진단 도구 (재작성 필요 -- 이번 세션 임시 test는 정리함)
corpus 함수를 트리로 빌드 후 (1) alive-op stream을 nzm+con 포함 덤프, (2) RuleSubvarZext.DoTrace 실패를
pullcount=0 vs setReplacement nil로 구분. add4(스택프레임 없는 최단)부터.

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
