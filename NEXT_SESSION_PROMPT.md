# 다음 세션 프롬프트 (2026-07-01 작성)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. **x64 실함수(register param RCX/RDX/RDI/RSI) 성공이 명시 목표.**

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다.

## 2026-07-01 완료: x64 corpus add4 + poly4 byte-identical MATCH (2/8) -- 1차 목표 달성
6 커밋 푸시(c5fc308/dc3e5ba/30abaa4/22957f9/e93ec58 + docs). 근본 체인 전부 해결:
1. **갭1 반환 narrowing**: `coreaction.go ActionReturnRecovery.Apply` 끝 `fp.ClearActiveOutput()`(coreaction.cc:1951)
   -> gatherConsumedReturn가 NZMask로 4바이트 consume. + `subvarflow.go tryReturnPull` 충실 포팅(subflow.cc:238).
   (핸드오프의 deriveOutputMap/assumedOutputExtension 가설은 오진 -- 그건 CALL-output 전용.)
2. **갭3 프로모션 캐스트**: heritage rename offset-only key가 EAX(0,4)/RAX(0,8) 충돌 -> EAX read가 RAX ZEXT에
   widened. `heritage.go normalizeReadSize`(SUBPIECE)/`normalizeWriteSize`(PIECE) 충실 포팅(heritage.cc:382/416)
   + Collect WriteMask 필터 + task 루프 normalizeRange. (refinedSubTaskSize는 red herring.)
3. **param_1 손실**: accumulator RCX(read+write)가 normalize로 8바이트 input -> subvar trim에 param HV 소멸.
   `printc.go` reclaim 경로(RegParam offset의 live input을 param 재분류, Ghidra ScopeLocal 주소 기반 parity).
4. **dead RAX-ZEXT**: stale consume로 in-loop deadcode 통과 -> `action.go` actcleanup 후 ActionDeadCode.
5. **poly4 괄호**: `printlanguage.go` PrintLanguage::parentheses 충실 포팅(printlanguage.cc:281) -- equal prec면
   동일 associative 연산자만 무괄호. ExprFragment.op + binaryChildString. assoc = `* + & ^ |`.
전 회귀 그린(10/10 트리 + production + 전 패키지). 모든 수정 유지할 것.

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

## 다음 작업 [최우선] -- 남은 corpus 6개 (max3/sum_to_n부터)

add4/poly4는 MATCH(2/8). 남은 6개: max3, sum_to_n, sum_array, classify, grid_score, process.
각각 `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v`로 WANT vs GOT 대조.

### max3/sum_to_n (다음 우선 -- stack frame locals)
- 갭2a(RSP 프레임)는 완료라 local_18/local_14 부분 복구됨. 남은 차이를 corpus diff로 측정해 케이스별 규명.
- **갭2b 루프 home-slot 통합**: Win x64 reg param의 home slot([rsp+8..]) read가 루프 back-edge 횡단 시 param_1로
  통합 안 되고 uVar1로 남음(sum_to_n). max3(비루프)는 통합됨. 루프 캐리 변수 merge/cover 문제.
- 진단: corpus 함수 트리 빌드 후 alive-op + scopelocal 덤프(이번 세션 임시 test 패턴 재사용, 정리됨).

### sum_array/classify/grid_score/process
포인터 deref, switch, 나눗셈 등 더 큰 기능. PARITY_AUDIT 참조. 각 함수 GOT/WANT 먼저 측정.

### 성공 기준 + 회귀(필수)
- corpus MATCH 수 증가. **회귀**: `TREE_MAP=1 TestTreeFullGoldenMap` 10/10 + production `TestMSVC*`/
  `TestAARCH64SimpleFunction`/`TestX8664`/`TestX64RegParamOrder` + 전 패키지. heritage/printc 공유 코드 수정은
  전 아키텍처 영향 -> x86-32 조심, 작은 단위 + 매번 전 스위트.

## 후속 (미션 #1 본체)
- 11개 production `TestMSVC*`를 트리 경로로 검증 후 `bridge.Decompile` 41-call subset 제거.
- (선택) heritage refineInput / refinement boundary-split / normalizeWriteSize의 CALL-def newIndirectCreation
  경로 미포팅(현재 skip) -- call 있는 함수에서 필요해지면 포팅.
- (선택) dead RAX-ZEXT의 in-loop 정리(현재 actcleanup 후 ActionDeadCode로 우회; 더 깊은 parity fix).

## 참고 문서
- `docs/STATUS.md` #2(갭 분석), CHANGELOG 2026-06-30~07-01, 메모리 `reference_x64_corpus`(파이프라인+갭),
  `project_gosleigh`(전체 상태). C++ 읽기: `ghidra-ref/.../cpp/coreaction.cc`, `fspec.cc`, `heritage.cc`.
