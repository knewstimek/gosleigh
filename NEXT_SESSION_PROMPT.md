# 다음 세션 프롬프트 (2026-07-01 작성)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. **x64 실함수(register param RCX/RDX/RDI/RSI) 성공이 명시 목표.**

## 핵심 규칙 (이번 세션에 어겼다가 사용자에게 지적받음 -- 반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. (이번 세션에 반환 크기를 max-write-size 휴리스틱으로 때우려다 사용자가 막음 -> 되돌림.)

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

## 다음 작업 [최우선] -- 갭1: 반환값 크기 추론 (faithful 포팅)

### 현상
x64 corpus 전 함수가 반환 타입/캐스트 오류. 예(add4):
- GOT: `unsigned long long add4(int p1,int p2,int p3,int p4) { return (unsigned long long)(unsigned int)((unsigned long long)(unsigned int)(... p1 + ... p2) + p3) + p4); }`
- WANT: `int add4(int p1,int p2,int p3,int p4) { return p1 + p2 + p3 + p4; }`
함수는 EAX(4바이트 int) 반환인데 트리가 RAX(8바이트)로 고정 -> `unsigned long long`/`undefined8` + ZEXT/
promotion 캐스트 도배. (x86-32은 EAX 폭=int 폭이라 안 걸렸음.)

### 근본 (코드 추적)
- `pkg/pcode/protomodel.go` buildDefaultModel(bridge.go)이 ReturnRegSize = RAX 자연 폭 = **8** 설정.
- `pkg/pcode/paramactive.go:826 ApplyGuardReturnsLive`가 `retSize := model.ReturnRegSize`(8)로 **고정 크기**
  반환 varnode를 각 RETURN에 append. 좁히는 output-trial 로직이 없음.
- x64 `add eax,x`는 암묵적 zero-extension을 명시 모델링 -> `RAX = ZEXT(EAX)` 8바이트 write 생성. 따라서 단순
  "최대 write 크기"는 8을 찾음(휴리스틱 실패 이유). Ghidra는 **ZEXT를 인식**해 4로 좁힘.

### 충실 경로 (C++ -- 그대로 포팅)
1. **`ActionReturnRecovery::apply`** (coreaction.cc:1909): 각 RETURN op에 대해 output ParamActive 트라이얼 ->
   `AncestorRealistic::execute` + `Funcdata::ancestorOpUse`로 active use 마킹 -> `active->finishPass()` /
   `markFullyChecked()`. fully checked면:
   - **`FuncProto::deriveOutputMap(active)`** -> `ProtoModel::deriveOutputMap` -> **`ProtoModel::assumedOutputExtension`**
     (fspec.cc): 출력이 자연 확장(ZEXT/SEXT)이면 출력 폭을 작은 레지스터로 좁힘. **여기가 RAX(8)->EAX(4) 핵심.**
   - **`ActionReturnRecovery::buildReturnOutput`** (coreaction.cc:1837): used 트라이얼로 RETURN op 입력 재구성
     (split 반환은 CPUI_PIECE 연결).
2. **`ActionOutputPrototype::apply`** (coreaction.cc:4776): RETURN op 입력(i>=1)을 vnlist로 모아
   **`FuncProto::updateOutputTypes(vnlist)`** (fspec.cc:4136) 호출 -> 출력 = `triallist[0]`의 addr +
   `getHigh()->getType()`. 즉 RETURN 입력 varnode가 출력 타입/크기를 결정.

### 수정 대상 Go 파일
- `pkg/pcode/paramactive.go`: ApplyGuardReturnsLive / ParamActive output 트라이얼 -- 고정 8바이트 append 대신
  output-trial 사이징. (함수 반환은 C++ ActionReturnRecovery 담당; Gosleigh는 H7에서 guardReturns만 포팅,
  deriveOutputMap/assumedOutputExtension/buildReturnOutput 사이징 미포팅.)
- `pkg/pcode/funcproto.go`: deriveOutputMap / updateOutputTypes / getActiveOutput.
- `pkg/pcode/protomodel.go`: **assumedOutputExtension**(ZEXT/SEXT 인식 -> 출력 폭 좁힘). 핵심 신규.
- `pkg/pcode/ancestor_realistic.go`, coreaction.go:1229 ancestorOpUseReturn -- 이미 일부 존재, 재사용 가능.
- 주의: coreaction.go:1159 `ActionActiveReturn`은 **CALL-output** 복구용 no-op stub(함수 반환과 별개). 혼동 말 것.

### 성공 기준
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v`: 먼저 **add4/poly4가 MATCH로 flip**
  (스택 프레임 없음, 갭1+갭3만). 그 다음 max3 등.
- **회귀(필수)**: `TREE_MAP=1 ... TestTreeFullGoldenMap` 10/10 유지 + production `TestMSVC*` +
  `TestAARCH64SimpleFunction`/`TestX8664`/`TestX64RegParamOrder` 그린. **반환 와이어링은 전 함수에 영향 ->
  x86-32 회귀 매우 조심.** 작은 단위로 고치고 매번 전 스위트 확인.

### 진단 1단계
add4(스택 프레임 없는 최단 케이스)의 RETURN op 입력 varnode와 그 def를 덤프. RAX(8) = ZEXT(EAX 4) 구조 확인 ->
assumedOutputExtension이 이걸 4로 좁혀야 함. (이번 세션에 임시 X64_DUMP 덤프 썼다가 제거함; 필요하면 재추가.)

## 후속 갭 (갭1 후)
- **갭3 promotion 캐스트**: `(unsigned long long)(unsigned int)`/`ZEXT` 연쇄 -- 갭1에서 파생. 갭1 해결 후 재측정,
  잔여만 ActionSetCasts/typeop에서 처리.
- **갭2b 루프 home-slot 통합**: Win x64 reg param의 home slot([rsp+8..]) read가 루프 back-edge 횡단 시 param_1로
  통합 안 되고 uVar1로 남음(sum_to_n). max3(비루프)는 통합됨. 별도.
- 그 다음: 11개 production `TestMSVC*`를 트리 경로로 검증 후 `bridge.Decompile` 41-call subset 제거(미션 #1 본체).

## 참고 문서
- `docs/STATUS.md` #2(갭 분석), CHANGELOG 2026-06-30~07-01, 메모리 `reference_x64_corpus`(파이프라인+갭),
  `project_gosleigh`(전체 상태). C++ 읽기: `ghidra-ref/.../cpp/coreaction.cc`, `fspec.cc`, `heritage.cc`.
