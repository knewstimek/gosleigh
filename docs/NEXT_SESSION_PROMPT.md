# 다음 세션 프롬프트 (복사해서 사용)

Gosleigh 작업 재개. master fc368a6, 전 패키지 그린 (loader/pcode/sla/bridge).
먼저 docs/STATUS.md(현재상태 + "다음 작업 1" = x64/ARM register-param root cause) + docs/CHANGELOG.md
(2026-06-30 RuleRangeMeld 항목) 읽고 파악.

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 동일 동작(identical behavior) 포팅. 실제 .sla(x86/x64/ARM) 로드해
임의 실제 함수를 Ghidra와 byte-identical C 출력하는 실사용 수준. x64 실함수(register param RCX/RDX/RDI/RSI)
성공도 명시 목표. 미션 본체 = #1 게이트: 손정렬 41-call subset(bridge/decompile.go)을 진짜 Ghidra
파이프라인 ActionDatabase.BuildUniversalAction(250 action/rule)으로 대체.

## 현재 상태 (전 세션 종료 시점)
트리 전체 골든 맵 8/10 byte-identical (TestTreeFullGoldenMap, TREE_MAP=1). **x86-32 8/8 전부 MATCH**
(gcd/abs_val/classify2/classify_sign/counted_loop/sum_list/multiply/add3). 잔여 MISMATCH 2개 = x64_add_ret,
aarch64_add_ret (register-param 트리 미배선). complex_max는 바이트 미보유.
전 세션: classify_sign 완성 = RuleRangeMeld 충실 포팅. 신규 pkg/pcode/circlerange.go(Ghidra CircleRange
subset: pullBack/intersect/circleUnion/translate2Op 등 rangeutil.cc 직접 포팅) + rules_ghidra_port.go
RuleRangeMeld.apply가 stub 대체. `BOOL_OR(INT_EQUAL(p,0),INT_SLESS(p,0))` -> `INT_SLESS(p,1)` collapse.
production TestMSVC* 무회귀(production은 BOOL_OR comparison-pair 미형성).

## 이번 세션 목표: x64/ARM register-param 트리 배선 = 8/10 -> 10/10
**핵심 통찰(전 세션 코드 근거로 확정): 인프라는 이미 존재하고 동작 증명됨. "미포팅"이 아니라
"트리의 buildDefaultModel이 x86-32 전용 하드코딩"이 문제. 검증된 경로를 arch-aware하게 미러링하면 됨.**

### 증명된 레퍼런스 (그대로 따라갈 모범 답안)
`pkg/loader/loader_test.go`의 `TestAARCH64SimpleFunction`(L2372, setup L2413-2456)은 register-param을 **완벽 복구**한다(PASS):
```
pcode.NewHeritage(...).Heritage(graph)
spf := pcode.NewActionStackPtrFlow("analysis"); spf.Apply(fd)
model := pcode.NewProtoModelFromCspec(cspec, spf.StackSpace(), nil)
model.WithReturnReg(regSpaceIdx, 16384, 8)   // X0: off 16384, size 8 (NOT x86 EAX 0,4)
model.WithRegParams([]uint64{16384, 16392})  // X0=param_0, X1=param_1 (AAPCS64)
pcode.ApplyCallingConvention(fd, model)
pcode.ApplyGuardReturnsLive(fd, model, heritageSpaces, graph)
... batch-a / InferTypes / BlockStructure / FinalStructure ...
```
-> `long entry(long param_1, long param_2) { return param_1 + param_2; }`. ScopeLocal이 register 입력을
param_1/param_2로 분류 + signed-long 타입까지 정확. **인프라(WithRegParams/RegParamOffsets/ScopeLocal/타입추론)는
전부 동작한다.**

### 현상 + 근본 (트리가 왜 못하나)
- **현상**: 트리가 x64_add_ret를 `undefined8 {return local_31+local_30;}`(WANT `long {... in_RDI/in_RSI ...}`),
  aarch64_add_ret를 `void entry(void){return;}`(WANT `long entry(long,long){...param_1+param_2;}`)로 출력.
- **근본**: 트리가 쓰는 `pkg/bridge/bridge.go:192 buildDefaultModel`이 위 모범 답안과 달리 **x86-32 하드코딩**:
  (a) `WithRegParams`/RegParamOffsets 미설정 -- `NewProtoModelFromCspec(cspec, nil, nil)`로 regLookup=nil
      (protomodel.go:139는 regLookup!=nil일 때만 RegParamOffsets 채움) + runTreeCase가 CspecPath 미전달이라 cspec도 nil.
  (b) `WithReturnReg(sp.Index, 0, 4)` -- **x86 EAX(offset 0, size 4) 하드코딩**. x64 RAX(0,8)/aarch64 X0(16384,8)
      에 틀림. (decompile.go:80도 동일 하드코딩 -- 둘 다 x86 전용.)
  => scopelocal.go:110 `len(sl.model.RegParamOffsets)>0` 게이트가 x64/aarch64에서 절대 안 걸림 + 반환 레지스터
     오설정으로 반환값/본문 복구 실패.

**작업** (C++ 먼저 읽고 충실 포팅, 추측/떔빵 금지):
1. **진단 1단계(가설 검증)**: x64/aarch64 트리 case에서 proto model의 RegParamOffsets가 비었는지 + ReturnReg가
   (0,4)인지 덤프 확인. (debug_aarch64_test.go 패턴 참고.)
2. **buildDefaultModel을 arch-aware로**(bridge.go) -- 모범 답안을 일반화해 미러링:
   - RegParamOffsets: cspec IntegerRegParams + regLookup(이미 WithEffectOffsets가 `xr.RegisterByName` 사용 -> 동일
     lookup으로 `func(name)(uint64,bool)` 구성) 경로로 채우거나, WithRegParams로 직접. 단 cspec 필요(아래 3).
   - ReturnReg: x86 EAX 하드코딩 제거. cspec default-proto의 return location(register space offset/size)에서 유도.
     (C++ Architecture가 cspec returnaddress/default proto에서 가져옴 -- ghidra-ref 확인.) 우선 arch별 올바른
     offset/size를 cspec에서 뽑는 것이 목표. decompile.go도 같은 문제이나 트리부터.
3. **runTreeCase(tree_fullmap_diag_test.go)**: 각 case에 cspecRel 추가 + BuildConfig.CspecPath 전달 -> CspecData
   non-nil. x64/aarch64 cspec 파일 경로 확인(testdata/sla/ 하위, .cspec 또는 pspec 내장). x86-32는 결과 불변이어야(회귀 확인).
4. **재측정 후 잔여 갭 단계별로**:
   - aarch64: 위 배선이면 `param_1+param_2`/`long` 1차 해소 기대(모범 답안과 동일 경로 도달).
   - x64 `in_RDI` 네이밍: x64 골든은 **processEntry 모드**라 RDI/RSI가 formal param이 아니라 live-on-entry
     레지스터 -> Ghidra가 `in_RDI`로 네이밍(aarch64는 plain entry라 param). 이 live-register 네이밍은 별도 경로
     (printc/ScopeLocal의 입력 레지스터 네이밍) -- aarch64 정렬 후 x64 차이로 좁혀 규명.
   - signed-long 반환(undefined8 -> long): 타입 추론. 모범 답안에선 동작하므로 배선만 맞으면 따라올 가능성.
5. **C++ 참조**: PrototypeModel/Architecture return-location 구성(ghidra-ref Architecture::setPrimitiveMethods,
   prototype.cc/cspec parsing), ScopeLocal::BuildFromVarnodes(scopelocal.go), ActionDefaultParams(coreaction.cc),
   register trial(paramactive.go:904), input-register 네이밍(printc / Varnode naming).

**검증** (매 단계):
- 트리 전체 맵: TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap -count=1 -v -timeout 180s
  (현재 8/10 -> 목표 10/10; aarch64 void 붕괴부터)
- x86-32 회귀 가드: 위 맵에서 x86-32 8개 MATCH 유지 + buildDefaultModel/decompile.go 수정 시 production 영향 확인
- aarch64/x64 production 레퍼런스(모범 답안 안 깨뜨리는지): go test ./pkg/loader/ -run 'TestAARCH64SimpleFunction|TestX8664' -count=1
- gcd 회귀: go test ./pkg/loader/ -run TestUniversalActionTreeGcdGolden -count=1
- production 회귀(공유 코드=buildDefaultModel/ApplyCallingConvention 수정 시 필수): go test ./pkg/loader/ -run TestMSVC -count=1
- 전 패키지: go test ./...

## 그 다음 (register-param 정렬 후): #1 게이트 완료
production 골든 전체를 트리로 검증 후 decompile.go 41-call subset 제거 = #1 게이트 완료.

## 주의 (전 세션 교훈)
- "미포팅/미배선"으로 단정하기 전에 **production-style 테스트가 이미 그 동작을 하는지 먼저 확인**할 것. 이번 건도
  aarch64 테스트가 완벽 복구하고 있었고, 진짜 문제는 트리 proto model의 x86 하드코딩이었다. 인프라 유무를 코드로
  확인한 뒤 전략을 정한다.

## 규칙
- C++(ghidra-ref/) 먼저 읽고 충실 포팅. 추측 말고 코드 근거. 떔빵/우회 금지 -- 진짜 버그를 C++ 원본과 대조해 고친다.
- 회귀 위험 크니 작은 단위 검증, 막히면 부분 상태로 깨끗이 체크포인트(전부 그린 유지). proto model/ScopeLocal은
  공유 경로라 production TestMSVC* 전수 회귀 필수.
- 커밋/푸시 직접, -m 백틱 금지. 한국어 답변. Opus 직접 구현. 내장 도구 대신 mcp__agent-tool__* 사용. 비ASCII raw UTF-8.
- 진행 여부 묻지 말 것 -- 미션이 곧 깊은 이슈 해결. 깊은 이슈를 넘기지 말고 C++ 대조로 끝까지 고친다.

## 진단 도구 (전부 env 가드)
- TestTreeFullGoldenMap(TREE_MAP=1): 멀티아치 전체 골든 맵. tree_fullmap_diag_test.go.
- TestTreeGoldensDiag(TREE_DIAG=1): x86-32 8케이스. tree_goldens_diag_test.go.
- TestTreeAccumDiag(ACCUM_DIAG=1, ACCUM_CASE=<...>, RAW_DUMP/PROD_DUMP): SSA + alive-ops + high 그룹 +
  raw/production 대조. tree_accum_diag_test.go.
