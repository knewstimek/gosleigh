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
**root cause는 전 세션에 코드 근거로 규명됨**(STATUS.md "다음 작업 1" 참조). 요약:
- **현상**: 트리가 x64_add_ret를 `undefined8 {return local_31+local_30;}`(WANT `long {... in_RDI/in_RSI ...}`),
  aarch64_add_ret를 `void entry(void){return;}`(WANT `long entry(long,long){return param_1+param_2;}`)로 출력.
- **근본**: 트리 proto model이 RegParamOffsets를 절대 안 채움.
  (a) `pkg/bridge/bridge.go:192 buildDefaultModel`이 `NewProtoModelFromCspec(cspec, nil, nil)` -- regLookup=nil
      전달. protomodel.go:139는 regLookup!=nil일 때만 RegParamOffsets 채움 -> nil이면 no-op.
  (b) `pkg/loader/tree_fullmap_diag_test.go runTreeCase`가 BuildConfig에 CspecPath 미전달 -> CspecData=nil
      -> NewProtoModelFromCspec(nil,...) early-return(ABI 정보 전무). x86-32는 스택 ABI 기본값으로 동작하나
      register-param 아키는 막힘.
  => scopelocal.go:110 `len(sl.model.RegParamOffsets)>0` 게이트가 x64/aarch64에서 절대 안 걸림.

**작업** (C++ 먼저 읽고 충실 포팅, 추측/떔빵 금지):
1. **진단 1단계**: x64 case에서 트리 proto model의 RegParamOffsets가 실제로 비어있는지 덤프 확인
   (가설 검증부터). 비어있으면 (a)(b) 둘 다 고친다.
2. **bridge.go buildDefaultModel**: NewProtoModelFromCspec에 regLookup 전달. 이미 WithEffectOffsets가
   `xr.RegisterByName(name)`을 쓰므로 동일 lookup으로 `func(name string)(uint64,bool)` 구성해 3번째 인자로.
   (단 cspec이 nil이면 의미 없으니 (b) 먼저.)
3. **runTreeCase**: 각 case에 cspecRel 추가하고 BuildConfig.CspecPath 전달. x64/aarch64 cspec 파일 경로 확인
   (testdata/sla/ 하위). x86-32 cspec도 일관되게(스택이라 결과 불변이어야 -- 회귀 확인).
4. RegParamOffsets 배선 후 **재측정**해 잔여 갭을 단계별로:
   - input-register 네이밍 in_RDI (현재 local_31): ScopeLocal/네이밍 경로.
   - signed-long 반환 추론 (undefined8 -> long): 타입 추론 경로.
   - aarch64 dead-code 전소: register 입력이 안 살아서 본문 전소 -> RegParamOffsets 배선이 1차 해소 기대.
5. C++ 참조: ScopeLocal::BuildFromVarnodes 대응(scopelocal.go), ActionDefaultParams/ActionPrototypeTypes
   (coreaction.cc), PrototypeModel 구성(Architecture::setPrimitiveMethods), register trial(paramactive.go:904).

**검증** (매 단계):
- 트리 전체 맵: TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap -count=1 -v -timeout 180s
  (현재 8/10 -> 목표 10/10; 최소 aarch64 void 붕괴부터)
- x86-32 회귀 가드(CspecPath 추가가 x86-32 안 깨뜨리는지): 위 맵에서 x86-32 8개 MATCH 유지 확인
- gcd 회귀: go test ./pkg/loader/ -run TestUniversalActionTreeGcdGolden -count=1
- production 회귀(공유 코드 수정 시 필수): go test ./pkg/loader/ -run TestMSVC -count=1
- 전 패키지: go test ./...

## 그 다음 (register-param 정렬 후): #1 게이트 완료
production 골든 전체를 트리로 검증 후 decompile.go 41-call subset 제거 = #1 게이트 완료.

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
