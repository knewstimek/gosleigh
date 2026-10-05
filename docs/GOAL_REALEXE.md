# GOAL: 실바이너리 parity (realexe)

**목표**: 실제 링크된 PE의 임의 함수를 Ghidra와 동일한 C로 디컴파일. 장난감 코퍼스(x64_auto)가 아니라
`tools/realexe` 층화 샘플 일치율이 진척 지표다. 기존 게이트(x64_auto/corpus2/`go test ./...`)는 매 단계 무회귀.

**측정**: `py -3 tools/realexe/realexe.py run --fresh && ... report` (작업 디렉터리 `local/realexe/<stem>/`, gitignored).
기준선 2026-10-06: x86-32 MSVC 클라이언트 200샘플 **10/200** (>32B 함수 0건).

## 근본 갭 (실측 확정, 의존 순서)

| # | 갭 | C++ 근거 | 상태 |
|---|---|---|---|
| R1 | cspec `extrapop="unknown"` 파싱 실패 -> x86win.cspec 통째 무시(bridge가 Warning으로 삼킴) | fspec.cc:2578 ProtoModel::decode | 미착수 |
| R2 | ProtoModel 축약판: 이름있는 모델 집합/extrapop/hasThis 부재, 기본모델 1개만 | fspec.cc ProtoModel, architecture.cc | 미착수 |
| R3 | call-site 스택 모델 부재: stackoffset 항상 unknown, placeholder 미해결 -> 스택 인자 복구 0 | fspec.cc:4849-4930, ruleaction.cc:4321 | 미착수 |
| R4 | ActionExtraPopSetup no-op, ActionStackPtrFlow(StackSolver) 미포팅 | coreaction.cc:20-500, 1437 | 미착수 |
| R5 | Heritage guardCalls 레지스터 전용(call별 hasEffectTranslate 아님), guardStores/guardLoads 미포팅 | heritage.cc:1156-1600 | 미착수 |
| R6 | ProtoModelMerged/evalfp_current 부재 -> thiscall/fastcall 추론 불가 | fspec.cc:2700-2930, coreaction.cc:4626 | 미착수 |
| R7 | p-code 0개 명령어에서 bridge 실패(`has no raw ops`, 4%) | - | 미조사 |

R1~R6 이후 재측정해 다음 클러스터(call 대상 명명, 상수 폭, 타입)를 이 표에 추가한다.
