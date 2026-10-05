# GOAL: 실바이너리 parity (realexe)

**목표**: 실제 링크된 PE의 임의 함수를 Ghidra와 동일한 C로. 진척 지표 = `gosleigh.realexe.measure`(200 층화 샘플)의
일치 수 + 토큰 유사도(sim). 매 단계 `gosleigh.gates`(`py -3 tools/gates.py`) 무회귀 + 게이트 골든 출력 바이트 동일.

| 커밋 | 내용 | 일치 | sim |
|---|---|---|---|
| `60b3835` | 기준선 | 10 | - |
| `e31d2b1` | 스택 포인터 흐름 + call 스택 인자 사슬 | 10 | 0.417 |
| `320acb4` | 호스트 심볼(callee 이름) + merged 모델(thiscall/fastcall) | 14 | 0.485 |
| `f98453d` | callee 프로토타입(extrapop/callee_pop), 반환 판정 | 14 | 0.506 |
| `873ee2e` | 플래그 그룹 버그(incidental_copy), 미사용 call 출력 제거 | 17 | 0.522 |

## 도구 (`tools/realexe/`)
- `realexe.py analyze|sample|measure|capture`, `gaps.py`(불일치 유형 집계), `difffn.py`(인덱스별 diff).
- **`capture`가 핵심**: `GenCapture.java`가 Ghidra 디버그 savefile을 만들고, `tools/decomp_dbg.exe`가 그 실바이너리
  맥락 그대로 C++ 코어를 돌린다(골든을 재현함). 갭 원인은 이걸로 실측한다.

## 원칙 (이번 작업에서 확인)
Gosleigh의 여러 층이 소형 골든 맞춤 재구현이었다. 실바이너리 갭의 근본은 대부분 (a) C++ 고리 누락(스텁/부분포팅)
또는 (b) **코어가 Java(호스트)에서 받는 정보의 부재**다. (b)는 `pcode.HostScope`/`bridge.BuildConfig`로 공급한다 --
이름 변환(IllegalCharCppTransformer), callee extrapop(purge+stackshift), flow override, 함수 로컬(localdb)은 하네스가
Ghidra API로 Java와 같은 값을 덤프한다.

## 남은 갭 (실측, 빈도 순 -- 갱신은 `gaps.py` + `capture`)

| # | 갭 | 근거 | 비고 |
|---|---|---|---|
| H3 | 전역 데이터 심볼(DAT_, vftable, TEB ExceptionList) + ActionConstantPtr isPointer + 호스트 타입 | ScopeGhidra queryContainer, coreaction.cc isPointer | tracked 레지스터(`ActionConstbase` 스텁, FS_OFFSET)와 묶임 |
| R | 반환/출력 복구 경로가 C++ 구조와 다름(ActionReturnRecovery 단일 패스, post-deadcode Go-local 판정) | coreaction.cc 1909 | 반환 void/int 오판 |
| P2 | Go는 메인루프에서 입력 프로토타입을 조기 잠금(ApplyActiveParamModel) -- C++은 ActionInputPrototype에서 | coreaction.cc 4718 | thiscall 스택 파라미터 누락 일부 |
| E | PrettyEmitter가 식을 평면 문자열로 받아 C++ 줄바꿈 지점을 못 냄 | prettyprint.cc | 긴 FID 이름 줄바꿈 |
| L | 라이브러리 함수 주석(FID plate comment), 네임스페이스 최소 출력 규칙 | printc.cc pushSymbolScope | 호스트 주석 공급 필요 |
| X | panic 2건(IsLoopIn, renameRecurse 블록 인덱스) | - | 미조사 |
| - | known mismatch: markNotMapped, guardCallOverlappingInput, LoadGuard(ValueSet), heritage 전체 구조 | heritage.cc, varmap.cc | |
