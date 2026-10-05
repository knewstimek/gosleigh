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
| `1aa498b` | 호스트 이름/로컬, flow override(꼬리 호출 CALL_RETURN) | 100 | 0.840 |
| `e9cbade` | ram heritage + 전역 심볼(호스트 savefile), RestrictLocal, mergeIndirect | 103 | 0.846 |
| `c87b817` | 헤더 주석(FID), C++ 이름 번호, noreturn halt, 문자열 리터럴, 크래시/행 수정 | 110 | 0.881 |
| `5ee1024` | callee/외부 잠긴 프로토타입, typedef, callfixup 인젝션, RulePiecePathology, deadcode 공간 게이트, unaff_ | 123 | 0.903 |

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
| T | 타입 추론 차이: 반환형(int vs uint/undefined4), STORE 포인터 캐스트(`*(undefined1 *)(p + 1)`), 1바이트 상수가 char로 출력 | typeop.cc propagateType, ActionInferTypes | 사례 다수 |
| F | fastcall/thiscall 파라미터 번호와 fill-in(앞 레지스터 슬롯), 조건 그룹 구조 순서 | fspec.cc fillinMap, blockaction.cc | P2와 연결 |
| R | 반환/출력 복구 경로가 C++ 구조와 다름(ActionReturnRecovery 단일 패스, post-deadcode Go-local 판정) | coreaction.cc 1909 | 반환 void/int 오판 |
| P2 | Go는 메인루프에서 입력 프로토타입을 조기 잠금(ApplyActiveParamModel) -- C++은 ActionInputPrototype에서 | coreaction.cc 4718 | thiscall 스택 파라미터 누락 일부 |
| E | PrettyEmitter가 식을 평면 문자열로 받아 C++ 줄바꿈 지점을 못 냄 | prettyprint.cc | 긴 FID 이름 줄바꿈 |
| L | 네임스페이스 최소 출력 규칙(공통 접두 생략) | printc.cc pushSymbolScope | |
| - | known mismatch: guardCallOverlappingInput, LoadGuard(ValueSet), RestrictLocal 호출 파라미터 부분, clearDeadVarnodes 스택/destroy, 공유 이름 카운터의 미출력 HV | heritage.cc, varmap.cc, coreaction.cc | |
