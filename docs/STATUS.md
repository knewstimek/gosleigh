# 프로젝트 상태

## 현재 단계: RulePropagateCopy addr-tied guard parity 수정 (2026-06-29)

2026-06-29 세션. SSA 덤프 실측으로 H8 gcd 근본 원인을 재특정.
- **버그**: `rules_copy.go`의 `isEffectivelyAddrTied`가 register/stack 공간 varnode를
  전부 addr-tied로 취급 -> RulePropagateCopy가 `stack param -> register-space phi`
  propagation을 잘못 차단. C++ `RulePropagateCopy::applyOp` (ruleaction.cc:3969)는
  실제 `Varnode::isAddrTied()` 플래그만 검사하며 register는 addr-tied가 아님.
- **수정**: guard를 실제 `vn.IsAddrTied()`로 교체, `isEffectivelyAddrTied` 제거.
  Gosleigh의 IsAddrTied()는 이미 정확 (스택파람=T, 레지스터=무플래그, 덤프로 확인).
- **부수 정리**: `merge.go markInternalCopies`의 잔존 `INTERNDBG` fmt.Printf 제거 + fmt import 정리.
- **효과**: 이제 propagation이 entry 값을 통합 -- pre-NodeJoin phi가
  `register:0x0 = MULTIEQUAL(stack#param_1, register:0x4)` 형태로 스택파람을 직접 입력.
  gcd 출력이 논리적으로 올바른 gcd로 수렴 (이전: 잘못된 for-loop). 회귀 0건
  (loader/pcode/sla 전 패키지 통과, gcd만 FAIL).

현재 gcd 출력 (golden 대조 경로):
```
tmp_125 = param_3;
iVar1 = param_4;
while (iVar1 != 0) { iVar1 = tmp_125 % iVar1; tmp_125 = iVar1; }
```
golden: `while (iVar1 = param_4, iVar1 != 0) { param_4 = param_3 % iVar1; param_3 = iVar1; }`

남은 gap (둘 다 같은 근본): live loop-var unique가 소스 스택파람과 병합되지 않아
param_3/param_4가 아닌 tmp/iVar로 명명되고, init COPY가 loop-head 스냅샷이 아닌
hoist된 대입으로 출력됨. 근본은 **merge/trim 머신리** -- block-0 트림 COPY
(`unique = COPY stack#param`)는 MergeMarker의 snipReads/mergeAddrTied가 마지막
propagation 패스 이후에 생성하므로 propagation 대상이 아님. snipReads/TrimOpOutput가
addr-tied 정체성을 어느 varnode에 남기는지가 관건. comma-while 렌더링(Gap 4)은
기본 포맷에서 이미 동작하므로 블로커 아님.

진단용 SSA 덤프: `pkg/loader/msvc_diag_test.go` `dumpSSA`/`vnStr` (GCD_DUMP=1 가드).

### 2026-04-14 오후 세션 커밋 (mergeAddrTied 포팅)

- **merge.go mergeAddrTied 파이프라인 전체 포팅**:
  `allocateCopyTrim`, `snipReads`, `eliminateIntersect`, `unifyAddress`, `mergeRangeMust`,
  `mergeAddrTied`, `processCopyTrims`, `markInternalCopies` 구현.
  C++ parity: `merge.cc` lines 411-648, 1415-1471.
- **varnode_bank.go VarnodeInsert flag parity fix**:
  C++ `VarnodeBank::xref`는 모든 non-free varnode에 `Varnode::insert` 설정.
  Gosleigh `CreateDef`/`SetDef`/`SetInput`에 `VarnodeInsert` 추가, `MakeFree`에서 제거.
- **scopelocal.go VarnodeAddrTied flag**: `BuildFromVarnodes`에서 스택 param/local
  varnode에 `VarnodeMapped|VarnodeAddrTied` 설정. C++ `database.cc:1150` 대응.
- **heritage.go 중복 input varnode 방지**: 같은 주소에 이미 input varnode가 있으면
  새로 생성하지 않고 기존 것 재사용. C++ `xref` dedup 대응 (partial).
- **merge.go eliminateIntersect 중복 input 스킵**: 같은 주소의 두 input varnode는
  실제 live-range 충돌이 없음. C++는 `xref`로 dedup하므로 이 케이스가 발생하지 않음.
  Gosleigh에서는 `ActionStackPtrFlow`가 LOAD당 독립 input varnode를 생성하므로 명시 스킵.

### 2026-04-14 H8 파이프라인 디버그 커밋
- `e04d0ac` **merge.go mergeOpcode Cover intersection guard**. C++ parity:
  `merge.cc Merge::mergeOpcode`가 `Merge::merge(h1,h2,false)` 래퍼를 호출하고
  그 래퍼 안에서 `testCache.intersection` 체크하는데 Go는 래퍼를 생략하고
  `mergeHighVariables`를 직접 호출해서 교차 검사 누락. 같은 공간(same-space)
  merge에 한해 intersection 체크 추가.
- `b33f6a2` **rules_misc.go RulePushMultiME cross-space substitute guard**.
  `functionalEqualityLevel==1` 분기가 생성하는 substitute MULTIEQUAL의 입력
  `buf1[0]`과 `buf2[0]`이 서로 다른 물리 저장 클래스(예: stack slot vs register)일 때
  downstream mergeMarker가 두 HighVariable을 하나로 붕괴시키는 것을 방지. Gcd의
  `register:0x8` snapshot이 stack `param_4`와 합쳐지던 정확한 bug site.
- `e6a082d` **action_mark.go markImpliedCheckCover LOAD/CALL cover-containment
  port** (`coreaction.cc markImplied`). 이전엔 known-mismatch stub으로 false 반환.
- `143344a` **.mcp.json gorchera 제거** (프로젝트 스코프).
- `2f5b50e` **action_forloops.go addrTied cross-COPY iterator rejection + pipeline
  reorder**. `tryMarkForLoop`에서 iterateOp이 pure COPY이고 in/out이 서로 다른
  addrTied 저장 주소일 때 (예: `param_3 = param_4`) for-loop 변환 거부.
  `msvc_diag_test.go runPipelineGhidra`에서 ActionMergeCopy를 ActionForLoops
  앞으로 재배치해 post-merge HV 상태 기반 판정.
- `2f5b50e` **action_forloops.go testIterateForm port**. `block.cc
  BlockWhileDo::testIterateForm` (~3287-3314) 직역 포팅. iterator의 input tree가
  loopVar HV에 도달하는지 DFS. C++ 원본은 explicit varnode에서 truncate하지만
  Go의 MergeCopy/MarkExplicit 미완성 때문에 single-use non-addrTied explicit
  varnode는 walk-through 허용 (CountedLoop/SumList의 register transient holder
  패턴 수용). Gcd의 cross-variable COPY (register:0x4 multi-use/addrTied)는
  truncate 유지로 reject. 결과: Gcd 출력에서 잘못된 for-loop 제거 (아래 GOT).
- `bc99850` **action_forloops.go within-HV COPY iterator 거부**.
  testIterateForm에서 iterateOp가 COPY이고 COPY input이 loop HV에 속하면
  (`inVn.High() == high`) 즉시 false 반환. Gcd의 phi-snapshot COPY (`tmp = COPY(phi_param_4)`)가
  for-loop iterator로 잘못 수락되던 버그 수정. CountedLoop path는 COPY input이
  다른 HV이므로 영향 없음. 결과: Gcd while-loop 정상 복구.

### H8 근본 원인 맵 (최신 -- 2026-04-15)

TestMSVC_Gcd 현재 출력 (RulePushMultiME 순서 수정 후):
```
void processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
    iVar1 = param_3;
    for (iVar2 = param_4; iVar2 != 0; iVar2 = iVar1 % iVar2) {
        iVar1 = iVar2;
    }
    return;
}
```

Ghidra golden (`testdata/ghidra_golden/ghidra_golden.json` `gcd_x86_32`):
```
int iVar1;
while (iVar1 = param_4, iVar1 != 0) {
    param_4 = param_3 % iVar1;
    param_3 = iVar1;
}
```

이번 세션 개선 (2026-04-15): RulePushMultiME 순서 수정으로 `tmp_131` 중복 phi 제거.
- joinblock phi #128(ECX phi)이 #131(stack/reg phi)에 정상 병합.
- tmp_124, tmp_129도 함께 사라짐 (의존 phi들이 같이 병합).
- phi 구조 변화로 for-loop 탐지가 재활성화됨 (iVar2 등장).

남은 gap 분석 (2026-04-15 갱신):

1. ~~**Cross-variable COPY를 iterateOp으로 선택**~~ **(CLOSED -- 2f5b50e + bc99850)**.
   (주의: PushMultiME 순서 수정 후 for-loop 탐지가 다시 활성화됨 -- Gap 3 해소 후 재평가 필요.)

2. ~~**mergeAddrTied 파이프라인 미구현**~~ **(CLOSED -- 2026-04-14 오후)**.

3. **구조적 gap: Gosleigh joinblock != Ghidra loop-head**
   - Gosleigh NodeJoin이 만드는 joinblock: `MULTIEQUAL(cond1, cond2)` + `CBRANCH(!merged_cond)`
   - Ghidra loop-head: `MULTIEQUAL(phi_param)` + `COPY(iVar1=phi)` + `INT_NOTEQUAL` + `CBRANCH`
   - 이 구조 차이 때문에 Gosleigh에서 snipReads COPY들이 entry block에 배치되어
     while 조건 이전에 `tmp_N = ...` 형태로 출력됨.
   - 근본 원인: Heritage 시 Ghidra는 stack-to-unique COPY를 생성하지만 Gosleigh는
     stack varnode를 직접 MULTIEQUAL 입력으로 연결. 이후 mergeAddrTied snipReads가
     entry block에 COPY를 삽입해도 loop-head에 위치하지 않음.
   - C++ 참조: `merge.cc snipReads` (lines 443-480): input varnode -> block 0 삽입.
     Ghidra에서는 MULTIEQUAL output unique에 대해서도 snipReads가 실행되어 loop-head에
     COPY 삽입됨. 이 경로가 Gosleigh에 없음.

4. **PrintC: tmp_N + comma-while 미구현**
   - `renderCondBlockComma` (printc.go)는 이미 있지만 condition block에 printable op이
     없어서 단순 `!cond` 형태만 출력.
   - comma-while (`while (iVar1 = param_4, iVar1 != 0)`)는 Gap 3 해소 이후에만 가능.
   - C++ parity: `printc.cc PrintC::emitBlockWhileDo` line 3186 `setMod(comma_separate)`.

진행 순서 제안:
1. **Heritage SSA shape 수정** (가장 근본적): block-0에 stack-to-unique COPY 삽입하면
   mergeAddrTied + snipReads가 loop-head에 COPY를 자연스럽게 배치함.
   C++ 참조: `heritage.cc` Heritage::mergeIn() 또는 유사 경로.
2. **snipReads input-varnode 경로 수정**: input varnode snipReads 시 각 MULTIEQUAL reader의
   parent block 인근에 삽입하는 로직 추가 (접근 C). 복잡하지만 gap 3 직접 해소.
3. 위 선행 없이는 gap 4 (comma-while)도 해소 불가.

## 작업 방향 (2026-04-13 확정)

golden diff 맞추기 목표를 폐기. 대신: **C++ actmainloop 순서대로 각 패스를 알고리즘 레벨에서 충실히 구현**. golden test는 검증 수단이지 목표가 아님. 각 패스 구현 시 C++ 코드 먼저 읽고 이해 후 Go로 포팅.

현재 구현율: Rules 78% (125/161), Actions ~12% (7/59). 미구현 Actions 중 foundational 6개가 핵심 gap.

---

### 미시작 -- actmainloop 순서 기반 foundational 패스

**NOTE**: 아래 항목들은 golden match가 아니라 C++ 알고리즘 충실 구현이 성공 기준. 각 항목 완료 후 `go test ./...` 기존 테스트 통과 여부로 regression 확인.

---

<!-- H3/H4/H5/H6 완료됨 -- 위 완료 섹션 참조 (2026-04-13) -->

- [ ] H7: ActionPrototypeTypes 정식 구현 -- 함수 반환형/인자형 결정
  - 역할: 함수 프로토타입(반환형, 인자 타입)을 Heritage 전에 확정.
    현재 ApplyCallingConvention이 Heritage 후에 실행 -- C++ 순서와 반대.
    gcd 반환형이 `int`로 잘못 추론되는 원인 (Ghidra는 `void`).
  - C++ 참조: `ghidra-ref/.../coreaction.cc` ActionPrototypeTypes::apply() (~line 4620),
    `ghidra-ref/.../funcdata.cc` Funcdata::startProcessing()
  - 수정 대상: `pkg/loader/msvc_diag_test.go` 파이프라인 순서 교정,
    `pkg/pcode/funcproto.go` ApplyCallingConvention 이동
  - 성공 기준: gcd 반환형 `void`로 정확히 결정. anchorReturnReg 휴리스틱 제거 가능해짐.

- [ ] H8: while-condition comma_separate 렌더링 (gcd 완성)
  - 역할: while 조건 블록에 MULTIEQUAL 할당이 있을 때
    `while (iVar1 = param_4, iVar1 != 0)` 형식으로 렌더링.
    현재 emitWhileBlock이 이 패턴 미지원.
  - C++ 참조: `ghidra-ref/.../printc.cc` PrintC::emitBlockWhile() (setMod(comma_separate)),
    `ghidra-ref/.../blockbasic.cc` BlockWhileDo::emit()
  - 수정 대상: `pkg/pcode/printc.go` emitWhileBlock()
  - 성공 기준: TestMSVC_Gcd PASS (t.Skip 제거), gcd_x86_32 golden 일치.

- [ ] H9: ActionSetCasts -- 타입 캐스트 삽입
  - 역할: 타입 불일치 지점에 명시적 캐스트 삽입.
    현재 수동 캐스트 로직(assignCastStr 등)이 근사로 처리.
  - C++ 참조: `ghidra-ref/.../coreaction.cc` ActionSetCasts::apply(),
    `ghidra-ref/.../printc.cc` EmitXml::tagOp() 캐스트 처리
  - 수정 대상: `pkg/pcode/printc.go`, `pkg/pcode/action_infertypes.go`
  - 성공 기준: 기존 캐스트 golden (sum_list의 `(int *)`, complex_max의 `(int)`) 유지.
