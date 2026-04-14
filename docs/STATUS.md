# 프로젝트 상태

## 현재 단계: H8 MergeMarker 체인 디버그 진행 중 (2026-04-14 아침)

2026-04-14 새벽~아침 세션에서 H8(TestMSVC_Gcd) 근본 원인 4단 파이프라인으로 좁혀 냄.
여섯 개의 parity fix 커밋 추가. TestMSVC_Gcd 여전히 FAIL, 나머지 loader 테스트 PASS 유지,
regression 0. Gap 1 (cross-variable COPY iterateOp)은 testIterateForm 포팅으로 완료.
남은 gap: cond-block snapshot hoist + unique-space 네이밍. `### H8 근본 원인 맵` 참조.

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
- (this session) **action_forloops.go testIterateForm port**. `block.cc
  BlockWhileDo::testIterateForm` (~3287-3314) 직역 포팅. iterator의 input tree가
  loopVar HV에 도달하는지 DFS. C++ 원본은 explicit varnode에서 truncate하지만
  Go의 MergeCopy/MarkExplicit 미완성 때문에 single-use non-addrTied explicit
  varnode는 walk-through 허용 (CountedLoop/SumList의 register transient holder
  패턴 수용). Gcd의 cross-variable COPY (register:0x4 multi-use/addrTied)는
  truncate 유지로 reject. 결과: Gcd 출력에서 잘못된 for-loop 제거 (아래 GOT).

### H8 근본 원인 맵 (2026-04-14 아침 기준)

TestMSVC_Gcd 현재 출력 (golden 불일치, testIterateForm 포팅 후):
```
void processEntry entry(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
    int iVar2;
    tmp_131 = param_4 == 0;
    tmp_129 = param_4;
    while (!tmp_131) {
        iVar2 = param_3 % tmp_129;
        tmp_131 = iVar2 == 0;
        tmp_129 = iVar2;
        param_3 = tmp_129;
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

남은 gap은 두 개 (Gap 1 closed):

1. ~~**Cross-variable COPY를 iterateOp으로 선택**~~ **(CLOSED this session)**.
   testIterateForm 포팅 + single-use non-addrTied explicit walk-through.
   Gcd의 잘못된 for-loop 제거, CountedLoop/SumList regression 없음.

2. **PrintC emitWhileBlock에 comma_separate 모드 미구현 (부분)**
   (`pkg/pcode/printc.go` `emitWhileBlock`, `renderCondBlockComma`)
   - `renderCondBlockComma`는 존재하고 호출도 되는데 gcd의 cond block에
     `iVar1 = param_4` 형태의 snapshot COPY가 실제로 들어오지 못함. 그 결과
     `while (!tmp_130)` 단독 조건만 렌더. snapshot COPY를 cond block head로
     끌어올리는 경로 누락.
   - C++ parity: `printc.cc PrintC::emitBlockWhileDo` (코드 3186 부근)에서
     `setMod(comma_separate)` 모드로 condBlock 전체를 comma-separated list로
     찍음. Go는 cond block에 printable op이 있을 때만 fallback하는 구조.

3. **tmp_N unique-space 유출 + ActionNameVars 누락**
   (`pkg/pcode/action_name_vars.go` `ActionNameVars.Apply`, 라인 135)
   - 현재 ActionNameVars는 non-unique non-input 인스턴스가 있는 HighVariable만
     iVar1/uVar1 이름 부여. Gcd의 snapshot HV는 unique-space 인스턴스만 있을
     때 네이밍 스킵 -> printc의 default fallback이 `tmp_<offset>` 형식으로 출력.
   - C++ parity: `variable.cc ScopeInternal::assignDefaultNames`는 storage class
     관계없이 명명. Go side는 의도적으로 보수화된 것으로 보이나 Gcd 시나리오
     관통에는 부족.

진행 순서 제안 (Gap 2,3 남음):
1. **cond block snapshot hoist** -- gcd의 entry block `COPY stack:0x8 -> unique:0xae433`
   (param_4 snapshot)와 body의 첫 COPY는 C++ Ghidra에서 NodeJoin/merge 이후 cond
   block에 자연스럽게 등장. Go에서는 entry와 body에 흩어짐. 확인된 구조
   (structured dump으로 확인):
   - entry: INT_EQUAL + 2 COPY (param_4/param_3 snapshot)
   - cond: 7 MULTIEQUAL + CBRANCH (printable op 없음)
   - body: COPY register:0x4 = ae416(param_4 phi) + SREM + EQUAL + 2 COPY
   `renderCondBlockComma`가 hoist 로직을 추가하거나, ActionBlockStructure 단계에서
   엔트리의 snapshot COPY를 cond 머리로 이동 필요.
2. **ActionNameVars 기준 완화** -- unique-space HV 중 loop-carried 표시가 있는
   것만 iVar 네이밍 허용. 현재 `tmp_131 = param_4 == 0`, `tmp_129 = param_4`
   처럼 unique-only HV가 tmp_N 이름으로 유출.
3. **(선택) Go Heritage/NodeJoin SSA shape 비교** -- 1/2가 부분 수정으로 안 되면
   근본 원인 추적. `register:0x8`와 `stack:0x8` merge가 기대대로 되지 않는 곳.

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
