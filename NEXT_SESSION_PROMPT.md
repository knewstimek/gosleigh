# 다음 세션 프롬프트 (2026-07-03 작성, master `a02b1a6`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다.**

## 현재 상태 (master `a02b1a6`, 전 패키지 그린)
- **미션 #1 게이트 달성 + H8-debt-2 완전 종료**: production `bridge.Decompile`이 universal-action 트리
  경로를 공유(Step1+Step2, master `eadd9c0`). Step3(레거시 테스트 하네스 13개를 트리 경로로 이전한 뒤
  bespoke `ActionStackPtrFlow` 파일 삭제, master `accd8a9`)까지 마쳐 production/트리 경로가 완전히
  하나로 수렴했다.
- **신규: H-dispatch Component 1 -- `FlowInfo::truncateIndirectJump` 충실 포팅(master `a02b1a6`)**.
  신규 `pkg/pcode/flow_jumptable.go`(+222)가 `RecoverJumpTables` 구동 드라이버(`bridge.Build`에 배선)로
  jump-table 복구를 먼저 실제 시도하고, 실패 시에만 BRANCHIND를 CALLIND + artificial return으로
  강등한다(무조건 truncate 아님). dispatch golden의 raw `goto *(...)`는 제거됐고 pcode 레벨 강등은
  정확하다. **단 RENDER는 악화**됐다(`(*0)()` 타깃 유실) -- 진짜 다음 블로커는 IOP-space 인코딩
  project-wide 미포팅(foundational, heritage.cc:2506-2517)으로 확정. 아래 (a) 참고.
- 트리 전체 골든 맵 **10/10** byte-identical(`TestTreeFullGoldenMap`, TREE_MAP=1) 무회귀.
- x64 corpus(기존 8함수) **7/8** MATCH(`TestX64CorpusGoldenMap`, X64_CORPUS=1) 무회귀: add4/poly4/max3/
  sum_to_n/sum_array/classify/grid_score. process만 잔여 -- 별개 deep-debt로 확정(아래 (b) 참고).
- struct/2D/switch 패턴 별도 x64 breadth corpus(`testdata/x64_breadth/`) **2/3** MATCH
  (`TestX64BreadthGoldenMap`, X64_BREADTH=1) 무회귀: dist_sq/sum2d MATCH, dispatch(switch/jumptable)는
  여전히 MISMATCH -- 실패 모드가 `goto *(...)` -> `(*0)()`로 바뀌었을 뿐, 아래 (a)/(a-2) 참고.
- production `TestMSVC_{CountedLoop,SumList,AbsVal,Classify2,Gcd}` 5/5 byte-identical, `TestAARCH64`/
  `TestX8664`/`TestX64RegParam` 전부 pass. `go test ./...` 클린(pkg/loader symbols_test 3건 missing-.exe
  사전실패는 무시 -- untracked fixture).

## 이번 세션 완료 (건드리지 말 것, 충실+검증완료)
직전 세션(H8-debt-2 본체 -- production을 트리로, master `eadd9c0`)에 이어진 세션. 두 가지를 완료했다.

**A: H8-debt-2 Step3 -- bespoke `ActionStackPtrFlow` 완전 삭제 (master `accd8a9`)**
- `pkg/pcode/action_stack_ptr_flow.go`(619줄) 삭제. `loader_test.go`의 legacy 직접-heritage 테스트 13개를
  트리 경로(`bridge.Build(+CspecPath[+EntryPoint])` -> `bridge.Decompile`이 universal-action 트리를
  구동)로 이전, 원본 assertion 무수정(x86 non-processEntry + x86gcc.cspec, AArch64 + AARCH64.cspec, x86
  processEntry + x86gcc.cspec+EntryPoint). 은퇴한 경로만 운동시키던 진단/중복 하네스도 삭제
  (`classify2diag_main.go`, `msvc_debug_test.go`, `msvc_diag_test.go`의 `runPipeline`,
  `tree_output_diag_test.go`의 `TestProductionStagesDiag`+`blockShape`). diff +59/-1794(7파일).
  `NewActionStackPtrFlow` Go 호출처 0건.
- 게이트: `go build` 클린, tree 10/10, x64 corpus 7/8 무회귀, production 전부 PASS, `go test ./...` 클린
  (symbols_test 3건 missing-.exe 무시, 기존과 동일).
- **이로써 H8-debt-2(Step1+Step2+Step3)가 완전히 종료됐다.**

**B: breadth 디스커버리 -- struct/2D/switch corpus + 갭 맵 (master `5276375`)**
- 별도 `testdata/x64_breadth/`(기존 `x64_corpus` 무건드림, 파이프라인은 MSVC x64 `/Od` -> COFF obj ->
  Ghidra 12 헤드리스 `GenGoldens.java` 재사용) + 하네스 `TestX64BreadthGoldenMap`(X64_BREADTH=1). 3함수
  2/3 MATCH: `dist_sq`(struct Point* 필드접근) MATCH, `sum2d`(2D 배열 `m[i*cols+j]`) MATCH -- struct/
  중첩주소산술 능력 확인(신규 갭 아님). `dispatch`(dense switch 0..7) MISMATCH -- 신규 갭.
- **dispatch 갭 근본**: (1) jumptable 머신러리(`pkg/pcode/jumptable.go`, 1671줄)는 포팅됐으나 decompile
  파이프라인에 신규 등록 드라이버가 없음. C++ 대응: `FlowInfo::generateOps`(flow.cc:799)가 `tablelist`를
  순회하며 `FlowInfo::recoverJumpTables`(flow.hh:138, flow.cc:1427)를 호출하는 구동 루프 -- Go 측
  `ActionSwitchNorm`(coreaction.go:3157)은 이미 등록된 JumpTable을 소비만 한다. (2) 실패 폴백
  `FlowInfo::truncateIndirectJump`(flow.cc:727, BRANCHIND -> CALLIND + artificial return) 미포팅 --
  `goto *(...)` vs CALLIND 렌더 차이의 직접 원인. (3) `goto label_missing`은 (1)/(2)의 파생 증상. (4)
  `&__ImageBase` 부재는 단일 `.text` 하네스의 loader/harness 계층 갭(별개, 저우선).
- **핵심**: 이 jump table은 `.rdata`의 `&__ImageBase` 상대 오프셋이라 relocation을 요구하는데, 단일
  `.text` 블롭 하네스에는 image base/reloc/.rdata가 없다. **Ghidra 자신도** headless로 이 테이블 복구에
  실패해 동일 폴백(`truncateIndirectJump`, fail_normal)을 탄다 -- parity 타깃은 완전한 switch 복구가
  아니라 CALLIND 폴백 자체다.
- **breadth 우선순위(ROI)**: (1) `truncateIndirectJump` 폴백[저비용, 즉시 parity] -> (2)
  multi-section+reloc 로더[테이블 실복구 전제조건] -> (3) struct 타입 복구[저우선]. breadth는 다세션
  규모.
- 게이트: tree 10/10, x64 corpus 7/8 무회귀, `go build` + `go test ./pkg/...` 그린. `breadth.obj`는
  gitignore(`*.obj`).

## 다음 작업 (우선순위)
H8-debt-2(본체+Step3)는 완전히 끝났다. 남은 작업을 우선순위 순으로 진행한다.

### (a) dispatch 수렴 -- truncateIndirectJump DONE, 다음 = IOP-space 인코딩 + reloc 로더
`FlowInfo::truncateIndirectJump`(flow.cc:727) 포팅은 **완료됐다**(H-dispatch Component 1, master
`a02b1a6` -- 신규 `pkg/pcode/flow_jumptable.go` +222, `RecoverJumpTables` 구동 드라이버가
`bridge.Build`에 배선됨). dispatch golden의 raw `goto *(...)`는 제거됐고 BRANCHIND -> CALLIND +
artificial return 강등은 pcode 레벨에서 정확하다. **그러나 RENDER는 더 나빠졌다**:
`undefined4 dispatch(void){...(*0)();return 1;}`(golden은 `undefined8 dispatch(long) {
uVar1=(*(code*)(...))(); return uVar1; }`) -- CALLIND 타깃(RAX) 유실이 원인. 남은 블로커 ROI 순:
1. **IOP-space 인코딩 포팅** [foundational, 최우선] -- INDIRECT op의 input(1)이 zero-const 스텁이라
   `Heritage`의 "INDIRECT는 cause op과 동시 발생" rename(heritage.cc:2506-2517)이 CALLIND 타깃(RAX)을
   식별 못 함. project-wide 갭이라 dispatch 전용 패치로 안 닫힌다. Go 대상: `pkg/pcode/heritage.go`,
   `pkg/pcode/double.go`/`constseq.go`/`funcdata.go`.
2. **reloc/COFF 로더** -- 단일 `.text` 하네스가 relocation이 없어 주소 상수가 raw literal
   (`&__ImageBase`/`0x5b40`)로 남는다. `dumpbin` 확인: `.text` REL32(`&__ImageBase` 기준) + 8개
   ADDR32NB(RVA 테이블). ghidra-ref는 Decompiler C++뿐이라 COFF/PE 로더는 원본이 없음(MS spec 기반
   직접 포팅, Go `debug/pe` 활용). Go 대상: `pkg/loader/`(신규 reloc 파싱).
3. **printc 타입명** -- `uint`/`undefined8` 렌더 차이(하위 우선, 위 2개 이후 재평가). Go 대상:
   `pkg/pcode/printc.go`.
- **핵심**: 위 3갈래를 전부 닫아도 도달하는 것은 "정확한 CALLIND 폴백 렌더"다 -- 진짜 switch 복구가
  아니다(bare `.obj`는 Ghidra 자신도 복구 실패하는 입력). 진짜 switch 복구는 아래 (a-2) track B.
- **C++ 참조**: `heritage.cc:2506-2517`(INDIRECT same-time rename).
- **성공 기준**: `X64_BREADTH=1 TestX64BreadthGoldenMap` dispatch MATCH(2/3 -> 3/3) + `TREE_MAP=1
  TestTreeFullGoldenMap` 10/10 무회귀 + `X64_CORPUS=1 TestX64CorpusGoldenMap` 7/8 무회귀.
- 상세: `testdata/x64_breadth/README.md`, `docs/STATUS.md` 미시작 (a), CHANGELOG 2026-07-03
  "H-dispatch Component 1".

### (a-2) [신규 우선] track B -- 실제 switch 복구 실검증 (full-link x64 .exe 코퍼스)
사용자와 합의된 전략(2026-07-03): "Ghidra보다 나은 switch 복구"는 **Ghidra 자신도 switch를 성공 복구
하는 입력**으로 골든을 만들어 그 골든과 MATCH해야 검증 가능하다 -- bare `.obj`는 비교 대상이 못 된다.
(a) CALLIND 폴백 완전 렌더보다 이쪽이 진짜 다음 메인 타깃이며, 방치된 `pkg/pcode/jumptable.go`
(1671줄, H-dispatch Component 1의 `RecoverJumpTables` 성공 경로 포함)를 실전 검증하는 것도 겸한다.
- **필요 작업**: (1) `pkg/loader/pe.go` PE32+/multi-section 확장 (2) MSVC 링커로 실제 `.exe` 생성
  (다중 섹션+import table+reloc) (3) Ghidra 12 headless 신규 골든 생성 (4)
  `recoverJumpTable`(funcdata_block.cc:639) 성공 경로 실검증 (5) `ActionSwitchNorm`(coreaction.go:3157)
  + printc switch(`case`/`default`) 렌더 확인.
- **C++ 참조**: `flow.cc:1427`(recoverJumpTables), `funcdata_block.cc:639`(recoverJumpTable),
  `jumptable.cc`(JumpTable::recoverAddresses).
- **성공 기준**: 신규 track B 코퍼스에서 switch case golden MATCH + 기존
  `TREE_MAP=1`/`X64_CORPUS=1`/`X64_BREADTH=1` 전부 무회귀.
- 상세: `docs/STATUS.md` 미시작 (a-2).

### (b) process 잔여 3갭 -- deep-debt, 별도 세션 (breadth 이후)
gap2/gap3/gap4는 return-recovery/type-snapshot/merge/structuring 파이프라인 재작업으로 수렴하는 트리 액션
내부 부채다. **H8-debt-2 완료로는 자동 해소되지 않는다(실측 확인)**. 독립 세션으로 gap2/gap3/gap4를
개별 시도하지 말 것(gap2 SEXT 가드 시도가 gcd 회귀로 기각된 전례 있음) -- 파이프라인 재작업으로 묶어서
접근.
- **gap2(64비트 signed division 반환 렌더링)**: golden `ulonglong ...(longlong)local_c/(longlong)local_10 &
  0xffffffff`. 진짜 근본(구현 시도는 미커밋, gcd 회귀로 기각) = 과축소 주체 `RuleSubCommute`
  (rules_ext.go:225). Go의 `RuleSubvarZext`(return narrowing)가 ZEXT를 RuleSubCommute의 overlap 체크 전에
  제거해 순서가 이탈한다. 충실 SEXT 가드 포팅 시 gcd가 회귀함(packed .sla가 dividend를 INT_OR로 인코딩하는데
  Ghidra는 INT_SEXT로 처리 -- `RuleOrSextForm` 미정규화).
- **gap3(단축평가 `&&` 조건 구조화)**: 진짜 근본은 RuleBlockOr/comma가 아니다(RuleBlockOr는 발화하나 이미
  붕괴된 그래프 위에서 오극성으로 발화, condexe는 process에서 애초 미발화). 실체 = 비대칭 clamp의
  단일-스토어 블록(v=hi)이 sibling count 블록으로 오폴딩(블록구조화 collapse 또는 RuleStoreVarnode heritage
  결함).
- **gap4(undefined 타입 누수)**: 진짜 근본은 스냅샷 타이밍이 아니다. MSVC eax 스크래치 임시가 스택-로컬로
  미접힘(Merge/copyprop parity 갭).
- **C++ 참조**: `coreaction.cc`(ActionReturnRecovery), `merge.cc`(HighVariable 병합), block 구조화 rule군
  (`ruleaction.cc` 계열, RuleBlockOr/RuleSubCommute/RuleSubvarZext -- Go 측 rules_ext.go:225 대응).
- **수정 대상 Go 파일**: `pkg/pcode/rules_ext.go`(RuleSubCommute/RuleSubvarZext 순서), `pkg/pcode/
  coreaction.go`(ActionReturnRecovery), `pkg/pcode/merge.go`, 구조화 rule(`pkg/pcode/rules_*.go`,
  `block_*.go`).
- **성공 기준**: `X64_CORPUS=1 TestX64CorpusGoldenMap`에서 process MATCH(7/8 -> 8/8) + `TREE_MAP=1
  TestTreeFullGoldenMap` 10/10 무회귀 + production `TestMSVC*` 무회귀.

## known-gap (별도, 낮은 우선순위)
- const space가 여전히 0xFFFF(Ghidra는 const이 loc_tree 맨 앞 index 0, 우리는 맨 뒤) -- 현 corpus 무해(실측),
  const=0 이관은 별도 세션.
- `HighVariable::remove`(variable.cc:515) 미포팅 = 인스턴스 수명 갭의 근본. `printc.go collectSymbols`의
  live-제한(highNameRepresentativeLive)이 국소 보정이고, 완전 해소는 remove 포팅(후속 과제).
- breadth `&__ImageBase`/multi-section/reloc 로더 갭(위 (a)-3) -- jump table 실복구의 전제조건, 별도
  세션 규모.

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (7/8 유지/증가)
- `X64_BREADTH=1 go test ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (2/3 유지/증가, 신규)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam'`
- `go test ./...` (symbols_test 3건 missing-.exe 무시)

## 방법론
- A/B 실측이 가설을 반증할 수 있다 -- 포팅 자체가 충실하면 유지하고, 반증된 가설만 따로 폐기한다. green이어도
  unfaithful이면 기각. 고위험 변경은 worktree + env 플래그 A/B 토글 -> parity 확인 후 플립 -> 플래그 제거 순.
- 배선/경로 교체 작업은 "같은 서브시스템을 건드린다"와 "그 서브시스템 내부 버그를 고친다"를 구분해서
  예측할 것(H8-debt-2가 process를 자동 해소한다는 예측이 실측으로 반증된 전례, 상세 CHANGELOG 참고).
- breadth 디스커버리처럼 새 코퍼스를 만들 때는 **Ghidra 자신의 headless 출력과 대조**해 parity 타깃이
  진짜 무엇인지 먼저 확정할 것(dispatch: Ghidra도 테이블 복구에 실패하므로 목표는 완전 복구가 아니라
  동일 폴백 재현).

## 참고 문서
- `docs/STATUS.md`(미시작 전문 + 다음 작업 우선순위 (a)/(b)), `docs/CHANGELOG.md`(2026-07-03 항목들),
  메모리 `project_gosleigh`.
- C++: `flow.cc:727`(FlowInfo::truncateIndirectJump), `flow.cc:799`/`flow.hh:138`/`flow.cc:1427`
  (FlowInfo::recoverJumpTables 구동 루프), `coreaction.cc`(ActionDatabase::universalAction,
  ActionReturnRecovery), `merge.cc`(HighVariable 병합).
- Go: `pkg/bridge/decompile.go`(Decompile, 트리 배선), `pkg/bridge/bridge.go`(Build, cspec/EntryPoint 계약),
  `pkg/pcode/jumptable.go`(JumpTable 머신러리, 구동 드라이버 신규 필요), `pkg/pcode/rules_ext.go`
  (RuleSubCommute:225).
