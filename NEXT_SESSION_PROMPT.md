# 다음 세션 프롬프트 (2026-07-03 작성, master `80a28d1`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다.**

## 현재 상태 (master `80a28d1`, 전 패키지 그린, origin 푸시됨)
- **미션 #1 게이트 + H8-debt-2 완전 종료**: production `bridge.Decompile`이 universal-action 트리 경로로
  완전히 수렴(Step1+2+3, master `eadd9c0`/`accd8a9`). bespoke `ActionStackPtrFlow`는 삭제됨.
- **H-dispatch Component 1 완료(master `a02b1a6`)**: `FlowInfo::truncateIndirectJump` 충실 포팅.
  `RecoverJumpTables` 드라이버가 jump-table 복구를 먼저 시도하고 실패 시에만 BRANCHIND를 CALLIND +
  artificial return으로 강등. dispatch golden의 raw `goto *(...)`는 제거됐으나 RENDER는 여전히
  `(*0)()`(IOP-space 인코딩 project-wide 미포팅 -- 아래 (a) 참고).
- **신규: track B -- 실제 switch 복구 (코퍼스+로더+엔진 완성, 파이프라인 통합만 남음)**. 이번 세션에
  4단계를 랜딩했다(커밋 체인 `a02b1a6` -> `9e6f7b9` -> `6e5d9a7` -> `bc9b936` -> `6bba62a` -> `80a28d1`):
  - **(a) 실 switch .exe 코퍼스(`6e5d9a7`)**: `testdata/x64_switch/` -- freestanding x64 PE32+ `.exe`
    (dense 0..7 switch). **Ghidra 자신이 이 입력에서 실제로 switch{case 0..7}로 복구함을 골든으로 확인**
    (bare `.obj` breadth 코퍼스와 달리 이건 Ghidra도 성공하는 입력).
  - **(b) B1 PE32+ 섹션 VMA 로더(`bc9b936`)**: `pkg/loader/pe.go` PE32+ 지원(OH32/OH64 분기) +
    `LoadPESections` + `EngineBuilder.Sections`(VMA 매핑, sparse image map). switch.exe 로드 +
    end-to-end 디컴파일 완주(단 MISMATCH=CALLIND 폴백, jump-table 복구가 아직 스텁이라 예상된 결과).
  - **(c) B2 phase1 emulator+circleRange wiring+이미지 read 훅(`6bba62a`)**: 신규 `emulate.go`
    (EmulatePcodeOp) + circleRange를 jumptable의 RawCircleRange 스텁 대신 배선 + `Funcdata.imageReader`
    훅(`bridge.Build`<-`engine.LoadImageBytes`<-`backend.LoadInstructionBytes`). 무회귀 근거:
    `JumpBasic.RecoverModel`이 여전히 false 반환 -> dormant.
  - **(d) B2 phase2 JumpBasic 모델 복구 엔진 완성(`80a28d1`)**: 신규 `jumptable_recover.go`(634줄) --
    `findDeterminingVarnodes`/`analyzeGuards`/`calcRange`/`RecoverModel`/`BuildAddresses` 등 실체화.
    **손수 구성한 heritage'd fixture에서 실 `switch.exe` 바이트로 8개 case 타깃 복구 검증 완료**
    (`0x140001039..0x14000109c`, 전부 `.text` 내 실제 case body). **엔진 자체는 완성** -- 남은 것은
    파이프라인 통합(phase3)과 라벨/폴드 렌더(phase4)뿐.
  - 상세: CHANGELOG 2026-07-03 "track B" 항목, `docs/STATUS.md` 미시작 (a-2).
- 트리 전체 골든 맵 **10/10** byte-identical(`TestTreeFullGoldenMap`, TREE_MAP=1) 무회귀.
- x64 corpus(기존 8함수) **7/8** MATCH(`TestX64CorpusGoldenMap`, X64_CORPUS=1) 무회귀. process만 잔여
  (별개 deep-debt, 아래 (b) 참고).
- x64 breadth corpus(struct/2D/switch) **2/3** MATCH(`TestX64BreadthGoldenMap`, X64_BREADTH=1) 무회귀:
  dist_sq/sum2d MATCH, dispatch(단일 `.text` obj -- Ghidra 자신도 복구 실패하는 입력)는 여전히 CALLIND
  폴백 렌더 갭.
- production `TestMSVC_{CountedLoop,SumList,AbsVal,Classify2,Gcd}` 5/5 byte-identical, `TestAARCH64`/
  `TestX8664`/`TestX64RegParam`/`TestPELoader`/`TestX86PEDecompile` 전부 pass. `go test ./...` 클린
  (pkg/loader symbols_test 3건 missing-.exe 사전실패는 무시 -- untracked fixture).

## 이번 세션 완료 (건드리지 말 것, 충실+검증완료)
직전 세션(H-dispatch Component 1, master `a02b1a6`)에 이어 track B(실제 switch 복구)를 착수해 코퍼스부터
엔진까지 랜딩했다.

**(a) 실 switch .exe 코퍼스 (master `6e5d9a7`)**
- `testdata/x64_switch/` 신설 -- freestanding x64 PE32+ `.exe`(dense 0..7 switch, import 0,
  `/NODEFAULTLIB /ENTRY:entry`). 대상 함수 `op_switch`(FUN_140001000, VMA `0x140001000`), imageBase
  `0x140000000`, `.text` RVA `0x1000`, jump table은 `.text` 내부 `0x10B8`. **Ghidra가 실제로
  `switch{case 0..7}`로 복구함을 골든으로 확인**(`x64_switch_goldens.json`). exe/obj는
  gitignore(`build.py`로 재생성 -- 다음 세션에서 이 코퍼스를 쓰려면 먼저 재빌드해야 함).

**(b) B1: PE32+ 섹션 VMA 로더 (master `bc9b936`)**
- `pkg/loader/pe.go`에 PE32+ 지원(`peImageBase` OH32/OH64 분기 + `PESection{Name,VMA,Bytes}` +
  `LoadPESections`), 기존 `LoadPE32*` API 무수정. `EngineBuilder.Sections` + Step6b가 섹션을
  `backend.SetInstructionBytes`로 VMA 매핑. 신규 `x64_switch_diag_test.go`(X64_SWITCH=1, 코퍼스 부재
  시 skip). 결과: switch.exe 로드+end-to-end 디컴파일 완주, 단 MISMATCH(CALLIND 폴백 렌더, jump-table
  복구가 아직 스텁이라 예상된 결과).

**(c) B2 phase1: emulator + circleRange wiring + 이미지 read 훅 (master `6bba62a`)**
- 신규 `emulate.go`(EmulatePcodeOp) + circleRange를 jumptable의 RawCircleRange 스텁 대신 배선 +
  `Funcdata.imageReader` 훅(이전엔 `pkg/pcode`에 이미지 read 경로가 전혀 없었음) + evalBinary
  outSize/shift/SUBPIECE 확장. 단위테스트: range `[0,8)` 8개 열거 + `emulatePath` 값=3 -> 실
  switch.exe RVA read -> case 3 타깃 산출. 무회귀 근거: `JumpBasic.RecoverModel`이 여전히 false 반환
  -> dormant.

**(d) B2 phase2: JumpBasic 모델 복구 엔진 완성 (master `80a28d1`, origin 푸시됨)**
- 신규 `jumptable_recover.go`(634줄) -- `findDeterminingVarnodes`(jumptable.cc:554) +
  `analyzeGuards`(:1061) + `calcRange`(:1135) + `findSmallestNormal`(:1180) + `findNormalized`(:1221) +
  `markFoldableGuards`(:1256) + guardQuasiCopy/valueMatch/oneOffMatch 등. `JumpBasic.RecoverModel`
  (:1435)/`BuildAddresses`(:1451) 실체화, `GuardRecord`가 실 circleRange 사용. `PathMeld.meld` 등은
  스텁 유지(이 코퍼스는 단일 path+단일 guard라 미도달, 코드에 명시). **엔진 검증**: 손수 구성한
  heritage'd fixture(SSA 체인 `selector->SEXT->MULT->ADD->LOAD->ZEXT->ADD->BRANCHIND`+guard)에 실
  switch.exe 바이트를 먹여 `RecoverAddresses`가 8개 case 타깃을 정확히 복구 + sanityCheck 통과까지
  확인. **엔진 자체는 완성** -- 남은 건 파이프라인 통합(phase3)+렌더(phase4).
- 게이트(모든 단계): `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1 TestX64CorpusGoldenMap`
  7/8, `X64_BREADTH=1 TestX64BreadthGoldenMap` 2/3(dispatch MISMATCH=CALLIND 폴백 -- phase3 이전이라
  정상), production `TestMSVC*`/`TestPELoader`/`TestX86PEDecompile` PASS 무회귀.

## 다음 작업 (우선순위)
track B의 코퍼스/로더/엔진은 끝났다. **최우선 = track B phase3(엔진을 실 파이프라인에 통합)**, 그
다음 phase4(렌더 완성), 그 후에야 (a)/(b)가 순서상 다음이다.

### (a-2) [최우선] track B phase3 -- switch 복구 엔진을 실 CFG/파이프라인에 통합
`X64_SWITCH=1` 하네스로 `switch.exe`의 `op_switch`를 디컴파일하면 여전히 CALLIND 폴백(`(*0)()`)으로
떨어진다 -- `RecoverJumpTables` 드라이버가 pre-heritage raw BRANCHIND 위에서 실행돼
`findDeterminingVarnodes`가 걸 SSA 체인이 없기 때문(엔진 검증은 fixture로 체인을 손으로 만들어 우회
했다).
- **설계 결정(확정, 2026-07-03)**: **(A) 채택 = Ghidra식 partial Funcdata + 자체 heritage.** (B)
  "복구를 main heritage 이후로 이동"은 **기각**(구조적으로 깨짐 -- MaxInstructions:200 선형 스캔이
  BRANCHIND에서 끊겨 case body가 decode조차 안 됨 + 틀린 CFG 위 SSA numbering 어긋남 + double
  heritage가 pass order 이탈).
  **Ghidra 실제 메커니즘**: `FlowInfo::generateOps`(flow.cc:785, main heritage 이전) 도중 별도 partial
  `Funcdata`(`recoverJumpTables`, flow.cc:1437)를 만들어 `stageJumpTable`(funcdata_block.cc:491)이
  `truncatedFlow`(funcdata_op.cc:792)로 raw pcode 클론+generateBlocks하고, "jumptable"
  액션그룹(ActionHeritage 포함, coreaction.cc:5445/5503)을 그 partial에만 perform해 **partial만
  SSA화**한 뒤 `recoverAddresses(partial)` 호출. 성공하면 `generateOps` 복귀해 `newAddress`(:807)+
  `fallthru`(:809)로 case body decode, `collectEdges`(:933-946)가 switch edge를 CFG에 삽입. main
  decompile 중 `ActionSwitchNorm`이 **완전 heritage된 main fd 위에서 recoverModel 재실행**+
  `switchOver`(jumptable.cc:2545).
  Go 지름길: op 클론 대신 기존 `InstructionTranslation` 레코드로 partial을 `addInstructionOps` 재생성.
- **회귀 격리**: partial은 별도 Funcdata라 main heritage 1회 불변(non-switch byte-identical).
  `addCFGEdges`의 BRANCHIND 분기는 `findJumpTable()!=nil`일 때만 새 경로(테이블 없으면 오늘과 동일).
- **스테이징(3a+3b 한 푸시 권고, 3c는 후속)**:
  1. **3a [최고위험, 우선 격리]**: partial 빌드+jumptable그룹 heritage+복구를 라이브 switch.exe 경로에
     붙여 **8-entry 테이블 복구를 assert만**(CFG/출력 미변경).
  2. **3b**: `Funcdata.Build`가 partial 결과로 재진입 -- case body 실제 decode
     (`discoverBlockStarts`/`addCFGEdges` BRANCHIND 처리) -- 8 case 블록+9 edge+dominator 확인.
  3. **3c**: `installSwitchDefaults`(`block_actions.go:68`, 스텁) 실구현 + `switchOver`.
  4. **phase4(후속)**: `recoverLabels`/`foldInNormalization`/`foldInGuards` -> `ActionSwitchNorm` 최종
     -> `x64_switch_goldens.json` byte-identical MATCH.
- **C++ 참조**: `flow.cc:785`(generateOps)/`:1437`(recoverJumpTables)/`:807`(newAddress)/`:809`
  (fallthru)/`:933-946`(collectEdges), `funcdata_block.cc:491`(stageJumpTable), `funcdata_op.cc:792`
  (truncatedFlow), `coreaction.cc:5445`/`:5503`(jumptable 액션그룹), `jumptable.cc:2545`(switchOver).
- **수정 대상 Go 파일**: `pkg/bridge/bridge.go`(collectInstructions:421/discoverBlockStarts:609/
  addCFGEdges:718/Build 순서), `pkg/pcode/flow_jumptable.go`(recoverJumpTable가 partial 받도록),
  `pkg/pcode/block_actions.go`(installSwitchDefaults:68).
- **성공 기준**: `X64_SWITCH=1 go test ./pkg/loader/ -run TestX64SwitchGoldenMap`(이름은 구현 세션
  재량)에서 op_switch MATCH + `TREE_MAP=1` 10/10 무회귀 + `X64_CORPUS=1` 7/8 무회귀 + `X64_BREADTH=1`
  2/3 무회귀.
- 상세: `docs/STATUS.md` 미시작 (a-2), CHANGELOG 2026-07-03 "track B".

### (a) [차순위, phase3 이후] dispatch 수렴 -- IOP-space 인코딩 + reloc 로더 + printc 타입명
`FlowInfo::truncateIndirectJump`(flow.cc:727) 포팅은 완료됐다(H-dispatch Component 1, master
`a02b1a6`). dispatch golden(단일 `.text` obj, Ghidra 자신도 복구 실패하는 입력)의 raw `goto *(...)`는
제거됐으나 완전한 렌더까지는 아니다: `undefined4 dispatch(void){...(*0)();return 1;}`(golden은
`undefined8 dispatch(long) { uVar1=(*(code*)(...))(); return uVar1; }`) -- CALLIND 타깃(RAX) 유실이
원인. 블로커 ROI 순:
1. **IOP-space 인코딩 포팅** [foundational] -- INDIRECT op의 input(1)이 zero-const 스텁이라
   `Heritage`의 "INDIRECT는 cause op과 동시 발생" rename(heritage.cc:2506-2517)이 CALLIND 타깃(RAX)을
   식별 못 함. project-wide 갭이라 dispatch 전용 패치로 안 닫힌다. Go 대상: `pkg/pcode/heritage.go`,
   `pkg/pcode/double.go`/`constseq.go`/`funcdata.go`.
2. **reloc/COFF 로더** -- 단일 `.text` 하네스가 relocation이 없어 주소 상수가 raw literal로 남는다.
   `dumpbin` 확인: `.text` REL32(`&__ImageBase` 기준) + 8개 ADDR32NB(RVA 테이블). ghidra-ref는
   Decompiler C++뿐이라 COFF/PE 로더는 원본이 없음(MS spec 기반 직접 포팅). Go 대상: `pkg/loader/`
   (신규 reloc 파싱 -- track B의 PE32+ 로더와는 별개, reloc 섹션 파싱이 필요).
3. **printc 타입명** -- `uint`/`undefined8` 렌더 차이(하위 우선). Go 대상: `pkg/pcode/printc.go`.
- **참고**: track B phase3/4가 끝나면 이 코퍼스(단일 `.text` obj) 자체의 parity 타깃이 "CALLIND 폴백
  정확 렌더"임은 변하지 않는다 -- 두 트랙은 서로 다른 입력(코퍼스 없는 obj vs 링크된 .exe)에 대한
  별개 목표다.
- **C++ 참조**: `heritage.cc:2506-2517`(INDIRECT same-time rename).
- **성공 기준**: `X64_BREADTH=1 TestX64BreadthGoldenMap` dispatch MATCH(2/3 -> 3/3) + `TREE_MAP=1` 10/10
  무회귀 + `X64_CORPUS=1` 7/8 무회귀.
- 상세: `testdata/x64_breadth/README.md`, `docs/STATUS.md` 미시작 (a).

### (b) process 잔여 3갭 -- deep-debt, 별도 세션 (track B/breadth 이후)
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
- breadth `&__ImageBase`/reloc 로더 갭(위 (a)-2) -- bare `.obj` dispatch 렌더의 전제조건, 별도 세션 규모.
- track B PathMeld.meld/internalIntersect/checkUnrolledGuard 스텁 -- 이 코퍼스는 단일 path+단일 guard라
  미도달, 여러 path/guard가 있는 switch가 나오면 채워야 함(track B 완주 이후 재평가).

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (7/8 유지/증가)
- `X64_BREADTH=1 go test ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (2/3 유지/증가)
- `X64_SWITCH=1 go test ./pkg/loader/ -run TestX64Switch -v` (track B, 코퍼스가 gitignore라 `testdata/
  x64_switch/build.py` 재실행 필요 -- 부재 시 skip)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam|TestPELoader|TestX86PEDecompile'`
- `go test ./...` (symbols_test 3건 missing-.exe 무시)

## 방법론
- A/B 실측이 가설을 반증할 수 있다 -- 포팅 자체가 충실하면 유지하고, 반증된 가설만 따로 폐기한다. green이어도
  unfaithful이면 기각. 고위험 변경은 worktree + env 플래그 A/B 토글 -> parity 확인 후 플립 -> 플래그 제거 순.
- 배선/경로 교체 작업은 "같은 서브시스템을 건드린다"와 "그 서브시스템 내부 버그를 고친다"를 구분해서
  예측할 것(H8-debt-2가 process를 자동 해소한다는 예측이 실측으로 반증된 전례, 상세 CHANGELOG 참고).
- breadth/track B처럼 새 코퍼스를 만들 때는 **Ghidra 자신의 headless 출력과 대조**해 parity 타깃이 진짜
  무엇인지 먼저 확정할 것(breadth dispatch: Ghidra도 테이블 복구에 실패하므로 목표는 CALLIND 폴백 재현;
  track B switch.exe: Ghidra가 성공 복구하므로 목표는 진짜 switch case 렌더).
- 다컴포넌트/다세션 규모 작업(track B 같은)은 스코핑 조사 -> 단계별 스테이징(각 단계 무회귀 게이트) ->
  최대 난관 단계는 별도 격리(track B의 heritage-on-partial=3a)로 진행할 것.

## 참고 문서
- `docs/STATUS.md`(미시작 전문 + 다음 작업 우선순위 (a-2)/(a)/(b)), `docs/CHANGELOG.md`(2026-07-03
  항목들, "track B" + "H-dispatch Component 1"), 메모리 `project_gosleigh`.
- C++: `flow.cc:785`(generateOps)/`:1427`/`:1437`(recoverJumpTables)/`:727`(truncateIndirectJump),
  `jumptable.cc:554`(findDeterminingVarnodes)/`:1435`(RecoverModel)/`:2545`(switchOver),
  `funcdata_block.cc:491`(stageJumpTable)/`:639`(recoverJumpTable), `coreaction.cc`
  (ActionDatabase::universalAction, ActionReturnRecovery), `merge.cc`(HighVariable 병합).
- Go: `pkg/bridge/decompile.go`(Decompile, 트리 배선), `pkg/bridge/bridge.go`(Build, cspec/EntryPoint
  계약 + collectInstructions/discoverBlockStarts/addCFGEdges), `pkg/pcode/flow_jumptable.go`
  (RecoverJumpTables 드라이버), `pkg/pcode/jumptable_recover.go`(B2 phase2 엔진), `pkg/pcode/emulate.go`
  (B2 phase1 emulator), `pkg/pcode/block_actions.go`(installSwitchDefaults 스텁), `pkg/loader/pe.go`
  (PE32+ 로더), `pkg/pcode/rules_ext.go`(RuleSubCommute:225).
