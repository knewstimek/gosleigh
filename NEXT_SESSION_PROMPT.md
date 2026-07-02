# 다음 세션 프롬프트 (2026-07-03 작성, master `c50ced5`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** `ghidra-ref/`의 동작을 재해석하지 말고 원본 C++를
다시 읽어 그대로 포팅한다. **golden이 통과해도 C++과 다르게 동작하면(unfaithful) 되돌린다.**

## 현재 상태 (master `c50ced5`, 전 패키지 그린, origin 푸시됨)
- **미션 #1 게이트 + H8-debt-2 완전 종료**: production `bridge.Decompile`이 universal-action 트리 경로로
  완전히 수렴(Step1+2+3, master `eadd9c0`/`accd8a9`). bespoke `ActionStackPtrFlow`는 삭제됨.
- **H-dispatch Component 1 완료(master `a02b1a6`)**: `FlowInfo::truncateIndirectJump` 충실 포팅.
  `RecoverJumpTables` 드라이버가 jump-table 복구를 먼저 시도하고 실패 시에만 BRANCHIND를 CALLIND +
  artificial return으로 강등.
- **track B 완성(코퍼스 -> 로더 -> 엔진 -> 파이프라인 통합 -> 렌더, 전 단계 origin 푸시됨)**: 방치돼
  있던 `pkg/pcode/jumptable.go`(1671줄, `EmulatePcodeOp`/`CircleRange`/`JumpBasic` 전부 스텁이던
  상태)를 실동작시켜 실 링크된 x64 `.exe`에서 Ghidra와 동일한 `switch(param_1){case 0:...break;
  default:...}` 구조를 복구한다. 이번 세션(phase3a `f137921` -> phase3b `e56439e` -> phase3c
  `528c116` -> phase4 `c50ced5`)에 엔진을 실 CFG/파이프라인에 통합하고 라벨/폴드 렌더까지 완주했다.
  **남은 diff는 switch 고유 갭이 아니라 (B) 공통 type-model deep-debt(uint/byte 단축타입명 + `uVar1`
  return-split/merge, x64 corpus `process`와 동일 class)뿐이다.** 상세는 아래 "이번 세션 완료" +
  CHANGELOG 2026-07-03 "track B 완성".
- 트리 전체 골든 맵 **10/10** byte-identical(`TestTreeFullGoldenMap`, TREE_MAP=1) 무회귀.
- x64 corpus(기존 8함수) **7/8** MATCH(`TestX64CorpusGoldenMap`, X64_CORPUS=1) 무회귀. process만 잔여
  (별개 deep-debt, 아래 (b) 참고 -- (a-2)의 type-model 갭과 동일 축).
- x64 breadth corpus(struct/2D/switch) **2/3** MATCH(`TestX64BreadthGoldenMap`, X64_BREADTH=1) 무회귀:
  dist_sq/sum2d MATCH, dispatch(단일 `.text` obj, relocation 없음)는 여전히 CALLIND 폴백 렌더 갭 --
  track B의 jumptable 엔진 자체는 이제 실동작하지만, breadth corpus는 raw `.obj`라 relocation이 없어
  절대주소를 계산 못 하는 것이 확정된 근본(아래 (a) 참고).
- x64 switch 코퍼스 `op_switch` 구조 MATCH(`TestX64SwitchGoldenMap`, X64_SWITCH=1) -- byte-MATCH는
  아직(위 type-model 갭), 구조(switch/case/break/default)는 골든과 일치.
- production `TestMSVC_{CountedLoop,SumList,AbsVal,Classify2,Gcd}` 5/5 byte-identical, `TestAARCH64`/
  `TestX8664`/`TestX64RegParam`/`TestPELoader`/`TestX86PEDecompile` 전부 pass. `go test ./...` 클린
  (pkg/loader symbols_test 3건 missing-.exe 사전실패는 무시 -- untracked fixture).

## 이번 세션 완료 (건드리지 말 것, 충실+검증완료)
직전 세션(B2 phase1/phase2, master `80a28d1`)에서 완성된 JumpBasic 모델 복구 엔진을 실 함수
디컴파일 파이프라인에 통합해(phase3) 라벨/폴드 렌더까지(phase4) 완주했다. 커밋 체인: 3a `f137921` ->
3b `e56439e` -> 3c `528c116` -> phase4 `c50ced5`(전부 origin 푸시됨).

**(a) phase3a: partial Funcdata + 자체 heritage로 실 바이트 8주소 복구 (master `f137921`)**
- 신규 `pkg/bridge/partial.go` `BuildJumpTablePartial`(라이브 `Build` 헬퍼 `collectInstructions`/
  `addInstructionOps`/`addCFGEdges`/`buildDefaultModel` 재사용, `RecoverJumpTables`만 생략 --
  `truncatedFlow`(funcdata_op.cc:792)의 Go 등가물, 기존 `InstructionTranslation` 레코드가 곧 raw
  ops라 op 클론이 불필요). `db.SetCurrent("jumptable").Perform(partial)`로 partial만 heritage한 뒤
  `RecoverAddresses(partial)` 호출. **실 `switch.exe` 바이트에서 8개 case 타깃
  (`0x140001039..0x14000109c`) 정확 복구 + BRANCHIND target `IsWritten()==true` + `jrange.Size==8`
  확인**(heritage-on-partial 메커니즘이 fixture가 아닌 실 바이트에서 동작함을 증명 -- track B 최대
  난관 해소). 순수 additive(신규 2파일, 기존 파일 무수정) -- 회귀 제로.
- 신규 회귀 가드: `TestX64SwitchPartialHeritageRecovers`.

**(b) phase3b: 라이브 CFG 통합 (master `e56439e`)**
- `bridge.Build`가 `collectInstructions` 직후 블록 빌드 전에 복구를 구동한다(`recoverLiveJumpTables`:
  partial 1개 빌드 + jumptable 액션그룹 heritage 1회 + 각 BRANCHIND `RecoverAddresses` -> map).
  성공하면 `registerRecoveredTables`가 main fd BRANCHIND에 relink + `AddJumpTable`(기존
  `linkJumpTable`이 complete 테이블을 찾아 truncate를 자연 skip) + `collectInstructionsSeeded`로
  8개 case body decode 재진입 + `discoverBlockStarts` seed 추가 + `addCFGEdges` BRANCHIND 케이스로
  8개 edge 삽입.
- **2중 격리 게이트**: `recordsHaveBranchInd`(없으면 드라이버 전체 skip -- pre-3b byte-identical) +
  `len(tables)>0`(미복구면 기존 empty-map truncate 폴백 그대로).
- 검증: `TestX64SwitchCFGIntegration` -- BRANCHIND 생존 + `NumJumpTables==1`(8-entry) + 8개 case
  body decode + out-edge 8 + dominator 정상. 8개 case 연산 전부 렌더(add/sub/mul/xor/or/and/shl/shr)
  + default. 이 시점 GOT는 BRANCHIND `goto *(...)` 생존 + 8개 case body 렌더(switch 라벨 미fold).

**(c) phase3c: switch{case} 구조 렌더 + goto* 완전 소멸 (master `528c116`)**
- 신규 `Funcdata.SwitchOverJumpTables`(flow_jumptable.go, funcdata_block.cc:678, `bridge.Build`에서
  `NumJumpTables>0`일 때 구동, blockByAddr resolver) + `installSwitchDefaults` 실구현
  (block_actions.go, funcdata_block.cc:687, default edge 마킹) + `FlowBlock.SetDefaultSwitch`
  (flowblock.go, block.cc:318) + `addCFGEdges`가 switch 부모 블록에 `BlockFlagSwitchOut` 세팅
  (block.cc:2287 -- **이 플래그가 없어서 기존에 이미 포팅돼 있던 `ActionSwitchNorm`/`SwitchOver`/
  `ruleBlockSwitch`/`emitSwitchBlock`이 발화하지 못하고 있었다**) + `printc` `emitSwitchBlock`의
  `case %d::` 이중콜론 렌더 버그 수정.
- 결과: `switch((ull)*(uint*)(...)+0x140000000){case 0:...case 7:}` + switch 밖 default -- 구조에
  도달(byte-MATCH는 아직).

**(d) phase4: fold machinery로 switch-고유 잔차 전부 닫힘 (master `c50ced5`)**
- `JumpBasic.FoldInNormalization`(jumptable.cc:1563, BRANCHIND `in(0)`을 unnormalized SwitchVn으로
  교체 -- 주소계산 체인이 dead로 소멸, `renderSwitchSelector`가 `in(0)`을 직접 렌더해
  `switch(param_1)`) + `FoldInGuards`/`foldInOneGuard`(jumptable.cc:1572/1390, guard target을
  `AddBlockToSwitch` + `SetLastAsDefault` + `PushBranch`로 default에 흡수) + `BuildLabels`/
  `backup2Switch`(jumptable.cc:1523/472, `normalvn==switchvn`이라 label 0..7 정확) +
  `FindUnnormalized`/`markModel`/`MarkPaths` + `emitBlockSwitch`의 `break` 렌더(printc.cc:3448,
  `isExit`=out-edge 0인 terminal BRANCH, 마지막 case가 아니면 `break`). 지원:
  `Funcdata.PushBranch`(funcdata_block.cc:403), `BlockBasic.NoInterveningStatement`(block.cc:2712).
- **crux**: `MatchModel` 스텁을 `saveModel` + `RecoverModel(fd)`로 실체화 -- 모델이 partial에서
  복구돼 varnode가 live fd 기준으로 외래이므로 live fd에서 재복구해야 한다(jumptable.cc:2700).
- **최종 GOT**: `switch(param_1){case 0: param_2=param_2+param_3; break; ... case 7: ...; break;
  default: param_2=0xffffffff;} return param_2;` -- switch 구조가 골든과 일치한다.
- **남은 diff = 오직 (B) 공통 type-model deep-debt**: `unsigned int` vs `uint` + `undefined1` vs
  `byte`(전역 typeop 단축타입명) + `param_2` 재사용 vs `uVar1` temp(return-split/merge) + 여분
  `& 0x3f`(RuleAndCollapse) + case7 `(int)` 캐스트(signedness). 이 4개는 x64 corpus `process`
  미MATCH와 동일 class -- switch 고유 갭이 아니다. uint/byte 단축명은 전역 typeop 변경이라 저위험
  조건 미충족 + `uVar1` merge 미해결로 byte-MATCH가 안 되므로 이번 세션엔 미시도(파리티 규율).

**게이트(전 단계)**: `TREE_MAP=1 TestTreeFullGoldenMap` 10/10, `X64_CORPUS=1 TestX64CorpusGoldenMap`
7/8, `X64_BREADTH=1 TestX64BreadthGoldenMap` 2/3, production `TestMSVC*`/`TestAARCH64*`/
`TestX8664*`/`TestX64RegParam*`/`TestPELoader`/`TestX86PEDecompile` 전부 PASS 무회귀. 감독관이 매 커밋
cherry-pick 후 독립 전 매트릭스 재실행 + 핵심 함수 C++ 스팟체크로 검증.

## 다음 작업 (우선순위)
track B(코퍼스 -> 로더 -> 엔진 -> 파이프라인 통합 -> 렌더)는 전부 끝났다. 남은 것은 광범위
type-model/merge deep-debt와 process 3갭(같은 축), breadth dispatch의 reloc 로더 갭이다.

### (a-2) [최우선] (B) 공통 type-model deep-debt -- uint/byte 단축타입명 + uVar1 return-split/merge
track B가 switch 복구 구조를 완성했다(`switch(param_1){case 0:...break; default:...}`까지 골든과
일치). 남은 diff는 switch 고유 갭이 아니라 x64 corpus `process`(아래 (b))와 공유하는 광범위
type-model/merge deep-debt다.
- **현상**: `X64_SWITCH=1`로 `op_switch`를 디컴파일하면 구조는 일치하나 4곳이 byte-MATCH를 막는다:
  1. `unsigned int` vs golden `uint`, `undefined1` vs golden `byte` -- 전역 typeop 단축타입명 렌더
     차이(switch 국소 아님).
  2. `param_2` 재사용 vs golden `uVar1` temp -- return-split/merge 차이(process gap4의 "eax
     스크래치 임시가 스택-로컬로 미접힘"과 동일 class).
  3. 여분 `& 0x3f`(RuleAndCollapse 미발화).
  4. case7 `(int)` 캐스트 누락(signedness).
- **판단**: uint/byte 단축타입명은 전역 typeop 변경이라 단독 시도 시 저위험 조건을 충족하지 못하고,
  `uVar1` merge를 해결하지 않으면 어차피 byte-MATCH에 도달하지 못한다 -- 휴리스틱 금지 규율상 단독
  시도 보류. 아래 (b) process 3갭(특히 gap4 eax 스크래치/merge)과 함께 묶어서 다뤄야 두 코퍼스가
  동시에 MATCH될 가능성이 높다.
- **C++ 참조**: `printlanguage.cc`/`typeop.cc`(단축타입명 렌더), `merge.cc`(HighVariable 병합), 아래
  (b) gap4 C++ 참조와 동일.
- **수정 대상 Go 파일**: `pkg/pcode/printc.go`(typeop 단축명 렌더), `pkg/pcode/merge.go`
  (return-split/merge), `pkg/pcode/rules_*.go`(RuleAndCollapse 등).
- **성공 기준**: `X64_SWITCH=1 go test ./pkg/loader/ -run TestX64SwitchGoldenMap` op_switch MATCH +
  `X64_CORPUS=1 TestX64CorpusGoldenMap` process MATCH(7/8 -> 8/8, 같은 축이라 함께 해소될 가능성) +
  `TREE_MAP=1 TestTreeFullGoldenMap` 10/10 무회귀 + `X64_BREADTH=1 TestX64BreadthGoldenMap` 2/3 무회귀.
- **PathMeld 스텁(별도, 낮은 우선순위)**: `PathMeld.meld`/`internalIntersect`/`checkUnrolledGuard`는
  여전히 스텁이다(이 코퍼스는 단일 path + 단일 guard라 미도달). 여러 path/guard가 있는 switch가
  코퍼스에 추가되면 채워야 한다.

### (a) [차순위] dispatch 수렴 -- IOP-space 인코딩 + reloc 로더 + printc 타입명
`FlowInfo::truncateIndirectJump`(flow.cc:727) 포팅은 완료됐다(H-dispatch Component 1, master
`a02b1a6`). **2026-07-03 재확인(track B 완성 후)**: track B(위 (a-2))가 switch 복구 엔진 자체를
실 CFG/파이프라인에 통합해 실동작함을 실증했다(x64_switch 코퍼스, 링크된 `.exe`, 8-entry table
정확 복구 + `switch{case}` 구조 렌더). breadth의 `dispatch`가 여전히 실패하는 것은 엔진 결함이
아니라 **아래 2번(reloc/COFF 로더 부재)** 하나로 좁혀졌다 -- breadth corpus는 단일 raw `.obj`라
relocation이 전혀 없어 점프테이블 절대주소(`&__ImageBase` 기준)를 계산할 수 없다. track B 코퍼스는
링크된 `.exe`라 이 문제가 없다.
dispatch golden(단일 `.text` obj, Ghidra 자신도 복구 실패하는 입력)의 raw `goto *(...)`는 제거됐으나
완전한 렌더까지는 아니다: `undefined4 dispatch(void){...(*0)();return 1;}`(golden은
`undefined8 dispatch(long) { uVar1=(*(code*)(...))(); return uVar1; }`) -- CALLIND 타깃(RAX)
유실이 원인. 블로커 ROI 순:
1. **IOP-space 인코딩 포팅** [foundational] -- INDIRECT op의 input(1)이 zero-const 스텁이라
   `Heritage`의 "INDIRECT는 cause op과 동시 발생" rename(heritage.cc:2506-2517)이 CALLIND 타깃(RAX)을
   식별 못 함. project-wide 갭이라 dispatch 전용 패치로 안 닫힌다. Go 대상: `pkg/pcode/heritage.go`,
   `pkg/pcode/double.go`/`constseq.go`/`funcdata.go`.
2. **reloc/COFF 로더** -- 단일 `.text` 하네스가 relocation이 없어 주소 상수가 raw literal로 남는다.
   `dumpbin` 확인: `.text` REL32(`&__ImageBase` 기준) + 8개 ADDR32NB(RVA 테이블). ghidra-ref는
   Decompiler C++뿐이라 COFF/PE 로더는 원본이 없음(MS spec 기반 직접 포팅). Go 대상: `pkg/loader/`
   (신규 reloc 파싱 -- track B의 PE32+ 로더와는 별개, reloc 섹션 파싱이 필요).
3. **printc 타입명** -- `uint`/`undefined8` 렌더 차이(하위 우선, 위 (a-2)의 type-model 갭과 합류).
- **C++ 참조**: `heritage.cc:2506-2517`(INDIRECT same-time rename).
- **성공 기준**: `X64_BREADTH=1 TestX64BreadthGoldenMap` dispatch MATCH(2/3 -> 3/3) + `TREE_MAP=1`
  10/10 무회귀 + `X64_CORPUS=1` 7/8 무회귀.
- 상세: `testdata/x64_breadth/README.md`, `docs/STATUS.md` 미시작 (a).

### (b) process 잔여 3갭 -- deep-debt, 별도 세션 (type-model 갭과 함께 묶어서 접근)
gap2/gap3/gap4는 return-recovery/type-snapshot/merge/structuring 파이프라인 재작업으로 수렴하는 트리 액션
내부 부채다. **H8-debt-2 완료로는 자동 해소되지 않는다(실측 확인)**. 독립 세션으로 gap2/gap3/gap4를
개별 시도하지 말 것(gap2 SEXT 가드 시도가 gcd 회귀로 기각된 전례 있음) -- 파이프라인 재작업으로 묶어서
접근. **gap4(eax 스크래치/merge)는 위 (a-2)의 `uVar1` return-split/merge 갭과 동일 축이므로 함께
다루면 두 코퍼스가 동시에 MATCH될 가능성이 높다.**
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
  미접힘(Merge/copyprop parity 갭). 위 (a-2)의 `uVar1` return-split/merge와 동일 축.
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
- breadth `&__ImageBase`/reloc 로더 갭(위 (a)) -- bare `.obj` dispatch 렌더의 전제조건, 별도 세션 규모.
  track B(a-2)의 jumptable 엔진 자체는 실동작 확인됐으므로, reloc 로더만 채우면 dispatch도 실제
  switch 복구로 갈 가능성이 있다(재평가 필요).
- track B `PathMeld.meld`/`internalIntersect`/`checkUnrolledGuard` 스텁 -- 이 코퍼스는 단일 path+단일
  guard라 미도달, 여러 path/guard가 있는 switch가 나오면 채워야 함.

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (7/8 유지/증가)
- `X64_BREADTH=1 go test ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (2/3 유지/증가)
- `X64_SWITCH=1 go test ./pkg/loader/ -run TestX64Switch -v` (track B, 코퍼스가 gitignore라 `testdata/
  x64_switch/build.py` 재실행 필요 -- 부재 시 skip. `TestX64SwitchGoldenMap`/`TestX64SwitchCFGIntegration`/
  `TestX64SwitchPartialHeritageRecovers` 3개 전부 무회귀 확인)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam|TestPELoader|TestX86PEDecompile'`
- `go test ./...` (symbols_test 3건 missing-.exe 무시)

## 방법론
- A/B 실측이 가설을 반증할 수 있다 -- 포팅 자체가 충실하면 유지하고, 반증된 가설만 따로 폐기한다. green이어도
  unfaithful이면 기각. 고위험 변경은 worktree + env 플래그 A/B 토글 -> parity 확인 후 플립 -> 플래그 제거 순.
- 배선/경로 교체 작업은 "같은 서브시스템을 건드린다"와 "그 서브시스템 내부 버그를 고친다"를 구분해서
  예측할 것(H8-debt-2가 process를 자동 해소한다는 예측이 실측으로 반증된 전례, 상세 CHANGELOG 참고).
- breadth/track B처럼 새 코퍼스를 만들 때는 **Ghidra 자신의 headless 출력과 대조**해 parity 타깃이 진짜
  무엇인지 먼저 확정할 것(breadth dispatch: Ghidra도 테이블 복구에 실패하므로 목표는 CALLIND 폴백 재현;
  track B switch.exe: Ghidra가 성공 복구하므로 목표는 진짜 switch case 렌더 -- 이 목표는 track B로 달성됨,
  남은 건 byte-MATCH뿐).
- 다컴포넌트/다세션 규모 작업(track B 같은)은 스코핑 조사 -> 단계별 스테이징(각 단계 무회귀 게이트) ->
  최대 난관 단계는 별도 격리(track B의 heritage-on-partial=3a)로 진행할 것.

## 참고 문서
- `docs/STATUS.md`(미시작 전문 + 다음 작업 우선순위 (a-2)/(a)/(b)), `docs/CHANGELOG.md`(2026-07-03
  항목들, "track B 완성" + 이전 "track B" + "H-dispatch Component 1"), 메모리 `project_gosleigh`.
- C++: `flow.cc:785`(generateOps)/`:1427`/`:1437`(recoverJumpTables)/`:727`(truncateIndirectJump),
  `jumptable.cc:554`(findDeterminingVarnodes)/`:1435`(RecoverModel)/`:1563`(FoldInNormalization)/
  `:1572`(FoldInGuards)/`:1523`(BuildLabels)/`:2545`(switchOver)/`:2700`(matchModel 재복구),
  `funcdata_block.cc:491`(stageJumpTable)/`:639`(recoverJumpTable)/`:678`(switchOverJumpTables)/
  `:687`(installSwitchDefaults)/`:403`(pushBranch), `block.cc:318`(setDefaultSwitch)/`:2287`
  (BlockFlagSwitchOut), `printc.cc:3448`(emitBlockSwitch break), `coreaction.cc`
  (ActionDatabase::universalAction, ActionReturnRecovery), `merge.cc`(HighVariable 병합).
- Go: `pkg/bridge/decompile.go`(Decompile, 트리 배선), `pkg/bridge/bridge.go`(Build, cspec/EntryPoint
  계약 + collectInstructions/discoverBlockStarts/addCFGEdges + recoverLiveJumpTables),
  `pkg/bridge/partial.go`(BuildJumpTablePartial, phase3a), `pkg/pcode/flow_jumptable.go`
  (RecoverJumpTables 드라이버 + SwitchOverJumpTables), `pkg/pcode/jumptable_recover.go`(B2 phase2
  엔진), `pkg/pcode/emulate.go`(B2 phase1 emulator), `pkg/pcode/block_actions.go`
  (installSwitchDefaults), `pkg/loader/pe.go`(PE32+ 로더), `pkg/pcode/printc.go`(typeop 단축명 렌더 +
  emitBlockSwitch), `pkg/pcode/merge.go`(return-split/merge), `pkg/pcode/rules_ext.go`
  (RuleSubCommute:225).
