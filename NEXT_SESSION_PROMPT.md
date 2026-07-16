# 다음 세션 프롬프트 (2026-07-17 세션3 작성, master `db12bfc`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. **green이어도 의미 손상(semantic damage)이면 착지 금지** -- 이번 세션 ReturnSplit이 전 게이트 green
이었으나 parse_steps를 의미 손상시켜 보류했다(아래 보존 브랜치).

## 현재 상태 (master `db12bfc`, origin 푸시됨, 전 게이트 green)
- **op_switch byte-MATCH 달성** (`X64_SWITCH=1 TestX64Switch`). 세션2 말미까지 "switch 구조는 맞으나 uVar1
  byte-MATCH는 게이팅"이던 것을 완전 착지.
- 트리 전체 골든 맵 **10/10** byte-identical (`TREE_MAP=1 TestTreeFullGoldenMap`).
- x64 corpus **8/8** byte-identical (`X64_CORPUS=1 TestX64CorpusGoldenMap`, process 포함 사수).
- x64 breadth **2/3** (`X64_BREADTH=1`): dist_sq/sum2d MATCH, **dispatch는 골든과 한 토큰 차이**(아래 (A)).
- x64 corpus2(신규 discovery) **2/13** (`X64_CORPUS2=1 TestX64Corpus2`): bump_scores/divmix MATCH.
- production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*`/`TestPELoader`/`TestX86PEDecompile` PASS.
- `go test ./...` green (단 fresh worktree는 `testdata/elfs/simple_add_sym.exe` 미생성으로 symbols_test 3건
  실패 가능 -- `go run testdata/elfs/gen_import_pe.go`로 생성; 환경 이슈, 코드 무관).

## 이번 세션(세션3) 확정 대반전 (다음 세션이 삽질하지 말 것)
- **switch uVar1 = Ghidra 디컴파일러 CORE 기본 동작으로 재확정 (세션2의 "headless 아티팩트" 결론 폐기).**
  재빌드한 `tools/decomp_dbg.exe`(CPUI_DEBUG Ghidra 12.0.4 core 콘솔)로 실측 savefile
  `tools/captures/debug_op_switch.xml`을 restore->decompile -> **C++ 코어가 골든과 byte-identical uVar1 출력**.
  기전 확정(인스트루먼트 빌드로 로그): savefile의 `merge="false"` 속성 -> Symbol isolate 플래그
  (database.cc:423-427) -> `Merge::mergeTestAdjacent`의 isolated-Symbol 가드(merge.cc:198-205)가 누산기<->param
  speculative merge를 기각. `merge="false"` 제거 ablation 시 C++도 Gosleigh 구버전처럼 `param_2` 재사용으로
  반전 -> 단일 기전 확정. **세션2의 "merge/cover 수정 절대 금지"는 폐기됨** -- Gosleigh의 param_2 재사용이
  진짜 버그였고 세션3에서 착지함(`7682720`).
- **methodology 자산 확보**: `tools/decomp_dbg.exe`로 이제 C++ 코어 ground truth를 온디맨드로 실측 가능
  (print C / print raw / print tree varnode / print cover high / break start <action>). savefile은
  `tools/captures/`. 인스트루먼트 빌드(로깅 삽입) 절차는 `tools/BUILD_NOTES.md` + scratchpad `cpp_instr/`,
  `build_instr.py`(93 obj 재사용 + 단일 TU 재컴파일). **가설을 코드로 박기 전에 이 도구로 실측하라.**

## 이번 세션(세션3) 완료 -- 28 faithful 커밋 (`11740fb..db12bfc`, 전부 감독관 C++ 스팟체크+전매트릭스+cherry-pick)
묶음별 요약(상세 CHANGELOG 2026-07-17):
1. **dispatch param_1 복구**: heritage 인접범위 병합 버그(`086fc39`) -- `Address::overlap`(address.cc:163)은
   정확히 인접(dist==size)이면 -1인데 Go가 `>=`로 병합 -> RAX+RCX 16byte task -> CALLIND INDIRECT가 ECX param
   삼킴. strict `>`로 수정.
2. **전역 심볼 주입 + code-pointer CALLIND**(`8ac541a`,`35bc7a3`,`b5c6a27`): opt-in `BuildConfig.InjectedGlobals`
   + `GlobalScope`(scope_global.go) -> `&__ImageBase` 심볼릭 보존; CALLIND 타깃 code-pointer 타입(typeop.cc:754)
   + bare-code 렌더; 하네스가 함수를 실 VA에 로드.
3. **comment/warning 인프라**(`94a9006`,`58e0411`,`17c113c`): CommentDatabase 포팅(신규 comment.go) +
   Funcdata.warning + printc 방출. dispatch WARNING 1줄 byte-match.
4. **stageJumpTable partial-clone heritage**(`41f7e9b`,`32413bd`): funcdata_block.cc:491 스테이징 포팅 ->
   dispatch 두 번째 WARNING("Could not emulate...") byte-match.
5. **locked-FuncProto 주입 + comment 접목**(`eb58de8`,`08df0f3`,`5e97b84`): opt-in `InjectedPrototype`,
   locked-output storage(opInsertInput 잠재버그 수정).
6. **cast/radix**(`801a004`,`4722583`,`38a9036`): mostNaturalBase radix(printc.cc:1376), TypeOpIntSright
   getInputCast(typeop.cc:1587), option_hide_exts 게이트(cast.cc:249).
7. **마스크 폴딩**(`66dbc16`,`6334812`): RuleCollapseConstants 전 opcode(op.cc:115 isCollapsible),
   RuleAndOrLump 상수-lump 정정(ruleaction.cc:413, 기존 Go는 흡수법칙 오구현).
8. **SUBPIECE 타입**(`c45365d`): TypeOpSubpiece.getOutputToken(typeop.cc:2144) -> `(byte)` 캐스트.
9. **op_switch uVar1 byte-MATCH**(`42f78c6`,`70ba8f0`,`e9d3400`,`7682720` + mergeTestAdjacent `83998c8`):
   Varnode-Symbol 링크 + HighVariable.getSymbol(variable.cc:418) + merge Symbol 가드(merge.cc:157-164) +
   isolate 가드(merge.cc:198-205) + mergeTestSpeculative(merge.cc:220-234) + 주입 param isolate/namelock 배선.
10. **Oppen pretty-printer**(`888736a`): EmitPrettyPrint 라인랩(prettyprint.cc, maxlinesize=100) -> corpus2
    bump_scores byte-MATCH.
11. **구조화**(`051b51c`,`0095ddb`): goto-엣지 제거(block.cc:1711 removeEdge, multi-exit 루프 collapse) +
    scopeBreak(block.cc:1270) -> break/continue 방출.
12. **dispatch carrier**(`db12bfc`): CALL-site 반환값 복구 -- ActionActiveReturn 스텁 실체화(coreaction.cc:1774)
    + guardCalls 출력 트라이얼(heritage.cc:1453) + printc call-output explicit. dispatch가 `uVar1 = (*(code
    *)(...))(); return uVar1;`로 골든과 **한 토큰 빼고 일치**.
13. **discovery 코퍼스 x64_corpus2**(`7d427df`): 13함수(do-while/중첩루프/short-circuit/struct/포인터/signed
    div/함수호출/goto/float/64bit곱) + 갭 지도(testdata/x64_corpus2/README.md).

## 보존 브랜치 (착지 안 함 -- 다음 세션이 이어받을 것)
- **`worktree-agent-a31599a51b280b836` @ `42522d9`**: **faithful ActionReturnSplit** -- NodeSplit/CloneBlockOps
  (funcdata_block.cc:845-1093) SSA 수술 완전 포팅 + gatherReturnGotos/getCopyMap(blockaction.cc:2205). **split
  엔진 자체는 byte-correct** (dowhile_scan 정상 개선 입증). **착지 금지 사유**: ReturnSplit을 켜면 parse_steps가
  의미 손상(multi-exit 루프를 whiledo로 구조화하는데 compound-head를 Go emitWhileBlock이 못 다뤄 가드 소실
  -> 항상 `return -1`). 근본은 split이 아니라 **하류 collapse의 multi-exit-loop -> infinite-loop 구조화 갭**
  (LoopBody.FindExit/ruleBlockWhileDo/isComplex 스텁/PrintC compound-head whiledo). 이 collapse 갭을 먼저
  고친 뒤 이 브랜치를 얹으면 parse_steps가 수렴한다.

## 우선 제작 툴 (레버리지 높음 -- 갭 작업보다 먼저 검토)
어젯밤 최대 병목 = 갭을 손으로 찾고 C++와 손으로 대조한 것. 아래 2개를 만들면 이후 전 작업이 빨라진다.
1. **골든 자동생성 + 갭 자동분류 원커맨드**: 지금은 C함수 추가에 MSVC->Ghidra headless->JSON 수동
   (testdata/x64_corpus*/build.py+run_ghidra.py+GenGoldens.java). 이걸 `add_func "<C코드>"` 하나로 골든 생성 +
   Gosleigh 대조 + diff를 토큰종류별(구조화/타입/캐스트/rule/미포팅)로 자동 분류까지. **갭 발견이 시간->분.**
   실전 코퍼스를 30~50개로 값싸게 넓혀 커버리지/갭지도를 자동 갱신. **최고 레버리지.**
2. **p-code SSA 나란히 비교기**: decomp_dbg `print raw`(C++ 코어) <-> Gosleigh SSA 덤프를 op 단위 정렬 표시.
   어젯밤 팀원 여럿이 매번 임시 로깅으로 손수 한 걸 상설화. merge/type/heritage 갭 규명 반복노동 제거.

## 다음 작업 (우선순위)
### (A) [자기완결, 중] dispatch `(ulonglong)` ZEXT -> breadth 3/3
- **현상**: dispatch가 `&__ImageBase + (ulonglong)*(uint *)(...)` vs 골든 `&__ImageBase + *(uint *)(...)`.
  **단 한 토큰.** carrier/WARNING/guard/구조 전부 이미 일치.
- **근본(실측 확정)**: 골든은 `INT_ADD(&__ImageBase, idx)`가 PTRADD(포인터 산술)라 ZEXT를 숨김. Go는
  spacebase PTRSUB 출력을 포인터로 타이핑 안 함(C++ funcdata.cc:413-419 `updateType(getTypePointerStripArray)`)
  -> int 유지 -> RulePtrArith 미발화 -> IsExtensionCastImplied metatype 체크 실패.
- **주의**: dispatch-carrier 팀원이 시도했다가 ActionInferTypes 리셋 + typelock시 spacebase-collapse로
  `&__ImageBase` 소실 부작용 확인 후 revert. **type-model 深부채** -- PTRSUB 출력 포인터 타이핑이 InferTypes
  수렴에서 유지되게 하는 게 관건.
- **수정 대상**: pkg/pcode의 spacebase constant 타이핑(funcdata.cc:413 대응), TypeOpPtrsub 출력 타입, RulePtrArith.

### (B) [대형, 고위험] collapse multi-exit-loop 구조화 -> ReturnSplit 착지 + corpus2 P1
- **현상**: corpus2 dowhile_scan/parse_steps/find_pair가 do-while/for 구조까지는 형성되나 early-return이
  goto로 남거나(ReturnSplit 부재) 2-exit 루프가 잘못 구조화됨. 보존 브랜치(위)가 ReturnSplit을 제공하나
  collapse 갭에 게이팅.
- **근본**: LoopBody.FindExit/ruleBlockWhileDo가 2-exit 루프를 compound-head whiledo로 만들고 Go
  emitWhileBlock이 compound-head 미지원; isComplex() 스텁(false); infinite-loop(while(true)) 라벨링 미포팅.
- **C++ 참조**: blockaction.cc(CollapseStructure, LoopBody), block.cc(BlockWhileDo/BlockInfLoop scopeBreak),
  printc.cc emitBlockWhileDo. **tree/corpus 공유 루프 코드라 회귀 극도 주의** -- 실측(decomp_dbg) 후 착수.
- **성공 기준**: corpus2 dowhile_scan/parse_steps 구조 수렴 + 보존 브랜치 얹어 parse_steps 의미 무손상.

### (C) [디스커버리 후속] corpus2 갭 지도 P3-P8 (testdata/x64_corpus2/README.md)
- P3 umulhi: copy-prop/CSE 깊이(여분 임시). P4 gate: De Morgan/분기반전 + 네이밍. P5 sum_via_pp/add_pt:
  포인터 원소 스케일링/struct CONCAT44 분해(type-model). P6 helper_sum: 스택 파라미터(5번째 인자) 미해결.
  P7 caller: IOP-space CALLIND + COFF reloc 부재(가짜 호출). P8 faverage: **FP 전면 미포팅**(탐침).

## 회귀 가드 (매 수정마다 필수, 2회 결정성)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (8/8 -- process 사수)
- `X64_SWITCH=1 go test ./pkg/loader/ -run TestX64Switch -v` (**op_switch byte-MATCH 사수** -- 코퍼스 gitignore,
  부재 시 testdata/x64_switch/build.py 재실행)
- `X64_BREADTH=1 go test ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (2/3, dispatch 개선 시 3/3)
- `X64_CORPUS2=1 go test ./pkg/loader/ -run TestX64Corpus2 -v` (2/13, 개선 목표; 코퍼스 gitignore, 부재 시
  testdata/x64_corpus2/build.py 재실행)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam|TestPELoader|TestX86PEDecompile'`
- `go test ./...`

## 방법론 (이번 세션에서 재검증)
- **decomp_dbg 실측 우선**: uVar1 headless 반전, isolate 기전 확정, dispatch carrier 구조 -- 전부 실측이 가설을
  뒤집거나 확정. **코드 박기 전 tools/decomp_dbg.exe로 C++ 코어 관찰.** 인스트루먼트 빌드로 특정 가드 발화도 로그.
- **green이어도 unfaithful/의미손상 기각**: ReturnSplit(전 게이트 green이나 parse_steps 손상) 보류. 오포팅
  발견 시(RuleAndOrLump 흡수법칙, goto-엣지 미제거) 근본 정렬.
- **감독관 병렬 2슬롯**(사용자 승인): worktree 격리 + 수정 파일 분할 + 매 landing 전매트릭스 게이트. 팀원이
  메인 repo 오염 사고 2회 -> 프롬프트에 "worktree 경로 기준" 명시 필수.
- 선행 팀원 가설도 실측으로 검증(cover 가설 3회 반증됨: Intersection 정확, Symbol 가드 아님, 최종 isolate).
