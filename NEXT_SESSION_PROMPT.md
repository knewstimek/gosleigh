# 다음 세션 프롬프트 (2026-07-03 세션2 작성, master `746a72c`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param RCX/RDX) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. 이번 세션에 이 규율이 실전에서 결정적이었다(아래 switch uVar1 참고).

## 현재 상태 (master `746a72c`, origin 푸시됨, 전 게이트 green)
- **x64 corpus 8/8 완전 MATCH 달성** (`TestX64CorpusGoldenMap`, X64_CORPUS=1). 메모리/STATUS가 반복적으로
  "가장 어렵다 / deep-debt / 1세션 착지 불가"로 기술했던 `process`가 골든과 byte-identical.
- 트리 전체 골든 맵 **10/10** byte-identical (`TestTreeFullGoldenMap`, TREE_MAP=1).
- x64 breadth **2/3** (`TestX64BreadthGoldenMap`, X64_BREADTH=1): dist_sq/sum2d MATCH, dispatch만 잔여.
- production `TestMSVC*`/`TestAARCH64*`/`TestX8664*`/`TestX64RegParam*`/`TestPELoader`/`TestX86PEDecompile` PASS.
- `go test ./...` 완전 green (전 패키지 ok).

## 이번 세션(세션2) 완료 -- 6 faithful 커밋 (건드리지 말 것, 전부 감독관 C++ 스팟체크+전매트릭스 검증)
process를 "구조적 붕괴+비결정성"에서 "전체 body byte-identical 골든"으로 5개 조각으로 쪼개 착지 + IOP-space
groundwork:
1. **`50a9557`(rewrite전 677382e) printc unsigned 단축타입명**: `unsigned int`->`uint`, `unsigned char`->
   `byte`, ushort, size-8은 longSize() split로 `ulonglong`(LLP64)/`ulong`(LP64). type.cc coretype getName 충실.
2. **`ad73759`(c7fcdf7) faithful BlockCondition**: Go BlockCondition 머신러리가 스텁이었음. boolean opcode
   INT_AND/OR seed(block.cc:1785)+forceFalseEdge(block.cc:1204)+De Morgan negate(block.cc:3023, opc flip)+
   emitBlockCondition &&/|| opcode 디스패치+comma(printc.cc:2968). process 조건 `if((param_3<=iVar1)&&
   (local_18=param_4,iVar1<=param_4))` 구조 골든 일치 + 누락됐던 배열로드 문장 복원.
3. **`781c9d6`(e1d3087) process 비결정성+반전 수정**: (a) addCFGEdges(bridge.go) map 순회->ascending 정렬
   (collectEdges flow.cc:906; map은 merge블록 in-edge순서 랜덤화->phi슬롯 permute->3-4개 비결정 출력). (b)
   halfDeleteInEdge/OutEdge swap-with-last->slide-down(block.cc:100/115; MULTIEQUAL trim opRemoveInput
   slide-down과 lockstep). => process loop/clamp byte-identical 골든, 결정적.
4. **`8bdd340`(e170c56) gap2 64bit signed div 반환**: RuleSubZext 미포팅(기존 Go RuleSubZext는 무관한
   SUBPIECE-cancel)이라 RuleSubvarZext가 ZEXT 벗기고 RuleSubCommute가 4byte 절단. fix=RuleSubZext::applyOp
   (ruleaction.cc:5057)->Go RuleSubZextMask(INT_ZEXT, RuleSubvarZext 앞 등록, coreaction.cc:5596<5638) +
   RuleOrSextForm를 live oppool1 등록(CDQ dividend INT_OR->INT_SEXT). => `(longlong)local_c/(longlong)local_10
   & 0xffffffff`, gcd 무회귀.
5. **`2296513`(31255aa) 반환 carrier 타입+번호 (process 8/8 완결)**: typeOrder는 이미 faithful했음(오진).
   실제 잔차는 printc 렌더: (A) return-only carrier를 TYPE_UINT/TYPE_UNKNOWN이면 undefined%d 강제하던 걸
   TYPE_UNKNOWN만으로 제한(real-typed->실타입, Ghidra buildVariableName). (B) per-prefix 카운터->Ghidra
   shared base 카운터(database.cc, carrier 마지막 생성이라 iVar1 다음 uVar2). (B)는 "국소 재현"(단일 global
   카운터 완전통합은 미포팅, mixed-prefix 다중temp+carrier 가상케이스만 영향, 현 골든 없음).
6. **`746a72c` IOP-space 인코딩 (Sonnet 5 작성, foundational)**: INDIRECT input(1)이 zero-const 스텁이라
   heritage same-time rename(heritage.cc:2506-2517)이 CALLIND 타깃 유실. fix=side-table
   BindIndirectCause/GetIndirectCause(addtreestate.go, C++ raw-pointer 인코딩은 Go GC-unsafe라 기존
   BindSpaceConstant idiom 재사용; input(1)은 여전히 zero constant라 기존 consumer 무영향) +
   NewIndirectOp/Creation input(1)=NewVarnodeIop(callOp)(funcdata_op.cc:695/725) + renameRecurse same-time
   체크. **necessary-not-sufficient for dispatch(2/3 불변)**. merge.go:953/1107 same-time은 여전히
   fallback(pre-existing, input(1) 상수라 안전).

## 확정된 벽 / 재규명 (다음 세션이 삽질하지 말 것)
- **switch uVar1 = HEADLESS 환경 아티팩트, merge 버그 아님 (decomp_dbg.exe CPUI_DEBUG로 실측 확정)**. 기존
  세션 자산 debug-built Ghidra 디컴파일러(CPUI_DEBUG)로 switch.exe를 x86:LE:64 .sla 로드->디컴파일:
  **Ghidra 디컴파일러 CORE도 `param_2 = param_2 + param_3`(param_2 재사용) = Gosleigh와 byte-identical,
  골든 uVar1 아님.** merge 발화+testCache.intersection=false(cover boundary, Gosleigh와 동일) -> **Gosleigh
  cover/merge는 정확, C++ 코어와 일치.** 골든의 uVar1은 full HEADLESS 분석(param/stack/symbol recovery가 다른
  Funcdata를 같은 merge 코어에 먹임)에서만. merge.cc/cover.cc는 12.0.4(골든생성)<->12.2 byte-identical.
  **=> switch uVar1 강제(merge.go/cover.go/heritage.go 수정, descending edge order, merge-gate 포팅
  landing)는 C++ 코어 파리티를 깨는 UNFAITHFUL. 절대 하지 말 것.** switch byte-MATCH는 headless-env
  recovery(아래)에 게이팅. (구 STATUS의 "(a-2) type-model uVar1 return-split/merge"는 이 발견으로 폐기 --
  uVar1은 type-model 갭이 아니라 headless 아티팩트.)
- **breadth dispatch "reloc/COFF 로더 갭" 프레이밍은 틀렸다 (Opus 실측 debunk)**. (1) 하네스
  (x64_breadth_diag_test.go:43-44)는 .obj를 안 읽고 골든 JSON의 hexToBytes(fn.Bytes)를 단일 base로 먹임 --
  relocation site 자체가 파이프라인에 없음, pe.go 미사용. (2) 골든 바이트가 이미 post-relocation(Ghidra가
  골든 캡처 전 reloc 적용; raw .obj addend 0). (3) 이 골든은 emulation-실패 폴백(CALLIND+setBadJumpTable);
  full-image 로딩하면 track-B 복구가 성공해 switch{} 방출->골든과 더 벌어짐. **=> reloc 로더 짓지 말 것(dead
  code).** stale doc 정정: truncateIndirectJump/ArtificialHalt/RecoverJumpTables/SetBadJumpTable는 이미
  포팅+구동중(flow_jumptable.go:72/199/241, funcproto.go:183, bridge.go:254) -- breadth README/STATUS의
  "미포팅"은 out-of-date.

## 다음 작업 (우선순위) -- converged frontier
남은 두 타겟(breadth dispatch, switch byte-MATCH)이 **같은 축으로 수렴**했다: **headless-environment
param/type/symbol recovery**. Gosleigh는 Ghidra 디컴파일러 CORE 포팅인데 골든은 full HEADLESS 출력이라,
대부분 함수는 core≈headless로 일치하나 일부(switch uVar1, dispatch param_1)는 headless 분석 계층(파라미터
recovery, type-lock, symbol homing)이 코어에 다른 Funcdata를 먹인다. 이 계층이 최종목표(Ghidra headless 출력
완전 일치)의 다음 대형 아키텍처 방향이다.

### (frontier) [최우선, 대형/고위험] headless-environment param/type/symbol recovery
- **현상**: (dispatch) `undefined4 dispatch(void)` vs golden `undefined8 dispatch(uint param_1)` -- param_1
  전면 유실 + CALLIND target 표현식(`&__ImageBase + table[param_1]`)이 param_1/심볼 recovery에 의존해 `(*0)`로
  붕괴. (switch) uVar1 return-split이 headless param recovery 산물.
- **후보 근본(미확정, 조사 선행 필수)**: headless가 recovered param을 type-lock하거나 stack Symbol로
  homing해 merge 입력을 바꾼다(ghidra-debug 팀원 강력 후보). Ghidra의 headless 분석 파이프라인
  (DecompileCallback/파라미터 recovery/prototype override)이 코어 Funcdata에 param/type을 주입하는 경로 규명 필요.
- **고위험**: param/type 코어를 건드려 방금 얻은 8/8 + tree 10/10을 위협. worktree 격리 + 전매트릭스 무회귀
  게이트 필수. green이어도 unfaithful이면 되돌림.
- **C++ 참조**: headless 경로는 ghidra-ref에 Decompiler C++만 있어 부분적 -- DecompileCallback/ifacedecomp
  주변 + prototype/param recovery(funcdata param, ScopeInternal). 조사부터.
- **성공 기준**: dispatch MATCH(2/3->3/3) 또는 switch op_switch byte-MATCH, + tree 10/10 + x64 8/8 무회귀.

### (a) [차순위, 자기완결적 조각] dispatch CALLIND target=0 붕괴 규명
IOP-space는 착지했으나 dispatch는 여전히 `(*0)`. breadth-reloc 팀원 미확정: target-0가 (a)언매핑 jumptable
load가 0 fold vs (b)emulation실패가 target varnode 0으로 vs (c)IOP-space 오rename. p-code 덤프 필요
(bridge.Build->RecoverJumpTables->TruncateIndirectJump 주변). 단 target 표현식이 param_1 recovery에 의존하니
frontier와 얽힘 -- 부분 진전만 가능.

### (b) [보류, 낮은 우선순위] switch Diffs 3/4/5
op_switch byte-MATCH의 잔차 중 uVar1(headless) 외: shift-count `(byte)` vs `(undefined1)` 타입추론, 여분
`& 0x3f`(RuleAndCollapse), case7 `(int)` 캐스트. 단 switch byte-MATCH는 uVar1(headless)에 게이팅되니 이것만으론
gate-win 불가. core-vs-headless 여부 미확정.

## 참고 / 자산
- 메모리 `project_gosleigh` 상단 "2026-07-03 (세션2)" 섹션들에 전부 상세.
- decomp_dbg.exe (CPUI_DEBUG Ghidra 12.2 디컴파일러): 기존 세션 scratchpad에 존재. Ghidra CORE 동작 관찰용
  (headless 아님 주의). x86:LE:64 .sla는 Ghidra 설치(SLEIGHHOME)서. `adjust vma`는 Win64서 32bit truncation
  버그 -> PE-mapped(file offset=RVA) base 0 로딩으로 우회.
- worktree 브랜치들(worktree-agent-*)에 이번 세션 실험 보존: d2adf57(merge-gate 포팅, faithful하나
  output-neutral+switch 무관 판명 -> landing 안 함), 그 외 landed 커밋들의 원본. 정리 가능.
- `.gocache`는 gitignore 처리됨(`/.gocache/`,`*.exe`,`*.obj`). `.git` 258MB bloat는 옛 blob 잔존 --
  `git gc --prune=now`로 로컬 회수(repo quiescent시). `.gorchera/`는 orchestrator goal 인프라(정상).

## 회귀 가드 (매 수정마다 필수)
- `TREE_MAP=1 go test ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10 유지 -- x86-32 회귀 극도 주의)
- `X64_CORPUS=1 go test ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (8/8 유지 -- process 사수)
- `X64_BREADTH=1 go test ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (2/3 유지/증가)
- `X64_SWITCH=1 go test ./pkg/loader/ -run TestX64Switch -v` (코퍼스 gitignore -- testdata/x64_switch/build.py
  재실행 필요, 부재 시 skip; structure MATCH, byte-MATCH는 headless 게이팅)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam|TestPELoader|TestX86PEDecompile'`
- `go test ./...` (전 패키지 green -- 단 fresh worktree는 testdata/elfs/simple_add_sym.exe 미생성으로 3건
  symbols_test 실패 가능, gen_*.go로 생성되는 fixture라 환경 이슈)

## 방법론 (이번 세션에서 재검증)
- **투자 전 조사(investigate-first)**: reloc 프레이밍이 틀렸음을 실측으로 debunk해 dead code 회피. switch uVar1이
  headless 아티팩트임을 decomp_dbg로 확정해 unfaithful 강제 회피. **가설을 코드로 박기 전에 실측/C++로 검증.**
- **green이어도 unfaithful 기각**: descending edge order가 골든 통과했으나 C++ collectEdges ascending 위배 ->
  기각하고 진짜 근본(halfDelete slide-down) 찾음. output-neutral 변경은 "실제 목표+실제 갭 해소"면 landing
  (IOP-space, ActionDoNothing 선례), "비-목표"면 보류(merge-gate 포팅).
- **비결정성 출력**: Go map 순회가 흔한 원인. 결정성 확인은 게이트 다회 실행.
- Sonnet 5는 hard foundational 포팅을 Opus급으로 수행(정확한 C++ 근거+안전한 설계결정+A/B검증). 어려운 위임 가능.
