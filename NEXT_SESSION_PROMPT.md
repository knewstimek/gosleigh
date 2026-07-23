# 다음 세션 프롬프트 (2026-07-23 세션6 작성, 엔진 tip `991be09`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. green이어도 의미 손상이면 착지 금지. 가설을 코드로 박기 전에 실측(decomp_dbg/ssadiff).
**선행 진단도 실측으로 재검증하라** (세션4 반증 3회). **붕괴형 mismatch(빈 함수/미초기화 read/CFG 파괴)는
입력 무결성부터 의심하라** -- 세션5에서 "엔진 갭"이 골든 bytes 손상(GenGoldens island 버그)으로 반증됨.

## 현재 상태 (엔진 tip `991be09` origin 푸시, 전 게이트 green -- 감독관 재검증)
- tree 10/10, x64 corpus 8/8, op_switch byte-MATCH, breadth 3/3, corpus2 **6/13**
  (bump_scores/divmix/parse_steps/dowhile_scan/find_pair/clamp3), x64_auto **20/32**, production PASS,
  `go test ./...` green.
- **세션6 착지(`991be09`) = A2 param-recovery undercount**: 충실 `ParamListStandard`/`ParamEntry`/`fillinMap`
  포팅(신규 paramlist.go 709줄) + fixateproto `recoverMissingStackParams`(진짜 fillinMap 소비, IsParamOffset
  휴리스틱 교체). helper_sum 스택 param_5 복구(ssadump 실측, golden 시그니처 일치), caller 5-인자 일치.
  corpus2 6/13 유지 -- body tmp_0는 param 무관 별개 갭(다음 작업 (A0)). 상세 CHANGELOG 세션6.
- 세션5 착지 = 골든 손상 수정(GenGoldens bodyHex 연속 span) + 전 코퍼스 무결성 감사(손상은 x64_auto 2건뿐,
  corpus1/2 무결) + 엔진 9건: cover 인덱스=블록위치(97084fa), LoopBody 포인터 안정성(e19d788), InfLoop
  do/while(true)(0af54ad), RuleCollectTerms 포팅(e908beb), RuleShift2Mult 컨텍스트 게이트(75c6db5),
  RuleDoubleShift 완전 포팅(3fbf15c), PTRADD 렌더 스케일 제거(caf44a2), heritage BuildADT faithful
  포팅(cd42ccb -- Bilardi-Pingali z-chain, clamp3 완결), **param-recovery overcount(ee592a9 -- phantom R8
  param 제거, ActionInputPrototype input-only trial + deadcode 후)**.
  상세 = CHANGELOG 2026-07-17 세션5. stale 워커 worktree 40개 전수 검증 후 일괄 삭제(현재 main뿐).
- 세션4 핸드오프의 (A) dowhile_count/find_pair, (D) 1바이트 반환 캐리어는 전부 완료.

## 툴 (있는 줄 모르면 못 쓴다 -- 착수 전 확인)
- **goldengap**: `py -3 tools/goldengap/goldengap.py all|add|gen|run|report|validate-corpus2` --
  C함수 추가 -> MSVC -> Ghidra headless 골든 -> Gosleigh 대조 -> 갭 자동분류 -> testdata/x64_auto/GAPMAP.md.
  **주의 1**: Gosleigh 단독 재실행은 `goldengap.py run`을 써라 -- bare `go run ./cmd/goldengap`은 -out 없이
  stdout에만 출력해 gosleigh_out.json이 갱신 안 됨(세션5에서 stale 검증 함정 실증). **주의 2**: report가
  GAPMAP.md 수동 섹션을 덮어씀(툴 개선 후보).
- **ssadiff**: `SLEIGHHOME='D:\News\Utility\리버싱\ghidra_12.0.4_PUBLIC' py -3 tools/ssadiff/ssadiff.py
  --golden <골든.json> --func <이름> --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe --fuzzy`
  -- C++ 코어 vs Gosleigh 최종 SSA op 단위 비교. Gosleigh 쪽만: `go run ./cmd/ssadump`. 사용법
  tools/ssadiff/README.md.
- **decomp_dbg**: `tools/decomp_dbg.exe`(CPUI_DEBUG Ghidra 12.0.4 core 콘솔) -- print C/raw/tree varnode/
  cover high, break start <action>. savefile: tools/captures/. 재빌드/인스트루먼트: tools/BUILD_NOTES.md.
- **바이트 무결성 감사 스크립트**: capstone으로 골든 bytes의 분기 타깃 검사(경계 밖/명령어 중간). 세션5
  scratchpad에서 사용 -- 필요 시 CHANGELOG 세션5 참조해 재작성(수십 줄).
- 골든 파이프라인: testdata/x64_corpus*/ + x64_auto/ (build.py + run_ghidra.py + GenGoldens.java).
  코퍼스 바이너리는 gitignore -- 부재 시 각 build.py 재실행. elfs는 `go run testdata/elfs/gen_import_pe.go`.

## 다음 작업 (우선순위)

### (A0) [소~중, 최우선 -- 세션6 사용자 지정] dead-negate 제거 -> helper_sum MATCH
세션6에서 A2 param 복구가 착지해 helper_sum이 `int helper_sum(param_1..param_5)`로 정확해졌으나 body는
여전히 `return (param_1+param_2+param_3) - tmp_0;`(golden `- param_4 * param_5`). 근본 = param 무관 별개 갭:
- 현상: ssadump helper_sum SSA에 `u0x96400 = R9D * s0x28`(=param_4*param_5) + **dead `u0x9670c = -u0x96400`**
  (INT_2COMP, use 없음) + `EAX = EAX - u0x96400`. dead negate가 곱셈을 2-use로 만들어 인라인 실패 -> explicit
  tmp_0. 제거 시 곱셈 1-use -> `param_4 * param_5` 인라인 -> helper_sum golden MATCH(corpus2 6->7).
- C++ 참조: decomp_dbg 실측상 C++ 코어는 이 INT_2COMP를 아예 생성 안 함. 원인 후보 2갈래: (1) packed
  .sla IMUL 번역이 플래그용 negate 방출하는데 Ghidra는 그 플래그를 소비 없는 dead로 정리, (2) consume-based
  DeadCode(action_deadcode.go, `GOSL_DESCENDANT_DC` fallback + descendant-count 루프 잔재)가 use 없는
  INT_2COMP를 못 걷어냄. **착수 전 decomp_dbg로 C++ IMUL 번역 raw p-code vs Gosleigh 대조 필수.**
- 수정 대상 Go: consume/deadcode 경로(action_deadcode.go) 또는 IMUL SLEIGH 번역. **다수 함수 회귀 위험 ->
  read-only 진단 먼저 신중 격리(세션5 clamp3 패턴).**
- 성공 기준: ssadump helper_sum body `- param_4 * param_5`, `X64_CORPUS2` corpus2 6->7, 전 게이트 무회귀.

### (A) [대형, 고위험] param-recovery 발산 -- 세션5 read-only 진단으로 3갈래 분해 (A1/A2 스택 착지됨)
공통 상위 원인: `pkg/pcode/paramactive.go` `ApplyActiveParamModel`이 C++ `ActionInputPrototype`
(coreaction.cc:4718, fixateproto 그룹, deadcode 다수 통과 이후)의 **조기·축약 대체품**이다. 세션4의
"spurious RDX(sz8)"는 이미 해소됨(param_2는 int 정확). 세 갈래는 별개 근본:

**(A1) overcount -- phantom R8 [세션5 착지 완료 `ee592a9`]**: reverse_bytes_inplace 시그니처 param 3->2
정확화. 근본 = `ApplyActiveParamModel`이 C++ `ActionInputPrototype::apply`(coreaction.cc:4728-4741)와 달리
(1) 전체 varnode bank 순회(C++은 `beginDef(input)..endDef(input)` = **input varnode만**) + (2) 활성 조건
`vn.IsInput() ||` 잉여 절 + (3) deadcode 前 발화. 수정 = 후보를 `isParamLocation && vn.IsInput()`으로 제한
+ 활성 조건 `NumDescend()>0`만(coreaction.cc:4737 `!hasNoDescend()`) + ActionActiveParam을 ActionDeadCode
**뒤로** 재배치(구조적으로 "deadcode 실행됨" 보장). 무회귀 수렴 확인. **잔여**: body `iVar1 = local_10`
(골든 `param_2 = local_10`) carrier는 A2 undercount 계열 -- MATCH는 아직 20(body gap).

**(A2) undercount [세션6 스택 param 착지 `991be09`; 잔여 = 완전대체/struct]**: helper_sum param_5(스택 param)는
세션6에 복구 완료(충실 ParamListStandard.fillinMap 포팅 + additive recoverMissingStackParams; body tmp_0는
(A0) dead-negate로 이관). **잔여**: 옛 ApplyActiveParamModel(IsParamOffset) 완전 대체 = updateInputTypes store
재빌드 + unref varnode 실체화; add_pt struct hi/lo + CONCAT44는 별개(param 무관, 스택 overlap load/store). 원래
근본 지도 = `FuncProto.resolveModel`
+ `deriveInputMap`(fspec.cc) 미포팅 -- 트라이얼을 모델 slot에 채워 레지스터 세트 밖 스택 param 복구 +
미참조 input 생성(coreaction.cc:4745-4759). caller의 전 param 소실 + `local_92()` call-target 실패는
helper_sum 프로토가 고쳐지면 연쇄 재확인.

**(A3) 무관 트랙 [별개, param 아님]**: sum_via_pp 잉여 `lVar1 = param_2` copy(copy-coalesce),
multi_return_early return 분기 2개 드롭(ActionReturnSplit -- control-flow 구조화). param 라인과 분리 처리.

권장 순서(세션6 갱신): **A0(dead-negate, 최우선)** -> A2 잔여(완전대체/struct) -> A3.
- 성공 기준(세션6 완료분): reverse_bytes_inplace 2 param(A1 세션5), helper_sum param_5 복구(A2 스택 세션6).
  잔여 성공 기준은 (A0)/(A2 잔여) 각 항목 참조.

### (B) [대형, 시스템, 단독 세션 권장] pre-structure SSA 정합 -- deadcode/MarkImplied 타이밍
- 세션4 지도 유지: Ghidra는 구조화 전에 ActionDeadCode/ActionMarkImplied 완료, Gosleigh는 print 시점으로
  미룸 -> (1) BlockBasic::isComplex leaf faithful 포팅 6게이트 회귀(40d00a3 known gap 스텁), (2) TEMP
  클러스터(umulhi/sum_via_pp/swap_via_temp/popcount_loop 등 임시 인라인 실패), (3) SSA parity 부채(phi
  SeqNum 주소, 블록 병합, return 캐리어 COPY).
- **세션5 추가 부채(같은 축)**: SeqNum.Order가 전역적으로 블록 위치로 유지 안 됨 -- cover는 97084fa로
  국소 해결했지만 다른 Order 소비자(double.go, funcdata.go:1483, rules_misc.go:2745, merge.go:1304 정렬)는
  여전히 stale decode order. 완전 포팅(BlockBasic::insert order 유지)은 Order를 opTree 맵 키에서 분리 필요.
- C++ 참조: coreaction.cc universalAction 순서, block.cc:2388 BlockBasic::isComplex, block.cc:2255/2638
  insert/setOrder.
- 착수 전 ssadiff로 현 SSA 갭 지도를 함수별로 뽑아 범위 확정.

### (C) [소~중] x64_auto/corpus2 잔여 (20/32 이후)
- switch_dense: 세션5 바이트 정정으로 실바이트 디코드 정상화 -- 잔여는 TYPECAST(cast int/uint/ulonglong
  want/got 불일치) + TEMP uVar2. 기존 "range-check idiom" 설명은 손상 바이트 시절 것이라 stale -- 재실측부터.
- strlen_style STRUCT(for/while, loop-variable phi depth-3, (B)와 얽힘).
- **multi_return_early: TYPECAST 태그는 오분류(세션5 진단)** -- 캐스트는 골든과 동일하고 진짜 갭은
  ActionReturnSplit: 4개 return이 한 블록(0x74)에 몰려 조건 분기 2개(`return -1`/`return 0`)가 통째로
  소실 + 루프-exit `return 2`가 `return 0`으로 오출력. C++은 return별 값-블록 분리(RAX = const) 후 0x70
  MULTIEQUAL -> 단일 return RAX. corpus2의 add_pt/sum_via_pp/helper_sum/caller 반환-캐리어 클러스터와
  같은 계열 -- (A) 착수 시 함께 지도에 넣어라. GAPMAP 휴리스틱이 캐스트 토큰 수만 세는 한계도 확인
  (블록 소실을 TYPECAST로 오분류 -- 툴 개선 후보).
- sum_pp_walk TEMP(lVar1 -- SEXT48 implied 실패, (B) 클러스터). array_init_then_sum PTR `* 4`+local_428
  (스택 배열 미복구 근본 -- PTRADD를 안 거침). longlong_combo/sign_extend_boundary
  TYPECAST. bit_rotate_left 리터럴 U 접미사. while_countdown/popcount_loop/swap_via_temp TEMP((B) 계열).
- corpus2 잔여 7건: gate(&&/|| 그룹핑 + param-as-return, De Morgan P4), add_pt/
  sum_via_pp/helper_sum/caller(반환 캐리어/call-site), faverage(FP), umulhi(spurious CAST). P5-P8은
  corpus2 README 지도 유지.

## 회귀 가드 (매 수정마다 필수, -count=1 2회 결정성)
- `TREE_MAP=1 go test -count=1 ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10)
- `X64_CORPUS=1 go test -count=1 ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (8/8)
- `X64_SWITCH=1 go test -count=1 ./pkg/loader/ -run TestX64Switch -v` (op_switch byte-MATCH 사수)
- `X64_BREADTH=1 go test -count=1 ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (3/3 사수)
- `X64_CORPUS2=1 go test -count=1 ./pkg/loader/ -run TestX64Corpus2 -v` (**6/13 사수**)
- `py -3 tools/goldengap/goldengap.py run && py -3 tools/goldengap/goldengap.py report` (**MATCH 20 사수**;
  bare `go run ./cmd/goldengap`은 파일 미갱신 주의)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam|TestPELoader|TestX86PEDecompile'`
- `go test ./...`

## 방법론 (세션5에서 재검증)
- **실측 우선 + 선행 진단 재검증 + 입력 무결성 우선**: 세션5의 최대 리턴은 "엔진 갭"을 골든 손상으로 반증한
  것. C++ 코어에 같은 입력을 넣어 같은 실패가 나면 엔진이 아니라 입력이다.
- **read-only 진단 -> 수정 분리**: clamp3에서 진단 워커가 파일 경계(heritage 금지) 때문에
  diagnose-and-stop으로 정확히 멈춤 -- 경계 명시가 고위험 영역 오염을 막았다. (A) 착수 시 같은 패턴 권장.
- **감독관 병렬 2슬롯**: worktree 격리 + 수정 파일 비중첩 분할(merge/heritage vs collapse/blockaction vs
  rules 계열로 나누면 안전) + 매 landing 스팟체크 + 전매트릭스 -count=1 2회 + cherry-pick + 즉시 push.
  워커 스냅샷 커밋은 분기점이 다르면 충돌 -- 엔진 fix만 cherry-pick하고 스냅샷은 master에서 재생성이 깔끔.
- **worktree 워커 준비물**: 코퍼스 바이너리 gitignore라 `cp -rn /d/News/Business/Gosleigh/testdata/. ./testdata/`
  선행 필수. decomp_dbg는 원본 절대경로 사용.
