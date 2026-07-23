# 다음 세션 프롬프트 (2026-07-23 세션6 작성, 엔진 tip `32fb2b6`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. green이어도 의미 손상이면 착지 금지. 가설을 코드로 박기 전에 실측(decomp_dbg/ssadiff).
**선행 진단도 실측으로 재검증하라** (세션4 반증 3회). **붕괴형 mismatch(빈 함수/미초기화 read/CFG 파괴)는
입력 무결성부터 의심하라** -- 세션5에서 "엔진 갭"이 골든 bytes 손상(GenGoldens island 버그)으로 반증됨.

## 현재 상태 (엔진 tip `53fce49` origin 푸시, 전 게이트 green -- 감독관 재검증)
- tree 10/10, x64 corpus 8/8, op_switch byte-MATCH, breadth 3/3, corpus2 **8/13**
  (+sum_via_pp), x64_auto **24/32**(+sum_pp_walk +strlen_style), production PASS, `go test ./...` green.
- **세션6 후속5 착지(`53fce49`) = char 리터럴 렌더**: `renderConstant`(printc.go)에 char-print 분기 추가
  (size-1 signed int -> `'\0'`, C++ type.cc:3642 cacheCoreTypes 재현). strlen_style strict MATCH. 상세 CHANGELOG 세션6 후속5.
- **세션6 후속4 착지(`4759d8e`) = (B) print-inline 일부**: `shouldInline`이 nd>1 implied 식을 term-dup
  인라인(printc.go) + `ActionNameVars` explicit-only 네이밍(action_name_vars.go). flag는 이미 C++ 일치였고(실측)
  순수 렌더+네이밍 수정. **잔여**: umulhi 줄바꿈(PrettyEmitter fold), swap_via_temp LOAD cover 오분류(merge),
  nd==1 full-faithful(heritage/merge marker) = 계속 STOP 경계. 상세 CHANGELOG 세션6 후속4.
- **세션6 후속3 착지(`60e01f0`) = for-loop 인식**: `findLoopVariable`(action_forloops.go)가 CPUI_CAST를
  투과하도록 수정 -- 근본은 액션 순서 차이(C++은 finalTransform을 ActionSetCasts 전에 실행, Gosleigh는 후).
  삽입 CAST가 depth-4 예산 소진해 loop-head MULTIEQUAL 은닉하던 것. strlen_style이 Ghidra와 **for 구조 일치**
  (유일 잔차 `!= 0` vs `'\0'` char 리터럴 = printc 상수렌더 STOP 경계라 MATCH 22 유지). 상세 CHANGELOG 세션6 후속3.
- **세션6 착지(`991be09`) = A2 param-recovery undercount**: 충실 `ParamListStandard`/`ParamEntry`/`fillinMap`
  포팅(신규 paramlist.go 709줄) + fixateproto `recoverMissingStackParams`(진짜 fillinMap 소비, IsParamOffset
  휴리스틱 교체). helper_sum 스택 param_5 복구(ssadump 실측, golden 시그니처 일치), caller 5-인자 일치.
  corpus2 6/13 -> 후속 dead-negate 제거로 7/13(A0 완료). 상세 CHANGELOG 세션6.
- **세션6 후속 착지(`ed0bbea`) = dead-negate 제거**: helper_sum body `tmp_0`의 근본 = Gosleigh cleanup 룰
  왕복(RuleSub2Add->RuleMultNegOne->Rule2Comp2Sub)이 만든 orphan INT_2COMP. `Rule2Comp2Sub`가 rewrite 후
  orphan 2COMP 파괴(ruleaction.cc:7254 패리티). helper_sum MATCH, **corpus2 7/13, x64_auto 21/32**. 상세 (A0).
- **세션6 후속2 착지(`f569034`) = multi_return_early**: 근본은 ActionReturnSplit 아님(정확) -- PrintC 이미터가
  `BlockIf` 조건헤드=BlockList일 때 선행 guarded-return 누락+최내곽 오렌더. `emitConditionLead`/`renderCondition`에
  BlockList 케이스 추가(emitBlockLs no_branch/only_branch 미러, printc.cc:2913). **x64_auto 21->22**. 상세 (C).
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
  stdout에만 출력해 gosleigh_out.json이 갱신 안 됨(세션5에서 stale 검증 함정 실증). **주의 2**: GAPMAP.md는 전체 자동생성(수동 섹션 없음)이라
  옛 '수동 섹션 덮어씀' 주의는 stale. 실제 한계는 TYPECAST/TEMP 토큰수 휴리스틱이 렌더 근본을 못 짚는 것.
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

### (A0) [세션6 후속 착지 완료 `ed0bbea`] dead-negate 제거 -> helper_sum MATCH
근본은 후보 (1)/(2) 둘 다 아니었다(decomp_dbg 실측): dead INT_2COMP는 Gosleigh cleanup 룰 왕복
(RuleSub2Add `V-W=>V+(W*-1)` -> RuleMultNegOne `W*-1=>INT_2COMP(W)` -> Rule2Comp2Sub `V+INT_2COMP(W)=>V-W`)이
만든 orphan(use 0). actcleanup 뒤엔 ActionDeadCode가 없어(universalAction 패리티) 미청소 -> 곱셈 2-use ->
tmp_0. C++ 코어는 이 INT_2COMP를 애초에 미생성. 수정 = `Rule2Comp2Sub.apply`(rules_arith.go)가 ADD->SUB
rewrite 후 orphan 2COMP(`NumDescend()==0`)를 `OpDestroy`(C++ ruleaction.cc:7254 패리티, 살아있는 2COMP는
가드로 미파괴). helper_sum body `- param_4 * param_5` MATCH. corpus2 6->7, x64_auto 20->21(longlong_combo
동반, 같은 orphan temp). 전 게이트 -count=1 2회 무회귀.

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
(골든 `param_2 = local_10`) carrier는 (B) print-inline/param 계열 잔여(reverse_bytes_inplace는 여전히 UNKNOWN/MISMATCH, x64_auto 24/32에 미포함).

**(A2) undercount [세션6 스택 param 착지 `991be09`; 잔여 = 완전대체/struct]**: helper_sum param_5(스택 param)는
세션6에 복구 완료(충실 ParamListStandard.fillinMap 포팅 + additive recoverMissingStackParams; body tmp_0는
(A0) dead-negate로 이관). **잔여**: 옛 ApplyActiveParamModel(IsParamOffset) 완전 대체 = updateInputTypes store
재빌드 + unref varnode 실체화; add_pt struct hi/lo + CONCAT44는 별개(param 무관, 스택 overlap load/store). 원래
근본 지도 = `FuncProto.resolveModel`
+ `deriveInputMap`(fspec.cc) 미포팅 -- 트라이얼을 모델 slot에 채워 레지스터 세트 밖 스택 param 복구 +
미참조 input 생성(coreaction.cc:4745-4759). caller의 전 param 소실 + `local_92()` call-target 실패는
helper_sum 프로토가 고쳐지면 연쇄 재확인.

**(A3) 무관 트랙 [세션6에 해소/재분류]**: multi_return_early는 세션6 후속2 착지(PrintC BlockList emitter 버그, ActionReturnSplit 아님, `f569034`).
sum_via_pp 잉여 `lVar1`은 copy-coalesce가 아니라 (B) print-inline(shouldInline이 IsImplied 미소비)으로 재분류(decomp_dbg 실측). => (A3)는 소진, 남은 건 (B).

권장 순서(세션7 갱신): (B) print-inline 부분 착지(후속4 `4759d8e` -- sum_via_pp/sum_pp_walk MATCH) -> **잔여
umulhi 그룹토큰 재아키텍처(아래 (B) 상세)** 또는 A2 잔여(IsParamOffset 완전대체) / swap_via_temp cover(merge) -> (C)/struct 잔여.
- 성공 기준(세션6 완료분): reverse_bytes_inplace 2 param(A1 세션5), helper_sum param_5 복구+body MATCH
  (A2 스택 세션6 + A0 dead-negate). 잔여 성공 기준은 (A2 잔여)/(A3)/(C) 각 항목 참조.

### (B) [대형, 시스템, 단독 세션 권장] pre-structure SSA 정합 -- deadcode/MarkImplied 타이밍
- 세션4 지도 유지: Ghidra는 구조화 전에 ActionDeadCode/ActionMarkImplied 완료, Gosleigh는 print 시점으로
  미룸 -> (1) BlockBasic::isComplex leaf faithful 포팅 6게이트 회귀(40d00a3 known gap 스텁), (2) TEMP
  클러스터(세션7 후속4로 sum_via_pp/sum_pp_walk 해소; 잔여 swap_via_temp[merge cover]/popcount_loop[네이밍]/
  umulhi[줄바꿈=그룹토큰]), (3) SSA parity 부채(phi SeqNum 주소, 블록 병합, return 캐리어 COPY).
- **세션5 추가 부채(같은 축)**: SeqNum.Order가 전역적으로 블록 위치로 유지 안 됨 -- cover는 97084fa로
  국소 해결했지만 다른 Order 소비자(double.go, funcdata.go:1483, rules_misc.go:2745, merge.go:1304 정렬)는
  여전히 stale decode order. 완전 포팅(BlockBasic::insert order 유지)은 Order를 opTree 맵 키에서 분리 필요.
- C++ 참조: coreaction.cc universalAction 순서, block.cc:2388 BlockBasic::isComplex, block.cc:2255/2638
  insert/setOrder.
- **[세션6->세션7 부분 착지 `4759d8e`] print-inline**: 후속4가 `shouldInline`을 nd>1 implied 식 term-dup
  인라인으로 수정(marker/call/branch/store 제외) + `ActionNameVars` explicit-only 네이밍(implied는 Symbol 없어
  이름카운터 미소비) -> **sum_via_pp/sum_pp_walk MATCH**. flag(IsImplied)는 이미 C++ 일치였음(ssadump 실측) =
  순수 렌더+네이밍이었다. **잔여 (전부 STOP 경계)**: (1) nd==1 경로 원본 보존(전면 flag-faithful화 시
  loop-carried PTRADD/CAST가 phi로 explicit 마킹돼 phantom 선언 누출, sum_list 회귀 실측 -- heritage/merge marker),
  (2) **umulhi**: 내용 byte-identical이나 **줄바꿈만 MISMATCH** -- Ghidra는 `+` width-optimal에서 접고 Gosleigh는
  `=` 경계에서 접음. 근본 = **PrintC 표현식 렌더가 하위식을 flat Go 문자열(불투명 content 토큰 1개)로 넘김**
  -> Oppen 코어(prettyprint.go, 이미 충실 포팅)는 굵은 토큰 사이(=/;)에서만 break 가능. 수정 = printc가 이항
  연산자마다 openGroup/closeGroup+break 토큰을 emit(Ghidra pushOp/emitOp 구조, printc.cc) -- 문자열빌드 -> 토큰스트림
  재아키텍처. **대형·고위험(전 함수 포맷 영향), 단독 세션.** (3) gate/faverage 등은 메 별건(De Morgan/FP).
- 착수 전 ssadiff/decomp_dbg로 현 SSA 갭 지도를 함수별로 뽑아 범위 확정.

### (C) [소~중] x64_auto/corpus2 잔여 (24/32 이후)
- switch_dense: 세션5 바이트 정정으로 실바이트 디코드 정상화 -- 잔여는 TYPECAST(cast int/uint/ulonglong
  want/got 불일치) + TEMP uVar2. 기존 "range-check idiom" 설명은 손상 바이트 시절 것이라 stale -- 재실측부터.
- **strlen_style [세션6 후속3+후속5 완료 -- strict MATCH]**: for 구조(후속3 `60e01f0` findLoopVariable CAST
  투과) + char 리터럴(후속5 `53fce49` renderConstant char-print 분기, `!= '\0'`) 둘 다 착지 -> strict MATCH.
- **multi_return_early [세션6 후속2 착지 `f569034`]**: 근본은 ActionReturnSplit 아님(그건 정확, decomp_dbg
  실측). PrintC 이미터가 `BlockIf` 조건헤드=BlockList일 때 선행 guarded-return 누락+최내곽 오렌더 ->
  `emitConditionLead`/`renderCondition`에 BlockList 케이스 추가(emitBlockLs no_branch/only_branch 미러). MATCH.
  교훈: GAPMAP TYPECAST 태그는 오분류였고 반환-캐리어 클러스터(add_pt/caller)와도 무관(그쪽은 A2 계열).
- sum_pp_walk TEMP(lVar1 -- SEXT48 implied 실패, (B) 클러스터). array_init_then_sum PTR `* 4`+local_428
  (스택 배열 미복구 근본 -- PTRADD를 안 거침). sign_extend_boundary
  TYPECAST(longlong_combo는 세션6 dead-negate로 MATCH). bit_rotate_left 리터럴 U 접미사. while_countdown/popcount_loop/swap_via_temp TEMP((B) 계열).
- corpus2 잔여 6건(helper_sum은 세션6 MATCH): gate(&&/|| 그룹핑 + param-as-return, De Morgan P4), add_pt/
  caller(반환 캐리어/call-site = A2 계열), sum_via_pp/umulhi((B) print-inline 재분류, 옛 spurious CAST는 오진), faverage(FP). P5-P8은
  corpus2 README 지도 유지.

## 회귀 가드 (매 수정마다 필수, -count=1 2회 결정성)
- `TREE_MAP=1 go test -count=1 ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10)
- `X64_CORPUS=1 go test -count=1 ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (8/8)
- `X64_SWITCH=1 go test -count=1 ./pkg/loader/ -run TestX64Switch -v` (op_switch byte-MATCH 사수)
- `X64_BREADTH=1 go test -count=1 ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (3/3 사수)
- `X64_CORPUS2=1 go test -count=1 ./pkg/loader/ -run TestX64Corpus2 -v` (**8/13 사수**)
- `py -3 tools/goldengap/goldengap.py run && py -3 tools/goldengap/goldengap.py report` (**MATCH 22 사수**;
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
