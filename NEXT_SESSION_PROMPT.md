# 다음 세션 프롬프트 (2026-07-17 세션5 오후 작성, master `be19010`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. green이어도 의미 손상이면 착지 금지. 가설을 코드로 박기 전에 실측(decomp_dbg/ssadiff).
**선행 진단도 실측으로 재검증하라** (세션4 반증 3회). **붕괴형 mismatch(빈 함수/미초기화 read/CFG 파괴)는
입력 무결성부터 의심하라** -- 세션5에서 "엔진 갭"이 골든 bytes 손상(GenGoldens island 버그)으로 반증됨.

## 현재 상태 (master `be19010`, origin 푸시됨, 전 게이트 green)
- tree 10/10, x64 corpus 8/8, op_switch byte-MATCH, breadth 3/3, corpus2 **5/13**
  (bump_scores/divmix/parse_steps/dowhile_scan/find_pair), x64_auto **20/32**, production PASS,
  `go test ./...` green.
- 세션5 착지 = 골든 손상 수정(GenGoldens bodyHex 연속 span) + 전 코퍼스 무결성 감사(손상은 x64_auto 2건뿐,
  corpus1/2 무결) + 엔진 6건: cover 인덱스=블록위치(97084fa), LoopBody 포인터 안정성(e19d788), InfLoop
  do/while(true)(0af54ad), RuleCollectTerms 포팅(e908beb), RuleShift2Mult 컨텍스트 게이트(75c6db5),
  RuleDoubleShift 완전 포팅(3fbf15c -- bit_mask_shift_combo MATCH). 상세 = CHANGELOG 2026-07-17 세션5.
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

### (A) [대형, 고위험, 최우선] heritage/stackvars 데이터플로 -- clamp3 + (B) param-recovery 공통 계열
- 현상 1 (corpus2 clamp3, **진단 완결 -- 세션5 read-only 워커, 실측 신뢰 높음**): dangling goto는 구조화
  무죄. `sub rsp,N` 후 bare 조정 SP(offset 0)로 접근하는 스택 슬롯(local_18)의 조정-RSP def가 접근마다
  3중 복제(`0x0d:38/39/3a RSP = RSP(i) + 0xffffffffffffffe8`) -> 스토어 2개/로드 1개가 서로 다른 버전 사용
  -> MULTIEQUAL 미형성 -> deadcode가 스토어 제거 -> 미초기화 read(local_306) + CBRANCH 양edge 동일 퇴화 ->
  collapse가 정직하게 goto 방출. C++ 코어는 단일 조정 RSP + phi 2단 형성(`s..ffe8 = R8D ? ECX`)으로 중첩 if
  구조화(goto 0). 반면 `RSP_in + (-0x14)` 형태(local_14)는 정상.
- 현상 2 (x64_auto reverse_bytes_inplace, 세션4 진단): spurious full-width RDX(sz8) + phantom R8 입력으로
  param_2가 실 캐리어 EDX(sz4)가 아닌 RDX에 바인딩 -> 캐리어 iVar2 유출 + 선언 소실. C++ 입력은 RCX+EDX 둘뿐.
  corpus2 gate의 iVar1도 같은 계열 추정.
- C++ 참조: heritage.cc guardStores/guardLoads(Gosleigh 미포팅 -- pkg/pcode/heritage.go ~1077 주석 참조,
  ProtectFreeStores:1213은 부분 대체물), coreaction.cc ActionActiveParam/trial, merge.cc mergeMarker.
- 수정 대상: pkg/pcode/heritage.go, rules_loadstore.go(stackvars 경로), scopelocal.go:171.
- 주의: 전 코퍼스 공유 최고위험 경로. read-only 진단(위 완결분 재확인 포함) -> 수정 분리 + ssadiff 함수별
  입력 varnode 집합 대조 필수. 세션5 워커 제안: 3중 RSP def 통합 또는 guardStores 포팅으로 STORE를 -0x18
  슬롯 def로 등록해 phi 형성.
- 성공 기준: clamp3 goto 소멸 + `int local_18` 선언 복원(corpus2 6/13), reverse_bytes_inplace spurious
  입력 소멸(ssadump 실측), 전 게이트 무회귀.

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
- strlen_style STRUCT(for/while, loop-variable phi depth-3, (B)와 얽힘). multi_return_early TYPECAST.
- sum_pp_walk/array_init_then_sum PTR(포인터 스케일 `* 8` raw 출력). longlong_combo/sign_extend_boundary
  TYPECAST. bit_rotate_left 리터럴 U 접미사. while_countdown/popcount_loop/swap_via_temp TEMP((B) 계열).
- corpus2 잔여 8건: gate(&&/|| 그룹핑 + param-as-return, De Morgan P4), clamp3((A)로 이관), add_pt/
  sum_via_pp/helper_sum/caller(반환 캐리어/call-site), faverage(FP), umulhi(spurious CAST). P5-P8은
  corpus2 README 지도 유지.

## 회귀 가드 (매 수정마다 필수, -count=1 2회 결정성)
- `TREE_MAP=1 go test -count=1 ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10)
- `X64_CORPUS=1 go test -count=1 ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (8/8)
- `X64_SWITCH=1 go test -count=1 ./pkg/loader/ -run TestX64Switch -v` (op_switch byte-MATCH 사수)
- `X64_BREADTH=1 go test -count=1 ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (3/3 사수)
- `X64_CORPUS2=1 go test -count=1 ./pkg/loader/ -run TestX64Corpus2 -v` (**5/13 사수**)
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
