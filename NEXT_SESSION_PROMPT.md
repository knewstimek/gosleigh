# 다음 세션 프롬프트 (2026-07-17 세션4 작성, master `65b57f1`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. green이어도 의미 손상이면 착지 금지. 가설을 코드로 박기 전에 실측(decomp_dbg/ssadiff).
**선행 진단도 실측으로 재검증하라** -- 세션4에서 선행 진단 반증 3회(dowhile "LoopBody exit 버그" -> emit,
"merge 오병합" -> 디코드 오염, for/while "과발화" -> under-firing).

## 현재 상태 (master `65b57f1`, origin 푸시됨, 전 게이트 green)
- tree 10/10, x64 corpus 8/8, **op_switch byte-MATCH**, breadth **3/3**, corpus2 **4/13**
  (bump_scores/divmix/parse_steps/dowhile_scan), x64_auto **15/32**, production PASS, `go test ./...` green.
- 세션3 핸드오프의 (A) dispatch ZEXT, (B) collapse/ReturnSplit 착지(보존브랜치 부채 해소), 우선 제작 툴
  2종 전부 완료. 세션4 상세 = CHANGELOG 2026-07-17 세션4 (11건 엔진 착지 + 툴 2종).

## 툴 (있는 줄 모르면 못 쓴다 -- 착수 전 확인)
- **goldengap**: `py -3 tools/goldengap/goldengap.py all|add|gen|run|report|validate-corpus2` --
  C함수 추가 -> MSVC -> Ghidra headless 골든 -> Gosleigh 대조 -> 갭 자동분류 -> testdata/x64_auto/GAPMAP.md.
  Gosleigh 단독 재실행: `go run ./cmd/goldengap -goldens <골든.json>`. **주의: report가 GAPMAP.md 수동
  섹션을 덮어씀** -- 재생성 후 수동 섹션 재보강(툴 개선 후보 1순위).
- **ssadiff**: `SLEIGHHOME='D:\News\Utility\리버싱\ghidra_12.0.4_PUBLIC' py -3 tools/ssadiff/ssadiff.py
  --golden <골든.json> --func <이름> --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe --fuzzy`
  -- C++ 코어 vs Gosleigh 최종 SSA op 단위 나란히 비교. Gosleigh 쪽만: `go run ./cmd/ssadump`.
  savefile 템플릿 자동 생성(unlocked-prototype). 사용법 tools/ssadiff/README.md.
- **decomp_dbg**: `tools/decomp_dbg.exe`(CPUI_DEBUG Ghidra 12.0.4 core 콘솔) -- print C/raw/tree varnode/
  cover high, break start <action>. savefile: tools/captures/. 재빌드/인스트루먼트: tools/BUILD_NOTES.md.
- 골든 파이프라인: testdata/x64_corpus*/ + x64_auto/ (build.py + run_ghidra.py + GenGoldens.java).
  코퍼스 바이너리는 gitignore -- 부재 시 각 build.py 재실행. elfs는 `go run testdata/elfs/gen_import_pe.go`.

## 다음 작업 (우선순위)

### (A) [중] dowhile_count 잔여 데이터플로 + find_pair 잔여 collapse -> corpus2/x64_auto STRUCT 정리
- 현상 1 (x64_auto dowhile_count): 구조는 do-while 수렴(ccbef67). 잔여 = `local_18 = 0;` 초기화 문장
  누락 + 증가 temp 미병합(`iVar1 = local_18 + 1; local_18 = iVar1;` vs 골든 `local_18 = local_18 + 1`).
  파서-컨텍스트 디코드 버그(8b23afa)와 무관 확인됨 -- 스택 reload/merge(SSA) 계열.
- 현상 2 (corpus2 find_pair): 2중 루프 + 조기 return에서 dangling goto 2개 잔여(세션4에 3->2). 골든은
  `while{ if{} }` 구조화. ReturnSplit/collapse 착지 후에도 남은 다중-exit 중첩 루프 케이스.
- C++ 참조: merge.cc(HighVariable 병합), blockaction.cc(CollapseStructure/LoopBody 중첩 루프 경로).
  ssadiff로 C++ 코어 SSA/구조를 먼저 실측하라 (세션4 반증 이력 -- collapse가 아니라 emit이었던 전례).
- 수정 대상: pkg/pcode merge/collapse/printc (실측 후 확정).
- 성공 기준: `X64_CORPUS2=1 go test ./pkg/loader/ -run TestX64Corpus2 -v` dowhile_count 관련 없음 --
  x64_auto는 `go run ./cmd/goldengap -goldens testdata/x64_auto/x64_goldens.json`; find_pair goto 소멸.

### (B) [대형, 고위험] param-recovery 발산 -- reverse_bytes_inplace/gate 선언 소실의 진짜 근본
- 현상: Gosleigh가 arg 레지스터에 spurious full-width 입력(RDX sz8) + phantom R8 입력을 만들어 param_2가
  실 캐리어 EDX(sz4)가 아닌 RDX에 바인딩 -> 캐리어가 iVar2로 새고 선언 소실(컴파일 불가 C). C++ 코어는
  입력이 RCX+EDX 둘뿐(세션4 read-only 진단, decomp_dbg 실측). corpus2 `gate`의 iVar1도 같은 계열 추정.
- C++ 참조: coreaction.cc ActionActiveParam/param trial, heritage sub-register 폭 결정, merge.cc mergeMarker.
- 수정 대상: pkg/pcode/scopelocal.go:171(BuildFromVarnodes 슬롯 대표), heritage/param trial 경로.
- 주의: 전 코퍼스 파라미터 복구 공유 -- 최고위험. ssadiff로 입력 varnode 집합을 함수별 대조하며 진행.
- 성공 기준: reverse_bytes_inplace에 spurious RDX/R8 입력 소멸(ssadump 실측) + iVar2 선언 문제 자연 해소 +
  전 byte-MATCH 사수.

### (C) [대형, 시스템] pre-structure SSA 정합 -- deadcode/MarkImplied 타이밍 (TEMP 클러스터 공통 축)
- 현상: Ghidra는 구조화(CollapseStructure) 전에 ActionDeadCode/ActionMarkImplied가 끝나 있는데 Gosleigh는
  print 시점으로 미룸. 이로 인해 (1) BlockBasic::isComplex leaf faithful 포팅이 6게이트 회귀(40d00a3에서
  known gap 스텁), (2) TEMP 클러스터(umulhi/sum_via_pp/gate 임시 인라인 실패 = ActionMarkImplied 깊이)
  잔존, (3) SSA parity 부채(ssadiff 캘리브레이션: phi SeqNum 주소, 블록 병합, return 캐리어 COPY).
- C++ 참조: coreaction.cc universalAction 순서(deadcode/markimplied 위치), block.cc:2388 BlockBasic::isComplex.
- 성공 기준: isComplex leaf faithful 포팅이 무회귀로 착지 가능해지는 것 + x64_auto TEMP 함수들 개선.
- **대형 재작업이라 단독 세션 권장. 착수 전 ssadiff로 현 SSA 갭 지도를 함수별로 뽑아 범위 확정.**

### (D) [소~중, 자기완결 후보들] x64_auto/corpus2 잔여
- switch_dense: range-check idiom(`param_1 - 10U < 8`) 미포팅. nested_if_ladder_grade: `label_missing`
  dangling(미정의 라벨 방출 = correctness). gate: De Morgan/분기 반전(P4). bit_mask_shift_combo: 상수
  시프트가 곱(`* 0x100`)으로 출력 + 마스크 단순화. param_reuse_accum: 대수 항 정리(term-collecting).
  bit_rotate_left: 리터럴 U 접미사. char 리터럴('\0') 렌더(상수 출력 전역 경로 -- 신중). strlen_style
  for/while(loop-variable phi depth-3, (C)와 얽힘). P5-P8(corpus2 README: struct CONCAT44/스택 파라미터/
  reloc/FP)은 기존 지도 유지.

## 회귀 가드 (매 수정마다 필수, -count=1 2회 결정성)
- `TREE_MAP=1 go test -count=1 ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10)
- `X64_CORPUS=1 go test -count=1 ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (8/8)
- `X64_SWITCH=1 go test -count=1 ./pkg/loader/ -run TestX64Switch -v` (op_switch byte-MATCH 사수)
- `X64_BREADTH=1 go test -count=1 ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (**3/3 사수**)
- `X64_CORPUS2=1 go test -count=1 ./pkg/loader/ -run TestX64Corpus2 -v` (**4/13 사수**)
- `go run ./cmd/goldengap -goldens testdata/x64_auto/x64_goldens.json` -> gosleigh_out.json 대조 (**MATCH 15 사수**)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam|TestPELoader|TestX86PEDecompile'`
- `go test ./...`

## 방법론 (세션4에서 재검증)
- **실측 우선 + 선행 진단 재검증**: 세션4에서 선행 진단이 실측으로 3회 반증됨(위 핵심 규칙 참조).
  ssadiff(신규)가 진단 시간을 크게 단축 -- umulhi 갭을 "op 하나"로 특정, 디코드 오염을 SSA 대조로 발견.
- **read-only 진단 -> 수정 분리**: 고위험 영역(merge/디코드)은 read-only 진단 워커로 근본 확정 후 별도
  수정 워커 투입이 효과적이었다 (cond_assign_abs, 파서-컨텍스트 pin).
- **회귀 없는 슬라이스 불가 시 기각**: worker-e(선언 경로 증상 봉합 기각), isComplex leaf(known gap 스텁).
- **감독관 병렬 2슬롯**: worktree 격리 + 수정 파일 비중첩 분할 + 매 landing 전매트릭스 2회 게이트 +
  cherry-pick(+즉시 push). 워커 diff 검토 시 **베이스 어긋남 아티팩트 주의** -- 워커 브랜치 분기 시점이
  master보다 뒤면 `git diff <master>..HEAD`에 타 워커 변경이 역방향으로 섞여 보인다. `git log`로 워커
  자신의 커밋만 확인 후 그것만 cherry-pick.
