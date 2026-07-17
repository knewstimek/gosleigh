# ssadiff -- p-code SSA 나란히 비교기

Gosleigh의 최종 SSA p-code(디컴파일 파이프라인 완료 직후, print 직전 상태)와
Ghidra C++ 코어(`tools/decomp_dbg.exe`)의 `print raw` 출력을 op 단위로 정렬해
나란히 비교하는 도구. merge/type/heritage 갭을 손으로 로깅해 대조하던 작업을
상설화한 것 (`NEXT_SESSION_PROMPT.md` "우선 제작 툴셋" #2).

## 구성

- `pkg/pcode/ssadump.go` (Go, 새 파일): `DumpSSA(fd *Funcdata, regNames map[string]string) string`.
  `Funcdata::printRaw`(funcdata.cc:209) 형식으로 최종 SSA를 텍스트 덤프한다.
  C++ 대응 지점은 파일 상단 doc 주석과 각 helper 옆에 `typeop.cc`/`block.cc`
  줄번호로 명시했다.
- `cmd/ssadump/main.go` (Go, 새 CLI): golden JSON 함수 하나를 골라
  `loader.EngineBuilder -> bridge.Build -> bridge.Decompile`(cmd/gosleigh와
  동일한 프로덕션 경로)로 돌리고 `DumpSSA` 출력을 표준출력에 낸다.
- `tools/ssadiff/capture.py`: golden JSON 항목(이름+bytes hex)에서 decomp_dbg
  savefile XML을 생성한다. `tools/captures/debug_op_switch.xml`과 달리
  파라미터/로컬 심볼을 전혀 잠그지 않는 "unlocked" 템플릿이다 -- x86-64 Windows
  fastcall 콜링컨벤션 모델만 고정하고 (Gosleigh 쪽도 동일 cspec으로 고정),
  나머지는 C++ 코어가 스스로 복구하게 둔다. 함수 바이트는 `ram` 오프셋 `0x0`에
  매핑한다 -- Gosleigh의 `loader.EngineBuilder`가 golden의 개별 함수 bytes를
  매핑하는 base와 동일해서, 두 덤프의 원본 명령어 주소가 그대로 비교 가능하다.
- `tools/ssadiff/run_cpp.py`: 생성된 savefile을 `tools/decomp_dbg.exe`에
  파이프(`restore` -> `load function` -> `decompile` -> `print raw` -> `quit`)해
  콘솔 출력에서 `print raw` 섹션만 잘라낸다.
- `tools/ssadiff/ssadiff.py` (메인 진입점): 위 둘을 호출해 두 덤프를 얻고,
  op 단위로 파싱 -> 정규화 -> 주소 기준 정렬 -> 2단 비교표 + 요약 통계를 출력한다.

## 사용법

저장소 루트에서 실행 (경로 기본값이 루트 기준):

```
py -3 tools/ssadiff/ssadiff.py --golden testdata/x64_corpus/x64_goldens.json \
    --func sum_to_n --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe --fuzzy
```

`SLEIGHHOME` 환경변수 필요(`tools/BUILD_NOTES.md` 참조). `decomp_dbg.exe`는
gitignore 대상이라 워크트리에는 없다 -- 메인 repo 절대경로(`D:\News\Business\Gosleigh\tools\decomp_dbg.exe`)를 넘긴다.

Gosleigh 쪽만 단독으로 보고 싶으면:

```
go run ./cmd/ssadump --golden testdata/x64_corpus/x64_goldens.json --func sum_to_n --print-c
```

C++ 코어 쪽 캡처만 재현하고 싶으면 (savefile을 직접 만들거나 저장해두고 싶을 때):

```
py -3 tools/ssadiff/capture.py --golden testdata/x64_corpus/x64_goldens.json --func sum_to_n --out /tmp/sum_to_n.xml
py -3 tools/ssadiff/run_cpp.py --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe --savefile /tmp/sum_to_n.xml --func sum_to_n
```

decomp_dbg를 아예 실행할 수 없는 환경에서는 미리 떠둔 raw 텍스트 파일로 비교:

```
py -3 tools/ssadiff/ssadiff.py --golden testdata/x64_corpus/x64_goldens.json --func sum_to_n --cpp-raw-file captured_sum_to_n_raw.txt
```

## 정규화 규칙

두 구현은 SSA를 완전히 독립적으로 build하므로, 아래 항목은 진짜 의미차가
아니라 "구현별 번호 매기기 차이"다. `ssadiff.py`의 `normalize_rest()`가
비교 전에 이를 지운다:

1. **op 앞 uniq (생성순서 카운터)는 애초에 비교 대상에 안 들어간다.** 각 op
   줄의 `<addr>:<uniq>:\t` 프리픽스에서 addr만 정렬 키로 쓰고 uniq는 표시만
   한다 (`OpRecord.uniq`).
2. **varnode def-annotation의 uniq** -- `(<addr>:<uniq>)` 형태에서 uniq를
   지운다 (`(<addr>)`만 남김). `--fuzzy` 플래그를 주면 addr까지 지우고
   `(DEF)`로 뭉갠다 -- 이유는 아래 "한계" 참고.
3. **unique-space 임시 varnode** (`u0x...`) -- 두 구현의 unique-space 할당
   순서/풀이 완전히 다르므로 `uTMP`로 통일한다.
4. **구조화 블록 인덱스** (`Block_10:0xADDR`의 `10`) -- RPO 넘버링이 두
   구현에서 다를 수 있어 `Block_N:`으로 마스킹한다. 대상 주소(`0xADDR`)는
   그대로 남긴다 (진짜 비교 대상).

## 정렬 방식

op 앞 uniq/블록 인덱스는 구현마다 완전히 다르므로 순번으로 정렬할 수 없다.
대신 **원본 명령어 주소**를 정렬 키로 쓴다 -- capture.py가 두 구현을 같은
base(`0x0`)에 매핑하므로, 힙/스택 슬롯 재사용이 없는 한 실제 op가 나온
명령어 주소는 두 구현에서 동일해야 한다. 같은 주소에 여러 op가 있으면
원래 순서대로 위치 매칭한다. 한쪽에만 있는 주소는 GOSLEIGH-ONLY/CPP-ONLY로
표시된다.

## 캘리브레이션 결과

### MATCH 함수: `sum_to_n` (`testdata/x64_corpus/x64_goldens.json`)

`print C` 출력은 두 구현이 완전히 동일(변수명 제외 -- capture.py 템플릿이
로컬 심볼을 안 잠그므로 Ghidra가 `uStack_14`/`uStack_18`로, Gosleigh
golden 쪽은 `local_14`/`local_18`로 자동 명명한 차이일 뿐). SSA 단위
정렬 결과:

- 기본(uniq만 정규화): 15쌍 중 2 MATCH (13.3%)
- `--fuzzy`(def-annotation 주소까지 정규화): 15쌍 중 5 MATCH (33.3%)

낮아 보이지만 **원인이 전부 식별됨** -- 아래 세 가지로 수렴한다(전부 이미
알려진 갭이거나 이번에 새로 드러난 갭이며, 셋 다 진짜 신호지 비교기 버그가
아니다):

1. **MULTIEQUAL(phi) op의 자체 주소가 다르다.** C++는 phi op의 SeqNum 주소로
   블록 진입 명령어 주소(`0x00000021`)를 쓰는데, Gosleigh는 그 자리에 피정의
   varnode의 저장 주소(스택 오프셋 `0xffffffffffffffec`)를 쓴다. 그 결과
   Gosleigh의 블록 헤더/goto 타깃까지 그 "가짜" 주소로 연쇄된다
   (`Basic Block 1 0xffffffffffffffec-0x00000028` vs C++
   `Basic Block 1 0x00000021-0x00000028`). heritage의 MULTIEQUAL 삽입 지점
   문제로 보이며, 이 세션 범위 밖(수정 안 함, 발견만).
2. **베이직블록 분할 단위가 다르다.** 루프 증분/비교에 해당하는 두 명령어
   (`0x31`, `0x1c`)를 C++는 한 블록(`0x19-0x39`)으로 합치는데 Gosleigh는
   별도 블록 두 개 + 그 사이 명시적 goto로 낸다. block-graph 구성 단계의
   차이로 보임.
3. **return 캐리어 COPY 누락.** C++는 `EAX = <병합값>` COPY를 먼저 넣고
   `return EAX`로 참조하는데, Gosleigh는 `return <병합값>`으로 병합
   varnode를 직접 반환한다. 최근 커밋(`db12bfc` "faithful CALL-site
   return-value recovery (dispatch carrier)")과 같은 계열의 return-value
   carrier 이슈로 보인다.

세 원인을 빼면 남은 나머지 op(산술/비교/COPY/상수)는 전부 MATCH -- 즉
"거의 일치"라는 수용 기준을 만족하되, 어긋나는 지점이 정확히 셋으로
좁혀진다는 게 이 도구의 핵심 가치.

### MISMATCH 함수: `umulhi` (`testdata/x64_corpus2/x64_goldens.json`)

64x64->상위64비트 곱(`testdata/x64_corpus2/README.md` P3, "단일사용 임시
전파/인라인" 갭으로 이미 문서화됨). SSA 정렬 결과: **19쌍 중 16 MATCH
(84.2%)** -- 나머지 3쌍(1 mismatch + 2 cpp-only)이 갭을 정확히 가리킨다:

```
 MATCH 0x00000062: RCX(0x00000062:5) = RCX(0x00000018:2) * RCX(0x0000003b:2)
!GOSL 0x00000067:26: u0x000dcb18(0x00000067:26) = (cast) RCX(0x00000062:5)
!CPP  0x00000067:a2: RCX(0x00000067:a2) = RCX(0x00000062:9b) >> #0x20:4
+GOSL 0x00000067:2: RCX(0x00000067:2) = u0x000dcb18(0x00000067:26) >> #0x20:4
 MATCH 0x0000006b: RAX(0x0000006b:2) = RAX(0x00000058:5) + RCX(0x00000067:2)
```

같은 주소(`0x67`)에서 C++는 SHIFT 한 op로 끝내는데(`RCX = RCX >> 0x20`),
Gosleigh는 CAST 한 op를 앞에 끼워 넣고 SHIFT가 그 CAST 결과를 입력으로
받는다(op 2개). 이후 흐름(`0x6b`부터)은 다시 전부 MATCH -- 즉 이 갭은 딱
그 지점의 불필요한 CAST 삽입(타입 추론/cast-elision 규칙 하나) 문제로
좁혀진다. corpus2 README의 "토큰 스트림이 거의 일치" 서술과 정확히 일치.

## 한계 / 막힌 지점

- **decomp_dbg savefile 템플릿은 unlocked 프로토타입만 검증했다.** 잠긴
  타입/이름이 필요한 케이스(예: struct 필드, 포인터 타입 골든)는
  `capture.py`가 심볼 주입을 지원하지 않는다 -- 필요해지면 확장 지점은
  `build_savefile()`의 빈 `<symbollist/>`.
- **암시적 goto 마커(`[ goto ... ]`) 줄은 비교 대상에서 제외했다** (`parse_dump`
  주석 참고) -- uniq가 없어 다른 op와 같은 틀로 비교하기 애매하고, 발생
  빈도가 낮아 신호 손실이 적다고 판단.
- **정렬은 주소 버킷 기준이라, 위 캘리브레이션 (1)처럼 op 자체의 주소가
  어긋나면 그 op와 그 이후 연쇄(블록 헤더/goto 타깃)까지 통째로
  GOSLEIGH-ONLY/CPP-ONLY로 갈라진다.** 위치 기반 폴백 정렬(블록 내 순서
  매칭)은 넣지 않았다 -- 지금은 "주소가 어긋난다"는 사실 자체가 유용한
  신호라 판단했고, 폴백을 넣으면 그 신호가 가려질 위험이 있다.
- C++ 측 파이프라인은 막히지 않았다 (savefile 템플릿이 `sum_to_n`/`umulhi`
  둘 다에서 바로 동작) -- "부분 산출물로 마무리" 조항을 발동할 필요는
  없었다.
