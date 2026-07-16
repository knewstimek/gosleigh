# goldengap -- 골든 자동생성 + 갭 자동분류 원커맨드 툴

"C 함수 추가 -> MSVC 컴파일 -> Ghidra 12 헤드리스 골든 생성 -> Gosleigh 출력과 대조 ->
갭 원인 분류"를 원커맨드로 자동화한다. 기존 `testdata/x64_corpus2`(build.py/run_ghidra.py/
GenGoldens.java) 파이프라인을 그대로 재사용하고, `pkg/loader/x64_corpus2_diag_test.go`가
쓰는 Gosleigh 실행 경로(`bridge.Build` -> `bridge.Decompile`)를 `cmd/goldengap`으로 뽑아
CLI화했다. **pkg/ 엔진 코드는 건드리지 않는다.**

## 요구 사항

- MSVC VS2022 (`cl.exe`/`dumpbin.exe`, 경로는 `build.py` 상단 상수)
- `C:\ghidra12`(analyzeHeadless) + JDK 21
- Go 1.25+, Python 3 (`py -3`)

## 구성

```
tools/goldengap/goldengap.py   오케스트레이터 (add/gen/run/report/all/validate-corpus2)
tools/goldengap/classify.py    갭 자동분류 휴리스틱 (독립 모듈, import해서 씀)
cmd/goldengap/main.go          Gosleigh 실행 CLI (골든 JSON -> {name,output,error} JSON)
testdata/x64_auto/             auto 코퍼스 (add로 자라남; build.py/run_ghidra.py/
                                GenGoldens.java는 x64_corpus2에서 복제, 경로 수정 불필요)
```

## 원커맨드

```
py -3 tools/goldengap/goldengap.py all
```

`testdata/x64_auto/corpus.c`를 MSVC로 컴파일하고, Ghidra 12 헤드리스로 골든을 뽑고,
Gosleigh로 같은 바이트를 디컴파일해 대조한 뒤, `testdata/x64_auto/GAPMAP.md` +
`gapmap.json`을 갱신한다. Ghidra 헤드리스는 1~2분 걸린다.

## 서브커맨드

### add -- 함수 추가 + 전체 재생성

```
py -3 tools/goldengap/goldengap.py add <name> <c파일경로 또는 인라인 C코드>
```

`<name>`은 코드 안에 실제로 정의된 함수 이름이어야 한다(재생성 후 골든에 그 이름이
있는지 검증한다). 두 번째 인자는 파일 경로면 그 내용을 읽고, 아니면 그 문자열 자체를
C 코드로 취급한다. 이미 같은 이름의 함수가 있으면 삽입을 건너뛰고 재생성만 한다.

예시(파일):
```
py -3 tools/goldengap/goldengap.py add sum_loop testdata/x64_auto/snippets/sum_loop.c
```

예시(인라인, 셸에 따라 따옴표/개행 이스케이프 필요):
```
py -3 tools/goldengap/goldengap.py add add3 "long add3(long a,long b,long c){ return a+b+c; }"
```

### gen -- MSVC 컴파일 + Ghidra 헤드리스만

```
py -3 tools/goldengap/goldengap.py gen
```

### run -- Gosleigh 실행만 (골든 JSON -> gosleigh_out.json)

```
py -3 tools/goldengap/goldengap.py run
```

내부적으로 `go run ./cmd/goldengap -goldens ... -sla ... -pspec ... -cspec ... -out ...`를
호출한다. `-sla/-pspec/-cspec`은 기본값이 `testdata/sla` + `pkg/sla/testdata`를 가리키며,
`x64_corpus2_diag_test.go`와 동일한 아키텍처/ABI(x86-64 windows) 설정이다.

### report -- 대조 + 자동분류 + 갭 지도 갱신

```
py -3 tools/goldengap/goldengap.py report
```

`x64_goldens.json`의 `c`와 `gosleigh_out.json`의 `output`을 indent-insensitive로 비교하고
(`pkg/loader`의 `normGhidraC`와 동일한 정규화), `classify.py`로 갭을 태그 분류해
`GAPMAP.md`(한국어 표) + `gapmap.json`(JSON 요약)을 쓴다.

### validate-corpus2 -- 분류기 검증 (읽기 전용)

```
py -3 tools/goldengap/goldengap.py validate-corpus2
```

`testdata/x64_corpus2`(기존 13함수 디스커버리 코퍼스)는 **전혀 수정하지 않고** 읽기만
해서, 이 분류기를 그 골든에 돌린 뒤 `testdata/x64_corpus2/README.md`의 사람 분류(P1~P8)와
비교표를 만든다. 결과는 `testdata/x64_auto/CORPUS2_GAPMAP.md` /
`corpus2_gapmap.json` / `corpus2_gosleigh_out.json`에 쓴다(전부 x64_auto 쪽 새 파일).

## 갭 자동분류 태그

`classify.py`는 정규화 후 문자열이 같으면(줄 단위 좌측 공백 제거 + 개행 통일) `MATCH`,
전체 공백을 한 칸으로 접었을 때 같으면(줄바꿈/랩만 차이) `WRAP`으로 즉시 확정한다. 그 외는
아래 휴리스틱을 전부 돌려 다중 태그를 허용한다(근거 문자열도 같이 남긴다):

| 태그 | 판정 근거 |
|---|---|
| STRUCT | 정의 안 된 라벨로 가는 `goto`, do/while/for/break/continue 등장 횟수 불일치 |
| TYPECAST | `(int)`/`(byte)`/`(ulonglong)` 등 캐스트 개수 불일치, CONCAT/SUBPIECE 개수 불일치 |
| PTR | `* 2`/`* 4`/`* 8`/`* 16` 같은 raw 포인터 스케일이 골든보다 많음 |
| TEMP | `uVarN`/`iVarN`/`local_N`/`tmp_N` 류 임시/미해결 식별자 개수 불일치 |
| CALL | `local_N(...)` 형태의 가짜 호출 타깃, 혹은 골든에 있는 호출이 출력에서 사라짐 |
| FP | 골든에 `float`/`double`/부동소수 리터럴이 있는데 출력에 없음(빈 함수 축소 포함) |
| NAMING | (위 전부 해당 없을 때만) 식별자만 alpha-rename하면 토큰열이 완전히 같음 |
| UNKNOWN | 위 어디에도 못 넣음 -- 솔직하게 미분류로 남김 |
| ENGINE-ERR | Gosleigh CLI 자체가 실패(BUILD-ERR/BRIDGE-ERR/EMIT-ERR/PANIC) -- 목표 문서의
              분류 체계에는 없는 실무용 예외 처리 |

## 한계 (분류기가 못 잡는 케이스)

- **의미 기반 판단이 아니라 토큰/정규식 휴리스틱이다.** 예: `gate`(short-circuit &&/||
  De Morgan 반전 + then/else 스왑)는 사람 눈에는 "조건식 구조가 재배열됐다"로 보이지만,
  이 분류기는 그 재배열 자체를 인식하지 못하고 부수적으로 발생한 미선언 임시변수만 보고
  `TEMP`로 분류한다. 태그는 맞는 방향이지만 "왜"에 대한 설명력은 없다.
- **카테고리 자체가 없는 갭도 있다.** `helper_sum`(5번째 인자가 스택으로 전달되는데
  Gosleigh가 놓치는 케이스, corpus2 P6)은 목표 문서가 정의한 10개 태그 중 어느 것도
  본질을 설명하지 못한다. 우연히 `tmp_0`이라는 미해결 임시가 `TEMP` 정규식에 걸려 태그가
  붙긴 하지만, 이건 "여분 임시변수"라는 TEMP의 원래 정의와는 다른 현상이다. 검증표에는
  이런 경우를 "N/A (no clean category)"로 솔직하게 표시한다.
- **다중 태그가 실제 다중 원인인지, 하나의 원인이 여러 휴리스틱에 동시에 걸린 것인지
  구분하지 않는다.** 예: `caller`(콜 타깃 소실)는 CALL 하나가 근본 원인이지만 그 여파로
  TYPECAST/TEMP도 같이 뜬다.
- WRAP/MATCH 판정 이후에는 더 분류하지 않으므로, 만약 그 상위 판정 자체가 잘못 정규화된
  케이스(예: 리터럴 문자열 안의 공백)라면 걸러내지 못한다. 지금까지 실측한 코퍼스(x64_auto
  3함수 + x64_corpus2 13함수)에서는 이런 오탐이 없었다.
- STRUCT의 "다행 goto" 판정은 라벨이 `이름:` 형태로 줄 맨 앞에 오는 것을 전제한다. Gosleigh
  PrintC가 라벨 표기 방식을 바꾸면 이 정규식도 같이 갱신해야 한다.
