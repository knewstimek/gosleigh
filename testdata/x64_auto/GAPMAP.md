# Golden Gap Map

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

12/32 MATCH (indent-insensitive).

## 함수별 분류

| 함수 | 태그 | 근거 |
|---|---|---|
| `sum_loop` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `dowhile_count` | STRUCT, TYPECAST, PTR, TEMP | STRUCT: dangling goto target(s) in output: label_0<br>TYPECAST: cast (int): want=1 got=2<br>TYPECAST: cast (longlong): want=1 got=2<br>PTR: raw pointer scale '* 4': want=1 got=2<br>TEMP: extra temp/local identifiers in output (3 vs 2): iVar1 |
| `sum_pp_walk` | PTR, TEMP | PTR: raw pointer scale '* 8': want=0 got=2<br>TEMP: extra temp/local identifiers in output (3 vs 2): lVar1 |
| `while_pretest_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `loop_forever_break` | STRUCT | STRUCT: dangling goto target(s) in output: label_0<br>STRUCT: keyword 'while': want=1 got=0<br>STRUCT: keyword 'for': want=0 got=1<br>STRUCT: keyword 'break': want=1 got=0 |
| `nested_while_matrix` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `while_countdown` | TEMP | TEMP: extra temp/local identifiers in output (2 vs 1): local_8 |
| `switch_dense` | STRUCT, TYPECAST, TEMP | STRUCT: dangling goto target(s) in output: label_missing<br>TYPECAST: cast (int): want=1 got=0<br>TYPECAST: cast (uint): want=1 got=2<br>TYPECAST: cast (ulonglong): want=0 got=1<br>TEMP: extra temp/local identifiers in output (2 vs 1): uVar2 |
| `switch_sparse` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_no_default` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_fallthrough` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_2d_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_init_then_sum` | TYPECAST, PTR, TEMP | TYPECAST: cast (int): want=0 got=2<br>TYPECAST: cast (longlong): want=0 got=2<br>PTR: raw pointer scale '* 4': want=0 got=2<br>TEMP: extra temp/local identifiers in output (4 vs 2): local_428, local_8 |
| `array_reverse_sum` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `reverse_bytes_inplace` | STRUCT, TYPECAST | STRUCT: keyword 'while': want=0 got=1<br>STRUCT: keyword 'for': want=1 got=0<br>TYPECAST: cast (longlong): want=0 got=2 |
| `bit_mask_shift_combo` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `popcount_loop` | STRUCT, TEMP | STRUCT: keyword 'while': want=0 got=1<br>STRUCT: keyword 'for': want=1 got=0<br>TEMP: extra temp/local identifiers in output (2 vs 1): local_8 |
| `xor_swap_pair` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `bit_rotate_left` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `unsigned_wrap_compare` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `longlong_combo` | TEMP | TEMP: extra temp/local identifiers in output (1 vs 0): lVar2 |
| `sign_extend_boundary` | TYPECAST | TYPECAST: cast (char): want=1 got=0 |
| `char_arith_promote` | TYPECAST, PTR | TYPECAST: cast (char): want=1 got=0<br>TYPECAST: cast (int): want=1 got=0<br>PTR: raw pointer scale '* 2': want=0 got=1 |
| `short_arith_trunc` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `cond_assign_abs` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `minmax_chain4` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `strlen_style` | STRUCT, TYPECAST | STRUCT: keyword 'while': want=0 got=1<br>STRUCT: keyword 'for': want=1 got=0<br>TYPECAST: cast (char): want=1 got=0 |
| `memcpy_style` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `multi_return_early` | STRUCT, TEMP | STRUCT: dangling goto target(s) in output: label_0, label_1, label_2, label_3<br>STRUCT: keyword 'while': want=1 got=0<br>STRUCT: keyword 'for': want=0 got=1<br>STRUCT: keyword 'break': want=1 got=0<br>TEMP: extra temp/local identifiers in output (2 vs 1): uVar1 |
| `nested_if_ladder_grade` | STRUCT, TEMP | STRUCT: dangling goto target(s) in output: label_missing<br>TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |
| `param_reuse_accum` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `swap_via_temp` | TEMP | TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |

## 태그 분포

- MATCH: 12
- PTR: 4
- STRUCT: 8
- TEMP: 10
- TYPECAST: 7
- UNKNOWN: 5

## 수동 요약 (T2 코퍼스 확장, 2026-07-17)

아래는 `goldengap.py report`가 자동 갱신하지 않는 수동 섹션이다. 위 표를 재생성하면
(`report`/`all` 재실행) 이 섹션은 그대로 남지만 표는 덮어써지므로, 다음에 report를
다시 돌릴 때는 이 섹션을 다시 확인/보강해야 한다.

### 클래스별 집계 (기존 3개 + 신규 29개 = 32개, 태그 중복 허용)

| 태그 | 개수 | 해당 함수 |
|---|---|---|
| MATCH | 12 | sum_loop, while_pretest_sum, nested_while_matrix, switch_sparse, switch_no_default, switch_fallthrough, array_2d_sum, xor_swap_pair, unsigned_wrap_compare, short_arith_trunc, minmax_chain4, memcpy_style |
| STRUCT | 8 | dowhile_count, loop_forever_break, switch_dense, reverse_bytes_inplace, popcount_loop, strlen_style, multi_return_early, nested_if_ladder_grade |
| TYPECAST | 7 | dowhile_count, switch_dense, array_init_then_sum, reverse_bytes_inplace, sign_extend_boundary, char_arith_promote, strlen_style |
| PTR | 4 | dowhile_count, sum_pp_walk, array_init_then_sum, char_arith_promote |
| TEMP | 10 | dowhile_count, sum_pp_walk, while_countdown, switch_dense, array_init_then_sum, popcount_loop, longlong_combo, multi_return_early, nested_if_ladder_grade, swap_via_temp |
| UNKNOWN | 5 | array_reverse_sum, bit_mask_shift_combo, bit_rotate_left, cond_assign_abs, param_reuse_accum |

12/32 MATCH -- 기존 x64_auto 1/3(sum_loop만) 대비 실측 표본이 32개로 늘면서 처음으로
"이 구조는 이미 통과한다"를 확신 있게 말할 수 있는 항목(while-pretest, 중첩 while,
switch 대부분 변형, 2D 배열 인덱싱, XOR swap, unsigned wraparound, min/max 체인,
memcpy 스타일 등)이 드러났다.

### 신규로 드러난 갭 신호 (corpus2 P1~P8 지도에 없던 것)

- **for/while 키워드 선택 불일치가 do-while에 국한되지 않는다.** corpus2의 STRUCT는
  전부 do-while 역엣지 문제였는데, 이번 표본에서는 do-while이 전혀 없는
  `loop_forever_break`(for(;;) -> Gosleigh가 `for`로, 골든은 `while`/`break`로),
  `reverse_bytes_inplace`/`popcount_loop`/`strlen_style`(반대로 골든이 `while`인데
  Gosleigh가 `for`)까지 STRUCT로 걸린다. 즉 STRUCT 태그의 실제 원인은 "do-while
  전용"이 아니라 "Gosleigh의 for/while 프린터 판단 로직이 Ghidra의 판단 규칙과
  다른 축(루프 헤더에 증감식이 있는지 등)을 쓴다"는 더 일반적인 문제로 재확인됐다.
- **다중 조기 return이 있는 루프는 STRUCT + 다중 dangling goto로 스케일된다.**
  `multi_return_early`는 label_0~label_3까지 4개의 미착지 goto가 한 함수에서
  동시에 발생한다(dowhile_count는 1개). 루프 안 조기-exit을 goto로 내리고 못
  접는 패턴이 dowhile_count류의 단일 사례가 아니라 개수에 비례해 반복됨을 확인.
- **`bit_mask_shift_combo`: 상수 shift-left가 `<<`가 아니라 곱셈으로 출력된다.**
  골든은 `(param_1 >> 8 & 0xff) << 8` 형태를 유지하는데 Gosleigh 출력은
  `(param_1 >> 8 & 0xff) * 0x100`으로 나온다(상위 16비트 항도 마찬가지로
  `>> 0x10) * 0x10000`). `classify.py`에는 이 축(SHIFT vs MULT 표현 선택)을 보는
  휴리스틱이 없어 UNKNOWN으로 빠졌지만, 실제로는 캐스트/포인터/템프 어느 것도
  아닌 새로운 종류의 프린터 표현 갭이다. 추가로 골든은 상위 비트 항을
  `(x>>16 & 0xffff)<<16`을 아예 `x & 0xffff0000`으로 대수적으로 접었는데
  Gosleigh는 이 단순화 자체를 하지 않는다 -- 두 가지 원인이 겹친 사례.
- **`cond_assign_abs`: 로컬 변수 선언문 자체가 출력에서 사라진다.** 골든은
  `undefined4 local_18;`을 선언한 뒤 대입하는데, Gosleigh 출력은 선언 없이
  바로 `local_18 = param_1;`로 시작한다(컴파일 불가능한 C가 나온다는 뜻).
  `classify.py`의 TEMP 휴리스티크는 식별자 집합만 비교해서 놓쳤지만, 이건
  "여분 임시변수"가 아니라 "필요한 선언이 통째로 빠짐"이라 TEMP의 정의와도 다른
  현상이다. 이번 코퍼스에서 처음 관찰된, 잠재적으로 심각한 신규 갭.
- **`param_reuse_accum`: 대수적 항 정리(term-collecting) 단순화 누락.** 소스는
  `a=a+b; a=a*2; a=a-b; return a;`인데 골든은 이를 `param_1 * 2 + param_2`로 완전히
  접었고, Gosleigh는 `(param_1 + param_2) * 2 - param_2`로 계산 순서를 그대로
  보존한다. 값은 동치이지만 Ghidra의 RuleCollectTerms류 규칙이 하는 다항식 정리를
  Gosleigh가 아직 안 한다는 신호 -- STATUS.md의 "param_2 재사용" 이슈와는 달리
  이번엔 바이트/값 버그가 아니라 순수 표현식 단순화 갭이다.
- **`array_reverse_sum`: 부호 비교의 정준형(canonical form) 불일치.** 골든은
  `-1 < local_18`으로, Gosleigh는 `0 <= local_18`으로 출력한다(둘 다 참인 조건은
  동일). SUB+signbit 계열 CBRANCH를 부등식으로 되돌릴 때 Ghidra와 Gosleigh가 서로
  다른 정준형을 고른다는, corpus2에는 없던 새로운 사소한 프린터 규칙 차이.
- **`bit_rotate_left`: 리터럴 U 접미사 불일치.** 골든은 `0x20 - param_2 & 0x1f`로
  U 없이 출력하는데 Gosleigh는 `0x1fU`로 U를 붙인다. 같은 함수 안 다른 곳의
  `0x1f`(첫 줄)에는 U가 안 붙는 것과도 대조적 -- unsigned 상수 리터럴 접미사 출력
  조건이 문맥에 따라 골든과 어긋나는 사소하지만 명확한 신규 신호.

### UNKNOWN 5개 개별 소견 (강제 분류 없이, diff 직접 확인)

- `array_reverse_sum` -- MISMATCH 원인은 위 "정준형 불일치" 항목 그대로: 부호 비교
  표현만 다르고 로직은 동일. 분류기 태그로는 딱히 넣을 곳이 없어 UNKNOWN이 맞다.
- `bit_mask_shift_combo` -- 위 "shift가 곱셈으로 출력" + "마스크 단순화 누락" 두
  원인이 겹친 사례. 새 SHIFT/MULT 태그가 생기기 전까지는 UNKNOWN이 맞는 분류.
- `bit_rotate_left` -- U 접미사 하나 차이뿐이라 STRUCT/TYPECAST/PTR/TEMP 어디에도
  해당 안 됨. 사실상 NAMING/포맷팅 수준의 초경미 갭이지만 리터럴 접미사는
  현재 태그 어휘에 없어 UNKNOWN.
- `cond_assign_abs` -- 로컬 선언문 소실은 이번 코퍼스에서 가장 걱정스러운 케이스.
  TEMP의 "여분/부족 식별자" 정의에 안 맞고(식별자 집합 자체는 동일), 다른 태그도
  안 걸림 -- 분류기가 못 잡는 것이 맞지만 엔진 쪽에서는 우선순위 있게 봐야 할
  후보로 본다(수정은 이 태스크 범위 밖, pkg/ 무수정 규칙).
- `param_reuse_accum` -- 대수적 항 정리 누락. 값은 맞고 구조도 goto/cast 문제가
  아니라서 기존 태그 어디에도 안 걸림. UNKNOWN이 정직한 분류.

### 툴 사용 중 발견한 점

- `goldengap.py all`은 32개 함수(신규 29 + 기존 3)까지 별문제 없이 한 번에
  MSVC 컴파일 -> Ghidra 12 헤드리스 -> Gosleigh 실행 -> 분류까지 완주했다(약
  8분 내외, 대부분 Ghidra 헤드리스 기동 시간). ENGINE-ERR/PANIC 태그가 하나도
  없어 `cmd/goldengap`도 32개 전부에서 안정적으로 동작을 확인.
- `classify.py`의 한계는 README에 이미 문서화된 대로였고, 이번에 실측으로 새로
  드러난 것은 위 "신규 갭 신호" 절의 SHIFT-vs-MULT, 선언 소실, 대수적 단순화,
  비교 정준형, 리터럴 접미사 5가지다. 툴 자체의 버그(크래시/오분류)는 발견하지
  못했다 -- 전부 "분류기 어휘에 없는 새로운 갭 종류"이지 툴 오작동이 아니다.

