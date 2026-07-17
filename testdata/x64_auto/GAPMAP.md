# Golden Gap Map

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

15/32 MATCH (indent-insensitive).

## 함수별 분류

| 함수 | 태그 | 근거 |
|---|---|---|
| `sum_loop` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `dowhile_count` | STRUCT, TYPECAST, PTR, TEMP | STRUCT: dangling goto target(s) in output: label_0<br>TYPECAST: cast (int): want=1 got=2<br>TYPECAST: cast (longlong): want=1 got=2<br>PTR: raw pointer scale '* 4': want=1 got=2<br>TEMP: extra temp/local identifiers in output (3 vs 2): iVar1 |
| `sum_pp_walk` | PTR, TEMP | PTR: raw pointer scale '* 8': want=0 got=2<br>TEMP: extra temp/local identifiers in output (3 vs 2): lVar1 |
| `while_pretest_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `loop_forever_break` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `nested_while_matrix` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `while_countdown` | TEMP | TEMP: extra temp/local identifiers in output (2 vs 1): local_8 |
| `switch_dense` | STRUCT, TYPECAST, TEMP | STRUCT: dangling goto target(s) in output: label_missing<br>TYPECAST: cast (int): want=1 got=0<br>TYPECAST: cast (uint): want=1 got=2<br>TYPECAST: cast (ulonglong): want=0 got=1<br>TEMP: extra temp/local identifiers in output (2 vs 1): uVar2 |
| `switch_sparse` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_no_default` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_fallthrough` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_2d_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_init_then_sum` | TYPECAST, PTR, TEMP | TYPECAST: cast (int): want=0 got=2<br>TYPECAST: cast (longlong): want=0 got=2<br>PTR: raw pointer scale '* 4': want=0 got=2<br>TEMP: extra temp/local identifiers in output (4 vs 2): local_428, local_8 |
| `array_reverse_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
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
| `cond_assign_abs` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `minmax_chain4` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `strlen_style` | STRUCT, TYPECAST | STRUCT: keyword 'while': want=0 got=1<br>STRUCT: keyword 'for': want=1 got=0<br>TYPECAST: cast (char): want=1 got=0 |
| `memcpy_style` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `multi_return_early` | TYPECAST | TYPECAST: cast (int): want=3 got=1<br>TYPECAST: cast (longlong): want=3 got=1 |
| `nested_if_ladder_grade` | STRUCT, TEMP | STRUCT: dangling goto target(s) in output: label_missing<br>TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |
| `param_reuse_accum` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `swap_via_temp` | TEMP | TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |

## 태그 분포

- MATCH: 15
- PTR: 4
- STRUCT: 6
- TEMP: 9
- TYPECAST: 8
- UNKNOWN: 3


## 수동 요약 (세션4 갱신 3차, 2026-07-17)

report 재실행 시 이 섹션은 덮어써지므로 재생성 후 다시 보강할 것 (툴 개선 후보: 수동 섹션 보존).

### 상태: 15/32 MATCH (12 -> 13 -> 14 -> 15)
- +cond_assign_abs (d6b7df4 phi 선언 가드), +loop_forever_break (852efc3 overflow while(true)),
  +array_reverse_sum (3c5f21a INT_LESSEQUAL 정준화 + replaceLessequal 마스크 수정).
- a693eaa에서 C++에 없던 invented rule(RuleSLessEqual2Constant) 제거 -- RuleIntLessEqual
  faithful 포팅으로 대체.

### 유효한 다음 후보 (우선순위 소견)
1. register 캐리어-param 선언 소실 (gate iVar1, reverse_bytes_inplace iVar2) -- 진행 중.
2. parse_steps 잔여 = EmitPrettyPrint 연산자 우선순위 개행 (prettyprint.cc) -- 비교/radix는
   골든 일치 완료, 개행만 남음.
3. umulhi P3: SSA 비교기 실측으로 "INT_RIGHT 앞 여분 CAST op 1개"로 특정됨 (tools/ssadiff
   캘리브레이션 참조). 같은 실측에서 byte-MATCH 함수도 SSA 계통 차이 3건 확인:
   (a) phi op SeqNum 주소가 블록 진입 주소 아닌 스택 오프셋, (b) 루프 증분+비교 블록 병합
   차이, (c) return 캐리어 COPY 부재. print C는 같아도 SSA parity 부채 -- 후속 작업 후보.
4. switch_dense: range-check idiom (x-cU < n) 미포팅. dowhile_count: do-while 구조화 +
   변수명. strlen_style/popcount_loop/nested_if_ladder_grade: STRUCT 잔여.
