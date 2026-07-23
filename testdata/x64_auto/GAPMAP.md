# Golden Gap Map

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

26/32 MATCH (indent-insensitive).

## 함수별 분류

| 함수 | 태그 | 근거 |
|---|---|---|
| `sum_loop` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `dowhile_count` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `sum_pp_walk` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `while_pretest_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `loop_forever_break` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `nested_while_matrix` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `while_countdown` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `switch_dense` | TYPECAST | TYPECAST: cast (int): want=1 got=0<br>TYPECAST: cast (uint): want=1 got=2<br>TYPECAST: cast (ulonglong): want=0 got=1 |
| `switch_sparse` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_no_default` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_fallthrough` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_2d_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_init_then_sum` | TYPECAST, PTR, TEMP | TYPECAST: cast (int): want=0 got=2<br>TYPECAST: cast (longlong): want=0 got=2<br>PTR: raw pointer scale '* 4': want=0 got=2<br>TEMP: extra temp/local identifiers in output (3 vs 2): local_423 |
| `array_reverse_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `reverse_bytes_inplace` | TEMP | TEMP: extra temp/local identifiers in output (4 vs 3): iVar1 |
| `bit_mask_shift_combo` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `popcount_loop` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `xor_swap_pair` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `bit_rotate_left` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `unsigned_wrap_compare` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `longlong_combo` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `sign_extend_boundary` | TYPECAST | TYPECAST: cast (char): want=1 got=0 |
| `char_arith_promote` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `short_arith_trunc` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `cond_assign_abs` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `minmax_chain4` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `strlen_style` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `memcpy_style` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `multi_return_early` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `nested_if_ladder_grade` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `param_reuse_accum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `swap_via_temp` | MATCH | MATCH: byte-identical (indent-insensitive) |

## 태그 분포

- MATCH: 26
- PTR: 1
- TEMP: 2
- TYPECAST: 3
- UNKNOWN: 2

