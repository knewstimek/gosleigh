# Golden Gap Map

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

102/103 MATCH (indent-insensitive).

## 함수별 분류

| 함수 | 태그 | 근거 |
|---|---|---|
| `sum_loop` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `dowhile_count` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `sum_pp_walk` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `while_pretest_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `loop_forever_break` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `nested_while_matrix` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `while_countdown` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_dense` | TYPECAST | TYPECAST: cast (int): want=1 got=0<br>TYPECAST: cast (uint): want=1 got=2<br>TYPECAST: cast (ulonglong): want=0 got=1 |
| `switch_sparse` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_no_default` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `switch_fallthrough` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_2d_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_init_then_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `array_reverse_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `reverse_bytes_inplace` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `bit_mask_shift_combo` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `popcount_loop` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `xor_swap_pair` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `bit_rotate_left` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `unsigned_wrap_compare` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `longlong_combo` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `sign_extend_boundary` | MATCH | MATCH: byte-identical (indent-insensitive) |
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
| `probe_distribute` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_dist_factor` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_dist_mixed` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_udiv` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_sdiv` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_smod` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ternary` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_clamp` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_sext` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_charsum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ushr` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_sshr` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ll_shift` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ptrdiff` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_widen` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_narrow` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_mask` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_3d` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_and` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_not` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_wide` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_early_return` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ptr2ptr` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_continue_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_mixed_sign` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_negconst` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_hexbig` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_const64` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_shiftmask` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_deref` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_subscript` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_derefadd` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_load8` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_sum_pos` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_strlen2` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_count_bits` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_short` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_char` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_ll` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_ushort` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_fib` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_power` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_stride_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_reverse_arr` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_bytecopy` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_sum_bytes` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_hash31` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_xor_reduce` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_poly` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_swap_nibbles` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_running_prod` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_memset` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_short_add` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_write_through` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_byte_store2` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_short_ident` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_sign` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_first_neg` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_classify` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_ll_add` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_usub` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_ll_shift2` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_ull` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_ret_uchar` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_find_ptr` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_max_idx` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_count_eq` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_compound` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_clearbit` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_setbit` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `probe_rotr` | MATCH | MATCH: byte-identical (indent-insensitive) |

## 태그 분포

- MATCH: 102
- TYPECAST: 1

