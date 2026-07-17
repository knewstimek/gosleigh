# Golden Gap Map

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

13/32 MATCH (indent-insensitive).

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
| `cond_assign_abs` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `minmax_chain4` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `strlen_style` | STRUCT, TYPECAST | STRUCT: keyword 'while': want=0 got=1<br>STRUCT: keyword 'for': want=1 got=0<br>TYPECAST: cast (char): want=1 got=0 |
| `memcpy_style` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `multi_return_early` | STRUCT, TEMP | STRUCT: dangling goto target(s) in output: label_0, label_1, label_2, label_3<br>STRUCT: keyword 'while': want=1 got=0<br>STRUCT: keyword 'for': want=0 got=1<br>STRUCT: keyword 'break': want=1 got=0<br>TEMP: extra temp/local identifiers in output (2 vs 1): uVar1 |
| `nested_if_ladder_grade` | STRUCT, TEMP | STRUCT: dangling goto target(s) in output: label_missing<br>TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |
| `param_reuse_accum` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `swap_via_temp` | TEMP | TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |

## 태그 분포

- MATCH: 13
- PTR: 4
- STRUCT: 8
- TEMP: 10
- TYPECAST: 7
- UNKNOWN: 4


## 수동 요약 (세션4 갱신, 2026-07-17)

report 재실행 시 이 섹션은 덮어써지므로 재생성 후 다시 보강할 것 (툴 개선 후보:
수동 섹션 보존).

### 상태
- 13/32 MATCH. T2 확장 직후 12/32에서 cond_assign_abs가 +1 (phi 선언 억제 가드 수정,
  master d6b7df4 -- markPhiReturnOnly가 실제 스택 심볼 phi의 선언까지 삼키던 버그).
- 남은 UNKNOWN 4: array_reverse_sum(부호 비교 정준형 -1<x vs 0<=x),
  bit_mask_shift_combo(상수 << 가 * 0x100 곱으로 출력 + 마스크 단순화 누락),
  bit_rotate_left(리터럴 U 접미사 비일관), param_reuse_accum(대수적 항 정리 누락 --
  골든 param_1*2+param_2 vs (param_1+param_2)*2-param_2).

### 신규 갭 신호 (corpus2 P1~P8에 없던 것, T2 발견)
- for/while 키워드 선택 불일치는 do-while 전용이 아닌 일반 문제 (loop_forever_break/
  reverse_bytes_inplace/popcount_loop/strlen_style이 do-while 없이 STRUCT).
- 다중 조기 return은 dangling goto 개수 비례 스케일 (multi_return_early: label_0~3).
- register 캐리어-param 저장소 공유로 인한 선언 소실 별건 존재 (gate iVar1,
  reverse_bytes_inplace iVar2) -- 선언 대표가 param 입력이라 isParamName 스킵 +
  캐리어 phi 억제가 겹친 구조. 스택 심볼 가드(d6b7df4)와 다른 메커니즘, 별도 goal 필요.
