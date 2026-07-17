# Golden Gap Map

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

14/32 MATCH (indent-insensitive).

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
| `multi_return_early` | TYPECAST | TYPECAST: cast (int): want=3 got=1<br>TYPECAST: cast (longlong): want=3 got=1 |
| `nested_if_ladder_grade` | STRUCT, TEMP | STRUCT: dangling goto target(s) in output: label_missing<br>TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |
| `param_reuse_accum` | UNKNOWN | UNKNOWN: no heuristic matched -- manual review needed |
| `swap_via_temp` | TEMP | TEMP: fewer temp/local identifiers than golden (0 vs 1), missing: uVar1 |

## 태그 분포

- MATCH: 14
- PTR: 4
- STRUCT: 6
- TEMP: 9
- TYPECAST: 8
- UNKNOWN: 4


## 수동 요약 (세션4 갱신 2차, 2026-07-17)

report 재실행 시 이 섹션은 덮어써지므로 재생성 후 다시 보강할 것 (툴 개선 후보: 수동 섹션 보존).

### 상태: 14/32 MATCH (세션 시작 시점 대비 +14, T2 확장 직후 12 -> 14)
- +cond_assign_abs (d6b7df4 phi 선언 억제 가드)
- +loop_forever_break (852efc3 overflow while(true) 신택스). multi_return_early는
  STRUCT -> TYPECAST로 완화 (3dc1479 ReturnSplit이 dangling goto 4개 제거).
- STRUCT 잔여 6: dowhile_count, switch_dense, reverse_bytes_inplace, popcount_loop,
  strlen_style, nested_if_ladder_grade.

### 유효한 다음 후보 (우선순위 소견)
1. 비교 정준형 + radix: parse_steps 잔여(`0x3e9 <=` vs 골든 `1000 <`)와 x64_auto
   array_reverse_sum(`-1 <` vs `0 <=`)이 같은 계열 -- INT_LESSEQUAL<->INT_LESS 정준화
   (C++ RuleLessEqual) + 10진 radix 선택. 여러 함수 동시 수렴 가능성.
2. register 캐리어-param 저장소 공유 선언 소실 (gate iVar1, reverse_bytes_inplace iVar2)
   -- 선언 대표가 param 입력이라 isParamName 스킵 + 캐리어 phi 억제 겹침. 스택 가드와 별건.
3. dowhile_scan 루프 back-edge 오구조화 (LoopBody/CollapseStructure 루프-exit 선택) +
   별건 param-reuse 데이터플로 버그.
4. BlockBasic::isComplex leaf faithful (40d00a3에서 명시적 known gap 스텁) --
   전제조건이 큼: Ghidra는 구조화 전에 ActionDeadCode/MarkImplied가 끝나 있는데 Gosleigh는
   print 시점으로 미룸. pre-structure SSA 상태 정합화가 선행돼야 하는 대형 작업.
