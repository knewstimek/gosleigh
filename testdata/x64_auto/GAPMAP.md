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


## 수동 요약 (세션4 갱신 4차, 2026-07-17)

report 재실행 시 이 섹션은 덮어써지므로 재생성 후 다시 보강할 것 (툴 개선 후보: 수동 섹션 보존).

### 상태: x64_auto 15/32 MATCH, corpus2 3/13 MATCH (bump_scores/divmix/parse_steps)
- f0a7a7d 연산자 경계 개행(printlanguage.cc:333 emitOp 대응 EmitBrokenExpr)으로 parse_steps
  corpus2 MATCH. known gap: 최외곽 연산자만 분할 -- 접은 후에도 100자 초과하는 조건(코퍼스에
  없음)은 안쪽 연산자로 더 못 접음. 완전 faithful은 표현식 전체 pushOp/emitOp 토큰 스트림
  포팅 필요 (15 MATCH 회귀 위험, 별도 대형 슬라이스).
- find_pair는 개행이 아니라 collapse(goto->구조화) 잔여.

### 유효한 다음 후보 (우선순위 소견)
1. umulhi 여분 CAST (진행 중), 2. reverse_bytes_inplace 파라미터 복구 발산(spurious RDX sz8 +
   phantom R8 -- ActionActiveParam/heritage sub-register 폭, 고위험이라 SSA 비교기 병행 권장),
3. switch_dense range-check idiom, 4. dowhile_count do-while 구조화, 5. SSA parity 부채 3건
   (phi SeqNum 주소/블록 병합/return 캐리어 COPY -- ssadiff 캘리브레이션 발견).
- b9aff6e TypeOpIntMult getOutputToken(typeop.cc:1627) 착지: umulhi SSA 0x67 여분 CAST 소멸
  (ssadiff 17/18 match, 0 mismatch), C 출력 캐스트 소거. 신규 known gap: 함수 시그니처
  반환 타입이 반환 varnode 타입에서 파생됨 -- C++은 별도 return-recovery (umulhi 시그니처
  longlong vs ulonglong). 후속: 반환 타입 recovery 분리.
- f8a2674 PcodeOp::isMoveable(op.cc:178) faithful 포팅: 기존 isOpMoveableToLast 오휴리스틱
  ("사이 op 전부 branch/dead") 대체 -> popcount_loop/reverse_bytes_inplace for-루프 복구
  (STRUCT 해소, 잔여는 TEMP 명명/param-recovery). strlen_style은 known gap: CAST+INT_SEXT
  잉여로 loop-variable phi가 depth-3 한계(block.cc path[4]) 밖 -- cast 경로 선행 필요.
- ebb21ad 반환 타입 recovery: C++은 ActionOutputPrototype(coreaction.cc:4776, casts보다 선행)이
  시그니처를 확정하고 SetCasts 부호 승격은 시그니처에 미반영 -- Gosleigh print-시점 재파생에
  같은 결과가 나오도록 FuncProto output(INT) 우선 가드. umulhi 시그니처 longlong 골든 일치.
- ccbef67 do-while emit faithful (printc.cc:3200 emitBlockDoWhile no_branch/only_branch):
  이전 세션 "LoopBody exit 선택 버그" 진단은 실측으로 반증 -- collapse는 정확했고 emit이
  front leaf에서 조건을 뽑던 것. dowhile_scan 루프 구조 골든 일치(잔여 = param-reuse
  데이터플로), dowhile_count dangling goto 소멸, find_pair goto 3->2. 신규 소견:
  dowhile_scan accumulator가 param_1(포인터)와 오병합(`(int)param_1 + iVar2`),
  dowhile_count 증가 temp 미병합 + local_18=0 초기화 누락 -- merge/heritage 데이터플로 계열.
