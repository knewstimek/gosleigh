# corpus2 gap map (classifier validation)

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

2/13 MATCH (indent-insensitive).

## 함수별 분류

| 함수 | 태그 | 근거 |
|---|---|---|
| `dowhile_scan` | STRUCT, TYPECAST | STRUCT: dangling goto target(s) in output: label_0<br>STRUCT: keyword 'break': want=0 got=1<br>TYPECAST: cast (int): want=1 got=2 |
| `find_pair` | STRUCT | STRUCT: dangling goto target(s) in output: label_0, label_1, label_2<br>STRUCT: keyword 'while': want=2 got=1 |
| `gate` | TEMP | TEMP: extra temp/local identifiers in output (1 vs 0): iVar1 |
| `clamp3` | STRUCT | STRUCT: dangling goto target(s) in output: label_0, label_1 |
| `add_pt` | TYPECAST, CALL | TYPECAST: cast (int): want=4 got=0<br>TYPECAST: cast (ulonglong): want=2 got=0<br>TYPECAST: cast (undefined4): want=0 got=1<br>TYPECAST: CONCAT/SUBPIECE: want=1 got=0<br>CALL: call(s) present in golden but missing in output: CONCAT44 |
| `bump_scores` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `sum_via_pp` | PTR, TEMP | PTR: raw pointer scale '* 8': want=0 got=2<br>TEMP: extra temp/local identifiers in output (3 vs 2): lVar1 |
| `divmix` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `helper_sum` | TEMP | TEMP: extra temp/local identifiers in output (1 vs 0): tmp_0 |
| `caller` | TYPECAST, TEMP, CALL | TYPECAST: cast (void): want=0 got=1<br>TEMP: extra temp/local identifiers in output (3 vs 2): local_146, local_92, uVar1<br>CALL: suspicious call target(s) in output: local_146, local_92<br>CALL: call(s) present in golden but missing in output: helper_sum |
| `parse_steps` | STRUCT | STRUCT: dangling goto target(s) in output: label_0, label_1<br>STRUCT: keyword 'while': want=1 got=0<br>STRUCT: keyword 'for': want=0 got=1<br>STRUCT: keyword 'break': want=1 got=0 |
| `faverage` | TYPECAST, FP | TYPECAST: cast (void): want=0 got=1<br>FP: golden uses float/double, output has none (FP subsystem gap)<br>FP: output drastically smaller than golden (9 vs 44 tokens) -- stub/empty body |
| `umulhi` | TYPECAST, TEMP | TYPECAST: cast (ulonglong): want=0 got=1<br>TEMP: extra temp/local identifiers in output (5 vs 1): uVar2, uVar3, uVar5, uVar6 |

## 태그 분포

- CALL: 2
- FP: 1
- MATCH: 2
- PTR: 1
- STRUCT: 4
- TEMP: 5
- TYPECAST: 5


## corpus2 사람 분류(P1~P8) 대조

testdata/x64_corpus2/README.md의 사람 분류와 이 분류기의 자동 태그를 비교한다.

| 함수 | 사람 분류 (README) | 자동 태그 | 일치 |
|---|---|---|---|
| `dowhile_scan` | P1 (struct) | STRUCT, TYPECAST | MATCH |
| `find_pair` | P1 (struct) | STRUCT | MATCH |
| `gate` | P3/P4 (temp + De Morgan) | TEMP | MATCH |
| `clamp3` | P1 (struct) | STRUCT | MATCH |
| `add_pt` | P5 (struct register packing) | TYPECAST, CALL | MATCH |
| `bump_scores` | P2 (wrap) | MATCH | MISS |
| `sum_via_pp` | P3/P5 (temp + ptr scale) | PTR, TEMP | MATCH |
| `divmix` | MATCH | MATCH | MATCH |
| `helper_sum` | P6 (stack param) | TEMP | N/A (no clean category -- known classifier limitation) |
| `caller` | P7 (call target/reloc) | TYPECAST, TEMP, CALL | MATCH |
| `parse_steps` | P1 (struct) | STRUCT | MATCH |
| `faverage` | P8 (FP unported) | TYPECAST, FP | MATCH |
| `umulhi` | P3 (temp propagation) | TYPECAST, TEMP | MATCH |

대조 가능 12건 중 11건 일치 (N/A 항목은 이름 기준 분류 체계가 달라 대조 제외).

