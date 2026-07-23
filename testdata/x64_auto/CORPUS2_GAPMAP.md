# corpus2 gap map (classifier validation)

goldengap.py 자동 생성 문서 (수동 편집 금지 -- `py -3 tools/goldengap/goldengap.py report`로 재생성).

10/13 MATCH (indent-insensitive).

## 함수별 분류

| 함수 | 태그 | 근거 |
|---|---|---|
| `dowhile_scan` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `find_pair` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `gate` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `clamp3` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `add_pt` | NAMING | NAMING: identical token structure; only identifier names differ |
| `bump_scores` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `sum_via_pp` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `divmix` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `helper_sum` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `caller` | TYPECAST, TEMP, CALL | TYPECAST: cast (ulonglong): want=0 got=16<br>TEMP: extra temp/local identifiers in output (4 vs 2): local_146, local_92, uVar1, uVar2<br>CALL: suspicious call target(s) in output: local_146, local_92<br>CALL: call(s) present in golden but missing in output: helper_sum |
| `parse_steps` | MATCH | MATCH: byte-identical (indent-insensitive) |
| `faverage` | TYPECAST, FP | TYPECAST: cast (void): want=0 got=1<br>FP: golden uses float/double, output has none (FP subsystem gap)<br>FP: output drastically smaller than golden (9 vs 44 tokens) -- stub/empty body |
| `umulhi` | MATCH | MATCH: byte-identical (indent-insensitive) |

## 태그 분포

- CALL: 1
- FP: 1
- MATCH: 10
- NAMING: 1
- TEMP: 1
- TYPECAST: 2


## corpus2 사람 분류(P1~P8) 대조

testdata/x64_corpus2/README.md의 사람 분류와 이 분류기의 자동 태그를 비교한다.

| 함수 | 사람 분류 (README) | 자동 태그 | 일치 |
|---|---|---|---|
| `dowhile_scan` | P1 (struct) | MATCH | MISS |
| `find_pair` | P1 (struct) | MATCH | MISS |
| `gate` | P3/P4 (temp + De Morgan) | MATCH | MISS |
| `clamp3` | P1 (struct) | MATCH | MISS |
| `add_pt` | P5 (struct register packing) | NAMING | MISS |
| `bump_scores` | P2 (wrap) | MATCH | MISS |
| `sum_via_pp` | P3/P5 (temp + ptr scale) | MATCH | MISS |
| `divmix` | MATCH | MATCH | MATCH |
| `helper_sum` | P6 (stack param) | MATCH | N/A (no clean category -- known classifier limitation) |
| `caller` | P7 (call target/reloc) | TYPECAST, TEMP, CALL | MATCH |
| `parse_steps` | P1 (struct) | MATCH | MISS |
| `faverage` | P8 (FP unported) | TYPECAST, FP | MATCH |
| `umulhi` | P3 (temp propagation) | MATCH | MISS |

대조 가능 12건 중 3건 일치 (N/A 항목은 이름 기준 분류 체계가 달라 대조 제외).

