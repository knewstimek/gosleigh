# x86-64 breadth corpus #2 (Ghidra golden, discovery)

기존 `testdata/x64_corpus`(add4/poly4/max3/sum_to_n/sum_array/classify/grid_score/
process -- 산술/비교/단순 for/if/배열/클램프)가 다루지 않는 C 구조로 x64 Ghidra 골든을
새로 만들어 Gosleigh 트리의 갭을 넓게 측정하는 재현 파이프라인. **디스커버리 목적 -- 엔진
무수정, MISMATCH는 실패가 아니라 신호다.**

## ABI / 파이프라인

corpus #1과 동일. MSVC `cl /c /Od /GS-` -> Windows x64 COFF obj -> Ghidra 12 헤드리스
(`x86:LE:64:default:windows`) -> `GenGoldens.java`가 함수별 {name, entry, bytes(hex),
디컴파일 C}를 JSON으로 덤프.

```
py -3 testdata/x64_corpus2/build.py        # corpus.c -> corpus.obj (MSVC x64)
py -3 testdata/x64_corpus2/run_ghidra.py   # obj -> Ghidra 12 헤드리스 -> x64_goldens.json
X64_CORPUS2=1 go test ./pkg/loader/ -run TestX64Corpus2GoldenMap -v   # 갭 맵
X64_CORPUS2=1 X64_CORPUS2_Q=1 go test ... # MISMATCH를 %q(개행 가시화)로 덤프
```

요구: `C:\ghidra12`(analyzeHeadless) + JDK 21 + MSVC VS2022 14.38.33130. `build.py`/
`run_ghidra.py`/`GenGoldens.java`는 corpus #1에서 그대로 복제(경로는 스크립트 자기 디렉터리
기준이라 수정 불필요). `corpus.obj`는 `*.obj` gitignore로 미추적, 바이트는 golden JSON에 포함.

## 함수 (13개 = 12개 구조 + static 콜리 1)

corpus #1이 안 다루는 구조 위주:

1. `dowhile_scan` -- do-while + continue + break
2. `find_pair` -- 2중 루프 + 조건부 조기 return(break-out)
3. `gate` -- short-circuit && / || 혼합 체인(4항)
4. `clamp3` -- 중첩 삼항 연산자
5. `add_pt` -- 8바이트 struct 값 전달/반환(레지스터 패킹, CONCAT44)
6. `bump_scores` -- struct 배열 인덱싱 + 필드 in-place 갱신
7. `sum_via_pp` -- 이중 포인터 순회 + 포인터 증감
8. `divmix` -- signed/unsigned 상수 나눗셈(magic-number division)
9. `helper_sum`(static) + `caller` -- 직접 함수 호출(인자 5개, 5번째 스택 전달)
10. `parse_steps` -- goto 기반 에러 핸들링(공유 fail 레이블)
11. `faverage` -- (탐침) float 산술 -- XMM + 상수풀
12. `umulhi` -- (탐침) 64x64 -> 상위 64비트 곱(32비트 분할, 128비트 중간값)

의도적 비-self-contained 2개(디스커버리):
- `caller`는 `helper_sum`을 호출 -> .text 내부 REL32 relocation.
- `faverage`는 float 상수 3.0을 RIP-relative로 로드 -> `.rdata` 심볼(`___real_40400000`).

이 둘은 로더/reloc + call-target + FP 경로를 자극하고 MISMATCH가 예상된다(그게 목적).

## 갭 맵 (X64_CORPUS2 측정, indent-insensitive)

**8/13 MATCH (2026-07-23 세션7 실측).** 최초 디스커버리 시점 1/13(divmix만)에서 세션4~7에 걸쳐 상향:
divmix / dowhile_scan / find_pair / parse_steps / clamp3 / bump_scores / helper_sum / sum_via_pp.
아래 P1~P8 클래스 분석은 **원본 디스커버리 스냅샷(대부분 해소됨)** -- 잔여 = gate(P4 De Morgan),
add_pt(P5 CONCAT44), caller(P7 reloc), umulhi(P3 -> 세션7 재분류: 내용 byte-identical, PrettyEmitter
줄바꿈만), faverage(P8 FP). 권위 있는 현재 갭은 `../x64_auto/CORPUS2_GAPMAP.md`(자동생성).
아래는 최초 분류(넓이 x 심각도 x 신규성 우선순위)를 이력으로 보존.

### P1 -- 제어흐름 구조화 실패 (신규, 최대 클러스터: 4함수)
`dowhile_scan`, `find_pair`, `parse_steps`, `clamp3`. Gosleigh가 do-while / 2중 루프 +
조기 return / while+공유-goto / 삼항(CMOV)을 구조화하지 못하고 dangling `goto label_N`
(정의 안 된 레이블)로 뱉는다. `dowhile_scan`은 의미 손상까지(포인터 `param_1`을 정수처럼
`(int)param_1 + iVar2`로 사용), `clamp3`은 미해결 임시 `local_306` 참조. corpus #1의
단순 for/if는 구조화가 됐으나(그래서 8/8), 이 4패턴에서 무너진다. **가장 넓고 심각한 신규
신호.** 루트: 구조화 액션(Ghidra ActionBlockStructure 계열의 do/while + 중간이탈 + 조건
collapse)이 미완.

### P2 -- 라인 랩 (emit, 최저비용 near-miss: bump_scores)
`bump_scores`는 토큰/타입/구조가 전부 일치하고 **유일 차이가 한 줄 랩**이다. Ghidra는 store
대입을 ~80칼럼에서 개행+연속들여쓰기로 접지만 Gosleigh PrintC는 한 줄로 뱉는다. 라인 폭
splitter만 넣으면 MATCH. 격리된 PrintC 이슈, ROI 최고.

### P3 -- 단일사용 임시 전파/인라인 (umulhi 외)
`umulhi`는 토큰 스트림이 거의 일치하나 Ghidra가 인라인한 `a>>0x20`, `a&mask` 등을 Gosleigh는
명명 임시(uVar4/uVar5...)로 남기고 `param_1`을 재사용해 덮어쓴다. copy-propagation/CSE 깊이
갭. `sum_via_pp`/`gate`의 여분 임시도 같은 뿌리.

### P4 -- short-circuit / De Morgan (gate)
`gate`는 Ghidra가 De Morgan + 분기 반전으로 소스 순서(`((a<1)||(b<1)) && (...)`, else-first)
형태를 복구하나 Gosleigh는 양성형(`(1<=a)&&(0<b) || ...`) + then/else 스왑 + 괄호 그룹핑
차이 + 미선언 `iVar1`. 기존 BlockCondition(&&/comma/De Morgan) 갭과 중복. 혼합 3항+ 케이스로
확장.

### P5 -- 타입/포인터/struct 복구 (기존 type-model deep-debt와 중복)
- `sum_via_pp`: 포인터 원소 스케일링 미적용 -> Ghidra `param_1 + param_2`(원소 단위)를
  Gosleigh는 raw 바이트 `param_1 + lVar1 * 8`, 증분도 `+ 1 * 8`. ptradd 타입화 갭.
- `add_pt`: 레지스터 패킹 struct(8바이트, .x/.y 두 int)를 Ghidra는 CONCAT44 + SUBPIECE로
  분해하나 Gosleigh는 두 8바이트 param을 통짜 long으로 더해(`(undefined4)(param_1+param_2)`)
  의미 오복구. 신규 sub-case(CONCAT44 field 분해).

### P6 -- 스택 파라미터 복구 (helper_sum)
5번째 인자가 스택 전달(`[RSP+...]`)인데 Gosleigh는 4개만 복구하고 `param_5`를 미해결
`tmp_0`로. register-param(RCX/RDX/R8/R9)은 되나 그 이상 스택 인자 미복구.

### P7 -- call-target + relocation (caller, 기존 알려진 갭 (a))
base 0에 단일 함수 바이트만 먹여 REL32 call 변위가 범위 밖 -> `local_92()`, `local_146()`
(가짜 주소 호출), param/return 전부 유실. IOP-space CALLIND 타깃 복구 + COFF reloc 로더
부재(known (a))와 동일. 예상된 결과.

### P8 -- FP 서브시스템 미포팅 (faverage, 기존 알려진 갭)
float 파라미터(XMM) + FP p-code op(ADDSS/DIVSS) 미모델 -> `void faverage(void){return;}`로
전부 소실. RIP-relative 상수도 미해결. 예상된 탐침 결과.

## 알려진 갭과의 중복

- P5/P3 = STATUS #(b) type-model deep-debt(uVar1 return-split, 단축타입명) 계열.
- P4 = 기존 BlockCondition De Morgan 갭 확장.
- P7 = STATUS #(a) reloc/COFF 로더 + IOP-space CALLIND.
- P8 = 미포팅 FP 서브시스템.
- **P1(제어흐름 구조화)과 P2(라인랩), P6(스택 파라미터)는 corpus #2가 새로 드러낸 신규
  신호.** 특히 P1이 실사용 함수 대부분을 막는 최우선 후보.
