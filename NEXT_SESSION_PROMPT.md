# 다음 세션 프롬프트 (2026-07-23 세션6 작성, 엔진 tip `32fb2b6`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. green이어도 의미 손상이면 착지 금지. 가설을 코드로 박기 전에 실측(decomp_dbg/ssadiff).
**선행 진단도 실측으로 재검증하라** (세션4 반증 3회). **붕괴형 mismatch(빈 함수/미초기화 read/CFG 파괴)는
입력 무결성부터 의심하라** -- 세션5에서 "엔진 갭"이 골든 bytes 손상(GenGoldens island 버그)으로 반증됨.

## 현재 상태 (master `4a45f96` origin 푸시, 전 게이트 green -- 감독관 재검증)
- tree 10/10, x64 corpus 8/8, op_switch byte-MATCH, breadth 3/3, corpus2 **10/13**,
  x64_auto **31/32**, production PASS, `go test ./...` green, `go vet ./pkg/...` clean.
- x64_auto 잔여 **1건** = **switch_dense**. (룰 감사 잔여 10건은 아래 표 -- 다음 세션 최대 광맥)
  corpus2 잔여 **3건** = **add_pt** / **caller** / **faverage**.
- 세션8 상세는 아래 "[2026-07-24 세션8 결과]" 블록 + CHANGELOG 세션8-1~12.

### [세션8 룰 전수 감사] 동명 다른 룰이 **12건 더** 있다 -- 다음 세션 최우선 광맥

세션8에 `RuleSubRight`/`RulePushPtr` 2건이 "이름만 같고 완전히 다른 룰"로 드러나 포팅했는데, read-only 감사
워커가 **Go 룰 156개를 C++ `getOpList`와 기계 대조**한 결과 같은 유형이 **12건 더** 나왔다. **전부 `action.go`
`actprop`에 실제 등록되어 실행 중이다**(RulePushMulti 제외). 대조 총계: opcode 집합 일치 117, 불일치 31,
Go-only 19, C++-only 21(그중 11은 명시적 stub).

| # | 룰 | C++이 하는 일 (위치) | Go가 하는 일 | 우선순위 |
|---|---|---|---|---|
| 1 | ~~`RuleXorCollapse`~~ | `{INT_EQUAL,NOTEQUAL}` `(V^W)==0 => V==W` (ruleaction.cc:4058) | `{INT_XOR}` 항등원 정리 | **착지 `31539bc`** (기존 본체는 `RuleXorIdentity`로 보존) |
| 2 | `RuleZextEliminate` | `{EQUAL,NOTEQUAL,LESS,LESSEQUAL}` `zext(V)==c => V==c` (2491) | `{INT_ZEXT}` COPY/fold | **최상** |
| 3 | `RuleShiftPiece` | `{INT_ADD,OR,XOR}` `(zext(V)<<16)+zext(W) => concat` (3773) | `{INT_LEFT,RIGHT}` -- **RuleConcatShift와 본체 완전 동일(중복)** | **최상** |
| 4 | `RuleDoubleSub` | `{SUBPIECE}` `sub(sub(V,c),d) => sub(V,c+d)` (1798) | `{INT_SUB}` 산술 뺄셈 접기 | 상 |
| 5 | `RuleRightShiftAnd` | `{INT_RIGHT,SRIGHT}` 시프트 **안쪽** 마스크 제거 (568) | `{INT_AND}` 시프트 **바깥** 마스크 제거(방향 반대) | 상 |
| 6 | ~~`RuleNotDistribute`~~ | `{BOOL_NEGATE}` 불리언 드모르간 (1139) | `{INT_NEGATE}` **비트** 드모르간 | **착지 `31539bc`** (발명 룰은 코퍼스에서 발화 0이라 제거해도 출력 바이트 동일) |
| 7 | `RuleHumptyOr` | `{INT_OR}` `(V&W)|(V&X) => V&(W|X)` (5339) | `{PIECE}` 조각 재결합 | 중 |
| 8 | `RuleOrCompare` | `{INT_OR}` `(V|W)==0 => (V==0)&&(W==0)` (10805) | `{BOOL_OR}` `<`+`==` => `<=` | 중 |
| 9 | `Rule2Comp2Mult` | `{INT_2COMP}` `-V => V*-1` (3979) | `{INT_MULT}` 상수 접기 | 중 |
| 10 | `RuleZextCommute` | `{INT_RIGHT}` `zext(V)>>W => zext(V>>W)` (4844) | `{ZEXT,SEXT}` COPY 우회(RulePropagateCopy와 중복) | 중 |
| 11 | `RuleBoolZext` | `{INT_ZEXT}` `zext(V)*-1` 계열 5형 (3001) | `{EQUAL,NOTEQUAL}` bool 비교만 | 중 |
| 12 | `RulePushMulti` | `{MULTIEQUAL}` 2-branch phi CSE (1062) | phi 입력 동일 치환 -- **Go판은 미등록 死코드**(진짜는 `RulePushMultiME`로 포팅됨) | 하(정리) |

**~~위험 1건~~ (세션8에 해소, `31539bc`)**: Go의 `RuleNotDistribute`는 비트 드모르간으로 식을 **전개**한다(1 op -> 3 op).
그런데 Ghidra에서 되접는 `RuleBitUndistribute`는 Gosleigh에서 **stub**이다. 되돌릴 경로가 없는 **편도 발산**이라
`~(a&b)`가 `~a|~b`로 출력될 위험이 있다. -> **제거 실험 결과 코퍼스 발화 0**이라 출력 바이트 동일했고, C++ BOOL_NEGATE판을 포팅해 넣었다.

**인접 결함(트리거만 역방향, 변환은 동일 -- 기록만)**: `Rule2Comp2Sub`가 C++의 `loneDescend` 요구를 빠뜨려
2COMP 다중 사용 시 부정 연산이 복제될 수 있음(코퍼스 발화 미확인). `RuleNegateIdentity`에 `INT_XOR` 누락.
`RuleConcatShift`는 `INT_LEFT`를 등록해놓고 본체 첫 줄이 `if op.Code()!=INT_RIGHT return 0`이라 **등록이 死**.

**死코드 (먼저 걷어내면 이후 감사 노이즈가 크게 준다)**: `newLoadStoreRuleSet`(rules_loadstore.go:286)과
`newPointerRuleSet`(rules_pointer.go:850)이 **어디서도 호출되지 않아** 그 안의 룰 14건(`RuleLoadConstAddr`,
`RulePtrsubCollapse` 등)이 전부 도달 불가. Go `RulePushMulti`도 미등록.

**가장 오해를 부른 지점(문서화 필수)**: **`action.go`의 명시적 `actprop.AddRule(...)` 목록이 유일한 authority**다.
`AddBatchARules`/`AddBatchC*Rules` factory 목록은 **테스트에서만** 호출된다.

**Go 전용 발명**: `RuleSubRight.applyIntSub`(세션8-10이 남긴 부채, 분리/제거 대상), `RuleOrSextForm`(packed `.sla`가
IDIV를 PIECE 대신 INT_OR로 내는 걸 보정 -- **정당한 발명**, 주석에 의도 명시).
**개명 포팅(기능 갭 아님)**: `RuleSubZextMask`=C++ `RuleSubZext`, `RulePushMultiME`=C++ `RulePushMulti`,
`RuleLessNotEqualBoolAnd`=C++ `RuleLessNotEqual`, `RuleTransformCPool`=C++ `RuleTransformCpool`.

**미확인**: 위 12건의 "예상 영향"은 코드 근거(등록 여부+opcode 집합+본체) 기반이고 **실제 코퍼스 발화 횟수는
미계측**이다. 필요하면 `RuleBase`에 이미 있는 `Rule.GetNumApply()` 카운터에 덤프 훅만 붙이면 된다.

---

### [세션8 착지 완료] 스택 배열 복구 -- `array_init_then_sum` MATCH (master `4a45f96`)
varmap 절반(`varmap.go` 신규 ~470줄: AliasChecker/MapState/RangeHint/adjustFit/createEntry/buildVariableName)과
printc 절반(배열 선언 Symbol 순회 + PTRSUB ScopeLocal 조회 + store 쪽 `checkArrayDeref` subscript)을 **함께** 착지.
varmap만 넣으면 렌더에서 `* 4`가 빠져 C가 틀려지므로 분리 착지하지 않았다.
**숨은 병목이었던 것**: `ResolveSpacebaseSymbol`이 심볼 유무와 무관하게 undefined1을 반환했다 -- 스택 spacebase
input varnode에 `BindSpaceConstant` side-table 항목이 없어서(C++은 space가 `TypeSpacebase::spaceid`에 내장,
Go는 `GetTypeSpacebase`가 인자를 버려 side-table이 유일 통로). 바인딩은 `Funcdata.Spacebase()`로 이관됨.
**남은 부채 2건**: (1) `mergeScopeOnlyDecls`가 Varnode 있는 스코프 Symbol을 제외하는 필터 -- 진짜 근본은
ScopeLocal이 Varnode 소멸 후 stale SymbolEntry를 유지하는 것이고, C++처럼 `ActionRestructureVarnode`가 deadcode
이후 한 번 더 돌면 필터가 불필요해진다(액션 순서 문제). (2) `printc_decl.go CDeclRenderer`의 배열 spacing이
C++ `array_expr`(printc.cc:76, spacing=1)와 불일치해 선언 경로만 `localDeclString`으로 우회 -- 통일 시
`printc_test.go:278-280` 기대값도 함께 수정 필요.

### 잔여 4건의 현재 위치 (전부 실측 확인)
| 함수 | 남은 차이 | 규모 |
|---|---|---|
| `add_pt` | **이름만 다름** -- golden `uStackX_c`/`uStackX_14`(C++ 코어 네이밍, Java DB 변수 없는 슬롯). 어느 슬롯을 Java가 잡았을지 모델링은 순수 휴리스틱이라 **parity 규칙상 금지** | (보류) |
| `caller` | **현 하네스로 strict MATCH 불가**(C++ 코어조차 `func_0x...`). 잔여 실무 = `uVar2 = (ulonglong)param_N;` 죽은 문장(8->4바이트 축소 = consume-bit deadcode/SubvariableFlow) | 중 |
| `faverage` | FP 서브시스템 통째 갭 | 대 |
| `switch_dense` | imagebase/reloc(주소 상수·`&__ImageBase`). caller처럼 하네스 한계 가능성 -- **착수 전 확인 필요** | 대 |
- **세션6 후속5 착지(`53fce49`) = char 리터럴 렌더**: `renderConstant`(printc.go)에 char-print 분기 추가
  (size-1 signed int -> `'\0'`, C++ type.cc:3642 cacheCoreTypes 재현). strlen_style strict MATCH. 상세 CHANGELOG 세션6 후속5.
- **세션6 후속4 착지(`4759d8e`) = (B) print-inline 일부**: `shouldInline`이 nd>1 implied 식을 term-dup
  인라인(printc.go) + `ActionNameVars` explicit-only 네이밍(action_name_vars.go). flag는 이미 C++ 일치였고(실측)
  순수 렌더+네이밍 수정. **잔여**: umulhi 줄바꿈(PrettyEmitter fold), swap_via_temp LOAD cover 오분류(merge),
  nd==1 full-faithful(heritage/merge marker) = 계속 STOP 경계. 상세 CHANGELOG 세션6 후속4.
- **세션6 후속3 착지(`60e01f0`) = for-loop 인식**: `findLoopVariable`(action_forloops.go)가 CPUI_CAST를
  투과하도록 수정 -- 근본은 액션 순서 차이(C++은 finalTransform을 ActionSetCasts 전에 실행, Gosleigh는 후).
  삽입 CAST가 depth-4 예산 소진해 loop-head MULTIEQUAL 은닉하던 것. strlen_style이 Ghidra와 **for 구조 일치**
  (유일 잔차 `!= 0` vs `'\0'` char 리터럴 = printc 상수렌더 STOP 경계라 MATCH 22 유지). 상세 CHANGELOG 세션6 후속3.
- **세션6 착지(`991be09`) = A2 param-recovery undercount**: 충실 `ParamListStandard`/`ParamEntry`/`fillinMap`
  포팅(신규 paramlist.go 709줄) + fixateproto `recoverMissingStackParams`(진짜 fillinMap 소비, IsParamOffset
  휴리스틱 교체). helper_sum 스택 param_5 복구(ssadump 실측, golden 시그니처 일치), caller 5-인자 일치.
  corpus2 6/13 -> 후속 dead-negate 제거로 7/13(A0 완료). 상세 CHANGELOG 세션6.
- **세션6 후속 착지(`ed0bbea`) = dead-negate 제거**: helper_sum body `tmp_0`의 근본 = Gosleigh cleanup 룰
  왕복(RuleSub2Add->RuleMultNegOne->Rule2Comp2Sub)이 만든 orphan INT_2COMP. `Rule2Comp2Sub`가 rewrite 후
  orphan 2COMP 파괴(ruleaction.cc:7254 패리티). helper_sum MATCH, **corpus2 7/13, x64_auto 21/32**. 상세 (A0).
- **세션6 후속2 착지(`f569034`) = multi_return_early**: 근본은 ActionReturnSplit 아님(정확) -- PrintC 이미터가
  `BlockIf` 조건헤드=BlockList일 때 선행 guarded-return 누락+최내곽 오렌더. `emitConditionLead`/`renderCondition`에
  BlockList 케이스 추가(emitBlockLs no_branch/only_branch 미러, printc.cc:2913). **x64_auto 21->22**. 상세 (C).
- 세션5 착지 = 골든 손상 수정(GenGoldens bodyHex 연속 span) + 전 코퍼스 무결성 감사(손상은 x64_auto 2건뿐,
  corpus1/2 무결) + 엔진 9건: cover 인덱스=블록위치(97084fa), LoopBody 포인터 안정성(e19d788), InfLoop
  do/while(true)(0af54ad), RuleCollectTerms 포팅(e908beb), RuleShift2Mult 컨텍스트 게이트(75c6db5),
  RuleDoubleShift 완전 포팅(3fbf15c), PTRADD 렌더 스케일 제거(caf44a2), heritage BuildADT faithful
  포팅(cd42ccb -- Bilardi-Pingali z-chain, clamp3 완결), **param-recovery overcount(ee592a9 -- phantom R8
  param 제거, ActionInputPrototype input-only trial + deadcode 후)**.
  상세 = CHANGELOG 2026-07-17 세션5. stale 워커 worktree 40개 전수 검증 후 일괄 삭제(현재 main뿐).
- 세션4 핸드오프의 (A) dowhile_count/find_pair, (D) 1바이트 반환 캐리어는 전부 완료.

## 툴 (있는 줄 모르면 못 쓴다 -- 착수 전 확인)
- **goldengap**: `py -3 tools/goldengap/goldengap.py all|add|gen|run|report|validate-corpus2` --
  C함수 추가 -> MSVC -> Ghidra headless 골든 -> Gosleigh 대조 -> 갭 자동분류 -> testdata/x64_auto/GAPMAP.md.
  **주의 1**: Gosleigh 단독 재실행은 `goldengap.py run`을 써라 -- bare `go run ./cmd/goldengap`은 -out 없이
  stdout에만 출력해 gosleigh_out.json이 갱신 안 됨(세션5에서 stale 검증 함정 실증). **주의 2**: GAPMAP.md는 전체 자동생성(수동 섹션 없음)이라
  옛 '수동 섹션 덮어씀' 주의는 stale. 실제 한계는 TYPECAST/TEMP 토큰수 휴리스틱이 렌더 근본을 못 짚는 것.
- **ssadiff**: `SLEIGHHOME='D:\News\Utility\리버싱\ghidra_12.0.4_PUBLIC' py -3 tools/ssadiff/ssadiff.py
  --golden <골든.json> --func <이름> --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe --fuzzy`
  -- C++ 코어 vs Gosleigh 최종 SSA op 단위 비교. Gosleigh 쪽만: `go run ./cmd/ssadump`. 사용법
  tools/ssadiff/README.md.
- **decomp_dbg**: `tools/decomp_dbg.exe`(CPUI_DEBUG Ghidra 12.0.4 core 콘솔) -- print C/raw/tree varnode/
  cover high, break start <action>. savefile: tools/captures/. 재빌드/인스트루먼트: tools/BUILD_NOTES.md.
- **바이트 무결성 감사 스크립트**: capstone으로 골든 bytes의 분기 타깃 검사(경계 밖/명령어 중간). 세션5
  scratchpad에서 사용 -- 필요 시 CHANGELOG 세션5 참조해 재작성(수십 줄).
- 골든 파이프라인: testdata/x64_corpus*/ + x64_auto/ (build.py + run_ghidra.py + GenGoldens.java).
  코퍼스 바이너리는 gitignore -- 부재 시 각 build.py 재실행. elfs는 `go run testdata/elfs/gen_import_pe.go`.

## 다음 작업 (우선순위)

### [2026-07-24 세션8 결과 -- 이게 최신 권위] master `2f08090`, x64_auto **29/32**, corpus2 8/13

**착지 8건** (상세 = CHANGELOG 2026-07-24 세션8-1~8):
`365aa20` markImplied cover parity / `636f820` INT_SUB 출력토큰(bit_rotate MATCH) / `f3dc442` **detached op**
(swap_via_temp MATCH) / `09e5cbc` local_res 네이밍 / `8a76c71` RuleAddUnsigned(while_countdown+popcount MATCH) /
`c54d295` **스택 heritage space 등록 + refinement**(sign_extend MATCH) / `2460b6b` 재대입 param 네이밍 /
`3afb5cd` free varnode 스킵(add_pt 구조) / `2f08090` **call-site 입력 trial 포팅**(caller 5-param).

**아래 N1/N2/N3 중 N1/N2는 착지 완료, N3도 착지 완료.** 남은 것은 그 아래 "세션8 이후 남은 작업" 참조.

#### 세션8 이후 남은 작업 (우선순위)
1. **array_init_then_sum 상류 3단** [중~대] -- 아래 (N2') 상세. 이게 뚫려야 varmap/ScopeLocal 작업이 의미를 가진다.
2. **reverse_bytes_inplace** [소?] -- for 헤더 comma 식 `local_10 = param_2 + -1,` 하나만 남음. gcd가 이미
   `while (iVar1 = param_4, ...)`를 내므로 기계는 존재. C++ `PrintC::emitForLoop`/`setMod(comma_separate)`.
3. **gate** [소~중] -- De Morgan 조건형 + then/else 스왑. C++ `BlockCondition` 구성 / `opFlipCondition`의 선택 규칙.
4. **caller 죽은 문장 제거** [중] -- `uVar2 = (ulonglong)param_N;` 누출. C++이 하류 consume-bit deadcode /
   SubvariableFlow로 얻는 8->4바이트 인자 축소가 없어서. call-site trial 포팅과는 별개 근본.
5. **add_pt strict MATCH** [중] -- SUBPIECE(x,4) -> `(int)((ulonglong)x >> 0x20)`, PIECE -> `CONCAT44` 렌더 +
   `uStackX_c`/`uStackX_14` 네이밍(= C++ 코어 `ScopeLocal::buildVariableName`, Java DB 변수가 없는 슬롯).
6. **umulhi** [대, 단독세션] -- printc 표현식 렌더를 flat-string -> 그룹토큰스트림으로 재아키텍처.
7. **faverage** [대] FP 서브시스템 / **switch_dense** [대] imagebase·reloc.
8. **부채**: `ActionInputPrototype`이 fixateproto에서 input map을 재유도하도록(coreaction.cc:4718) +
   `ProtoStoreSymbol::setInput` Symbol 재생성 -- 세션8-6이 naming 계층으로 우회한 부분의 진짜 근본.

#### (N2') array_init_then_sum 상류 3단 [세션8에 probe로 확인, 미착지]
1. `Funcdata.Spacebase()`가 `vn.UpdateType(ptr)`만 한다 -- C++ `funcdata.cc:264`는 `updateType(ptr,true,true)`
   (**lock + override**). 그래서 RSP input의 pointer 타입이 `ActionInferTypes`에 덮여 `int`가 된다.
   probe로 lock을 주면 TYPE_PTR로 유지됨을 확인했다.
2. `action_infertypes.go`의 `inferPropagateIntAdd`가 pointer-forward에서 `return nil`이고 `propagateAddPointer`에
   **`CPUI_INT_ADD` 케이스 자체가 없다**(C++ `typeop.cc:1291-1313` `TypeOpIntAdd::propagateType` /
   `propagateAddIn2Out` / `propagateAddPointer`). 그래서 `RSP + -0x48`의 출력이 포인터가 안 되고
   `RulePtrArith`(`rules_pointer.go:419`)의 `ptrInputSlot`이 실패 -> `AddTreeState` 미진입 -> PTRSUB/PTRADD 없음.
3. 1+2를 probe로 뚫어도 여전히 PTRSUB이 없다 -- `ActionSetCasts`가 `CAST(ptr->int)`를 끼워 체인을 끊는다
   (downChain / TypePointerRel 미포팅 포함).
**증명**: 골든과 동일한 심볼(`stack:-0x48`, size 0x48, `int[18]`, 이름 `aiStack_48`)을 ScopeLocal에 손으로 주입해도
출력이 **바이트 무변화**였다. 즉 상류가 안 뚫리면 varmap(MapState/RangeHint/AliasChecker) 포팅은 출력에 0의 영향.
상류 착지 후 varmap 쪽에서 할 일: `AliasChecker::gatherAdditiveBase/gatherOffset`(varmap.cc:741/817) ->
`MapState::addRange(offset, ptrTo(type), open, minItems=3)`(varmap.cc:1221-1238) -> `ScopeLocal::restructure`의
open 확장 `cur.size = next->sstart - cur.sstart`(varmap.cc:1315) -> `createEntry`가 `0x48/4 = 18 > 1`이라
`getTypeArray`(varmap.cc:617-628) -> `buildVariableName`(varmap.cc:548-581)이 `aiStack_48`.
(참고: `MapState::addGuard` LoadGuard 경로는 사용 불가 -- `heritage.go`의 `loadGuards`/`storeGuards` 필드를
아무도 채우지 않고 `Funcdata.GetLoadGuards()`도 없다.)

---

### [세션8 착수 시점의 read-only 진단 기록 -- N1/N2/N3는 모두 착지 완료]
진단 워커가 decomp_dbg(C++ ground truth, 하네스와 **동일 입력**: 단일 함수 바이트/base 0/unlocked proto) +
계측 사본으로 실측 확정. 착수 순서는 아래 표 순.

**(N1) `local_res` 스택 네이밍 [소, ~30줄, ROI 최고]**
- 스택 로컬 **이름**은 C++ 코어가 아니라 **Ghidra Java(Program DB) 층**이 붙인다(실측: decomp_dbg는
  `uStackX_8`/`uStack_18`, 골든은 `local_res8`/`local_18`; ghidra-ref C++에 `_res` 문자열 없음).
  Gosleigh엔 이미 선례가 있다 -- `scopelocal.go:24-40 localHexName`이 음수 오프셋 `local_%x`를 에뮬레이션 중.
- 골든 `add_pt`가 규칙을 드러낸다: `0x08->local_res8`, `0x0c->uStackX_c`, `0x10->local_res10`, `0x14->uStackX_14`
  = **MS x64 shadow space의 레지스터 param home 슬롯 시작(RCX@8/RDX@0x10/R8@0x18/R9@0x20)만 `local_res%x`,
  그 외 양수는 `uStackX_%x`, 음수는 `local_%x`** (가설 -- 골든 전수 실측으로 확정할 것).
- 영향: `while_countdown`, `popcount_loop`, `array_init_then_sum`, `sign_extend_boundary`, `add_pt` **5개 전부**가
  이 이름 때문에 MISMATCH. while_countdown/popcount는 사실상 이름만 남은 상태.
- 대상: `scopelocal.go localHexName` + 호출부(`funcdata.go:572`, `scopelocal.go:341`, `scopelocal_ext.go:643`).
- 위험: 전 골든 네이밍 영향 -> **TREE_MAP 10/10(x86-32) 회귀 확인 필수**(호출규약이 달라 arch 분기가 필요할 수 있음).

**(N2) 스택 heritage refinement 부재 [중~대, 단독 세션] -- add_pt + sign_extend_boundary 공통 근본**
- 근본(확정): `fd.heritageSpaces`를 `bridge.go:1029 collectHeritageSpace`가 **번역 직후 raw p-code varnode space만**
  수집한다. 스택 varnode는 mainloop 중 `RuleLoadVarnode`/`RuleStoreVarnode`가 만들므로 **영원히 목록에 못 든다**.
  C++ `Heritage::buildInfoList`(heritage.cc:2648-2658)는 `manage->numSpaces()` 전체를 등록해 스택이 항상 포함된다.
  대신 Gosleigh는 `funcdata.go:416-445 heritageNewStackSlots`가 (offset,size) 슬롯 단위로 `heritage.go:1003-1024
  HeritageRange`를 호출하는데, 거기엔 **`refinement` 분할도 `normalizeRange`(SUBPIECE/PIECE 삽입)도 없다**.
  -> 크기 다른 read/write가 같은 offset 키로 rename되어 **8바이트 def가 4바이트 read 자리에 그대로 치환**
  (`ECX(4) = RCX(8) + RDX(8)` = 사이즈 불변식 위반).
- **`normalizeReadSize`/`normalizeWriteSize`는 이미 포팅돼 있다(heritage.go:451-540) -- 도달 경로만 끊긴 것.**
- C++ 참조: `heritage.cc:2599-2645 placeMultiequals`(2608-2616 refinement 진입 조건 `size>4 && max<size`),
  `1890-1938 refinement`, `1704 buildRefinement`/`1733 splitByRefinement`/`1772 refineRead(PIECE)`/
  `1806 refineWrite(SUBPIECE)`/`1836 refineInput`/`1857 remove13Refinement`, `2663-2755 heritage`, `2648-2658 buildInfoList`.
- 대상: `bridge.go:1029-1043`(스택 space 포함) / `funcdata.go:370-445`(슬롯 우회 제거) / `heritage.go:886-990`
  (`refinedSubTaskSize` 근사 -> `Heritage::refinement` 충실 포팅) / `heritage.go:1003-1024 HeritageRange`.
- **실험 실측(~50줄 패치)**: add_pt SSA가 C++ ground truth와 op 단위 일치, 시그니처 `undefined8 add_pt(undefined8,undefined8)`
  골든 일치; sign_extend_boundary는 `int f(short param_1)`로 **param 타입 short 복구**. **회귀 0**(8/8, 8/13, 25/32 유지).
  53함수 중 크기불일치 겹침 스택 슬롯 보유는 add_pt/sign_extend_boundary **2개뿐**.
- **VariablePiece/partial-HighVariable 인프라는 불필요**(C++ 코어가 같은 입력에서 SUBPIECE/PIECE만으로 골든 형태 산출 -- 실측).
- 잔여(별건): SUBPIECE->`(int)((ulonglong)x>>0x20)` / PIECE->`CONCAT44` 렌더, 스택 심볼(`local_res8`) 실체화(ScopeLocal).
- 미측정: x86-32 tree 골든 회귀 영향 -> **착수 시 먼저 확인**.

**(N3) call-site 입력 trial 복구 미포팅 [대, 단독 세션] -- caller**
- **입력 무결성 이상 없음**(capstone: `call 0x2840` 2회, helper_sum entry 정확 착지). reloc/로더/flow 갭 **아님**.
  결정적 근거: 같은 입력으로 decomp_dbg가 `int caller(undefined4 p1..p5) { iVar1 = func_0xffff...c0(p1..p5); ... }`
  로 **5인자를 전부 복구**한다(callee가 이미지 밖이어도).
- 근본: (1) `heritage.go:83-151 guardCalls`가 출력 trial만 등록 -- C++ `heritage.cc:1495-1508`의 `isInputActive()`
  블록(`registerTrial` + `opInsertInput`)이 통째로 없음. (2) `coreaction.go:1166-1171 ActionActiveParam`이
  `ApplyActiveParamModel`(현 함수 proto 전용)만 호출 -- C++ `coreaction.cc:1726-1772`는 `numCalls()` 전체를 순회하며
  `checkInputTrialUse -> finishPass -> resolveModel -> deriveInputMap -> buildInputFromTrials`. (3) 헬퍼 미포팅:
  `checkInputTrialUse`/`finalInputCheck`/`buildInputFromTrials`/`FuncCallSpecs::resolveModel`/`characterizeAsInputParam`.
  `FuncCallSpecs`는 48줄 스텁(`GetFuncdata()` 항상 nil). (4) 연쇄: call 인자 미복구 -> 진입부 shadow-space 스토어 dead
  -> 입력 varnode descendant 0 -> `paramactive.go:786`에서 탈락 -> `void caller(void)`.
- **이미 있는 인프라**: `ParamActive` 완비(paramactive.go:424-736), `AncestorRealistic` 완비, `deriveInputMap`
  완비(paramlist.go:665), **출력 측 전체가 완비(funccallspec_output.go 204줄 + coreaction.go:1207-1225) = 입력 측 포팅의 대칭 템플릿**.
  미포팅: `AliasChecker`(varmap.cc:633-830), 범용 `ancestorOpUse`, `characterizeAsInputParam`.
- C++ 참조: `heritage.cc:1443-1520`(1495-1508), `coreaction.cc:1726-1772`, `fspec.cc:5585-5670`/`5564-5576`/`5685-5745`,
  `fspec.cc:3767 resolveModel`, `fspec.cc:4289 characterizeAsInputParam`, `varmap.cc:633-830`, `printc.cc:3493 genericFunctionName`.
- 대상/규모: `guardCalls`(~50줄) + `ActionActiveParam` call 루프(~40줄) + 신규 `funccallspec_input.go`(~250-350줄,
  output 대칭) + AliasChecker 축소 포팅(~150줄) + `printc.go:4207-4228 nameOf`에 `func_0x%x` fallback(~10줄).
- **게이트 사실(반드시 선반영)**: **caller는 현 하네스로 어떤 완벽한 포팅으로도 strict MATCH 불가**.
  C++ 코어 ground truth조차 `func_0xffffffffffffffc0(...)`를 내고 골든은 `helper_sum(...)`이다(하네스가 함수 1개
  바이트만 base 0에 로드하므로 callee가 이미지 밖). 성공 기준을 **"5인자 + `iVar1 + iVar2` 구조 복구, 이름은 `func_0x...`"**
  로 잡을 것. strict MATCH를 원하면 골든 함수들을 entry 기준 단일 이미지로 로드+심볼 주입하는 **하네스 변경**이 필요(별건, 중).
- 병렬성: (N2)와 독립이나 `heritage.go guardCalls`만 양쪽이 건드리므로 그 함수만 조율.


### (A0) [세션6 후속 착지 완료 `ed0bbea`] dead-negate 제거 -> helper_sum MATCH
근본은 후보 (1)/(2) 둘 다 아니었다(decomp_dbg 실측): dead INT_2COMP는 Gosleigh cleanup 룰 왕복
(RuleSub2Add `V-W=>V+(W*-1)` -> RuleMultNegOne `W*-1=>INT_2COMP(W)` -> Rule2Comp2Sub `V+INT_2COMP(W)=>V-W`)이
만든 orphan(use 0). actcleanup 뒤엔 ActionDeadCode가 없어(universalAction 패리티) 미청소 -> 곱셈 2-use ->
tmp_0. C++ 코어는 이 INT_2COMP를 애초에 미생성. 수정 = `Rule2Comp2Sub.apply`(rules_arith.go)가 ADD->SUB
rewrite 후 orphan 2COMP(`NumDescend()==0`)를 `OpDestroy`(C++ ruleaction.cc:7254 패리티, 살아있는 2COMP는
가드로 미파괴). helper_sum body `- param_4 * param_5` MATCH. corpus2 6->7, x64_auto 20->21(longlong_combo
동반, 같은 orphan temp). 전 게이트 -count=1 2회 무회귀.

### (A) [대형, 고위험] param-recovery 발산 -- 세션5 read-only 진단으로 3갈래 분해 (A1/A2 스택 착지됨)
공통 상위 원인: `pkg/pcode/paramactive.go` `ApplyActiveParamModel`이 C++ `ActionInputPrototype`
(coreaction.cc:4718, fixateproto 그룹, deadcode 다수 통과 이후)의 **조기·축약 대체품**이다. 세션4의
"spurious RDX(sz8)"는 이미 해소됨(param_2는 int 정확). 세 갈래는 별개 근본:

**(A1) overcount -- phantom R8 [세션5 착지 완료 `ee592a9`]**: reverse_bytes_inplace 시그니처 param 3->2
정확화. 근본 = `ApplyActiveParamModel`이 C++ `ActionInputPrototype::apply`(coreaction.cc:4728-4741)와 달리
(1) 전체 varnode bank 순회(C++은 `beginDef(input)..endDef(input)` = **input varnode만**) + (2) 활성 조건
`vn.IsInput() ||` 잉여 절 + (3) deadcode 前 발화. 수정 = 후보를 `isParamLocation && vn.IsInput()`으로 제한
+ 활성 조건 `NumDescend()>0`만(coreaction.cc:4737 `!hasNoDescend()`) + ActionActiveParam을 ActionDeadCode
**뒤로** 재배치(구조적으로 "deadcode 실행됨" 보장). 무회귀 수렴 확인. **잔여**: body `iVar1 = local_10`
(골든 `param_2 = local_10`) carrier는 (B) print-inline/param 계열 잔여(reverse_bytes_inplace는 여전히 UNKNOWN/MISMATCH, x64_auto 24/32에 미포함).

**(A2) undercount [세션6 스택 param 착지 `991be09`; 잔여 = 완전대체/struct]**: helper_sum param_5(스택 param)는
세션6에 복구 완료(충실 ParamListStandard.fillinMap 포팅 + additive recoverMissingStackParams; body tmp_0는
(A0) dead-negate로 이관). **잔여**: 옛 ApplyActiveParamModel(IsParamOffset) 완전 대체 = updateInputTypes store
재빌드 + unref varnode 실체화; add_pt struct hi/lo + CONCAT44는 별개(param 무관, 스택 overlap load/store). 원래
근본 지도 = `FuncProto.resolveModel`
+ `deriveInputMap`(fspec.cc) 미포팅 -- 트라이얼을 모델 slot에 채워 레지스터 세트 밖 스택 param 복구 +
미참조 input 생성(coreaction.cc:4745-4759). caller의 전 param 소실 + `local_92()` call-target 실패는
helper_sum 프로토가 고쳐지면 연쇄 재확인.

**(A3) 무관 트랙 [세션6에 해소/재분류]**: multi_return_early는 세션6 후속2 착지(PrintC BlockList emitter 버그, ActionReturnSplit 아님, `f569034`).
sum_via_pp 잉여 `lVar1`은 copy-coalesce가 아니라 (B) print-inline(shouldInline이 IsImplied 미소비)으로 재분류(decomp_dbg 실측). => (A3)는 소진, 남은 건 (B).

권장 순서(세션7 갱신): (B) print-inline 부분 착지(후속4 `4759d8e` -- sum_via_pp/sum_pp_walk MATCH) -> **잔여
umulhi 그룹토큰 재아키텍처(아래 (B) 상세)** 또는 A2 잔여(IsParamOffset 완전대체) / swap_via_temp cover(merge) -> (C)/struct 잔여.
- 성공 기준(세션6 완료분): reverse_bytes_inplace 2 param(A1 세션5), helper_sum param_5 복구+body MATCH
  (A2 스택 세션6 + A0 dead-negate). 잔여 성공 기준은 (A2 잔여)/(A3)/(C) 각 항목 참조.

### (B) [대형, 시스템, 단독 세션 권장] pre-structure SSA 정합 -- deadcode/MarkImplied 타이밍
- 세션4 지도 유지: Ghidra는 구조화 전에 ActionDeadCode/ActionMarkImplied 완료, Gosleigh는 print 시점으로
  미룸 -> (1) BlockBasic::isComplex leaf faithful 포팅 6게이트 회귀(40d00a3 known gap 스텁), (2) TEMP
  클러스터(세션7 후속4로 sum_via_pp/sum_pp_walk 해소; 잔여 swap_via_temp[merge cover]/popcount_loop[네이밍]/
  umulhi[줄바꿈=그룹토큰]), (3) SSA parity 부채(phi SeqNum 주소, 블록 병합, return 캐리어 COPY).
- **세션5 추가 부채(같은 축)**: SeqNum.Order가 전역적으로 블록 위치로 유지 안 됨 -- cover는 97084fa로
  국소 해결했지만 다른 Order 소비자(double.go, funcdata.go:1483, rules_misc.go:2745, merge.go:1304 정렬)는
  여전히 stale decode order. 완전 포팅(BlockBasic::insert order 유지)은 Order를 opTree 맵 키에서 분리 필요.
- C++ 참조: coreaction.cc universalAction 순서, block.cc:2388 BlockBasic::isComplex, block.cc:2255/2638
  insert/setOrder.
- **[세션6->세션7 부분 착지 `4759d8e`] print-inline**: 후속4가 `shouldInline`을 nd>1 implied 식 term-dup
  인라인으로 수정(marker/call/branch/store 제외) + `ActionNameVars` explicit-only 네이밍(implied는 Symbol 없어
  이름카운터 미소비) -> **sum_via_pp/sum_pp_walk MATCH**. flag(IsImplied)는 이미 C++ 일치였음(ssadump 실측) =
  순수 렌더+네이밍이었다. **잔여 (전부 STOP 경계)**: (1) nd==1 경로 원본 보존(전면 flag-faithful화 시
  loop-carried PTRADD/CAST가 phi로 explicit 마킹돼 phantom 선언 누출, sum_list 회귀 실측 -- heritage/merge marker),
  (2) **umulhi**: 내용 byte-identical이나 **줄바꿈만 MISMATCH** -- Ghidra는 `+` width-optimal에서 접고 Gosleigh는
  `=` 경계에서 접음. 근본 = **PrintC 표현식 렌더가 하위식을 flat Go 문자열(불투명 content 토큰 1개)로 넘김**
  -> Oppen 코어(prettyprint.go, 이미 충실 포팅)는 굵은 토큰 사이(=/;)에서만 break 가능. 수정 = printc가 이항
  연산자마다 openGroup/closeGroup+break 토큰을 emit(Ghidra pushOp/emitOp 구조, printc.cc) -- 문자열빌드 -> 토큰스트림
  재아키텍처. **대형·고위험(전 함수 포맷 영향), 단독 세션.** (3) gate/faverage 등은 메 별건(De Morgan/FP).
- 착수 전 ssadiff/decomp_dbg로 현 SSA 갭 지도를 함수별로 뽑아 범위 확정.

### (C) [소~중] x64_auto/corpus2 잔여 (24/32 이후)
- switch_dense: 세션5 바이트 정정으로 실바이트 디코드 정상화 -- 잔여는 TYPECAST(cast int/uint/ulonglong
  want/got 불일치) + TEMP uVar2. 기존 "range-check idiom" 설명은 손상 바이트 시절 것이라 stale -- 재실측부터.
- **strlen_style [세션6 후속3+후속5 완료 -- strict MATCH]**: for 구조(후속3 `60e01f0` findLoopVariable CAST
  투과) + char 리터럴(후속5 `53fce49` renderConstant char-print 분기, `!= '\0'`) 둘 다 착지 -> strict MATCH.
- **multi_return_early [세션6 후속2 착지 `f569034`]**: 근본은 ActionReturnSplit 아님(그건 정확, decomp_dbg
  실측). PrintC 이미터가 `BlockIf` 조건헤드=BlockList일 때 선행 guarded-return 누락+최내곽 오렌더 ->
  `emitConditionLead`/`renderCondition`에 BlockList 케이스 추가(emitBlockLs no_branch/only_branch 미러). MATCH.
  교훈: GAPMAP TYPECAST 태그는 오분류였고 반환-캐리어 클러스터(add_pt/caller)와도 무관(그쪽은 A2 계열).
- sum_pp_walk TEMP(lVar1 -- SEXT48 implied 실패, (B) 클러스터). array_init_then_sum PTR `* 4`+local_428
  (스택 배열 미복구 근본 -- PTRADD를 안 거침). sign_extend_boundary
  TYPECAST(longlong_combo는 세션6 dead-negate로 MATCH). bit_rotate_left 리터럴 U 접미사. while_countdown/popcount_loop/swap_via_temp TEMP((B) 계열).
- corpus2 잔여 6건(helper_sum은 세션6 MATCH): gate(&&/|| 그룹핑 + param-as-return, De Morgan P4), add_pt/
  caller(반환 캐리어/call-site = A2 계열), sum_via_pp/umulhi((B) print-inline 재분류, 옛 spurious CAST는 오진), faverage(FP). P5-P8은
  corpus2 README 지도 유지.

## 회귀 가드 (매 수정마다 필수, -count=1 2회 결정성)
- `TREE_MAP=1 go test -count=1 ./pkg/loader/ -run TestTreeFullGoldenMap` (10/10)
- `X64_CORPUS=1 go test -count=1 ./pkg/loader/ -run TestX64CorpusGoldenMap -v` (8/8)
- `X64_SWITCH=1 go test -count=1 ./pkg/loader/ -run TestX64Switch -v` (op_switch byte-MATCH 사수)
- `X64_BREADTH=1 go test -count=1 ./pkg/loader/ -run TestX64BreadthGoldenMap -v` (3/3 사수)
- `X64_CORPUS2=1 go test -count=1 ./pkg/loader/ -run TestX64Corpus2 -v` (**8/13 사수**)
- `py -3 tools/goldengap/goldengap.py run && py -3 tools/goldengap/goldengap.py report` (**MATCH 22 사수**;
  bare `go run ./cmd/goldengap`은 파일 미갱신 주의)
- `go test ./pkg/loader/ -run 'TestMSVC|TestAARCH64|TestX8664|TestX64RegParam|TestPELoader|TestX86PEDecompile'`
- `go test ./...`

## 방법론 (세션5에서 재검증)
- **실측 우선 + 선행 진단 재검증 + 입력 무결성 우선**: 세션5의 최대 리턴은 "엔진 갭"을 골든 손상으로 반증한
  것. C++ 코어에 같은 입력을 넣어 같은 실패가 나면 엔진이 아니라 입력이다.
- **read-only 진단 -> 수정 분리**: clamp3에서 진단 워커가 파일 경계(heritage 금지) 때문에
  diagnose-and-stop으로 정확히 멈춤 -- 경계 명시가 고위험 영역 오염을 막았다. (A) 착수 시 같은 패턴 권장.
- **감독관 병렬 2슬롯**: worktree 격리 + 수정 파일 비중첩 분할(merge/heritage vs collapse/blockaction vs
  rules 계열로 나누면 안전) + 매 landing 스팟체크 + 전매트릭스 -count=1 2회 + cherry-pick + 즉시 push.
  워커 스냅샷 커밋은 분기점이 다르면 충돌 -- 엔진 fix만 cherry-pick하고 스냅샷은 master에서 재생성이 깔끔.
- **worktree 워커 준비물**: 코퍼스 바이너리 gitignore라 `cp -rn /d/News/Business/Gosleigh/testdata/. ./testdata/`
  선행 필수. decomp_dbg는 원본 절대경로 사용.
