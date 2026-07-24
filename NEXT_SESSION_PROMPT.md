# 다음 세션 프롬프트 (2026-07-23 세션6 작성, 엔진 tip `32fb2b6`)

## THE mission (절대 잊지 말 것)
Ghidra C++ 디컴파일러 엔진을 Go로 **byte-identical** 포팅. 실제 .sla(x86/x64/ARM) 로드해 임의 실제 함수를
Ghidra와 같은 C 출력까지. x64 실함수(register param) 성공이 명시 목표.

## 핵심 규칙 (반드시 지킬 것)
**원본 C++ parity 최우선. 추정/근사/휴리스틱 절대 금지.** golden이 통과해도 C++과 다르게 동작하면(unfaithful)
되돌린다. green이어도 의미 손상이면 착지 금지. 가설을 코드로 박기 전에 실측(decomp_dbg/ssadiff).
**선행 진단도 실측으로 재검증하라** (세션4 반증 3회). **붕괴형 mismatch(빈 함수/미초기화 read/CFG 파괴)는
입력 무결성부터 의심하라** -- 세션5에서 "엔진 갭"이 골든 bytes 손상(GenGoldens island 버그)으로 반증됨.

## 현재 상태 (master `f541dc6` origin 푸시, 전 게이트 green -- 세션11 반환타입 fix + 감사맵 실측 재검증)
- tree 10/10, x64 corpus 8/8, op_switch byte-MATCH, breadth 3/3, corpus2 **10/13**,
  x64_auto **60/61**(세션11 프로브 20건 추가로 분모 증가, switch_dense만 non-match),
  production PASS, `go test ./...` green, `go vet ./pkg/...` clean.
- **[세션11]** 반환타입 LOAD-경계 fix 착지(`0720f83`): `inferReturnType`의 `hasArithmeticAncestor`가 LOAD의
  주소 산술을 따라가 raw memory-read 반환을 잘못 int로 승격하던 것을 LOAD 경계에서 차단(undefined%d 유지). +
  goldengap 프로브 10건으로 감사맵 #1 반증/#2 측정불가/#3 부분확정 + 신규 #6(struct 혼합폭 cast 누락) 특성화
  (아래 감사맵 세션11 블록). 잔여 golden = switch_dense(imagebase 하네스) + corpus2 add_pt/caller/faverage.
- 세션8/9/10 상세는 CHANGELOG. 다음 작업은 아래 "다음 작업" + 감사맵(세션11 블록 = 최신).

### [세션10 후속 감사맵] 비-룰 레이어 무표기 HOT divergence -- 다음 세션 최대 광맥
룰 감사(12건 완결)를 엔진 나머지로 확장. `known mismatch` 마커 ~200개는 **전부 명시 선언**(숨은 휴리스틱 아님,
대다수 DORMANT). 문제는 **무표기(선언 안 된) HOT divergence**. Opus 검증 완료분:

| # | 위치 | C++ 참조 | gap | 상태 |
|---|---|---|---|---|
| 4 | action_mark.go checkImpliedCover | coreaction.cc:3408 `op->isCall()` | `CPUI_CALL` 리터럴 -> CALLIND/CALLOTHER 누락 | **착지 `48bd5b4`** |
| 5 | action_infertypes.go inferPropagateEdge | typeop.cc:2270 TypeOpPtradd | PTRADD 타입전파 미배선(배열인덱스마다 끊김) | **착지 `48bd5b4`** |
| 1 | addtreestate.go AddTreeState | ruleaction.cc:6036-6069/6463-6493 | 2-pass distribute fixup(preventDistribution/isDistributeUsed/distributeIntMultAdd) 부재 = 단일 pass 반쪽포팅. `ptr[(x+y)*c]` 인덱싱 재구성 shape/term-set divergence | **미착지(최대/최난)** |
| 2 | merge.go MergeMarker | merge.cc:846-882 mergeIndirect | addrForce 분기+snipOutputInterference 부재, 모든 marker를 mergeOp 균일 처리. addrForce 로컬이 call 넘어 살 때 | **미착지** |
| 3 | action_mark.go markExplicitBase | coreaction.cc:3024-3065 | isAddrTied fallthrough 예외(ZEXT/SUBPIECE/PIECE)를 무조건 return -1로 축약. 혼합크기 addrtied 로컬 explicit/implied 분류(모든 함수) | **미착지** |

추가 무표기(2차): merge.go mergeAdjacentCopies가 `Type()`(전파값) 비교 -> C++은 `outputTypeLocal/inputTypeLocal`(intrinsic);
mergeAddrTied가 exact (space,offset,size)만 -> C++ overlapLoc 확장 부재. printc.go markPrologueOps/inferSignedConstType는
render-time 근사(선언됨, 후자 주석은 `48bd5b4`로 정정). **착수법: 워커 발견을 그대로 믿지 말고 C++ 원문 실측 검증(세션10에
워커 metatype 오진 반증). 착지 시 전 골든 게이트 -- #1/#3는 출력 shape 바꿀 수 있어 특히 주의.**

### [세션11] 감사맵 #1/#2/#3 실측 재검증 (goldengap 프로브) + 신규 divergence #6~#12

**== 다음 세션 우선순위 맵 (세션11 프로브 발굴, 전부 C++ 실측 확정) ==**
gap이 4개 family로 수렴한다. 각 family는 별개 근본이라 하나씩 단독 세션. 가치×tractability 순:
1. **[최우선] #9 비교 반환/대입 미collapse** (RuleConditionalMove 스텁): `return a==b`가 if/else+stack local로 방출.
   **최다빈도 C 패턴**이라 최고가치. 다부품(룰 포팅 + bool 반환 렌더 + subvar). 상세 아래 #9.
2. **[심각-correctness] param/return recovery 붕괴 2건**: **#7** do-while 누산기(반환값이 EAX->ECX 이동 후 deadcode),
   **#12** 1바이트 반환(SubvariableFlow 후 1바이트 param unjustified -> deadcode). 둘 다 함수가 `void`로 붕괴(계산+반환
   드롭). decomp_dbg ssadiff로 엔진버그 확정. deadcode가 param/return justify보다 먼저 도는 액션순서 의심 공통. 상세 #7/#12.
3. **[타입전파 back-prop family] #6 struct 혼합폭 cast + find_max pointer element**: Ghidra의 풍부한 타입 역전파
   (load-size->pointer, 부호비교->element) 미포팅 -> undefined%d* 유지 + 여분 cast. broad-blast 타입전파. 상세 #6.
4. **[cosmetic 저우선] #8** -x*c 미fold, **#10** for 과승격, dot `;` 줄바꿈(umulhi-class). 동값/형식, 회귀위험 대비 ROI 낮음.
**착수 공통: goldengap 프로브 재추가 -> decomp_dbg ssadiff로 C++ 대조 -> SSA_DUMP_AFTER stage-dump으로 소실/발산 시점
확정(세션11 신설 툴) -> faithful 수정 -> 전 골든+pcode/bridge 발진 게이트. broad-blast(타입전파/copy-prop)는 특히 주의.**

세션11은 감사맵 latent 항목을 **goldengap 프로브(실측)로 확정/반증**했다. 하네스가 단일함수 base-0 격리라
외부콜/전역이 전부 out-of-image인 점이 측정 경계를 규정한다.
- **#1 (AddTreeState 2-pass distribute) 반증**: `arr[(i+j)*3]`(probe_distribute), `arr[i*3+j*3]`(probe_dist_factor),
  `arr[(i+j)*3+j]`(probe_dist_mixed) 3-shape 전부 **byte-identical**. 특히 dist_mixed는 Ghidra가 `(i+j)*3+j`를
  `i*3 + j*4`로 distribute하는 것까지 Gosleigh가 동일 재현. **표준 `ptr[(x+y)*c]` shape에서 divergence 없음**
  (세션10 metatype 반증과 동형). 감사맵 #1 "shape divergence" 주장은 이 shape들에선 미발화. 커밋 `9c4a6f8`(회귀 프로브).
- **#2 (mergeIndirect addrForce) 측정 불가**: addrForce 로컬이 call을 넘으려면 콜이 필요한데 하네스에선 콜리가
  항상 out-of-image(caller와 동일 클래스). probe_addrforce는 `void(void)`+콜리 `local_71`(코드주소를 `local_%x`로
  오명명)로 붕괴 -- 전부 하네스 산물이라 #2를 이 하네스로 clean 측정 불가. **콜리 명명 `func_%x` fallback은
  renderCallTarget(printc.go:4078)에 이미 있으나 direct-const 경로만 -- 콜 타깃이 상수 인식 안 되면 로컬로 샘. 실사용
  (풀이미지 로드)에선 콜이 심볼로 resolve되므로 저영향.**
- **#3 (markExplicitBase) 부분 확정 + 인프라 갭**: C++ coreaction.cc:3024-3065은 addrtied 블록 안에서 ZEXT/PIECE를
  **조건부**로만 return -1 하고 ZEXT(vn 포함 addrtied 출력)/PIECE(내부 struct)는 fall through. Go action_mark.go:99-101은
  `IsAddrTied()||IsMapped()||IsProtoPartial()`을 무조건 return -1로 축약(확정 divergence). 단 **ZEXT 슬라이스만 포팅
  가능**(Contains/LoneDescend 존재), PIECE 분기는 `PieceNode.findRoot`/`isPartialRoot`/`overlapJoin` **미포팅**이라
  faithful 불가. 게다가 clean C로 트리거 난해(array_2d_sum MATCH가 시사하듯 현 코퍼스 dormant). broad blast(explicit/
  implied 분류=전 함수 렌더) 대비 confirmed benefit 없어 미착수. C++ 3062-3065(def=PIECE+in0 protoPartial->explicit)도 Go 누락.

**[신규 #6 -- struct 혼합폭 필드 로드: cast 누락 (HOT, 실측 확정, 미착지=깊은 타입전파)]**
- 재현: `struct PrbS{int a;int b;long long c;}; long long f(struct PrbS*p){return (long long)p->a+p->b+p->c;}`
  (goldengap `probe_struct`). Ghidra: `... + *(longlong *)(param_1 + 2)`. Gosleigh: `... + param_1[2]`
  (**int* 첨자 = 4바이트 read, 8바이트 필드인데 폭 손실 + `(longlong *)` cast 누락**).
- 근본(LOADCAST 계측 확정, ssadump): 세 번째 필드 LOAD는 `PTRADD(RCX,#0x2,#0x4)`(scale 4) 주소 + 8바이트 출력.
  `typeOpLoad.GetInputCast`(typeop_cast.go:411)에서 reqtype=out.type=**int/8**, curtype=주소 pointee=**int/8**
  -> 둘이 같아 `CastStandard`가 nil -> cast 미삽입. **즉 PTRADD pointee가 scale=4인데도 int/4가 아닌 int/8로
  widening됐고(역전파가 8바이트 로드/반환에서 pointee를 덮음), 8바이트 타입이 "longlong"이 아닌 "int"로 오명명.**
  Ghidra는 PTRADD pointee를 scale에 고정(int/4)해 reqtype(longlong/8)과 불일치 -> `(longlong *)` 삽입.
- 두 갈래 수정 필요: (1) **subscript 폭 가드**(printc.go `tryRenderSubscript`): accessSize(load out/store value 크기)를
  받아 `accessSize != pointeeSize`면 subscript 거부(INT_ADD/PTRADD 두 분기 모두). C++ opLoad/checkArrayDeref는
  크기 일치 때만 첨자화(printc.cc:506-537, 899). **단 이 가드만 넣으면 `*(param_1+2)`가 되어 여전히 4바이트(cast
  없음) -- lateral move. 반드시 (2)와 함께.** (2) **진짜 근본**: PTRADD pointee를 scale-크기로 고정(int/4 유지)
  또는 8바이트 int를 longlong으로 명명. 그러면 GetInputCast가 자연히 `(longlong *)` 삽입. 대상=typeop.go
  typeOpPtradd/typeOpLoad PropagateType + 8바이트 int 명명(datatype.go). **broad blast(타입전파)라 단독 세션 + 전
  골든 게이트 필수.** 성공기준: goldengap `probe_struct` MATCH(재추가). 세션11은 (1) 임시 구현 후 (2) 부재로 lateral임을
  확인하고 되돌림 -- 반환타입 LOAD-경계 fix(`0720f83`)만 clean 착지.
- **#6 동류(타입전파 back-prop): `probe_find_max`**(세션11 프로브, 제거). `int f(int*a,int n){int m=a[0];
  for(i=1..) if(a[i]>m) m=a[i]; return m;}`. Ghidra: `int *param_1` + `if(m < param_1[i])`. Gosleigh:
  `undefined4 *param_1` + `if(m < (int)param_1[i])`(여분 cast). 근본=**부호비교 INT_LESS의 int 피연산자 타입을 배열
  element/pointer로 역전파 못함**(TypeOpIntSless/Less::propagateType back-edge). #6과 같은 "Ghidra의 풍부한 타입
  back-propagation 미포팅" family. broad-blast 타입전파. **정리(형식/저severity): `probe_dot`(내적)은 긴 식에서
  `;`가 줄바꿈되는 PrettyEmitter 포맷 차이 = umulhi-class 기존 갭(그룹토큰 스트림), 의미 무관.**

**[신규 #7 -- do-while + accumulator: 누산기+반환값 통째 드롭 (HOT, 심각, C++ 실측 확정, 미착지=flow/heritage 딥)]**
- 재현: `int f(int n){ int i=0,s=0; do{ s+=i; i++; } while(i<n); return s; }` (goldengap `probe_neg`가 아니라
  `probe_dowhile` -- 세션11에 제거, 재현코드는 이 문단). MSVC /Od: i=[rsp](-0x18), s=[rsp+4](-0x14).
  Ghidra: 두 로컬 + `return local_14`(=s). **Gosleigh: `void(void)` -- 누산기 s와 반환값을 통째로 드롭.**
- **입력 무결성 OK 확인**(핸드오프 붕괴형-mismatch 프로토콜): 골든 64바이트 디스어셈블 시 `03c8`(s+=i)/`89442404`(store s)/
  `8b442404`(return-load s) 전부 존재 = 바이트 완전. **decomp_dbg(C++ 코어, 동일 격리 바이트) ssadiff: C++은 s(-0x14
  슬롯)의 phi/`ECX=s+i`/`EAX=ECX`/`return EAX`를 완벽 복구.** 즉 gosleigh 엔진 버그 확정.
- 증상 국소화(ssadiff): gosleigh SSA에 `s0xffffffffffffffec`(-0x14, =s) 전(全) op 부재. gosleigh exit는
  `Block_2:0x3f`(0x37의 return-load `mov eax,[rsp+4]` 스킵) vs C++ `0x37`. **주의: 루프백 라벨 `0xffffffffffffffe8`
  (=-0x18)은 branch-target 버그 아님 -- ssadump blockHeader가 loop-head MULTIEQUAL의 첫 op 주소를 쓰는데 스택 phi가
  varnode 주소(-0x18)를 가지는 display 아티팩트(SeqNum/MULTIEQUAL 배치 이슈). CFG 자체는 정상 추정.**
- **근본 국소화(SSA_DUMP_AFTER stage-dump, 세션11 신설 툴 -- 아래 툴 섹션). [정정: 세션11 초기 "dominance violation"
  주장은 오류 -- 세션10 교훈대로 재검증하니 반증됨. r8 def는 루프 body지만 exit는 body 통해서만 도달 -> r8가 exit를
  dominate함(위반 아님).]** 확정된 기전: **반환값이 ABI 반환 레지스터 EAX에서 누산기 레지스터 ECX로 이동**한 것이 근본.
  - stage1-9: exit(Block 2, 0x37)가 `EAX = ZEXT48(s[-0x14] 스택 reload)` -> `return EAX` (정상, EAX=반환레지스터).
  - stage10 라운드: exit 스택 reload `u = s[-0x14]`가 **store-to-load forward로 in-loop 누산기 `ECX(=r0x8, 0x1e:2 =
    s+i)`로 치환**. 동시에 `return`이 `EAX`->`ECX(0x1e:2)`로 바뀜(+ dead `EAX=ECX` copy 생성).
  - stage13 deadcode: 반환이 ECX(비-반환레지스터)를 참조 -> EAX에 반환값 없음 -> 반환 입력 제거 + dead EAX-materialize
    op 제거 -> `return(#0x0)` -> s 연쇄 deadcode -> `void(void)`.
  C++ 코어는 exit 스택 reload를 forward하지 않고 유지 -> `EAX = [rsp+4]` -> `return EAX`(반환값이 EAX에 남음).
- **수정 방향(가설, 미확정)**: store-to-load forward/copy-prop이 **반환값을 ABI 반환 레지스터(EAX) 밖으로 옮기지
  않도록**(또는 in-loop store를 exit reload로 forward하지 않도록 -- Ghidra는 heritage된 스택 값을 reload로 유지).
  **정확한 culprit 룰/액션 미확정**: stage9->10 사이 액션(actprop pool 내 rule일 가능성 -- 현 stage-dump은 action
  단위라 pool 결과만 봄, rule 단위 계측 필요할 수 있음). SSA_DUMP_AFTER를 그 구간으로 좁혀 확정할 것. C++ 대응 rule
  (RuleLoadVarnode/store-forward 또는 propagateCopy의 반환레지스터 가드)을 찾아 faithful 대조. **copy-prop broad-blast
  -> 전 골든 게이트 + decomp_dbg ssadiff 필수.** 확정 사실: 입력바이트 완전 / C++ 동일바이트로 s 완복구(엔진버그) /
  트리거=do-while+둘째 스택로컬(dowhile_count 단일=MATCH, sum_loop for+accum=MATCH). **흔한 패턴의 심각 correctness
  버그(계산+반환 드롭)라 고우선.** 성공기준: goldengap `probe_dowhile`(재추가) MATCH + ssadiff 100%.

**[신규 #8 -- `-x*c` 정규화 미fold (cosmetic, 저위험이나 발진 룰이라 미착수)]**
- 재현: `int f(int x){ return -x*3; }`. Ghidra: `param_1 * -3`. Gosleigh: `-param_1 * 3`(동값, 미정규화).
  SSA: gosleigh `INT_2COMP(x) * 3` 유지. Ghidra는 2COMP를 계수 -1로 접어 `x * -3`.
- 근본: `Rule2Comp2Mult`(INT_2COMP=>x*-1, 세션10 `60b66a9`)가 MULT-feed 케이스에 미발화 + 중첩상수MULT fold 부재.
  **주의: 이 룰은 RuleMultNegOne과 역쌍 co-pool 발진 이력(세션9 차단/세션10 가드로 착지)이라 발화조건 확대는 고위험.**
  cosmetic(동값)이라 ROI 낮음. 착수 시 `go test ./pkg/pcode/`+`./pkg/bridge/` 발진 게이트 필수.

**[신규 #9 -- 비교 반환/대입 미collapse: `RuleConditionalMove`가 스텁 (HOT, 최다빈도 패턴, 최고가치, 다부품)]**
- 재현: `int f(int a,int b){ return a==b; }` (goldengap `probe_ret_eq`/`probe_ret_lt`/`probe_ret_uge`, 세션11 제거).
  MSVC /Od는 **실제 분기**로 bool을 materialize(`cmp; jne; mov [rsp],1; jmp; mov [rsp],0; mov eax,[rsp]` -- 디스어셈블 확인,
  SETcc 아님). Ghidra: `bool f(int,int){ return param_1 == param_2; }`. **Gosleigh: `undefined4` + `if(c){local=1}else{local=0}
  return local`** -- if/else와 stack local을 그대로 방출(collapse 실패).
- 근본(확정): `rules_misc.go:821 RuleConditionalMove.apply`는 **스텁** -- MULTIEQUAL의 모든 입력이 **동일**할 때만 COPY로
  축약(=C++ 9499-9503 trivial 부분케이스 only). C++ `RuleConditionalMove::applyOp`(ruleaction.cc:9392-9551 +
  checkBoolean:9280 + gatherExpression:9307 + constructBool:9348 + CloneBlockOps)의 **2-입력 conditional-move 본체가
  통째 미포팅**(이름만 같은 룰 = 세션8-10 name-collision 클래스인데 미포착/미표기). SSA 확인: MULTIEQUAL(1,0) +
  조건 `ECX==EDX`가 정확히 형성돼 있음(gosleigh `probe_ret_eq` ssadump) -- 룰만 없어서 미발화.
- **다부품(단일 룰 포팅으로 부족)**: (1) both-constant 케이스(9498-9525, CloneBlockOps 불필요): 블록구조(inblock0/1/
  rootblock/CBRANCH) + path0istrue + `MULTIEQUAL(1,0)`->`INT_ZEXT(cond)`(sz>1) 또는 `COPY/BOOL_NEGATE`(sz==1). ~60-80줄.
  (2) **bool 반환 렌더 미검증(세션11 예측)**: 룰만 넣으면 `local=INT_ZEXT(a==b); return local`(inline시 `return
  zext(a==b)`). `inferReturnType`(printc.go)에 **TYPE_BOOL/zext-drop 처리 없음**(세션11 확인) -> 산출 예측 =
  `undefined4 f(){ return (uint)(a==b); }`(구조는 개선되나 **bool 아님 = non-MATCH**). Ghidra `bool return a==b`엔
  subvariable/bool-flow + 반환타입=bool 추론 추가 필요(현 코퍼스에 bool 반환 MATCH 함수 0개 = 이 경로 untested). 즉
  **both-constant 룰 단독 착지는 partial(project 규범상 미착지)**이라 세션11 미착수 -- 룰+렌더 동반 세션 필요.
  **단, both-constant 룰은 기존 골든에 MULTIEQUAL(상수,상수) 부재라 회귀 0(게이트 증명) -> 룰+렌더를 한 세션에 묶으면
  안전.** (3) 비상수 케이스(BOOL_AND/OR, 9449-9548)는 CloneBlockOps(gatherExpression/constructBool) 필요 = 별도 대공사.
  API 메모(세션11): 블록 in-edge는 `op.Parent()`(BlockBasic).getIn(i) + `asBasic(*FlowBlock)->*BlockBasic`.LastOp()로
  CBRANCH 접근(action_nodejoin.go 선례), BooleanFlip=`HasFlag(PcodeOpBooleanFlip)`, ZEXT 삽입=OpUninsert+OpSetOpcode.
- 대상: rules_misc.go RuleConditionalMove(스텁 교체) + FlowBlock API(In/SizeOut/TrueOut/isBooleanFlip/LastOp) +
  op-surgery(opUninsert/opInsertBegin/opBoolNegate) + 렌더/subvar 검증. **게이트: goldengap probe_ret_eq/lt/uge
  재추가 MATCH + 전 골든 + pcode/bridge 발진 + 구조화 회귀(if/else collapse가 타 함수 오발화 주의).** 세션11은
  스텁임을 실측 확정하고 다부품이라 미착수 -- **이게 다음 세션 최우선(최다빈도 C 패턴).**

**[신규 #12 -- 1바이트 반환/param이 SubvariableFlow 후 void로 붕괴 (HOT, 심각, C++ 실측 확정)]**
- 재현: `unsigned char f(int x){ return (unsigned char)(x & 0xff); }` (goldengap `probe_ret_uchar`, 세션11 제거).
  바이트=`mov [rsp+8],ecx; mov eax,[rsp+8]; and eax,0xff; ret`. Ghidra: `undefined1 f(undefined1 param_1){ return
  param_1; }`. **Gosleigh: `void f(void){ return; }`** -- param/반환 전멸. decomp_dbg(동일 격리바이트): C++은
  `AL = CL; return AL`로 정상(1바이트 subvariable 축소). = gosleigh 엔진버그 확정.
- 근본(SSA_DUMP_AFTER 추적): stage12(deadcode)까진 **정상** -- `EAX = (param&0xff); return EAX`(4바이트). 이후
  **SubvariableFlow가 반환을 1바이트 `CL`(=r0x8:1, param 저바이트)로 축소**(stage17: `return r0x00000008:1(i)`,
  C++의 `AL=CL`와 동형). 그런데 **1바이트 param(CL)이 input prototype에 justify 안 됨** -> 4바이트 체인은 dead(반환이
  CL 씀), 1바이트 CL 참조는 "unjustified input" -> stage18 deadcode가 제거 -> `return(void)` -> 전체 붕괴. C++은
  1바이트 param을 등록해 `return AL` 유지. **액션 순서/justify 문제 의심**: deadcode(stage18)가 activeparam/
  unjustparams(stage19/22)의 1바이트 param 등록보다 먼저 돌아 조기 제거. 대상=SubvariableFlow 후 param/return
  justify(paramactive.go / ActionInputPrototype / unjustparams) + 1바이트 input 등록. **흔한 패턴(바이트/char 반환
  함수)이라 심각.** 성공기준: goldengap `probe_ret_uchar`(재추가) MATCH + ssadiff.
- **[착지 세션11] `probe_memset` 저장 드롭 FIXED** (`markPrologueOps` param-instance 수정): `void f(char*p,int c,int n)
  {for(i) p[i]=(char)c;}`가 for body 비어있게(store 드롭) 방출되던 것. 근본(stage-dump→STORE_DEBUG 계측)=**markPrologueOps
  (printc.go, render 휴리스틱)가 store를 callee-saved spill로 오분류**. 이유: paramVns를 `vn.High()==paramHV`
  AllVarnodes 스캔으로 구축했는데 **1바이트 param 슬라이스(DL)가 param_2의 HV(RDX 8바이트)에 back-link 없어 스캔이 RDX를
  놓침** -> paramVns에 param_2 부재 -> store값 DL이 "비-param 레지스터" spill로 마킹 -> emit 스킵. 수정: paramVns를
  `hv.Instances()`로 구축(authoritative) + val이 param storage에 overlap하면(1바이트 슬라이스) skip. **uchar(#12
  잔여)와는 다른 root**(memset=render 휴리스틱, uchar=subvar deadcode). 전 골든 무회귀. **uchar는 아래 #12에 잔존.**
- **경미(형식/local-type, 별도 세션 불필요)**: `probe_toupper_buf`=사실상 byte-identical, 루프변수만 `undefined4`(golden)
  vs `int`(gosleigh)=local 타입추론 차이. `probe_scale_arr`=WRAP(긴 식 `;` 줄바꿈, umulhi-class 포맷). `probe_dot`도 동류.

**[신규 #10 -- for-loop 과승격 (cosmetic, 저severity, 구조화 회귀위험)]**
- 재현: `int f(int*p,int n){ int s=0; while(n-->0) s+=*p++; return s; }` (goldengap `probe_ptr_incr`, 세션11 제거).
  Ghidra: `while(true){ if(local_res10<1) break; ...; local_res10 += -1; }`. Gosleigh: `for(local_res10=param_2;
  0<local_res10; local_res10+=-1){ ... }`. **의미 동일**(조건 `0<n` === `!(n<1)`), 루프 구조화만 차이 -- gosleigh
  ActionForLoops가 Ghidra가 while(true)+break로 남기는 루프를 for로 승격. 근본 미확정(Ghidra for-승격 가드가
  gosleigh보다 엄격 -- 아마 body가 second iterator(`p++`=local_res8)를 수정 + `n--`가 post-decr-in-condition일 때
  for 거부). **저우선**: cosmetic + 구조화 수정은 정상 for 다수(sum_loop 등) 회귀 위험. 대상 후보 action_forloops.go
  findLoopVariable 가드. C++ 참조: PrintC for-emission + BlockWhileDo 구조화.
- **#10 동류(구조화): `probe_gcd2`**(세션11 프로브, 제거). `while(b){t=b;b=a%b;a=t;}`. Ghidra: `local_res10=param_2`를
  루프 밖 hoist + 임시 `iVar1`. Gosleigh: `while(local_res10=param_2, local_res10!=0){ param_2 = a%b; ... }`
  (init을 while 코마-식에 넣고 param_2를 임시로 재사용). init-hoist vs 코마-폼 + 임시변수 materialization 차이(둘 다
  gcd 정확 계산). cosmetic 저우선, 루프-rotation/변수수명 구조화 영역.

### [세션8 룰 전수 감사 -- 세션10 완결] 동명 다른 룰 12건 전부 착지

세션8 감사가 **Go 룰 156개를 C++ `getOpList`와 기계 대조**해 "이름만 같고 다른 룰" 12건을 확인(전부 `action.go`
`actprop` 실행 중, RulePushMulti만 예외). **세션8: 3건 / 세션9: 4건 + RuleAndMask(`a67beda`)·RuleAndDistribute
(`e336502`) 충실화 / 세션10: 잔여 5건** = **12건 완결, 회귀 0**. 세션10 5건(상세 = CHANGELOG 세션10):
`60b66a9` Rule2Comp2Mult(INT_2COMP=>V*-1, 세션9 co-pool 차단 해소) / `7c0e31c` RuleBoolZext(INT_ZEXT 5형) /
`992ed24` RuleOrCompare(INT_OR (V|W)==0 분해) / `6a8d953` RulePushMulti(死코드 정리) /
`d9d52f0` RuleHumptyOr(INT_OR (V&W)|(V&X)=>V&(W|X), 세션9 발진 해소 -- 상수 a 완전덮음 skip 가드).

**이 광맥(동명 다른 룰)은 소진됨.** 룰 감사 영구 교훈: 이름 아닌 `getOpList`+본체 대조, `action.go`
`actprop.AddRule`이 유일 authority(AddBatch* factory는 테스트 전용), 방향 반대 룰 쌍의 발진은 pcode 배치가
아니라 **pkg/bridge 실디컴파일에서만** 드러날 수 있어 계측(op 마스크 덤프)이 정답 -- HumptyOr↔AndDistribute
사이클을 55858회로 확정한 것이 세션10의 결정타.

전체 12건 표/착수노트는 **CHANGELOG(세션8-10)로 이관**(전부 착지 완료). #7 RuleHumptyOr의 slot-symmetric
RuleAndMask 실험(blast radius 대비 traversal-order 못 잡아 revert)과 최종 가드 근본은 CHANGELOG 세션10 참조.

**룰 착지 공통 게이트(세션9-10 확립 -- 향후 모든 룰/정규화 작업에 적용)**: `go test ./pkg/pcode/`(배치 발진) **+
`go test ./pkg/bridge/ -timeout 90s`(실디컴파일 발진 -- 이걸로만 잡히는 발진 있음) + `go test -timeout 60s ./...`**
-> 5개 loader 골든(TREE_MAP/X64_CORPUS/X64_SWITCH/X64_BREADTH/X64_CORPUS2 각 `-count=1`) -> goldengap run+report(31/32).
**pcode 배치 통과 != 발진 없음.** 방향 반대 룰 쌍(distribute/factor, 2comp/multneg)의 발진은 프로덕션 풀 분리를
봐도 안심 말 것. **발진 진단은 이론 아닌 계측**(op 마스크 덤프로 사이클 확정).

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
  순수 렌더+네이밍 수정. (당시 "잔여"로 적었던 umulhi 줄바꿈/swap_via_temp cover/nd==1 full-faithful은
  **세션8에 전부 해소** -- umulhi `ee6dde2`, swap `365aa20`+`f3dc442`, nd==1 phantom누출 가설은 detached op로 반증.)
  상세 CHANGELOG 세션6 후속4 + 세션8-2.
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
- **SSA stage-dump (세션11 신설, action.go)**: `SSA_DUMP_AFTER="heritage,deadcode,returnrecovery,restructure_varnode,
  merge,setcasts,..." go run ./cmd/ssadump --golden <골든> --func <이름> 2>stages.txt` -- 액션명 substring 매칭 시
  그 액션 직후 전(全)함수 SSA를 stderr로 덤프. **ssadump는 최종 SSA만 보여주지만 이건 파이프라인 stage별 스냅샷**이라
  varnode/op가 **언제** 사라지는지 정확히 짚는다(세션11에 #7 do-while의 s 소실을 store-forward dominance 위반으로
  국소화한 결정타). env 미설정 시 완전 inert(액션당 문자열 비교 1회). 액션명 목록 = action.go `NewAction*("...")`
  + GetName()(heritage/guardreturns/returnrecovery/deadcode/restructure_varnode/returnsplit/activereturn/merge*/
  copymarker/setcasts 등). 반복 파이프라인이라 같은 액션이 여러 라운드 덤프됨(라운드별 diff로 전이 추적).
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


### [아카이브] 세션6/7-era (A0)/(A)/(B)/(C) 블록 삭제됨
이 블록들은 bit_rotate/while_countdown/popcount/swap_via_temp/umulhi/sign_extend/reverse_bytes/gate/array_init을
"다음 작업"으로 나열했으나 **세션8에 전부 MATCH**가 되어 stale이라 삭제했다(완료 서사는 CHANGELOG 세션8-1~17).
살아있는 forward 부채는 위 "[2026-07-24 세션8 결과]" 블록 + docs/STATUS.md "잔여 부채"에 이미 반영돼 있다:
- **A2 param-recovery 완전 대체**: 옛 `ApplyActiveParamModel`(IsParamOffset 휴리스틱)을 C++ `ActionInputPrototype`
  (coreaction.cc:4718, fixateproto에서 최종 SSA로 input map 재유도) + `ProtoStoreSymbol::setInput` Symbol 재생성으로
  대체. 세션8-6이 naming 계층으로 우회한 부분의 진짜 근본. `FuncProto.resolveModel`+`deriveInputMap` 기반.
- **BlockBasic::isComplex leaf faithful 포팅**(block.cc:2388): 40d00a3 스텁, 6게이트 회귀 이력. pre-structure SSA 축.
- **SeqNum.Order 전역 stale**: cover만 국소 해결(97084fa). double.go/funcdata.go/rules_misc.go/merge.go 정렬 소비자는
  여전히 decode order -- 측정 실패 없음. 완전 포팅은 Order를 opTree 맵 키에서 분리 필요.
- **switch_dense**(x64_auto 유일 잔여): imagebase/reloc 주소 상수. caller처럼 하네스 한계일 가능성 -- 착수 전 확인.

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
