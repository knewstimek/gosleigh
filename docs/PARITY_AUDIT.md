# Parity Audit

## 원칙

- 이 문서는 Gosleigh 구현이 원본 Ghidra C++와 어디까지 일치하는지 추적하는 용도다.
- 분류 기준은 다음 다섯 가지로 고정한다.
  - `match`: 원본 C++와 동등하다고 확인됨
  - `simplified-safe`: 단순화됐지만 현재 확인 범위에서 의미 차이가 없음
  - `guessed`: 원본 기준으로 동등성이 확인되지 않았음
  - `mismatch`: 원본과 의미가 다름
  - `unimplemented`: 원본에 있는 동작이 아직 없음
- `guessed`, `mismatch`, `unimplemented`는 완료로 취급하지 않는다.
- parity가 속도, 편의, 로컬 단순화보다 우선한다.

## Audit Table

| Area | Go symbol | C++ counterpart | Status | Reason |
|------|-----------|-----------------|--------|--------|
| pattern/decision | `matchPatternBlock()` | `PatternBlock::isInstructionMatch()` / `isContextMatch()` | `match` | packed bytes를 big-endian으로 읽도록 수정했고 회귀 테스트를 추가했다 |
| pattern/decision | `extractBits()` | `ParserWalker::getInstructionBits()` / `getContextBits()` | `simplified-safe` | constructor-relative instruction offset을 반영하고 big-endian bit packing 공식을 원본 기준으로 맞췄다. 다만 아직 full `ParserWalker` 모델은 아니다 |
| pattern/decision | `constructorByID()` | `SubtableSymbol::getConstructor(id)` | `simplified-safe` | constructor id를 명시적으로 보존하고 id lookup으로 바꿨다. 현재 decode 경로에서는 원본처럼 subtable-local id를 사용한다 |
| pattern/decision | `matchPattern()` on `elemCombinePat` | `CombinePattern` composition in `slghpattern.cc` | `simplified-safe` | 원본 `CombinePattern::isMatch()`는 instruction/context 둘 다 만족해야 한다. 현재 구현도 AND semantics는 맞지만, 원본의 고정 구조 표현까지는 아직 반영하지 않았다 |
| lowering | `lowerOpcode()` / `lowerOpTpl()` | `PcodeBuilder::build()` | `mismatch` | special `OpTpl`을 raw opcode로 낮추면 안 되며 control directive는 runtime hook 또는 explicit unimplemented 상태로 분리해야 한다 |
| lowering | `ConstructTplBoundary.Result` handling | constructor result `FixedHandle` propagation | `match` | `runtime.go`에 `ResolveConstructorResult()` / `PropagateConstructorResult()`를 추가해 result propagation 경계를 분리했다 |
| lowering | `lowerVarnodeTpl()` | dynamic `FixedHandle` semantics / `VarnodeTpl::isDynamic()` | `simplified-safe` | direct varnode lowering은 이제 dynamic handle-backed 경우를 strict하게 감지하고, concrete raw varnode로 추정해서 낮추지 않는다. direct path 자체는 original `VarnodeTpl::isDynamic()` guard와 충돌하지 않는다 |
| lowering | dynamic input/output expansion in `lowerOpTpl()` | `SleighBuilder::dump()` / `generatePointer()` | `simplified-safe` | safe subset에 한해 dynamic input은 main op 앞에 `LOAD`, dynamic output은 main op 뒤에 `STORE`를 합성한다. pointer는 handle의 `offset_space/offset_offset/offset_size`를 사용해 만들고, 첫 `LOAD`/`STORE` input은 target space identity를 constant-space 값으로 실어 나른다 |
| lowering | dynamic `v_offset_plus` / unique temp details | `generatePointerAdd()` / `setUniqueOffset()` / `generateLocation()` | `simplified-safe` | `v_offset_plus`는 이제 original low-16 split을 따라 low-16 `0` no-op subset, constant-pointer non-zero low-16 subset, 그리고 non-constant-pointer `INT_ADD` runtime-temp side-op까지 내려간다. `uniqueoffset = (instruction.offset & uniquemask) << 8`도 unique-space location/pointer에 반영된다. dynamic `LOAD`/`STORE`의 space-selector payload는 이제 process-local pointer identity로 내려가서 C++ `(uintp)AddrSpace*` 의미에 더 가깝고, runtime temp unique space도 `ctx.UniqueSpace`가 없으면 `SpacesByIndex`의 unique space를 deterministic fallback으로 찾는다. 다만 cross-run stable parity는 아니고, unique space가 어디에도 없을 때는 typed parity gap으로 남긴다 |
| lowering | `lowerOffsetConst()` / `lowerScalarConst()` | `ConstTpl::fix()` | `mismatch` | `flowref`, `flowref_size`, `flowdest`, `flowdest_size`는 `runtime.go` 쪽으로 이동했지만 `lower.go` 경로는 아직 직접 parity가 아니다 |
| lowering | `NewLoweringContext()` constant space synthesis | `ParserContext::const_space` | `simplified-safe` | 로컬 합성은 유지하지만 parity 핵심은 `RuntimeContext` 쪽으로 이동했다 |
| lowering | `DelaySlot`, `NumLabels` runtime behavior | `PcodeBuilder::build()` label/delay state | `simplified-safe` | `LABELBUILD`는 실행 경로가 들어갔고, `BUILD`는 walker child state를 따라 main/named section 재귀 실행을 한다. named section이 비어 있을 때 `buildEmpty()` 재귀도 들어갔다. `DELAY_SLOT`은 cache loop re-entry 수준까지 들어갔지만 unique-state 복구는 아직 shell이다. `CROSSBUILD`는 cache re-entry named section build 경로까지 들어갔다 |
| runtime | `runtime.go` | `FixedHandle`, `RuntimeContext`, `HandleTpl::fix`, `ConstTpl::fix`, `sleigh.cc` result propagation | `match` | `FixedHandle`, `RuntimeContext`, `ResolveHandleTpl()`, `ResolveConstructorResult()`, `PropagateConstructorResult()`를 추가했다 |
| builder | `AppendBuild()` / `ConstructState.TemplateForSection()` | `SleighBuilder::appendBuild()` | `simplified-safe` | `BUILD`는 walker child state를 따라 main/named section을 선택하고, named section이 없을 때만 `buildEmpty()`로 떨어진다. active walker state 없이 package-level no-op empty recursion으로 조용히 성공하지는 않도록 조였다 |
| builder | `SetLabel()` | `SleighBuilder::setLabel()` | `match` | `LABELBUILD`가 label base를 더한 뒤 실행되도록 연결됐다 |
| builder | `AppendCrossBuild()` / `delaySlotFromWalker()` | `SleighBuilder::appendCrossBuild()` / `delaySlot()` | `simplified-safe` | `CROSSBUILD`는 cache re-entry named section build까지, `DELAY_SLOT`은 cache loop re-entry까지 들어갔다. failure 시 outer walker를 너무 일찍 복구하지 않아 `oneInstruction()` catch rewrite가 failing inner walker를 볼 수 있게 했다. nested lowering의 unique-temp bits는 active walker에서 다시 계산되므로 current cache-backed path에서는 C++ `uniqueoffset` save/restore intent를 이미 충족한다. nested delay-slot end-to-end proof test도 추가됐다. 다만 decode pipeline이 cache를 채우는 경로는 아직 더 올려야 한다 |
| obtain context | `ObtainContext()` / `DisassemblyCache.ObtainParserContext()` | `Sleigh::obtainContext()` / `DisassemblyCache::getParserContext()` | `simplified-safe` | same-address hit reuse, circular slot reuse, address reassignment 시 parse-state reset과 `N2Addr` invalidation이 들어갔다. 다만 Go는 deterministic injection용 explicit `contexts` map을 같이 유지하고, original `minimumreuse/windowsize` guarantee 전체는 아직 아니다 |
| obtain context | typed unimplemented normalization in `obtain_context.go` | `Sleigh::obtainContext()` promotion failure boundaries | `simplified-safe` | disassembly/pcode promotion hook 경계의 sentinel-style `ErrObtainContextUnimplemented`가 typed `*UnimplError`로 정규화된다 |
| mutation | `ParserWalkerChange` shell | `ParserWalkerChange` / `ParserContext::deallocateState()` / `allocateOperand()` | `simplified-safe` | root reset, operand allocation, length 계산, commit reservation shell만 들어갔고 실제 mutation/commit 적용은 아직 hook 경계 뒤에 남아 있다 |
| resolve | `Resolve()` / `resolveFrame()` | `Sleigh::resolve()` | `simplified-safe` | `setDelaySlot(0) -> setOffset(0) -> clearCommits() -> loadContext() -> root resolve -> setConstructor() -> applyContext queue -> operand descent -> calcCurrentLength() -> setNaddr() -> setParserState(disassembly)` 순서를 shell 수준에서 맞췄다. 실제 symbol resolution은 아직 hook 경계 뒤에 있다 |
| resolve | upstream typed unimplemented normalization in `resolve.go` | `Sleigh::resolve()` throw/catch boundary intent | `simplified-safe` | resolve 경로의 sentinel-style `ErrResolveUnimplemented`는 이제 typed `*UnimplError`로 정규화되어 translation catch가 original `catch (UnimplError&)` 형태에 더 가깝게 동작한다 |
| resolve | flow address propagation in `ResolveOutcome` / `resolveFrame()` | `ParserContext.calladdr` / `getRefAddr()` / `getDestAddr()` usage from resolve/oneInstruction path | `simplified-safe` | resolve 결과가 flow address를 `ParserContext`에 실어 나르고, 한쪽만 주어졌을 때는 calladdr-style fallback으로 ref/dest를 같이 채운다. 다만 C++는 single `calladdr` backing이고 현재 Go는 양쪽이 모두 주어지면 split 값을 유지할 수 있다 |
| resolve | `ResolveSubtableDecision()` / `ResolveDecisionNode()` | `SubtableSymbol::resolve()` / `DecisionNode::resolve()` | `simplified-safe` | decision bits 선택과 terminal pair first-match는 원본 흐름대로 들어갔다. 현재 boundary 모델 범위에서는 `elemInstructPat`, `elemContextPat`, `elemCombinePat`, `elemOrPat`만 직접 처리한다 |
| resolve handles | `ResolveHandles()` | `Sleigh::resolveHandles()` | `simplified-safe` | walker state loop, operand push/pop, main template result propagation, parser state 승격 shell은 들어갔다. preserved operand metadata가 있으면 `defexp` 직접 평가와 일부 boundary symbol fixed handle을 자동으로 처리한다. 현재 automatic path는 `ContextSymbol` (ValueSymbol 상속 경로 -- pattern 평가 후 constant-space handle), `ValueMapSymbol` (pattern 평가 -> ValueTable 인덱싱 -> constant-space handle), `Value`, `Name`, `Epsilon` 계열 constant-space handle, persisted `VarnodeSymbol` fixed tuple reconstruction, persisted `VarnodeListSymbol` selector/table reconstruction, 그리고 safe opaque-boundary `inst_dest` / `inst_ref` flow-symbol reconstruction까지 포함한다. sentinel-style `ErrResolveHandlesUnimplemented`도 이제 typed `*UnimplError`로 정규화된다. `runtimeContextForWalker`는 이제 child handles와 `SpacesByIndex`를 함께 전달해 `HandleTpl::fix()` parity를 올렸고, `findWalkerSpaceByIndex`는 `SpacesByIndex` 우선 참조로 바뀌었다. 다만 dynamic varnode-style semantics는 아직 완결되지 않았다 |
| pattern expression | typed unimplemented normalization in `patexpr.go` | `PatternExpression::getValue()` hook/recursive failure boundaries | `simplified-safe` | operand-value hook 및 recursive expression 경계의 sentinel-style `ErrPatternExpressionUnimplemented`가 typed `*UnimplError`로 정규화된다 |
| context cache | `LoadContext()` / `AddCommit()` / `ApplyCommits()` | `ParserContext::loadContext()` / `clearCommits()` / `addCommit()` / `applyCommits()` | `simplified-safe` | local context word load, commit queue, operand-symbol일 때 commit point child handle 사용, constant-space address normalization, non-flow next-address 계산까지 들어갔다. 비-operand symbol의 `getFixedHandle()`와 실제 cache write만 hook 경계 뒤에 있다 |
| instruction context | `ObtainPcodeContext()` / lazy `ParserContext.GetN2addr()` | `oneInstruction()` pre-build context path (`obtainContext(..., pcode)` then `applyCommits()`) / `ParserContext::getN2addr()` | `simplified-safe` | Go에서는 원본 순서를 보존하는 wrapper helper로 분리했고, 현재 translation entry와 `Engine.TranslateInstructionAt()`가 실제로 이 helper를 사용한다. `inst_next2`는 이제 pcode obtain마다 stale 값을 지우고 lazy resolver를 바인딩해 첫 `GetN2addr()` 시점에 adjacent disassembly를 유도한다. fallthrough는 `addr + length`를 우선 사용하고, adjacent context에 constant space가 비어 있으면 request constant space를 fallback으로 쓴다. 다만 C++처럼 unavailable 시 throw하지 않고 invalid address를 유지하며, direct `translate->instructionLength(naddr)` 모델까지는 아직 아니다 |
| translation entry | `TranslateSubtable()` / `translateResolveHooks()` | `Sleigh::oneInstruction()` / `Sleigh::resolve()` load boundaries | `simplified-safe` | 이제 alignment gate -> `ObtainPcodeContext()` -> delay-slot context preparation -> `ParserWalker` -> builder-owned raw-build begin -> `SleighBuilder.Build()` -> cache-backed `resolveRelatives()` -> cache-backed `emit()` 순서를 따른다. translation tail은 builder-owned emitted slice 없이 translation sink를 주입해 emitted ops를 직접 수집하고, 기존 builder sink가 있으면 체인한다. package-wide typed `UnimplError`도 들어갔고, alignment failure는 typed unimplemented 경로로 정규화됐다. `wrapTranslateUnimplError()`는 이제 strict top-level typed `*UnimplError`만 rewrite하고, usable current walker/constructor state가 있을 때만 explain text를 다시 쓴다. upstream builder/resolve/resolve-handles 경로도 typed 정규화가 추가되어 catch reach가 넓어졌고, translation entry 내부의 load-fill/load-context는 address-scoped payload source와 first-class `Loader(addr)`를 지원하되, explicit `LoadFill` / `LoadContext`가 있을 때는 bundled `MatchInput`을 per-phase compatibility fallback으로만 사용한다. root instruction address도 sink-visible emission address로 propagate된다. 다만 full catch coverage, exact same-object mutation semantics, full constructor-print/catch-format parity, 그리고 full `PcodeCacher` pool ownership은 아직 아니다 |
| backend | `Backend.LoadInstructionBytes()` / `PayloadLoader()` / raw instruction source attachment / `AdjustRawInstructionVMA()` | `LoadImage::loadFill()` / `RawLoadImage::{open,loadFill,adjustVma}` / `Sleigh::resolve()` external loader path | `simplified-safe` | current backend는 in-memory fetch뿐 아니라 `RawLoadImage`-style reader/file-backed raw instruction source도 가진다. first-byte-outside-image miss, started-read trailing zero-fill, 그리고 word-size scaled `adjustVma(long)` rebasing도 반영했다. 다만 broader `LoadImage` surface, process-backed loaders, and merged overlay reads are 아직 아니다 |
| backend | `Backend.LoadContextWords()` / `SetContextChangePoint()` / `SetContextRegion()` / `AllowContextSet()` | `ContextDatabase` / `ContextCache` read-write path | `simplified-safe` | current in-memory backend는 default context blob, flowing/non-flowing context write, conservative valid-range query, `allowSet`, 그리고 change-point clipping까지 제공한다. full `partmap` split structure, tracked register sets, encode/decode는 아직 아니다 |
| backend | `RegisterContextVariable()` / `SetVariableDefault()` / `GetVariableDefault()` / `SetVariable()` / `GetVariable()` | `ContextDatabase::{registerVariable,setVariableDefault,getDefaultValue,setVariable,getVariable}` | `simplified-safe` | named context variable registration과 bit-range based default/value access가 들어갔다. 현재는 one-word 변수만 허용하는 최소 parity core이며, current runtime scope에서는 충분하다 |
| backend | `GetFileName()` / `GetArchType()` / `ContextSize()` / `SetVariableRegion()` | `LoadImage::getFileName()` / `LoadImage::getArchType()` / `ContextDatabase::getContextSize()` / `ContextDatabase::setVariableRegion()` | `simplified-safe` | `GetFileName`/`GetArchType`은 `LoadImage` 인터페이스 표면을 추가로 커버한다. `ContextSize()`는 등록된 context word 수를 반환한다. `SetVariableRegion()`은 `[begad, endad)` 범위에 named context variable을 페인팅하며 `setVariableRegion()` 의미를 따른다 |
| engine | `FindInstructionRootSubtable()` / `NewEngine()` / `NewEngineFromMetadataSymbols()` / `TranslateInstructionAt()` | `SleighBase::decode()` instruction-root lookup + `Sleigh::oneInstruction()` reusable entry | `simplified-safe` | high-level one-instruction API가 추가되어 backend loader, parser-context cache, runtime authority path, 그리고 cached fallthrough length를 한 entry로 묶는다. root subtable은 이제 `sleighbase.cc`처럼 global-scope `instruction` symbol에서 자동으로 찾고, backend adapter는 split `LoadFill` / `LoadContext` hooks를 통해 bundled payload loader보다 더 원본에 가까운 authority path를 우선 사용할 수 있다. 다만 assembly printer path와 broader standalone UX는 아직 없다 |
| builder/cache | `buildEmpty()` / staged raw-build in `DisassemblyCache` / `SleighBuilder.leaveRawBuild()` | `SleighBuilder::buildEmpty()` / `PcodeCacher::{clear,addLabelRef,addLabel,resolveRelatives,emit}` | `simplified-safe` | named section이 비었을 때 subtable operand 재귀를 따르도록 바뀌었고, builder/cache가 authoritative raw-build lifecycle을 가진다. root tail은 이제 explicit `resolve -> emit` 순서이며 builder 쪽 fallback slice-return 분기는 제거됐다. `FinishRawBuild()`와 `EmitRawBuild()`도 제거됐다. staging은 issued-op이 cache-owned varnode pool을 직접 가리키고, pool growth 시 pointer-search 대신 explicit ownership record로 deterministic rebind를 수행한다. raw-build staging ownership은 이제 map+reusable-indirection이 아니라 single active reusable stage object로 조여졌고, 한 active instruction address만 유지한다. relative label tracking도 이제 direct `labelRefs` plus id-indexed `labels` vector로 바뀌어 원본 `PcodeCacher::addLabelRef()` / `addLabel()` / `resolveRelatives()` 구조에 더 가깝다. `ResolveRawBuild()`는 unchanged staging에 대해 idempotent하게 no-op 처리되어 이미 patched된 relative ref를 다시 덮어쓰지 않는다. `EmitRawBuildTo(addr, RawEmitter)`는 unresolved staging을 `ErrRawBuildUnresolved`로 거부한다. resolved staged issued ops만 clone해서 sink로 내보내며, 성공 시점에 cache-owned committed snapshot 하나만 남긴다. builder는 `RawEmitter` hook이 없을 때도 internal no-op sink를 써서 root tail 형태를 sink-facing으로 유지한다. initial varnode pool 크기는 `PcodeCacher::PcodeCacher()` 기본값(`uint4 maxsize = 600`)과 일치하게 `defaultVarnodePoolSize = 600`으로 고정됐고, `reset()` 시 pool backing storage를 유지해 `PcodeCacher::clear()` 의미를 따른다. `appendIssued()`는 이제 `allocateVarnodes() -> fill inputs -> allocateInstruction() -> fill PcodeData`의 C++ `dump()` 순서를 따르며, `allocateInstruction()`이 issued/refs의 authoritative append point다. `PcodeEmit::dump()`와의 sink semantics mismatch(C++는 void/infallible, Go는 error-returning)는 의도적 Go-only deviation으로 `emitRawBuildToLocked` 주석에 명시됐다. null construct(child exists, no pcode) 경로는 `*UnimplError("", 0)`을 반환해 `PcodeBuilder::build(nullptr)` throw parity를 갖췄다 |
| builder helpers | `builder_build.go` / `builder_cross.go` / `builder_delay.go` | builder directive helper failure boundaries under `SleighBuilder` | `simplified-safe` | sentinel 의미의 `ErrBuilderUnimplemented` 경로는 이제 typed `*UnimplError`로 정규화되어 translation strict catch까지 더 일관되게 전달된다. `errors.Is(..., ErrBuilderUnimplemented)` 호환도 유지한다. `builder_delay.go`와 `builder_cross.go`는 이제 인프라 에러(plain `error`)와 build 에러(`*UnimplError`)를 명시적으로 분리해 C++ `LowlevelError` vs `UnimplError` 구분을 따른다. `builder.go` null construct 경로는 `*UnimplError("", 0)`을 반환해 `PcodeBuilder::build(nullptr)` throw parity를 갖춘다 |
| symbols/metadata | `OperandSymbolBoundary` decode in `symbols.go` | `OperandSymbol::decode()` / `slghsymbol.cc:1013-1072` | `simplified-safe` | persisted body의 `subsym`, `off`, `base`, `minlen`, `code`, `index`, `localexp`, optional `defexp`를 별도 boundary로 보존한다 |
| symbols/metadata | `PatternSymbolBoundary.ValueTable` / `NameTable` | `ValueMapSymbol::decode()` / `NameSymbol::decode()` | `simplified-safe` | valuemap과 nametable persisted body를 boundary에 보존해 이후 fixed-handle/print 경로가 원본 데이터를 참조할 수 있게 했다 |
| symbols/metadata | `SymbolBodyBoundary.Varnode` / `.VarnodeList` decode in `symbols.go` | `VarnodeSymbol::decode()` / `VarnodeListSymbol::decode()` | `simplified-safe` | `varnode_sym` body의 `space/off/size`, `varlist_sym` body의 selector expression, ordered table entry ids/null slots를 boundary에 보존한다. 이 persisted body는 이제 `ResolveHandles()` automatic fixed-handle reconstruction에도 직접 쓰인다 |
| pattern expr | `GetPatternExpressionValue()` | `PatternExpression::getValue()` / `TokenField::getValue()` / `ContextField::getValue()` / unary-binary getValue | `simplified-safe` | constant, start/end, next2, token, context, 기본 unary-binary는 원본 흐름을 따라간다. `OperandValue`는 `defexp` 또는 `defsym->getPatternExpression()`가 boundary에 있을 때 `setOutOfBandState()` 기반 automatic 경로를 탄다. constructor-relative operand는 prebuilt child state가 없어도 계산되며, non-relative missing-child는 이제 explicit unimplemented gap으로 남긴다. `ContextSymbol` pattern 접근 경로가 수정되어 `Context`/`Pattern` 양쪽을 모두 확인한다 |
| symbols/metadata | `ConstructorBoundary.FlowThruIndex` in `symbols.go` / `SetConstructor()` in `walker.go` | `Constructor::flowthruindex` in `slghsymbol.cc` / `slghsymbol.hh` | `match` | `FlowThruIndex`는 boundary decode 시 `printpiece` 단일 operand ref 조건을 검사해 설정되고, `SetConstructor()`에서도 매번 재계산해 일관성을 보장한다. C++ `Constructor::decode()` 조건(`printpiece.size()==1 && printpiece[0][0]=='\n'`)을 직접 따른다 |
| translation | `flowthruindex` recursion in `translate.go` / `VarnodeSymbol::print()` | `Constructor::printMnemonic()` / `Constructor::printBody()` / `VarnodeSymbol::print()` in `slghsymbol.cc` | `simplified-safe` | `printMnemonic`/`printBody` 모드에서 `FlowThruIndex >= 0`이면 해당 operand 자식 constructor로 재귀 위임한다. `printAll` 모드는 C++처럼 flowthruindex를 사용하지 않는다. `VarnodeSymbol::print()`는 `getName()`을 그대로 출력한다 |
| symbols/metadata | `ContextSymbolBoundary` in `symbols.go` | `ContextSymbol::decode()` in `slghsymbol.cc` | `runtime active` | `varnode`, `low`, `high`, `flow` 속성을 boundary로 보존한다. `low`/`high`/`flow` 필드는 이제 `ApplyCommits()`에서 실제로 사용되어 parser context의 context word 배열의 올바른 bit range에 context word를 기록한다. `ContextSymbol::getFixedHandle()` 자동 경로가 `resolveBoundarySymbolFixedHandle`에 구현됐고 `BuildXrefs()` context field 등록과 연결됐다 |
| symbols/metadata | `ContextOpBoundary` in `symbols.go` | `ContextCommit` / context-op decode in `slghsymbol.cc` | `runtime active` | `num`, `shift`, `mask` 필드를 갖는 신규 타입이며, 이제 `ApplyContextOps()`에서 실제로 사용되어 `(value << shift) & mask`를 context word[num]에 적용한다. `EpsilonSymbol` body opaque 버그도 수정됐다 |
| symbols/metadata | `BuildXrefs()` in `xrefs.go` / `Engine.XRefs()` | `SleighBase::buildXrefs()` / `SleighBase::userop` / `SleighBase::registerContext()` | `simplified-safe` | post-decode xref, userop, context variable 등록 경로를 구현했다. `SleighBase::buildXrefs()` 원본 흐름을 따른다. `Engine` struct에 `*XRefs` 필드가 추가됐고 `Engine.XRefs()` accessor를 통해 translate/runtime 경로로 전달 가능하다. `GetUserOpName()` wiring과 `ContextFields` direct access는 테스트로 검증됐다 |
| symbols/metadata | `packed.go` type 5/6 decode | `slaformat.cc` `TYPECODE_ADDRESSSPACE` / `TYPECODE_SPECIALSPACE` | `match` | type 5(`TYPECODE_ADDRESSSPACE`)와 type 6(`TYPECODE_SPECIALSPACE`) 디코딩을 추가했다. `requiredSpaceAttr()` helper가 `symbols.go`와 `templates.go`에서 space 속성 읽기를 통일한다 |
| symbols/metadata | XML v3 `.sla` loading in `container.go` / `xml.go` | Ghidra `.sla` v3 XML format | `simplified-safe` | `container.go`는 magic byte로 XML/packed을 자동 감지한다. `xml.go`는 `encoding/xml`로 XML payload를 파싱해 내부 `element`/`attribute` 모델로 변환한다. `metadata.go`는 v3(XML)과 v4(packed) 양쪽을 수용한다. 실제 Ghidra 12 `6502.sla`(XML v3)로 7단계 통합 테스트 7/7 통과 확인 |
| symbols/metadata | `discache.go` / `builder_build.go` error messages | `PcodeCacher` C++ error strings | `match` | emit/resolve error 문구가 원본 C++ `PcodeCacher` 문구와 일치하도록 맞췄다 |
| symbols/metadata | `symbols.go`, `metadata.go` 전반 | `slghsymbol.cc`, `sleighbase.cc`, `slaformat.cc` | `pending` | `ContextSymbolBoundary`/`ContextOpBoundary` runtime 활용은 완료됐다. 나머지 symbol/metadata parity audit는 계속 진행 중이다 |

## Critical Findings

- `translate.go`의 pattern/decision 경로는 핵심 오동작을 1차로 막았고, `CombinePattern`은 현재 확인 결과상 AND semantics는 맞지만 구조 parity는 아직 미달이다.
- `special OpTpl`은 raw opcode가 아니라 runtime control directive로 취급해야 한다.
- `LABELBUILD`는 실행 경로가 들어갔고, `BUILD`는 이제 walker child state를 따라 재귀 실행한다.
- `DELAY_SLOT`은 cache loop re-entry 수준까지 들어갔고, `CROSSBUILD`는 cache re-entry named section build까지 들어갔다.
- named section이 비어 있을 때도 `buildEmpty()`가 subtable operand를 따라 implied BUILD 재귀를 수행한다.
- `runtime.go`의 `FixedHandle` / `RuntimeContext` / result propagation 경계가 새로 생겼고, `lower.go`는 현재 그 모델을 경유하도록 정리 중이다.
- `walker.go`와 `builder.go`는 shell에서 시작해 `BUILD` / `CROSSBUILD` / `DELAY_SLOT`의 최소 실행 경로까지 올라왔다.
- `resolve`, `resolveHandles`, `DecisionNode::resolve`, `PatternExpression::getValue`, `loadContext/applyCommits`는 이제 hook-backed shell까지 들어갔다.
- `ResolveHandles()`는 `ContextSymbol` / `ValueMapSymbol` / `NameSymbol` / `EpsilonSymbol` fixed-handle도 자동으로 처리한다.
- `symbols.go`는 이제 `VarnodeSymbol` fixed tuple과 `VarnodeListSymbol` selector/table body도 persisted boundary로 보존한다.
- `ResolveHandles()`는 이제 그 persisted `VarnodeSymbol` / `VarnodeListSymbol` body를 직접 써서 static fixed handle을 자동 복원한다.
- `ResolveHandles()`는 이제 `OperandSymbol::getFixedHandle()` handoff도 automatic path로 처리한다.
- `appendIssued()`가 C++ `dump()` 순서(`allocateVarnodes -> fill -> allocateInstruction -> fill PcodeData`)를 따르도록 변경됐다. `allocateInstruction()`이 issued/refs의 authoritative append point다.
- `PcodeEmit::dump()` infallible semantics vs. Go sink error-returning 차이는 의도적 deviation으로 명시됐다.
- `Engine` struct에 `*XRefs` 필드가 추가됐고, `BuildXrefs()` 결과를 translate/runtime 경로로 전달할 수 있다.
- `OperandSymbol` boundary는 `reloffset`, `offsetbase`, `minimumlength`, `subsym`, `localexp`, `defexp`까지 보존한다.
- `DisassemblyCache`와 `ObtainContext()`는 이제 same-address hit, circular slot reuse, parse-state reset을 가지는 parser-context reuse path를 가진다.
- `ObtainPcodeContext()`가 `obtainContext(..., pcode)` 다음 `applyCommits()` 순서를 별도 helper로 고정했다.
- `Resolve()`는 이제 flow address를 `ParserContext`에 실어 나르고, calladdr-style fallback으로 ref/dest를 함께 채울 수 있다.
- `TranslateSubtable()`는 이제 runtime authority path를 실제 진입점으로 사용하고, named section 선택과 recursive `BUILD`까지 그 경로를 탄다.
- 원본 `Sleigh::oneInstruction()` tail은 `pcode_cache.clear() -> builder.build() -> resolveRelatives() -> emit()` 순서다.
- `SleighBuilder`와 `DisassemblyCache`는 이제 위 tail을 cache-backed raw-build lifecycle로 직접 수행하고, root tail은 explicit `resolve -> emit` 순서를 가진다.
- `DisassemblyCache` raw-build staging은 이제 issued-op record와 owned varnode storage를 분리해 보관하고, relative-label patch도 cache-owned staged data에 적용한다.
- `DisassemblyCache` raw-build staging은 released state 1개를 재사용해서 backing storage를 유지한 채 resolver state를 reset할 수 있다.
- staged issued op는 이제 cache-owned varnode storage를 직접 가리키고, pool growth 시 rebind를 수행한다.
- builder raw-build tail은 이제 builder-owned emitted slice를 유지하지 않고, cache/sink-owned `resolve -> emit` 이후 translation tail이 committed cache result만 읽는다.
- `DisassemblyCache`는 이제 `EmitRawBuildTo(addr, RawEmitter)`를 통해 sink-style emission 경로를 가진다.
- alignment failure는 이제 typed local unimplemented error로 정규화되고, known unimplemented path는 substring이 아니라 type 기반으로 재포장된다.
- `ErrBuilderUnimplemented` 계열 실패는 `Instruction not implemented in pcode:` prefix, mnemonic/body 출력, instruction length를 담는 보수적 `UnimplError` 재포장 경로를 가진다.
- 기존 typed translation error는 now in-place rewrite를 타서 C++의 same-object mutation 방향에 더 가깝고, top-level thrown `*UnimplError`만 rewrite하도록 조여졌다.
- typed translation error rewrite는 이제 usable current walker가 없는 경우 기존 explain text를 억지로 덮어쓰지 않는다.
- nested `DELAY_SLOT` / `CROSSBUILD` 실패는 이제 outer walker를 너무 일찍 복구하지 않아 failing inner walker 기준으로 rewrite를 수행할 수 있다.
- raw lowering은 이제 active instruction semantics와 sink-visible root instruction address를 분리해, emitted raw op `SeqNum.Address`가 `oneInstruction(baseaddr)` parity를 따르도록 propagate한다.
- nested delay-slot translation proof test는 이제 outer/inner `uniqueoffset` 계산과 root `SeqNum.Address` 고정을 한 번에 검증한다.
- relative-label path는 이제 direct staged `labelRefs` / `labels` vector를 써서 undefined-label failure와 id-indexed label assignment까지 테스트된다.
- key runtime/translation shell은 이제 package-wide typed `UnimplError`를 사용한다.
- catch formatting은 더 concrete한 non-subtable operand text를 출력하고, 이전 Go-only gap suffix는 제거됐다.
- typed unimplemented rewrite는 이제 `TranslateSubtable()`의 local build/resolve/emit tail block 전체를 감싼다.
- 아직 decode pipeline이 `DisassemblyCache`를 채우는 완전한 원본 경로와, hook 없이 symbol/operand metadata를 따라가는 full parity 경로는 없다.
- 따라서 현재 실행 경로는 `runtime entry connected, full oneInstruction parity not yet complete` 상태로 보아야 한다.
- `builder_delay.go`와 `builder_cross.go`는 이제 인프라 에러(plain `error`)와 build 에러(`*UnimplError`)를 명시적으로 분리한다. C++에서 `delaySlot()`과 `appendCrossBuild()`의 인프라 실패는 `LowlevelError`를 던지고 이는 `oneInstruction()`의 `catch(UnimplError&)`에 걸리지 않는다. Go도 이제 같은 구분을 가진다.
- null construct(`child exists but no pcode`) 경로에서 `*UnimplError("", 0)` 반환이 추가됐다. C++ `PcodeBuilder::build(nullptr)` throw semantics와 일치한다.
- `ConstructorBoundary.FlowThruIndex` 필드가 추가됐고, `walker.go` `SetConstructor()`에서 매번 재계산된다. C++ `Constructor::flowthruindex`와 match 수준이다.
- `translate.go`는 `flowthruindex` recursion을 구현해 `printMnemonic`/`printBody`에서 단일 operand ref constructor는 자식으로 위임한다. `VarnodeSymbol::print()` parity도 추가됐다.
- `discache.go` varnode pool initial capacity가 600으로 고정됐고, `reset()` 후 pool 유지 semantics가 `PcodeCacher::clear()` 의미와 일치한다. `allocateInstruction()` 메서드가 추가됐으나 `AppendRawBuild` 경로의 direct 통합은 아직 남아 있다.
- `backend.go` `GetFileName`/`GetArchType`/`ContextSize`/`SetVariableRegion`이 추가되어 `LoadImage`/`ContextDatabase` 인터페이스 표면 커버리지가 넓어졌다.
- `resolve_handles.go` `runtimeContextForWalker`가 이제 child handles와 `SpacesByIndex`를 함께 전달한다. `findWalkerSpaceByIndex`는 `SpacesByIndex` 우선 참조로 바뀌어 walker-visible space scan에만 의존하지 않는다.
- `walker.go` `ParserContext`에 `SpacesByIndex` 필드가 추가돼 space lookup 경로가 walker 없이도 가능해졌다.
- `symbols.go`에 `ContextSymbolBoundary` (varnode/low/high/flow)와 `ContextOpBoundary` (num/shift/mask)가 신설됐다. `EpsilonSymbol` body opaque 버그가 수정됐다.
- `xrefs.go` `BuildXrefs()`가 구현되어 post-decode xref/userop/context registration 경로가 생겼다. 등록된 테이블을 runtime에 연결하는 작업은 남아 있다.
- `patexpr.go` `ContextSymbol` 접근 경로가 수정됐고, `translate.go` `evalPatternSymbolValue`가 Context/Pattern 양쪽을 확인한다.
- `packed.go`에 type 5/6 디코딩이 추가됐고, `requiredSpaceAttr()` helper가 space 속성 읽기를 통일한다.
- XML v3 `.sla` 지원이 추가됐다. container 자동 감지, xml.go 파서, metadata v3/v4 양쪽 수용. 실제 Ghidra 12 `6502.sla`(XML v3)로 7/7 통합 테스트 통과 확인.
- emit/resolve error 문구가 원본 C++ `PcodeCacher` 문구와 일치하도록 맞춰졌다.
- `instruction_context.go` N2addr delay-slot known gap이 문서화됐고 lazy derivation parity 주석이 보강됐다.

## Golden/Bridge Test Findings (Stabilization Chain, 2026-04-04)

이 섹션은 golden test harness 및 bridge E2E 테스트에서 실측된 parity gap을 기록한다.
테스트 범위: `pkg/sla/golden_test.go`, `pkg/bridge/bridge_test.go`, `testdata/golden/`.

### Audit Table -- Constructor Resolution Gaps

| Area | Go symbol | C++ counterpart | Status | Reason |
|------|-----------|-----------------|--------|--------|
| constructor resolution | `ResolveSubtableDecision()` / decision tree walk for 6502 NOP (0xEA) | `DecisionNode::resolve()` in `slghsymbol.cc` | `mismatch` | `TranslateInstructionAt()` returns plain `"unable to resolve constructor"` (not `*UnimplError`) for opcode 0xEA. The decision tree walker does not find a matching constructor for NOP in the 6502 symbol table. Root cause: context/decision-tree resolution path has a gap for most 6502 opcodes beyond BRK (0x00). Golden fixture records this as `"unimplemented"`. |
| constructor resolution | `ResolveSubtableDecision()` / decision tree walk for 6502 LDA immediate (0xA9) | `DecisionNode::resolve()` in `slghsymbol.cc` | `mismatch` | Same root cause as NOP. `TranslateInstructionAt()` returns plain `"unable to resolve constructor"` for 0xA9. This is not a typed `*UnimplError` so bridge.Build() treats it as a hard error. Golden fixture records as `"unimplemented"`. This blocks E2E bridge tests that begin with an LDA sequence. |
| constructor resolution | `ResolveSubtableDecision()` / branch instructions (6502 BNE 0xD0 etc.) | `DecisionNode::resolve()` in `slghsymbol.cc` | `unimplemented` | bridge.Build() E2E test with a multi-instruction sequence (LDA + BNE + ...) skips because LDA (0xA9) fails before reaching the branch. Branch constructor resolution itself is untested. Classified as `unimplemented` pending decision tree fix. |
| constructor resolution | `ResolveSubtableDecision()` overall coverage | `DecisionNode::resolve()` / `SubtableSymbol::resolve()` full 6502 table | `mismatch` | Only BRK (0x00) resolves successfully in the current decision tree walk and produces 29 p-code ops. All other tested 6502 opcodes (NOP 0xEA, LDA 0xA9, BNE 0xD0) fail with `"unable to resolve constructor"`. The pattern matching / context bit extraction path works for BRK but does not generalize to the full 6502 instruction set. |

### Critical Findings (Golden/Bridge)

- BRK (0x00): resolves correctly and emits 29 p-code ops. This is the only confirmed working 6502 opcode in the current decision tree walk.
- NOP (0xEA) and LDA immediate (0xA9): fail with `"unable to resolve constructor"` -- plain error, not `*UnimplError`. The error type distinction matters: bridge.Build() hard-fails on plain errors but gracefully records `*UnimplError` as Warnings.
- The Sleigh decision tree resolution path (`ResolveSubtableDecision` / `DecisionNode::resolve`) has gaps for most 6502 opcodes. The pattern bits are likely being matched against wrong context/instruction bit positions for opcodes where the `PatternBlock` mask covers non-trivial bit ranges.
- `bridge.Result.Warnings` field (added in stabilization chain) provides a graceful degradation path when `*UnimplError` is returned, but cannot catch the plain-error `"unable to resolve constructor"` failures. This means the plain-error path is still a hard failure at the bridge layer.
- Recommended next action: audit `DecisionNode::resolve()` against the C++ `slghsymbol.cc` terminal pair matching logic for non-zero-opcode entries to find what bit extraction step diverges.

## 디컴파일러 액션 -- 스택 공간 복구 parity (2026-07-02)

이 문서의 나머지 표는 Sleigh 번역 계층(`pkg/sla`) 범위다. 아래는 디컴파일러 액션/룰 계층(`pkg/pcode`)의 스택
복구 parity 갱신이며, 별도로 기록한다.

| Area | Go symbol | C++ counterpart | Status | Reason |
|------|-----------|-----------------|--------|--------|
| decompiler action (stack recovery, tree) | `Funcdata.Spacebase()` | `Funcdata::spacebase` (funcdata.cc:230-269) | `match` | 이전 no-op stub이었으나 충실 구현으로 교체됐다. 모든 RSP 계열 varnode(input/sub-result/phi)에 spacebase 마킹을 걸어 이후 `RuleLoadVarnode`/`RuleStoreVarnode`가 `[rsp+k]` 접근을 스택 공간 varnode로 변환할 수 있게 한다. universal-action 트리의 기본 경로다 |
| decompiler action (stack recovery, tree) | `RuleAddMultCollapse` / `RuleCollapseConstants` | `ruleaction.cc:4113-4182` | `match` | `sub rsp,N` 오프셋 누적에 필요한 누락 분기를 `RuleAddMultCollapse`에 추가하고 `RuleCollapseConstants`를 신규 포팅했다 |
| decompiler action (stack recovery, legacy tests) | `ActionStackPtrFlow` (action_stack_ptr_flow.go) | 원본 대응 없음(Gosleigh 전용 bespoke def-use 전파, heritage 이후 1회 실행) | `simplified-safe` | H8-debt-2 Step 1-2 완료로 production `bridge.Decompile`은 universal-action 트리(faithful spacebase 경로)로 교체됐다. bespoke는 이제 production 경로에서 빠졌고 레거시 테스트 하네스(loader_test.go 등)에만 남아 있다. 완전 제거(Step 3)는 이 하네스들을 트리 경로로 이전한 뒤 진행하는 후속 작업 |

- production `bridge.Decompile`은 이제 트리(faithful spacebase)로 스택을 복구한다. bespoke
  `ActionStackPtrFlow`는 production 경로에서 은퇴했고 레거시 테스트에만 잔존한다(Step 3에서 완전 제거 예정).

## Next Actions

1. strict `oneInstruction()` parity에서 남은 catch-path gap을 줄인다: remaining full catch coverage, stricter same-object mutation semantics, full constructor-print/catch-format parity를 맞춘다.
2. `AppendRawBuild` 경로를 `allocateInstruction()` / `allocateVarnodes()` direct 통합으로 전환해 `PcodeCacher` dump() 흐름에 더 가깝게 맞춘다. infallible sink semantics도 이어서 정리한다.
3. staged raw-build storage를 full `PcodeCacher` ownership 모델로 끌어올린다: long-lived cache lifecycle, direct sink emission, full container/pool parity.
4. `BuildXrefs()`로 등록된 xref/userop/context 테이블을 runtime resolve와 pattern-evaluation 경로에 연결한다.
5. `decode pipeline`이 `DisassemblyCache`를 실제로 채우는 경로를 만든다.
6. dynamic varnode-style fixed-handle parity를 더 줄이고, flow-symbol path는 현재 safe opaque-boundary runtime reconstruction으로 유지한다.
7. parser-context circular reuse 위에 실제 decode population을 더 얹어 `DisassemblyCache` populated-state parity를 올린다.
8. sink error semantics와 remaining internal cache ownership differences를 원본 `PcodeCacher`에 더 가깝게 정리한다.
9. `symbols.go`, `metadata.go` 나머지 parity audit를 이어서 완료한다. (`ContextSymbolBoundary`/`ContextOpBoundary` runtime 활용은 완료됐다.)
10. **[우선순위 높음]** `DecisionNode::resolve()` 결함 수정: 6502 BRK 외 대부분 opcode에서 발생하는 `"unable to resolve constructor"` 오류의 원인을 C++ `slghsymbol.cc` 대조로 찾아 수정한다. 수정 후 golden fixture를 `GOSLEIGH_UPDATE_GOLDEN=1`로 재생성한다.
