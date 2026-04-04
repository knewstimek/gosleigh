package sla

import (
	"fmt"
	"strings"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

// MatchInput is the minimum byte-oriented state needed to resolve a constructor.
type MatchInput struct {
	Instruction       []byte
	InstructionOffset int64
	Context           []byte
}

// TranslatePayloadSource provides address-scoped instruction/context bytes.
// It mirrors Sleigh::resolve() calling loadFill()/loadContext() per parser-context address.
type TranslatePayloadSource struct {
	ByAddress map[address.Address]MatchInput
	Lookup    func(addr address.Address) (MatchInput, bool)
	// Loader mirrors Sleigh::resolve() external load route by address. When present,
	// it is the authoritative source before in-memory lookup/map fallbacks.
	Loader func(addr address.Address) (MatchInput, bool, error)
}

// TranslateInput combines constructor matching and lowering context for one translation request.
type TranslateInput struct {
	Match          MatchInput
	Payloads       TranslatePayloadSource
	Lowering       LoweringContext
	Alignment      uint64
	Section        *int64
	Cache          *DisassemblyCache
	Symbols        *SymbolTableBoundary
	Resolve        ResolveHooks
	ResolveHandles ResolveHandlesHooks
	Commits        ApplyCommitsHooks
}

func hasSeededTranslateMatch(match MatchInput) bool {
	return len(match.Instruction) != 0 || len(match.Context) != 0
}

func translateMatchForAddress(input TranslateInput, addr address.Address) (MatchInput, bool, error) {
	if input.Payloads.Loader != nil {
		// Mirrors Sleigh::resolve()/loadFill+loadContext obtaining bytes from external loaders per address.
		match, ok, err := input.Payloads.Loader(addr)
		if err != nil {
			return MatchInput{}, false, fmt.Errorf("translate subtable: payload loader failed for %v: %w", addr, err)
		}
		if ok {
			return match, true, nil
		}
	}
	if input.Payloads.Lookup != nil {
		if match, ok := input.Payloads.Lookup(addr); ok {
			return match, true, nil
		}
	}
	if input.Payloads.ByAddress != nil {
		if match, ok := input.Payloads.ByAddress[addr]; ok {
			return match, true, nil
		}
	}
	if addr == input.Lowering.Instruction && hasSeededTranslateMatch(input.Match) {
		return input.Match, true, nil
	}
	return MatchInput{}, false, nil
}

func effectiveAlignment(input TranslateInput) uint64 {
	if input.Alignment == 0 {
		return 1
	}
	return input.Alignment
}

func checkInstructionAlignment(addr address.Address, alignment uint64) error {
	if alignment <= 1 {
		return nil
	}
	if addr.Offset%alignment != 0 {
		// Mirrors Sleigh::oneInstruction(): throw UnimplError with instruction_length=0 on misalignment.
		return newUnimplErrorWithInstructionLength(nil, fmt.Sprintf("Instruction address not aligned: %v", addr), 0)
	}
	return nil
}

type constructorPrintMode uint8

const (
	constructorPrintAll constructorPrintMode = iota
	constructorPrintMnemonic
	constructorPrintBody
)

const (
	translateUnimplExplainPrefix = "Instruction not implemented in pcode:\n "
	translateMaxPrintDepth       = 32
)

func wrapTranslateUnimplError(err error, builder *SleighBuilder, instructionLength int) error {
	if err == nil {
		return nil
	}
	existing, ok := err.(*UnimplError)
	if ok {
		// Mirrors Sleigh::oneInstruction() catch(UnimplError&) rewrite before rethrow.
		// The C++ catch rewrites the thrown UnimplError object itself, not an unwrapped
		// error buried inside another wrapper.
		if explain, ok := formatTranslateUnimplExplain(builder); ok {
			existing.Explain = explain
			existing.explain = existing.Explain
		}
		existing.InstructionLength = instructionLength
		existing.instructionLength = instructionLength
		existing.HasInstructionLength = true
		return existing
	}
	// Mirrors Sleigh::oneInstruction() catch(UnimplError&): only typed UnimplError
	// is rewritten. Non-Unimpl errors must pass through untouched.
	return err
}

func formatTranslateUnimplExplain(builder *SleighBuilder) (string, bool) {
	var out strings.Builder
	out.WriteString(translateUnimplExplainPrefix)
	if builder == nil || builder.State.Walker == nil {
		return "", false
	}
	// Mirrors Sleigh::oneInstruction() catch block resetting the walker to base state.
	walker := builder.State.Walker
	walker.BaseState()
	if !walker.IsState() || walker.Point == nil || walker.Point.Constructor == nil {
		return "", false
	}
	addr := walker.GetAddr()
	mnemonic, _ := formatConstructorPrintWithWalker(walker, walker.Point, constructorPrintMnemonic, 0)
	body, _ := formatConstructorPrintWithWalker(walker, walker.Point, constructorPrintBody, 0)
	out.WriteString(addr.String())
	out.WriteString(": ")
	out.WriteString(mnemonic)
	out.WriteString("  ")
	out.WriteString(body)
	return out.String(), true
}

func formatConstructorPrint(state *ConstructState, mode constructorPrintMode, depth int) (string, bool) {
	return formatConstructorPrintWithWalker(nil, state, mode, depth)
}

func formatConstructorPrintWithWalker(walker *ParserWalker, state *ConstructState, mode constructorPrintMode, depth int) (string, bool) {
	if state == nil || state.Constructor == nil {
		return "<constructor unavailable>", true
	}
	if depth >= translateMaxPrintDepth {
		return "<constructor print depth exceeded>", true
	}
	// Mirrors C++ Constructor::printMnemonic()/printBody() flowthruindex delegation.
	// When a constructor has exactly one operand ref (no markup), and that operand
	// resolves to a subtable child, delegate mnemonic/body printing to the child.
	// printAll (Constructor::print) does NOT use flowthruindex in C++.
	if mode != constructorPrintAll && state.Constructor.FlowThruIndex >= 0 {
		idx := int(state.Constructor.FlowThruIndex)
		child, childOK := state.Child(idx)
		if childOK && child != nil && child.Constructor != nil {
			// The child resolved to a subtable constructor; recurse into it.
			if walker != nil && walker.Point == state {
				if err := walker.PushOperand(idx); err == nil {
					text, gap := formatConstructorPrintWithWalker(walker, walker.Point, mode, depth+1)
					walker.PopOperand()
					return text, gap
				}
			}
			return formatConstructorPrintWithWalker(nil, child, mode, depth+1)
		}
		// flowthruindex is set but the operand is not a subtable; fall through
		// to the normal piece-by-piece print path (mirrors C++ behavior).
	}
	start, end, gap := constructorPrintRange(state.Constructor, mode)
	if start >= end {
		return "", gap
	}
	var out strings.Builder
	for i := start; i < end; i++ {
		piece := state.Constructor.PrintPieces[i]
		if !piece.IsOperandRef {
			out.WriteString(piece.Text)
			continue
		}
		operandText, operandGap := formatOperandPrintWithWalker(walker, state, piece.OperandIndex, depth+1)
		out.WriteString(operandText)
		gap = gap || operandGap
	}
	return out.String(), gap
}

func constructorPrintRange(constructor *ConstructorBoundary, mode constructorPrintMode) (int, int, bool) {
	if constructor == nil {
		return 0, 0, true
	}
	// Mirrors Constructor::printMnemonic()/printBody() split in slghsymbol.cc.
	pieceCount := len(constructor.PrintPieces)
	switch mode {
	case constructorPrintAll:
		return 0, pieceCount, false
	case constructorPrintMnemonic:
		if constructor.FirstWhitespace == -1 {
			return 0, pieceCount, false
		}
		if constructor.FirstWhitespace < 0 {
			return 0, 0, true
		}
		if constructor.FirstWhitespace > int64(pieceCount) {
			return 0, pieceCount, true
		}
		return 0, int(constructor.FirstWhitespace), false
	case constructorPrintBody:
		if constructor.FirstWhitespace == -1 {
			return 0, 0, false
		}
		if constructor.FirstWhitespace < 0 {
			return 0, 0, true
		}
		if constructor.FirstWhitespace+1 > int64(pieceCount) {
			return 0, 0, true
		}
		return int(constructor.FirstWhitespace + 1), pieceCount, false
	default:
		return 0, pieceCount, true
	}
}

func formatOperandPrint(state *ConstructState, operandIndex int64, depth int) (string, bool) {
	return formatOperandPrintWithWalker(nil, state, operandIndex, depth)
}

func formatOperandPrintWithWalker(walker *ParserWalker, state *ConstructState, operandIndex int64, depth int) (string, bool) {
	if state == nil || operandIndex < 0 {
		return fmt.Sprintf("<op%d?>", operandIndex), true
	}
	child, ok := state.Child(int(operandIndex))
	if ok && child != nil && child.Constructor != nil {
		if walker != nil && walker.Point == state {
			if err := walker.PushOperand(int(operandIndex)); err == nil {
				// Mirrors Constructor::print() recursion into nested subtable operands.
				text, gap := formatConstructorPrintWithWalker(walker, walker.Point, constructorPrintAll, depth)
				walker.PopOperand()
				if text == "" {
					return fmt.Sprintf("<op%d?>", operandIndex), true
				}
				return text, gap
			}
		}
		// Mirrors Constructor::print() recursion through operand->print() when child constructor exists.
		text, gap := formatConstructorPrint(child, constructorPrintAll, depth)
		if text == "" {
			return fmt.Sprintf("<op%d?>", operandIndex), true
		}
		return text, gap
	}
	if walker != nil && walker.Point == state {
		if err := walker.PushOperand(int(operandIndex)); err == nil {
			// Mirrors OperandSymbol::print() in slghsymbol.cc: pushOperand() may materialize
			// shell child state even when the operand child was not pre-resolved.
			text, handled, gap := tryFormatOperandSymbolPrint(walker, state, int(operandIndex))
			walker.PopOperand()
			if handled {
				return text, gap
			}
		}
	}
	// Gap: slghsymbol.cc OperandSymbol::print() can still cover more triple symbol kinds
	// than the current shell. Keep an explicit placeholder for unsupported forms.
	return fmt.Sprintf("<op%d?>", operandIndex), true
}

func tryFormatOperandSymbolPrint(walker *ParserWalker, parent *ConstructState, operandIndex int) (string, bool, bool) {
	if walker == nil || walker.ParserContext() == nil || walker.ParserContext().GetSymbolTable() == nil {
		return "", false, false
	}
	if parent == nil || parent.Constructor == nil {
		return "", false, false
	}
	symbols := walker.ParserContext().GetSymbolTable()
	operand, ok := symbols.FindOperandForConstructor(parent.Constructor, operandIndex)
	if !ok || operand == nil {
		return "", false, false
	}
	if operand.HasDefiningSymbolID {
		defining, ok := symbols.FindSymbol(operand.DefiningSymbolID)
		if ok {
			text, handled, gap := tryFormatBoundarySymbolPrint(defining, walker)
			if handled {
				return text, true, gap
			}
		}
	}
	if operand.DefiningExpression != nil {
		value, err := GetPatternExpressionValue(operand.DefiningExpression, walker, PatternExpressionValueHooks{})
		if err != nil {
			return "", true, true
		}
		return formatSignedHex(value), true, false
	}
	return "", false, false
}

func tryFormatBoundarySymbolPrint(symbol *SymbolBoundary, walker *ParserWalker) (string, bool, bool) {
	if symbol == nil {
		return "", false, false
	}
	switch symbol.HeaderElement {
	case elemValueSymHead, elemContextSymHead:
		value, err := evalPatternSymbolValue(symbol, walker)
		if err != nil {
			return "", true, true
		}
		return formatSignedHex(value), true, false
	case elemValueMapSymHead:
		index, err := evalPatternSymbolValue(symbol, walker)
		if err != nil {
			return "", true, true
		}
		if index < 0 || int(index) >= len(symbol.Body.Pattern.ValueTable) {
			return "", true, true
		}
		return formatSignedHex(symbol.Body.Pattern.ValueTable[int(index)]), true, false
	case elemNameSymHead:
		index, err := evalPatternSymbolValue(symbol, walker)
		if err != nil {
			return "", true, true
		}
		if index < 0 || int(index) >= len(symbol.Body.Pattern.NameTable) {
			return "", true, true
		}
		name := symbol.Body.Pattern.NameTable[int(index)]
		if len(name) == 1 && name[0] == '\t' {
			return "", true, true
		}
		return name, true, false
	case elemStartSymHead:
		addr := walker.GetAddr()
		if addr.Space == nil {
			return "", true, true
		}
		return formatSignedHex(int64(addr.Offset)), true, false
	case elemEndSymHead:
		addr := walker.GetNaddr()
		if addr.Space == nil {
			return "", true, true
		}
		return formatSignedHex(int64(addr.Offset)), true, false
	case elemNext2SymHead:
		addr := walker.GetN2addr()
		if addr.Space == nil {
			return "", true, true
		}
		return formatSignedHex(int64(addr.Offset)), true, false
	case elemVarnodeSymHead:
		// Mirrors VarnodeSymbol::print() in slghsymbol.hh: just outputs getName().
		return symbol.Name, true, false
	default:
		// known mismatch: FlowDestSymbol and FlowRefSymbol print() are not yet
		// handled because those symbol header elements are not decoded. They print
		// walker.getDestAddr()/getRefAddr() offset as hex in C++.
		return "", false, false
	}
}

func evalPatternSymbolValue(symbol *SymbolBoundary, walker *ParserWalker) (int64, error) {
	if symbol == nil {
		return 0, fmt.Errorf("pattern symbol expression is unavailable")
	}
	// ContextSymbol stores its expression inside ContextSymbolBoundary.Pattern.
	var expr *PatternExprBoundary
	if symbol.Body.Context != nil && symbol.Body.Context.Pattern != nil {
		expr = symbol.Body.Context.Pattern.Expression
	} else if symbol.Body.Pattern != nil {
		expr = symbol.Body.Pattern.Expression
	}
	if expr == nil {
		return 0, fmt.Errorf("pattern symbol expression is unavailable")
	}
	return GetPatternExpressionValue(expr, walker, PatternExpressionValueHooks{})
}

func formatSignedHex(value int64) string {
	if value >= 0 {
		return fmt.Sprintf("0x%x", value)
	}
	return fmt.Sprintf("-0x%x", -value)
}

// TranslateSubtable mirrors Sleigh::oneInstruction() around the local runtime shell:
// obtainContext(..., pcode), applyCommits(), ParserWalker, then the pcode tail.
// C++ tail order (sleigh.cc): clear cache -> build -> resolveRelatives -> emit.
func TranslateSubtable(subtable *SubtableBoundary, input TranslateInput) ([]pcode.RawOp, error) {
	if subtable == nil {
		return nil, fmt.Errorf("subtable is nil")
	}
	if err := input.Lowering.Instruction.Validate(); err != nil {
		return nil, fmt.Errorf("translate subtable: instruction address: %w", err)
	}
	input.Lowering = normalizeTranslationLowering(input.Lowering)
	// Mirrors Sleigh::oneInstruction() alignment gate before obtainContext().
	if err := checkInstructionAlignment(input.Lowering.Instruction, effectiveAlignment(input)); err != nil {
		return nil, err
	}
	cache := input.Cache
	if cache == nil {
		cache = NewDisassemblyCache()
	}
	ctx, err := ObtainPcodeContext(cache, translatePcodeContextRequest(subtable, input, input.Lowering.Instruction))
	if err != nil {
		return nil, err
	}
	if input.Symbols != nil && ctx.GetSymbolTable() == nil {
		ctx.SetSymbolTable(input.Symbols)
	}
	fallOffset, err := prepareDelaySlotContexts(cache, subtable, input, ctx)
	if err != nil {
		return nil, err
	}
	walker := NewParserWalker(ctx)
	walker.BaseState()
	if !walker.IsState() || walker.Point.Constructor == nil {
		return nil, fmt.Errorf("translate subtable: parser walker has no resolved constructor")
	}
	sectionID := int64(-1)
	if input.Section != nil {
		sectionID = *input.Section
		if err := walker.SetCurrentSection(sectionID); err != nil {
			return nil, err
		}
	}
	section, err := selectActiveSection(walker, input.Section)
	if err != nil {
		return nil, err
	}
	runtime := translateRuntimeContext(walker, input.Lowering)
	builder := NewSleighBuilder(runtime, input.Lowering.LabelBase, sectionID, BuilderHooks{})
	builder.Pcode.rawInstruction = input.Lowering.RootInstruction
	builder.State.SetDisassemblyCache(cache)
	builder.State.Walker = walker
	// Wire ObtainContextFallback so that delay-slot/crossbuild paths can populate
	// the cache for adjacent instructions when called without prior prepareDelaySlotContexts.
	// Mirrors Sleigh::obtainContext() pre-population inside oneInstruction().
	builder.State.ObtainContextFallback = func(addr address.Address, targetState ParseState) (*ParserContext, error) {
		return ObtainContext(cache, ObtainContextRequest{
			Address:       addr,
			TargetState:   targetState,
			ConstantSpace: selectConstantSpace(input.Lowering),
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					if input.Symbols != nil {
						ctx.SetSymbolTable(input.Symbols)
					}
					_, err := Resolve(ctx, translateResolveHooks(subtable, input))
					return err
				},
				ResolveHandles: func(ctx *ParserContext) error {
					if input.Symbols != nil && ctx.GetSymbolTable() == nil {
						ctx.SetSymbolTable(input.Symbols)
					}
					// Propagate space index map so propagateConstructorResult can resolve
					// space-indexed varnodes (e.g. ConstKindSpaceID in HandleTpl::fix).
					if ctx.SpacesByIndex == nil && input.Lowering.SpacesByIndex != nil {
						ctx.SpacesByIndex = input.Lowering.SpacesByIndex
					}
					return ResolveHandles(ctx, input.ResolveHandles)
				},
			},
		})
	}
	// Mirrors SleighBuilder::dump() -> PcodeCacher staged raw emission through LowerRaw.
	builder.Hooks.LowerRaw = func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
		active := state
		active.Walker = builder.State.Walker
		active.Cache = builder.State.Cache
		active.Runtime = translateRuntimeContext(builder.State.Walker, input.Lowering)
		lowered, err := lowerOpTpl(op, translateLoweringContext(active, input.Lowering), active.SectionID, order)
		if err != nil {
			return nil, err
		}
		return lowered, nil
	}

	// Mirrors Sleigh::oneInstruction() catch scope over build/resolveRelatives/emit tail.
	emitted, err := translateBuildTail(builder, *section, sectionID)
	if err != nil {
		return nil, wrapTranslateUnimplError(err, builder, fallOffset)
	}
	return emitted, nil
}

type translateCaptureRawEmitter struct {
	ops []pcode.RawOp
}

func (e *translateCaptureRawEmitter) EmitRaw(op pcode.RawOp) error {
	e.ops = append(e.ops, cloneRawOp(op))
	return nil
}

func (e *translateCaptureRawEmitter) Ops() []pcode.RawOp {
	return cloneRawOps(e.ops)
}

type rawEmitterChain struct {
	sinks []pcode.RawEmitter
}

func (c rawEmitterChain) EmitRaw(op pcode.RawOp) error {
	for i := range c.sinks {
		if c.sinks[i] == nil {
			continue
		}
		if err := c.sinks[i].EmitRaw(op); err != nil {
			return err
		}
	}
	return nil
}

func translateBuildTail(builder *SleighBuilder, section ConstructTplBoundary, sectionID int64) ([]pcode.RawOp, error) {
	if builder == nil {
		return nil, fmt.Errorf("builder is nil")
	}
	// Mirrors Sleigh::oneInstruction() tail ownership through PcodeCacher.
	// Translation requires cache-backed lowering/emit, not builder-local staging.
	if builder.Hooks.LowerRaw == nil {
		return nil, newUnimplError(ErrBuilderUnimplemented, "translate subtable: cache-backed raw emission hook is required")
	}
	if builder.State.Cache == nil {
		return nil, newUnimplError(ErrBuilderUnimplemented, "translate subtable: cache-backed raw emission requires a disassembly cache")
	}
	capture := &translateCaptureRawEmitter{}
	prevEmitter := builder.Hooks.RawEmitter
	if prevEmitter == nil {
		builder.Hooks.RawEmitter = capture
	} else {
		// Keep existing sink behavior while capturing the same emitted stream for TranslateSubtable return.
		builder.Hooks.RawEmitter = rawEmitterChain{sinks: []pcode.RawEmitter{prevEmitter, capture}}
	}
	defer func() {
		builder.Hooks.RawEmitter = prevEmitter
	}()
	if err := builder.Build(section, sectionID); err != nil {
		return nil, err
	}
	// Mirrors sleigh.cc oneInstruction() tail ownership (build -> resolveRelatives -> emit):
	// return the ops directly from sink-facing emission handoff, not cache readback.
	return capture.Ops(), nil
}

func normalizeTranslationLowering(ctx LoweringContext) LoweringContext {
	if err := ctx.RootInstruction.Validate(); err == nil {
		return ctx
	}
	// Mirrors Sleigh::oneInstruction(baseaddr) carrying baseaddr through the
	// full build -> resolveRelatives -> emit tail as the raw-op root address.
	ctx.RootInstruction = ctx.Instruction
	return ctx
}

func lowerResolvedSection(section ConstructTplBoundary, ctx LoweringContext) ([]pcode.RawOp, error) {
	return LowerConstructTpl(section, ctx)
}

func translatePcodeContextRequest(subtable *SubtableBoundary, input TranslateInput, addr address.Address) ObtainPcodeContextRequest {
	resolveHooks := translateResolveHooks(subtable, input)
	commitHooks := input.Commits
	if commitHooks.ApplyCommit == nil {
		commitHooks.ApplyCommit = func(req ApplyCommitRequest) error {
			return nil
		}
	}
	if commitHooks.LookupOperandIndex == nil && commitHooks.ResolveFixedHandle == nil && commitHooks.ResolveCommitAddress == nil {
		commitHooks.ResolveCommitAddress = func(req ResolveCommitAddressRequest) (address.Address, error) {
			if req.Context == nil {
				return address.Address{}, fmt.Errorf("translate subtable: nil parser context for commit resolution")
			}
			return req.Context.GetAddr(), nil
		}
	}
	return ObtainPcodeContextRequest{
		Context: ObtainContextRequest{
			Address:       addr,
			TargetState:   ParseStatePcode,
			ConstantSpace: selectConstantSpace(input.Lowering),
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					if input.Symbols != nil {
						ctx.SetSymbolTable(input.Symbols)
					}
					_, err := Resolve(ctx, resolveHooks)
					return err
				},
				ResolveHandles: func(ctx *ParserContext) error {
					if input.Symbols != nil && ctx.GetSymbolTable() == nil {
						ctx.SetSymbolTable(input.Symbols)
					}
					// Propagate space index map so propagateConstructorResult can resolve
					// space-indexed varnodes (e.g. ConstKindSpaceID in HandleTpl::fix).
					if ctx.SpacesByIndex == nil && input.Lowering.SpacesByIndex != nil {
						ctx.SpacesByIndex = input.Lowering.SpacesByIndex
					}
					return ResolveHandles(ctx, input.ResolveHandles)
				},
			},
		},
		Commits: commitHooks,
	}
}

func translateResolveHooks(subtable *SubtableBoundary, input TranslateInput) ResolveHooks {
	hooks := input.Resolve
	matchForAddress := func(addr address.Address) (MatchInput, bool, error) {
		return translateMatchForAddress(input, addr)
	}
	type matchCacheEntry struct {
		addr     address.Address
		match    MatchInput
		hasMatch bool
		loaded   bool
	}
	var cacheEntry matchCacheEntry
	loadAddressMatch := func(ctx *ParserContext) (MatchInput, bool, error) {
		if ctx == nil {
			return MatchInput{}, false, nil
		}
		addr := ctx.GetAddr()
		if cacheEntry.loaded && cacheEntry.addr == addr {
			return cacheEntry.match, cacheEntry.hasMatch, nil
		}
		match, hasMatch, err := matchForAddress(addr)
		if err != nil {
			return MatchInput{}, false, err
		}
		cacheEntry = matchCacheEntry{
			addr:     addr,
			match:    match,
			hasMatch: hasMatch,
			loaded:   true,
		}
		return match, hasMatch, nil
	}
	userLoadFill := hooks.LoadFill
	fallbackLoadFill := userLoadFill == nil
	hooks.LoadFill = func(ctx *ParserContext) error {
		if fallbackLoadFill {
			match, hasMatch, err := loadAddressMatch(ctx)
			if err != nil {
				return err
			}
			if err := translateLoadFill(ctx, match, hasMatch, false); err != nil {
				return err
			}
		}
		if userLoadFill != nil {
			return userLoadFill(ctx)
		}
		return nil
	}
	userLoadContext := hooks.LoadContext
	fallbackLoadContext := userLoadContext == nil
	hooks.LoadContext = func(ctx *ParserContext) error {
		if input.Symbols != nil && ctx != nil {
			ctx.SetSymbolTable(input.Symbols)
		}
		if fallbackLoadContext {
			match, hasMatch, err := loadAddressMatch(ctx)
			if err != nil {
				return err
			}
			if err := translateLoadContext(ctx, match, hasMatch, false); err != nil {
				return err
			}
		}
		if userLoadContext != nil {
			return userLoadContext(ctx)
		}
		return nil
	}
	if hooks.ResolveSymbol == nil {
		// Mirrors Sleigh::resolve() dispatch through root->resolve()/tsym->resolve().
		hooks.ResolveSymbol = func(frame ResolveFrame) (ResolveOutcome, error) {
			return resolveTranslateFrame(subtable, frame)
		}
	}
	return hooks
}

func translateLoadFill(ctx *ParserContext, match MatchInput, hasMatch bool, hasUserHook bool) error {
	if ctx == nil {
		return nil
	}
	if !hasMatch {
		if hasUserHook {
			return nil
		}
		return newUnimplError(
			ErrObtainContextUnimplemented,
			fmt.Sprintf("translate subtable: parser context %v requires an instruction payload or load-fill hook", ctx.GetAddr()),
		)
	}
	if len(match.Instruction) == 0 {
		return nil
	}
	ctx.SetInstructionBytes(match.Instruction)
	return nil
}

func translateLoadContext(ctx *ParserContext, match MatchInput, hasMatch bool, hasUserHook bool) error {
	if ctx == nil {
		return nil
	}
	if !hasMatch {
		if hasUserHook {
			return nil
		}
		return newUnimplError(
			ErrObtainContextUnimplemented,
			fmt.Sprintf("translate subtable: parser context %v requires a context payload or load-context hook", ctx.GetAddr()),
		)
	}
	if len(match.Context) == 0 {
		return nil
	}
	ctx.SetContextWords(contextWordsFromBytes(match.Context))
	return nil
}

func contextWordsFromBytes(data []byte) []uint64 {
	if len(data) == 0 {
		return nil
	}
	words := make([]uint64, (len(data)+7)/8)
	for i, b := range data {
		word := i / 8
		shift := uint((7 - (i % 8)) * 8)
		words[word] |= uint64(b) << shift
	}
	return words
}

func prepareDelaySlotContexts(cache *DisassemblyCache, subtable *SubtableBoundary, input TranslateInput, ctx *ParserContext) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("translate subtable: nil parser context")
	}
	fallOffset := ctx.GetLength()
	if ctx.GetDelaySlot() <= 0 {
		return fallOffset, nil
	}
	byteCount := 0
	for byteCount < ctx.GetDelaySlot() {
		delayAddr := ctx.GetAddr().Add(uint64(fallOffset))
		delayCtx, err := ObtainPcodeContext(cache, translatePcodeContextRequest(subtable, input, delayAddr))
		if err != nil {
			return 0, err
		}
		length := delayCtx.GetLength()
		if length <= 0 {
			return 0, newUnimplError(
				ErrObtainContextUnimplemented,
				fmt.Sprintf("translate subtable: delay-slot parser context %v has no resolved length", delayAddr),
			)
		}
		fallOffset += length
		byteCount += length
	}
	ctx.SetNaddr(ctx.GetAddr().Add(uint64(fallOffset)))
	return fallOffset, nil
}

func selectActiveSection(walker *ParserWalker, requested *int64) (*ConstructTplBoundary, error) {
	if walker == nil || walker.Point == nil {
		return nil, fmt.Errorf("translate subtable: parser walker has no active state")
	}
	if requested == nil {
		return selectConstructorSection(walker.Point.Constructor, nil)
	}
	return selectConstructorSection(walker.Point.Constructor, requested)
}

func translateRuntimeContext(walker *ParserWalker, base LoweringContext) RuntimeContext {
	runtime := base.runtimeContext()
	if runtime.SpacesByIndex == nil {
		runtime.SpacesByIndex = make(map[int64]*address.Space)
	}
	if walker == nil || walker.ParserContext() == nil {
		return runtime
	}
	ctx := walker.ParserContext()
	runtime.Instruction = ctx.GetAddr()
	if cur := ctx.GetCurSpace(); cur != nil {
		runtime.CurrentSpace = cur
		runtime.SpacesByIndex[int64(cur.Index)] = cur
	}
	if cons := ctx.GetConstSpace(); cons != nil {
		runtime.ConstantSpace = cons
		runtime.SpacesByIndex[int64(cons.Index)] = cons
	}
	if next := ctx.GetNaddr(); !next.IsInvalid() {
		runtime.Next = next
		runtime.HasNext = true
	}
	if next2 := ctx.GetN2addr(); !next2.IsInvalid() {
		runtime.Next2 = next2
		runtime.HasNext2 = true
	}
	if ref := ctx.GetRefAddr(); !ref.IsInvalid() {
		runtime.Ref = ref
		runtime.HasRef = true
	}
	if dest := ctx.GetDestAddr(); !dest.IsInvalid() {
		runtime.Dest = dest
		runtime.HasDest = true
	}
	if walker.Point != nil {
		runtime.ParentHandle = &walker.Point.Handle
		if len(walker.Point.Children) != 0 {
			runtime.Handles = make([]FixedHandle, len(walker.Point.Children))
			for i, child := range walker.Point.Children {
				if child != nil {
					runtime.Handles[i] = child.Handle
				}
			}
		}
	}
	return runtime
}

func translateLoweringContext(state BuilderState, base LoweringContext) LoweringContext {
	ctx := base
	ctx.Instruction = state.Runtime.Instruction
	ctx.CurrentSpace = state.Runtime.CurrentSpace
	ctx.ConstantSpace = state.Runtime.ConstantSpace
	ctx.SpacesByIndex = state.Runtime.SpacesByIndex
	ctx.Handles = translateHandleRefs(state.Runtime.Handles)
	if state.Runtime.HasNext {
		ctx.HasNext = true
		ctx.NextOffset = state.Runtime.Next.Offset
	} else {
		ctx.HasNext = false
		ctx.NextOffset = 0
	}
	if state.Runtime.HasNext2 {
		ctx.HasNext2 = true
		ctx.Next2Offset = state.Runtime.Next2.Offset
	} else {
		ctx.HasNext2 = false
		ctx.Next2Offset = 0
	}
	return ctx
}

func translateHandleRefs(handles []FixedHandle) []HandleReference {
	if len(handles) == 0 {
		return nil
	}
	out := make([]HandleReference, len(handles))
	for i, hand := range handles {
		out[i] = HandleReference{
			Space:       hand.Space,
			Size:        hand.Size,
			OffsetSpace: hand.OffsetSpace,
			Offset:      hand.OffsetOffset,
			OffsetSize:  hand.OffsetSize,
			TempSpace:   hand.TempSpace,
			TempOffset:  hand.TempOffset,
		}
	}
	return out
}

func resolveTranslateFrame(subtable *SubtableBoundary, frame ResolveFrame) (ResolveOutcome, error) {
	target, operand, err := resolveTranslateFrameSubtable(subtable, frame)
	if err != nil {
		return ResolveOutcome{}, err
	}
	// nil target with a non-nil parent means a non-subtable operand (token field, context field).
	// Signal the caller to skip recursive state setup by returning an empty outcome with nil constructor.
	if target == nil && frame.Parent != nil {
		return ResolveOutcome{}, nil
	}
	constructor, err := resolveTranslateConstructor(target, frame.Walker.Walker)
	if err != nil {
		return ResolveOutcome{}, err
	}
	outcome := ResolveOutcome{Constructor: constructor}
	if frame.Parent == nil {
		outcome.Offset = 0
	} else {
		offset, err := resolveTranslateOperandOffset(frame.Parent, operand)
		if err != nil {
			return ResolveOutcome{}, err
		}
		outcome.Offset = offset
	}
	if constructor != nil && constructor.MainSection != nil {
		if constructor.MainSection.DelaySlot > uint64(^uint(0)>>1) {
			return ResolveOutcome{}, fmt.Errorf("translate subtable: delay slot %d overflows int", constructor.MainSection.DelaySlot)
		}
		outcome.DelaySlot = int(constructor.MainSection.DelaySlot)
	}
	return outcome, nil
}

func resolveTranslateConstructor(subtable *SubtableBoundary, walker *ParserWalker) (*ConstructorBoundary, error) {
	if subtable == nil {
		return nil, fmt.Errorf("translate subtable: nil subtable")
	}
	if subtable.Decision == nil {
		if len(subtable.Constructors) == 1 {
			return &subtable.Constructors[0], nil
		}
		return nil, fmt.Errorf("translate subtable: subtable has no decision tree")
	}
	return ResolveSubtableDecision(subtable, walker)
}

func resolveTranslateFrameSubtable(subtable *SubtableBoundary, frame ResolveFrame) (*SubtableBoundary, *OperandSymbolBoundary, error) {
	if frame.Parent == nil {
		return subtable, nil, nil
	}
	if frame.Context == nil || frame.Context.GetSymbolTable() == nil {
		return nil, nil, fmt.Errorf("translate subtable: symbol table is required to resolve operand %d", frame.Operand)
	}
	operand, ok := frame.Context.GetSymbolTable().FindOperandForConstructor(frame.Parent.Constructor, frame.Operand)
	if !ok {
		return nil, nil, fmt.Errorf("translate subtable: operand %d is not available on constructor %d", frame.Operand, frame.Parent.ConstructorID)
	}
	if !operand.HasDefiningSymbolID {
		// Token-field or context-field operand: no subtable to recurse into.
		// Return nil/nil/nil to signal the caller to skip recursive resolution.
		// Mirrors Ghidra C++ SubtableSymbol::resolve() which skips non-SubtableSymbol operands.
		return nil, nil, nil
	}
	sym, ok := frame.Context.GetSymbolTable().FindSymbol(operand.DefiningSymbolID)
	if !ok {
		return nil, nil, fmt.Errorf("translate subtable: operand %d defining symbol %d not found", frame.Operand, operand.DefiningSymbolID)
	}
	if sym.Body.Subtable == nil {
		// Non-subtable defining symbol (e.g. VarnodeList, VarnodeSymbol): treat as a leaf operand.
		// Mirrors Ghidra C++ SubtableSymbol::resolve() which only recurses into SubtableSymbol.
		// Handle resolution for VarnodeList is deferred to ResolveHandles (resolve_handles.go).
		return nil, nil, nil
	}
	return sym.Body.Subtable, operand, nil
}

func resolveTranslateOperandOffset(parent *ConstructState, operand *OperandSymbolBoundary) (uint64, error) {
	if parent == nil || operand == nil {
		return 0, fmt.Errorf("translate subtable: operand offset requires a parent state and operand metadata")
	}
	var base uint64
	if operand.OffsetBase < 0 {
		base = parent.Offset
	} else {
		child, ok := parent.Child(int(operand.OffsetBase))
		if !ok {
			return 0, fmt.Errorf("translate subtable: operand offset base %d is not available", operand.OffsetBase)
		}
		base = child.Offset + uint64(child.Length)
	}
	if operand.RelativeOffset >= 0 {
		return base + uint64(operand.RelativeOffset), nil
	}
	delta := uint64(-(operand.RelativeOffset + 1))
	delta++
	if delta > base {
		return 0, fmt.Errorf("translate subtable: operand relative offset %d underflows base offset %d", operand.RelativeOffset, base)
	}
	return base - delta, nil
}

func selectConstantSpace(ctx LoweringContext) *address.Space {
	if ctx.ConstantSpace != nil {
		return ctx.ConstantSpace
	}
	return ctx.runtimeContext().ConstantSpace
}

// ResolveConstructor walks the persisted decision tree and returns the first matching constructor.
func ResolveConstructor(subtable *SubtableBoundary, input MatchInput) (*ConstructorBoundary, error) {
	if subtable == nil {
		return nil, fmt.Errorf("subtable is nil")
	}
	if subtable.Decision == nil {
		if len(subtable.Constructors) == 1 {
			return &subtable.Constructors[0], nil
		}
		return nil, fmt.Errorf("subtable has no decision tree")
	}
	constructor, err := resolveDecisionNode(*subtable.Decision, subtable, input)
	if err != nil {
		return nil, err
	}
	return constructor, nil
}

func resolveDecisionNode(node DecisionNodeBoundary, subtable *SubtableBoundary, input MatchInput) (*ConstructorBoundary, error) {
	if node.Size == 0 {
		for _, pair := range node.Pairs {
			matched, err := matchPattern(pair.Pattern, input)
			if err != nil {
				return nil, err
			}
			if !matched {
				continue
			}
			constructor, err := constructorByID(subtable, pair.ConstructorID)
			if err != nil {
				return nil, err
			}
			return constructor, nil
		}
		return nil, fmt.Errorf("unable to resolve constructor from terminal decision node")
	}
	value, err := extractBits(selectData(node.Context, input), selectBitBase(node.Context, input), node.StartBit, node.Size)
	if err != nil {
		return nil, err
	}
	if value >= uint64(len(node.Children)) {
		return nil, fmt.Errorf("decision child index %d out of range", value)
	}
	return resolveDecisionNode(node.Children[value], subtable, input)
}

func constructorByID(subtable *SubtableBoundary, id uint64) (*ConstructorBoundary, error) {
	for i := range subtable.Constructors {
		if subtable.Constructors[i].ConstructorID == id {
			return &subtable.Constructors[i], nil
		}
	}
	return nil, fmt.Errorf("constructor id %d not found", id)
}

func matchPattern(pattern *DisjointPatternBoundary, input MatchInput) (bool, error) {
	if pattern == nil {
		return true, nil
	}
	switch pattern.ElementID {
	case elemOrPat:
		for _, child := range pattern.Children {
			matched, err := matchPattern(&child, input)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	case elemInstructPat, elemContextPat:
		if pattern.Block == nil {
			return false, fmt.Errorf("pattern %d missing pattern block", pattern.ElementID)
		}
		return matchPatternBlock(*pattern.Block, selectPatternData(pattern.ElementID, input), selectPatternBase(pattern.ElementID, input)), nil
	case elemCombinePat:
		for _, child := range pattern.Children {
			matched, err := matchPattern(&child, input)
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported pattern element %d", pattern.ElementID)
	}
}

func matchPatternBlock(block PatternBlockBoundary, data []byte, baseOffset int64) bool {
	if block.NonZeroSize <= 0 {
		return block.NonZeroSize == 0
	}
	off := baseOffset + block.Offset
	for range block.MaskWords {
		if off < 0 || off > int64(len(data)) {
			return false
		}
		off += 8
	}
	off = baseOffset + block.Offset
	for _, word := range block.MaskWords {
		chunk := readPackedBytesBigEndian(data, off, 8)
		if (word.Mask & chunk) != word.Val {
			return false
		}
		off += 8
	}
	return true
}

func readPackedBytesBigEndian(data []byte, offset int64, width int64) uint64 {
	if offset < 0 || width <= 0 {
		return 0
	}
	var result uint64
	for i := int64(0); i < width; i++ {
		result <<= 8
		pos := offset + i
		if pos >= 0 && pos < int64(len(data)) {
			result |= uint64(data[pos])
		}
	}
	return result
}

func extractBits(data []byte, baseOffset int64, startBit int64, size int64) (uint64, error) {
	if startBit < 0 || size < 0 || size > 64 {
		return 0, fmt.Errorf("invalid bit range start=%d size=%d", startBit, size)
	}
	byteOffset := baseOffset + (startBit / 8)
	if byteOffset < 0 || byteOffset >= int64(len(data)) {
		return 0, fmt.Errorf("bit range start=%d size=%d exceeds available data", startBit, size)
	}
	bitOffset := startBit % 8
	byteSize := ((bitOffset + size - 1) / 8) + 1
	packed := readPackedBytesBigEndian(data, byteOffset, byteSize)
	leftShift := uint((8 * (8 - byteSize)) + bitOffset)
	packed <<= leftShift
	packed >>= uint((8 * 8) - size)
	return packed, nil
}

func selectData(context bool, input MatchInput) []byte {
	if context {
		return input.Context
	}
	return input.Instruction
}

func selectBitBase(context bool, input MatchInput) int64 {
	if context {
		return 0
	}
	return input.InstructionOffset
}

func selectPatternData(elementID uint32, input MatchInput) []byte {
	if elementID == elemContextPat {
		return input.Context
	}
	return input.Instruction
}

func selectPatternBase(elementID uint32, input MatchInput) int64 {
	if elementID == elemContextPat {
		return 0
	}
	return input.InstructionOffset
}

func selectConstructorSection(constructor *ConstructorBoundary, sectionID *int64) (*ConstructTplBoundary, error) {
	if constructor == nil {
		return nil, fmt.Errorf("constructor is nil")
	}
	if sectionID == nil {
		if constructor.MainSection == nil {
			return nil, fmt.Errorf("constructor has no main section")
		}
		return constructor.MainSection, nil
	}
	for _, section := range constructor.NamedSections {
		if section.SectionID == *sectionID {
			copy := section.Template
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("constructor section %d not found", *sectionID)
}
