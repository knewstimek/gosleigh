package sla

import (
	"fmt"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

const (
	// Mirrors SleighBase::decode() in sleighbase.cc:
	// root = (SubtableSymbol *)symtab.getGlobalScope()->findSymbol("instruction");
	standardInstructionRootName = "instruction"
	globalSymbolScopeID         = uint64(0)
)

// EngineBackendAdapter is the address-scoped backend boundary for one-instruction translation.
// It mirrors the external loader/context bridge used by Sleigh::resolve()/loadFill()/loadContext().
type EngineBackendAdapter struct {
	LoadMatchInput func(addr address.Address) (MatchInput, bool, error)
	LoadFill       func(ctx *ParserContext) error
	LoadContext    func(ctx *ParserContext) error
	Resolve        ResolveHooks
	ResolveHandles ResolveHandlesHooks
	Commits        ApplyCommitsHooks
}

// EngineConfig wires the high-level one-instruction translation entry point.
type EngineConfig struct {
	// RootSubtable overrides the entry subtable. If nil, NewEngine attempts to
	// derive the standard root from Symbols using FindInstructionRootSubtable().
	RootSubtable    *SubtableBoundary
	Metadata        *Metadata
	Symbols         *SymbolTableBoundary
	LoweringTemplate LoweringContext
	Alignment       uint64
	Section         *int64
	Cache           *DisassemblyCache
	Backend         EngineBackendAdapter
	// XRefs is the optional cross-reference table built by BuildXrefs() after
	// .sla decode. When non-nil it is passed through to translate/runtime paths
	// for register-name lookup, user-op naming, and context field resolution.
	// Mirrors SleighBase::buildXrefs() output available to Sleigh at runtime.
	XRefs *XRefs
}

// InstructionTranslation is the high-level translation result for one instruction address.
type InstructionTranslation struct {
	Address address.Address
	Next    address.Address
	Length  int
	Ops     []pcode.RawOp
}

// Engine is the high-level translation entry point over TranslateSubtable and parser-context caching.
type Engine struct {
	rootSubtable    *SubtableBoundary
	symbols         *SymbolTableBoundary
	loweringTemplate LoweringContext
	alignment       uint64
	section         *int64
	cache           *DisassemblyCache
	backend         EngineBackendAdapter
	// xrefs is the optional runtime cross-reference table (BuildXrefs output).
	// nil means no xref data is available; callers must not panic on nil.
	xrefs *XRefs
}

// FindInstructionRootSubtable mirrors SleighBase::decode() root lookup from sleighbase.cc:
// find global-scope symbol named "instruction" and use its subtable body.
func FindInstructionRootSubtable(symbols *SymbolTableBoundary) (*SubtableBoundary, bool) {
	if symbols == nil {
		return nil, false
	}
	for i := range symbols.Symbols {
		sym := &symbols.Symbols[i]
		if sym.ScopeID != globalSymbolScopeID {
			continue
		}
		if sym.Name != standardInstructionRootName {
			continue
		}
		if sym.Body.Subtable == nil {
			return nil, false
		}
		return sym.Body.Subtable, true
	}
	return nil, false
}

// FindStandardRootSubtable is a compatibility alias for instruction-root lookup.
func FindStandardRootSubtable(symbols *SymbolTableBoundary) (*SubtableBoundary, bool) {
	return FindInstructionRootSubtable(symbols)
}

// NewEngineFromMetadataSymbols creates an engine from the core decoded boundaries.
// If cfg.RootSubtable is nil, NewEngine falls back to FindInstructionRootSubtable().
func NewEngineFromMetadataSymbols(metadata *Metadata, symbols *SymbolTableBoundary, backend EngineBackendAdapter, cfg EngineConfig) (*Engine, error) {
	cfg.Metadata = metadata
	cfg.Symbols = symbols
	cfg.Backend = backend
	return NewEngine(cfg)
}

// NewEngineFromBoundaries creates an engine from decoded boundaries.
// Metadata/Symbols default to boundaries when not explicitly set in cfg.
func NewEngineFromBoundaries(boundaries *Boundaries, cfg EngineConfig) (*Engine, error) {
	if boundaries == nil {
		return nil, fmt.Errorf("new engine from boundaries: boundaries are nil")
	}
	if cfg.Metadata == nil {
		cfg.Metadata = boundaries.Metadata
	}
	if cfg.Symbols == nil {
		cfg.Symbols = boundaries.SymbolTable
	}
	return NewEngineFromMetadataSymbols(cfg.Metadata, cfg.Symbols, cfg.Backend, cfg)
}

// NewEngine prepares a reusable one-instruction translation engine over the current Go runtime shell.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	rootSubtable := cfg.RootSubtable
	if rootSubtable == nil {
		var ok bool
		rootSubtable, ok = FindInstructionRootSubtable(cfg.Symbols)
		if !ok {
			return nil, fmt.Errorf("new engine: root subtable is nil and standard %q root symbol was not found in global scope", standardInstructionRootName)
		}
	}
	cache := cfg.Cache
	if cache == nil {
		cache = NewDisassemblyCache()
	}
	alignment := cfg.Alignment
	if alignment == 0 && cfg.Metadata != nil && cfg.Metadata.Align > 0 {
		alignment = uint64(cfg.Metadata.Align)
	}
	loweringTemplate := cfg.LoweringTemplate
	if isZeroLoweringTemplate(loweringTemplate) {
		loweringTemplate = NewLoweringContext(cfg.Metadata, address.Address{})
	}
	loweringTemplate = normalizeLoweringTemplate(loweringTemplate)

	return &Engine{
		rootSubtable:    rootSubtable,
		symbols:         cfg.Symbols,
		loweringTemplate: loweringTemplate,
		alignment:       alignment,
		section:         cloneSectionID(cfg.Section),
		cache:           cache,
		backend:         cfg.Backend,
		xrefs:           cfg.XRefs,
	}, nil
}

// DisassemblyCache returns the cache used by this engine.
func (e *Engine) DisassemblyCache() *DisassemblyCache {
	if e == nil {
		return nil
	}
	return e.cache
}

// XRefs returns the cross-reference table associated with this engine.
// Returns nil when no xref data was provided at construction time.
func (e *Engine) XRefs() *XRefs {
	if e == nil {
		return nil
	}
	return e.xrefs
}

// TranslateInstructionAt mirrors Sleigh::oneInstruction() authority flow through TranslateSubtable:
// obtainContext(pcode) -> applyCommits -> resolveHandles -> build/resolve/emit.
func (e *Engine) TranslateInstructionAt(addr address.Address) (InstructionTranslation, error) {
	if e == nil {
		return InstructionTranslation{}, fmt.Errorf("engine translate instruction: engine is nil")
	}
	cache := e.cache
	if cache == nil {
		cache = NewDisassemblyCache()
		e.cache = cache
	}
	if err := addr.Validate(); err != nil {
		return InstructionTranslation{}, fmt.Errorf("engine translate instruction: address: %w", err)
	}
	resolveHooks := e.backendResolveHooks()
	ops, err := TranslateSubtable(e.rootSubtable, TranslateInput{
		Payloads: TranslatePayloadSource{
			Loader: enginePayloadLoader(e.backend.LoadMatchInput, resolveHooks),
		},
		Lowering:       e.loweringContextForAddress(addr),
		Alignment:      e.alignment,
		Section:        e.section,
		Cache:          cache,
		Symbols:        e.symbols,
		Resolve:        resolveHooks,
		ResolveHandles: e.backend.ResolveHandles,
		Commits:        e.backend.Commits,
	})
	if err != nil {
		return InstructionTranslation{}, err
	}
	ctx, ok := cache.GetPcodeParserContext(addr)
	if !ok || ctx == nil {
		return InstructionTranslation{}, fmt.Errorf("engine translate instruction: missing pcode parser context for %v", addr)
	}
	length, err := instructionLengthFromPcodeContext(addr, ctx)
	if err != nil {
		return InstructionTranslation{}, err
	}
	return InstructionTranslation{
		Address: addr,
		Next:    ctx.GetNaddr(),
		Length:  length,
		Ops:     cloneRawOps(ops),
	}, nil
}

func (e *Engine) backendResolveHooks() ResolveHooks {
	hooks := e.backend.Resolve
	// Mirrors Sleigh::resolve() authority split: loadFill/loadContext are distinct
	// callbacks and do not need to be bundled through one payload object.
	if hooks.LoadFill == nil {
		hooks.LoadFill = e.backend.LoadFill
	}
	if hooks.LoadContext == nil {
		hooks.LoadContext = e.backend.LoadContext
	}
	return hooks
}

func enginePayloadLoader(loader func(addr address.Address) (MatchInput, bool, error), hooks ResolveHooks) func(addr address.Address) (MatchInput, bool, error) {
	if hooks.LoadFill != nil && hooks.LoadContext != nil {
		// When both hooks are explicit, resolve owns decode inputs directly and
		// does not need MatchInput-bundled authority for this instruction path.
		return nil
	}
	return loader
}

func (e *Engine) loweringContextForAddress(addr address.Address) LoweringContext {
	ctx := e.loweringTemplate
	ctx.Instruction = addr
	// Mirrors Sleigh::oneInstruction(baseaddr) using the entry address as the
	// sink-visible raw-op address passed through PcodeCacher::emit(baseaddr,...).
	ctx.RootInstruction = addr
	ctx.CurrentSpace = addr.Space
	ctx.HasNext = false
	ctx.NextOffset = 0
	ctx.HasNext2 = false
	ctx.Next2Offset = 0
	ctx.Handles = nil
	ctx.SpacesByIndex = cloneSpacesByIndex(e.loweringTemplate.SpacesByIndex)
	if ctx.SpacesByIndex == nil {
		ctx.SpacesByIndex = make(map[int64]*address.Space)
	}
	if addr.Space != nil {
		ctx.SpacesByIndex[int64(addr.Space.Index)] = addr.Space
	}
	if ctx.ConstantSpace != nil {
		ctx.SpacesByIndex[int64(ctx.ConstantSpace.Index)] = ctx.ConstantSpace
	}
	if ctx.UniqueSpace != nil {
		ctx.SpacesByIndex[int64(ctx.UniqueSpace.Index)] = ctx.UniqueSpace
	}
	return ctx
}

func normalizeLoweringTemplate(ctx LoweringContext) LoweringContext {
	if ctx.ConstantSpace == nil {
		// Mirrors NewLoweringContext() fallback when no serialized constant space is available.
		ctx.ConstantSpace = NewLoweringContext(nil, address.Address{}).ConstantSpace
	}
	if ctx.SpacesByIndex == nil {
		ctx.SpacesByIndex = make(map[int64]*address.Space)
	}
	if ctx.CurrentSpace != nil {
		ctx.SpacesByIndex[int64(ctx.CurrentSpace.Index)] = ctx.CurrentSpace
	}
	if ctx.ConstantSpace != nil {
		ctx.SpacesByIndex[int64(ctx.ConstantSpace.Index)] = ctx.ConstantSpace
	}
	if ctx.UniqueSpace != nil {
		ctx.SpacesByIndex[int64(ctx.UniqueSpace.Index)] = ctx.UniqueSpace
	}
	return ctx
}

func isZeroLoweringTemplate(ctx LoweringContext) bool {
	return ctx.CurrentSpace == nil &&
		ctx.ConstantSpace == nil &&
		ctx.UniqueSpace == nil &&
		len(ctx.SpacesByIndex) == 0 &&
		ctx.UniqueBase == 0 &&
		ctx.UniqueMask == 0 &&
		ctx.LabelBase == 0 &&
		!ctx.HasNext &&
		!ctx.HasNext2 &&
		ctx.NextOffset == 0 &&
		ctx.Next2Offset == 0 &&
		len(ctx.Handles) == 0
}

func instructionLengthFromPcodeContext(addr address.Address, ctx *ParserContext) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("engine translate instruction: parser context is nil")
	}
	next := ctx.GetNaddr()
	if !next.IsInvalid() && next.Space == addr.Space {
		if next.Offset < addr.Offset {
			return 0, fmt.Errorf("engine translate instruction: parser context next address %v precedes %v", next, addr)
		}
		delta := next.Offset - addr.Offset
		maxInt := uint64(int(^uint(0) >> 1))
		if delta > maxInt {
			return 0, fmt.Errorf("engine translate instruction: parser context length overflows int: %d", delta)
		}
		// Mirrors Sleigh::oneInstruction() returning fallOffset, not base constructor length.
		return int(delta), nil
	}
	length := ctx.GetLength()
	if length < 0 {
		return 0, fmt.Errorf("engine translate instruction: parser context length is negative: %d", length)
	}
	return length, nil
}

func cloneSpacesByIndex(src map[int64]*address.Space) map[int64]*address.Space {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[int64]*address.Space, len(src))
	for idx, space := range src {
		dst[idx] = space
	}
	return dst
}

func cloneSectionID(section *int64) *int64 {
	if section == nil {
		return nil
	}
	value := *section
	return &value
}

// RegisterNamesByLocation returns a map of "spaceIdx:offset:size" -> register name
// for all VarnodeSymbol entries in the SLA symbol table.
// Key format matches the encoding used by PrintC.SetRegisterNames.
// When multiple symbols map to the same location, the shortest name wins (prefer
// canonical short names like "eax" over longer aliases).
// C++ parity: AddrSpace/VarnodeSymbol name table in slghsymbol.cc
func (e *Engine) RegisterNamesByLocation() map[string]string {
	result := make(map[string]string)
	if e == nil || e.symbols == nil {
		return result
	}
	for i := range e.symbols.Symbols {
		sym := &e.symbols.Symbols[i]
		if sym.Body.Varnode == nil || sym.Name == "" {
			continue
		}
		v := sym.Body.Varnode
		key := fmt.Sprintf("%d:%d:%d", v.SpaceIndex, v.Offset, v.Size)
		if existing, ok := result[key]; !ok || len(sym.Name) < len(existing) {
			result[key] = sym.Name
		}
	}
	return result
}
