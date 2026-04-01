package sla

import (
	"errors"
	"fmt"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

var ErrBuilderUnimplemented = errors.New("builder directive is unimplemented")

// UnimplError mirrors ghidra::UnimplError by carrying explain text plus optional instruction length.
type UnimplError struct {
	Explain              string
	InstructionLength    int
	HasInstructionLength bool
	Cause                error
	// Legacy compatibility fields for in-package transitional callsites/tests.
	explain           string
	instructionLength int
	cause             error
}

func (e *UnimplError) Error() string {
	if e == nil {
		return ""
	}
	explain := e.Explain
	if explain == "" {
		explain = e.explain
	}
	if explain != "" {
		return explain
	}
	cause := e.Cause
	if cause == nil {
		cause = e.cause
	}
	if cause != nil {
		return cause.Error()
	}
	return "instruction not implemented in pcode"
}

func (e *UnimplError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.Cause != nil {
		return e.Cause
	}
	return e.cause
}

func newUnimplError(cause error, explain string) *UnimplError {
	return &UnimplError{
		Explain: explain,
		Cause:   cause,
		explain: explain,
		cause:   cause,
	}
}

func newUnimplErrorWithInstructionLength(cause error, explain string, instructionLength int) *UnimplError {
	return &UnimplError{
		Explain:              explain,
		InstructionLength:    instructionLength,
		HasInstructionLength: true,
		Cause:                cause,
		explain:              explain,
		instructionLength:    instructionLength,
		cause:                cause,
	}
}

func normalizeBuilderUnimpl(err error) error {
	if err == nil {
		return nil
	}
	var existing *UnimplError
	if errors.As(err, &existing) {
		return err
	}
	if errors.Is(err, ErrBuilderUnimplemented) {
		return newUnimplError(ErrBuilderUnimplemented, err.Error())
	}
	return err
}

// BuilderState carries the runtime state needed by the builder shell.
type BuilderState struct {
	Runtime   RuntimeContext
	Walker    *ParserWalker
	Cache     *DisassemblyCache
	SectionID int64
}

// SetDisassemblyCache attaches a parser-context cache to the builder state.
func (s *BuilderState) SetDisassemblyCache(cache *DisassemblyCache) {
	if s == nil {
		return
	}
	s.Cache = cache
}

// HasPcodeParserContext reports whether the cache has a pcode parser context for an address.
func (s BuilderState) HasPcodeParserContext(addr address.Address) bool {
	if s.Cache == nil {
		return false
	}
	return s.Cache.HasPcodeParserContext(addr)
}

// RequirePcodeParserContext returns a cached pcode parser context or an error.
func (s BuilderState) RequirePcodeParserContext(addr address.Address) (*ParserContext, error) {
	if s.Cache == nil {
		return nil, fmt.Errorf("builder state has no disassembly cache")
	}
	return s.Cache.RequirePcodeParserContext(addr)
}

// RequireWalkerPcodeParserContext resolves the current walker address through the cache.
func (s BuilderState) RequireWalkerPcodeParserContext() (*ParserContext, error) {
	if s.Walker == nil || s.Walker.ParserContext() == nil {
		return nil, fmt.Errorf("builder state has no walker parser context")
	}
	return s.RequirePcodeParserContext(s.Walker.ParserContext().GetAddr())
}

// BuilderHooks routes control directives and ordinary op emission to runtime callbacks.
type BuilderHooks struct {
	Dump         func(op OpTplBoundary, state BuilderState) error
	// LowerRaw enables cache-backed raw-op ownership, mirroring SleighBuilder::dump() + PcodeCacher.
	LowerRaw     func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error)
	// RawEmitter mirrors PcodeCacher::emit(addr, PcodeEmit*) sink routing for root cache-backed builds.
	RawEmitter   pcode.RawEmitter
	OnLabel      func(labelID uint64, state BuilderState) error
	ResolveBuild func(op OpTplBoundary, operandIndex int64, sectionID int64, state BuilderState) (*ConstructTplBoundary, int64, bool, error)
	OnBuild      func(op OpTplBoundary, operandIndex int64, sectionID int64, state BuilderState) error
	OnDelaySlot  func(op OpTplBoundary, state BuilderState) error
	OnCrossBuild func(op OpTplBoundary, crossSectionID int64, state BuilderState) error
}

// PcodeBuilder stores label scope state across nested builds.
type PcodeBuilder struct {
	LabelBase     uint64
	LabelCount    uint64
	LabelResolver RawLabelResolver
	rawInstruction address.Address
	rawBuildDepth  int
}

// SleighBuilder is the parity-oriented shell for Ghidra's builder layer.
type SleighBuilder struct {
	Pcode PcodeBuilder
	State BuilderState
	Hooks BuilderHooks
}

type builderNoopRawEmitter struct{}

func (builderNoopRawEmitter) EmitRaw(op pcode.RawOp) error {
	return nil
}

// NewSleighBuilder creates a builder shell with explicit runtime hooks.
func NewSleighBuilder(runtime RuntimeContext, labelBase uint64, sectionID int64, hooks BuilderHooks) *SleighBuilder {
	return &SleighBuilder{
		Pcode: PcodeBuilder{
			LabelBase:      labelBase,
			LabelCount:     labelBase,
			LabelResolver:  NewRawLabelResolver(),
			rawInstruction: runtime.Instruction,
		},
		State: BuilderState{
			Runtime:   runtime,
			SectionID: sectionID,
		},
		Hooks: hooks,
	}
}

// Build walks a decoded constructor and dispatches each op through the builder shell.
func (b *SleighBuilder) Build(construct ConstructTplBoundary, sectionID int64) (err error) {
	if b == nil {
		return fmt.Errorf("builder is nil")
	}
	rootRawBuild := false
	if b.Hooks.LowerRaw != nil {
		rootRawBuild, err = b.enterRawBuild(len(construct.Ops))
		if err != nil {
			return err
		}
		defer func() {
			if leaveErr := b.leaveRawBuild(rootRawBuild, err); err == nil && leaveErr != nil {
				err = leaveErr
			}
		}()
	}

	prevSection := b.State.SectionID
	prevBase := b.Pcode.LabelBase
	b.State.SectionID = sectionID
	b.Pcode.LabelBase = b.Pcode.LabelCount
	b.Pcode.LabelCount += construct.NumLabels
	defer func() {
		b.State.SectionID = prevSection
		b.Pcode.LabelBase = prevBase
	}()

		for _, op := range construct.Ops {
			if err = b.dispatch(op); err != nil {
				return normalizeBuilderUnimpl(err)
			}
		}
		return nil
}

// Dispatch exposes directive routing for callers that want to process one op at a time.
func (b *SleighBuilder) Dispatch(op OpTplBoundary) error {
	if b == nil {
		return fmt.Errorf("builder is nil")
	}
	return normalizeBuilderUnimpl(b.dispatch(op))
}

func (b *SleighBuilder) dispatch(op OpTplBoundary) error {
	switch directiveName(op) {
	case "BUILD":
		return b.AppendBuild(op, b.State.SectionID)
	case "DELAY_SLOT":
		return b.DelaySlot(op)
	case "LABELBUILD":
		return b.SetLabel(op)
	case "CROSSBUILD":
		return b.AppendCrossBuild(op, b.State.SectionID)
	default:
		return b.dump(op)
	}
}

func (b *SleighBuilder) dump(op OpTplBoundary) error {
	if b.Hooks.LowerRaw != nil {
		return b.dumpToRawCache(op)
	}
	if b.Hooks.Dump == nil {
		return newUnimplError(ErrBuilderUnimplemented, fmt.Sprintf("raw opcode %q", op.Opcode))
	}
	return b.Hooks.Dump(op, b.State)
}

// AppendBuild routes BUILD through the runtime hook or returns an explicit unimplemented error.
func (b *SleighBuilder) AppendBuild(op OpTplBoundary, sectionID int64) error {
	operandIndex, err := directiveOperandIndex(op, "BUILD")
	if err != nil {
		return err
	}
	if handled, err := b.appendBuildFromWalker(op, operandIndex, sectionID); handled || err != nil {
		return normalizeBuilderUnimpl(err)
	}
		if b.Hooks.ResolveBuild != nil {
			child, childSection, ok, err := b.Hooks.ResolveBuild(op, operandIndex, sectionID, b.State)
			if err != nil {
				return normalizeBuilderUnimpl(err)
			}
			if !ok || child == nil {
				if b.State.Walker != nil && b.State.Walker.IsState() && childSection >= 0 {
					return normalizeBuilderUnimpl(b.buildEmpty(childSection))
				}
				if childSection >= 0 {
					return newUnimplError(ErrBuilderUnimplemented, fmt.Sprintf("BUILD named section %d requires active walker state for empty-section recursion", childSection))
				}
				// Parity gap: ResolveBuild cannot yet distinguish C++'s ignored
				// non-subtable BUILD from a missing main-section constructor.
				return nil
			}
			return normalizeBuilderUnimpl(b.Build(*child, childSection))
		}
		if b.Hooks.OnBuild != nil {
		return normalizeBuilderUnimpl(b.Hooks.OnBuild(op, operandIndex, sectionID, b.State))
	}
	return newUnimplError(ErrBuilderUnimplemented, "BUILD")
}

func (b *SleighBuilder) appendBuildFromWalker(op OpTplBoundary, operandIndex int64, sectionID int64) (bool, error) {
	if b.State.Walker == nil || !b.State.Walker.IsState() {
		return false, nil
	}
	if operandIndex < 0 {
		return true, fmt.Errorf("BUILD operand index must be non-negative")
	}
	current := b.State.Walker.Point
	child, ok := current.Child(int(operandIndex))
	if !ok || child == nil || child.Constructor == nil {
		return false, nil
	}
	if err := b.State.Walker.PushOperand(int(operandIndex)); err != nil {
		return true, err
	}
	defer b.State.Walker.PopOperand()
	selected, ok := child.TemplateForSection(sectionID)
	if !ok {
		if sectionID >= 0 {
			return true, b.buildEmpty(sectionID)
		}
		return true, fmt.Errorf("BUILD child constructor has no main section")
	}
	return true, b.Build(*selected, sectionID)
}

// DelaySlot routes DELAY_SLOT through the runtime hook or returns an explicit unimplemented error.
func (b *SleighBuilder) DelaySlot(op OpTplBoundary) error {
	if handled, err := b.delaySlotFromWalker(); handled || err != nil {
		return normalizeBuilderUnimpl(err)
	}
	if b.Hooks.OnDelaySlot == nil {
		return newUnimplError(ErrBuilderUnimplemented, "DELAY_SLOT")
	}
	return normalizeBuilderUnimpl(b.Hooks.OnDelaySlot(op, b.State))
}

// SetLabel routes LABELBUILD through the runtime hook and updates label scope state.
func (b *SleighBuilder) SetLabel(op OpTplBoundary) error {
	labelIndex, err := directiveOperandIndex(op, "LABELBUILD")
	if err != nil {
		return err
	}
	absolute := b.Pcode.LabelBase + uint64(labelIndex)
	if b.Hooks.LowerRaw != nil {
		if err := b.cacheRawLabel(absolute); err != nil {
			return err
		}
	}
	if b.Hooks.OnLabel != nil {
		return normalizeBuilderUnimpl(b.Hooks.OnLabel(absolute, b.State))
	}
	if b.Hooks.LowerRaw != nil {
		return nil
	}
	return newUnimplError(ErrBuilderUnimplemented, "LABELBUILD")
}

func (b *SleighBuilder) enterRawBuild(capacityHint int) (bool, error) {
	if b == nil {
		return false, fmt.Errorf("builder is nil")
	}
	if b.State.Cache == nil {
		return false, newUnimplError(ErrBuilderUnimplemented, "cache-backed raw emission requires a disassembly cache")
	}
	root := b.Pcode.rawBuildDepth == 0
	if root {
		instruction, err := b.rawInstructionAddress()
		if err != nil {
			return false, err
		}
		b.Pcode.rawInstruction = instruction
		if err := b.State.Cache.BeginRawBuild(instruction, capacityHint); err != nil {
			return false, err
		}
	}
	b.Pcode.rawBuildDepth++
	return root, nil
}

func (b *SleighBuilder) leaveRawBuild(root bool, buildErr error) error {
	if b == nil || b.Hooks.LowerRaw == nil {
		return nil
	}
	if b.Pcode.rawBuildDepth > 0 {
		b.Pcode.rawBuildDepth--
	}
	if !root {
		return nil
	}
	if buildErr != nil {
		b.State.Cache.CancelRawBuild(b.Pcode.rawInstruction)
		return nil
	}
	// Mirrors sleigh.cc oneInstruction() tail: PcodeCacher::resolveRelatives() then PcodeCacher::emit().
	if err := b.State.Cache.ResolveRawBuild(b.Pcode.rawInstruction); err != nil {
		b.State.Cache.CancelRawBuild(b.Pcode.rawInstruction)
		return err
	}
	// Keep root-tail sink-shaped like PcodeCacher::emit(addr, PcodeEmit*):
	// when no external sink is provided, use a no-op sink rather than slice-return fallback.
	emitter := b.Hooks.RawEmitter
	if emitter == nil {
		emitter = builderNoopRawEmitter{}
	}
	if err := b.State.Cache.EmitRawBuildTo(b.Pcode.rawInstruction, emitter); err != nil {
		b.State.Cache.CancelRawBuild(b.Pcode.rawInstruction)
		return err
	}
	return nil
}

func (b *SleighBuilder) rawInstructionAddress() (address.Address, error) {
	if err := b.Pcode.rawInstruction.Validate(); err == nil {
		return b.Pcode.rawInstruction, nil
	}
	if err := b.State.Runtime.Instruction.Validate(); err == nil {
		return b.State.Runtime.Instruction, nil
	}
	if b.State.Walker != nil && b.State.Walker.ParserContext() != nil {
		addr := b.State.Walker.ParserContext().GetAddr()
		if err := addr.Validate(); err == nil {
			return addr, nil
		}
	}
	return address.Address{}, newUnimplError(ErrBuilderUnimplemented, "cache-backed raw emission requires a valid instruction address")
}

// dumpToRawCache mirrors SleighBuilder::dump() into PcodeCacher
// allocateInstruction/allocateVarnodes/addLabelRef staging flow.
func (b *SleighBuilder) dumpToRawCache(op OpTplBoundary) error {
	if b.State.Cache == nil {
		return newUnimplError(ErrBuilderUnimplemented, "cache-backed raw emission requires a disassembly cache")
	}
	if b.Pcode.rawBuildDepth <= 0 {
		return newUnimplError(ErrBuilderUnimplemented, "cache-backed raw emission is inactive")
	}
	order, err := b.State.Cache.RawBuildLength(b.Pcode.rawInstruction)
	if err != nil {
		return err
	}
	lowered, err := b.Hooks.LowerRaw(op, b.State, order)
	if err != nil {
		return normalizeBuilderUnimpl(err)
	}
	return normalizeBuilderUnimpl(b.State.Cache.AppendRawBuild(b.Pcode.rawInstruction, op, lowered, b.Pcode.LabelBase))
}

func (b *SleighBuilder) cacheRawLabel(labelID uint64) error {
	if b.State.Cache == nil {
		return newUnimplError(ErrBuilderUnimplemented, "cache-backed raw emission requires a disassembly cache")
	}
	if b.Pcode.rawBuildDepth <= 0 {
		return newUnimplError(ErrBuilderUnimplemented, "cache-backed raw emission is inactive")
	}
	return b.State.Cache.AddRawBuildLabel(b.Pcode.rawInstruction, labelID)
}

// AppendCrossBuild routes CROSSBUILD through the cached parser-context re-entry path.
func (b *SleighBuilder) AppendCrossBuild(op OpTplBoundary, sectionID int64) error {
	return normalizeBuilderUnimpl(b.appendCrossBuild(op, sectionID))
}

func directiveName(op OpTplBoundary) string {
	switch op.Opcode {
	case "BUILD", "DELAY_SLOT", "LABELBUILD", "CROSSBUILD":
		return op.Opcode
	}
	switch op.OpcodeID {
	case int64(pcode.CPUI_MULTIEQUAL):
		return "BUILD"
	case int64(pcode.CPUI_INDIRECT):
		return "DELAY_SLOT"
	case int64(pcode.CPUI_PTRADD):
		return "LABELBUILD"
	case int64(pcode.CPUI_PTRSUB):
		return "CROSSBUILD"
	default:
		return ""
	}
}

func directiveOperandIndex(op OpTplBoundary, name string) (int64, error) {
	if len(op.Inputs) == 0 {
		return 0, fmt.Errorf("%s expects at least one input, got %d", name, len(op.Inputs))
	}
	return realConstValue(op.Inputs[0].Offset, name+" operand")
}

func realConstValue(c ConstBoundary, name string) (int64, error) {
	if c.Kind != ConstKindReal && c.Kind != ConstKindRelative {
		return 0, fmt.Errorf("%s requires a real constant, got %q", name, c.Kind)
	}
	if c.Value > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("%s overflows int64", name)
	}
	return int64(c.Value), nil
}
