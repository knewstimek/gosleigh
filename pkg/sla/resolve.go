package sla

import (
	"errors"
	"fmt"

	"gosleigh/pkg/address"
)

var ErrResolveUnimplemented = errors.New("resolve step is unimplemented")

func normalizeResolveUnimpl(err error) error {
	if err == nil {
		return nil
	}
	var existing *UnimplError
	if errors.As(err, &existing) {
		return err
	}
	if errors.Is(err, ErrResolveUnimplemented) {
		return newUnimplError(ErrResolveUnimplemented, err.Error())
	}
	return err
}

// ResolveHooks carries the hook-only parts of Sleigh::resolve().
// The shell handles state mutation, operand allocation, and commit reservation wiring.
type ResolveHooks struct {
	LoadFill      func(ctx *ParserContext) error
	LoadContext   func(ctx *ParserContext) error
	ResolveSymbol func(frame ResolveFrame) (ResolveOutcome, error)
}

// ResolveFrame describes the current parser state handed to the symbol-resolution hook.
type ResolveFrame struct {
	Context   *ParserContext
	Walker    *ParserWalkerChange
	State     *ConstructState
	Parent    *ConstructState
	Depth     int
	Operand   int
	SectionID int64
}

// ResolveOutcome carries the shell-visible data returned by the symbol-resolution hook.
type ResolveOutcome struct {
	Constructor *ConstructorBoundary
	Offset      uint64
	Length      int
	DelaySlot   int
	Commits     []ContextCommitBoundary
	HasRefAddr  bool
	RefAddr     address.Address
	HasDestAddr bool
	DestAddr    address.Address
}

// ResolveResult reports the shell state after a resolve pass.
type ResolveResult struct {
	Walker             *ParserWalkerChange
	Root               *ConstructState
	CommitReservations []ContextCommitBoundary
}

// Resolve mirrors the original Sleigh::resolve() shell.
func Resolve(ctx *ParserContext, hooks ResolveHooks) (*ResolveResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("resolve: parser context is nil")
	}
	if hooks.LoadFill != nil {
		if err := hooks.LoadFill(ctx); err != nil {
			return nil, normalizeResolveUnimpl(err)
		}
	}
	if hooks.ResolveSymbol == nil {
		return nil, newUnimplError(ErrResolveUnimplemented, "resolve symbol hook")
	}
	if ctx.BaseState == nil {
		ctx.BaseState = NewConstructState()
	}
	resetConstructState(ctx.BaseState)

	walker := NewParserWalker(ctx)
	change := NewParserWalkerChange(walker)
	if err := change.DeallocateState(); err != nil {
		return nil, err
	}
	change.ClearCommitReservations()
	ctx.SetDelaySlot(0)
	if err := change.SetOffset(0); err != nil {
		return nil, err
	}
	ctx.ClearCommits()
	if hooks.LoadContext != nil {
		if err := hooks.LoadContext(ctx); err != nil {
			return nil, normalizeResolveUnimpl(err)
		}
	}

	if err := resolveFrame(ctx, change, hooks.ResolveSymbol, 0); err != nil {
		return nil, normalizeResolveUnimpl(err)
	}

	if length := ctx.GetLength(); length > 0 {
		ctx.SetNaddr(ctx.GetAddr().Add(uint64(length)))
	} else {
		ctx.SetNaddr(ctx.GetAddr())
	}
	ctx.SetParserState(ParseStateDisassembly)

	return &ResolveResult{
		Walker:             change,
		Root:               ctx.BaseState,
		CommitReservations: change.CommitReservations(),
	}, nil
}

func resolveFrame(ctx *ParserContext, change *ParserWalkerChange, resolve func(ResolveFrame) (ResolveOutcome, error), depth int) error {
	if ctx == nil || change == nil || change.Walker == nil || change.Walker.Point == nil {
		return fmt.Errorf("resolve: missing active walker state")
	}
	frame := ResolveFrame{
		Context: ctx,
		Walker:  change,
		State:   change.Walker.Point,
		Parent:  change.Walker.Point.Parent,
		Depth:   depth,
		Operand: change.Walker.GetOperand(),
	}
	if sec, ok := change.Walker.CurrentSection(); ok {
		frame.SectionID = sec
	}
	outcome, err := resolve(frame)
	if err != nil {
		return normalizeResolveUnimpl(err)
	}
	if outcome.Constructor == nil {
		if depth == 0 {
			return newUnimplError(ErrResolveUnimplemented, fmt.Sprintf("constructor resolution at depth %d", depth))
		}
		// Non-subtable operand (token field, context field): resolve signaled no subtable
		// recursion needed by returning nil constructor without error.
		// Mirrors C++ SubtableSymbol::resolve() which skips non-SubtableSymbol operands.
		return nil
	}
	if err := change.SetConstructor(*outcome.Constructor); err != nil {
		return err
	}
	if err := change.SetOffset(outcome.Offset); err != nil {
		return err
	}
	if outcome.Length > 0 {
		if err := change.SetCurrentLength(outcome.Length); err != nil {
			return err
		}
	} else if outcome.Constructor.MinimumLength > 0 {
		if err := change.SetCurrentLength(int(outcome.Constructor.MinimumLength)); err != nil {
			return err
		}
	}
	if outcome.DelaySlot > 0 {
		ctx.SetDelaySlot(outcome.DelaySlot)
	}
	applyResolveFlowAddresses(ctx, outcome)
	for _, commit := range outcome.Constructor.ContextCommits {
		if err := queueContextCommit(ctx, change, commit); err != nil {
			return err
		}
	}
	for _, commit := range outcome.Commits {
		if err := queueContextCommit(ctx, change, commit); err != nil {
			return err
		}
	}

	for operand := 0; operand < len(outcome.Constructor.OperandSymbolIDs); operand++ {
		if _, err := change.AllocateOperand(operand); err != nil {
			return err
		}
		if err := resolveFrame(ctx, change, resolve, depth+1); err != nil {
			return normalizeResolveUnimpl(err)
		}
		change.Walker.PopOperand()
	}
	return nil
}

func applyResolveFlowAddresses(ctx *ParserContext, outcome ResolveOutcome) {
	if ctx == nil {
		return
	}
	switch {
	case outcome.HasRefAddr && outcome.HasDestAddr:
		ctx.SetRefAddr(outcome.RefAddr)
		ctx.SetDestAddr(outcome.DestAddr)
	case outcome.HasRefAddr:
		// Mirrors ParserContext::setCalladdr()/getRefAddr()/getDestAddr() in context.hh.
		ctx.SetRefAddr(outcome.RefAddr)
		ctx.SetDestAddr(outcome.RefAddr)
	case outcome.HasDestAddr:
		// Gap: Go shell still allows split ref/dest when both fields are set explicitly.
		ctx.SetDestAddr(outcome.DestAddr)
		ctx.SetRefAddr(outcome.DestAddr)
	}
}

func queueContextCommit(ctx *ParserContext, change *ParserWalkerChange, commit ContextCommitBoundary) error {
	if ctx == nil || change == nil || change.Walker == nil || change.Walker.Point == nil {
		return fmt.Errorf("resolve: missing active state for context commit")
	}
	if err := ctx.AddCommit(commit, change.Walker.Point); err != nil {
		return err
	}
	change.ReserveCommit(commit)
	return nil
}

func resetConstructState(state *ConstructState) {
	if state == nil {
		return
	}
	for _, child := range state.Children {
		resetConstructState(child)
	}
	state.ConstructorID = 0
	state.SectionID = nil
	state.Constructor = nil
	state.Handle = FixedHandle{}
	state.Parent = nil
	state.Children = nil
	state.OperandIndex = -1
	state.Offset = 0
	state.Length = 0
}
