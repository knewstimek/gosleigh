package sla

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"gosleigh/pkg/address"
)

var ErrLoadContextUnimplemented = errors.New("loadContext shell is unimplemented")
var ErrApplyCommitsUnimplemented = errors.New("applyCommits shell is unimplemented")
var ErrApplyContextOpsUnimplemented = errors.New("applyContextOps shell is unimplemented")

// ContextSet records one pending formal context change, matching the data
// ParserContext stores in contextcommit in the original C++.
type ContextSet struct {
	SymbolID uint64
	Point    *ConstructState
	Number   int
	Mask     uint64
	Value    uint64
	Flow     bool
}

// LoadContextHooks supplies the cache read boundary behind ParserContext::loadContext().
type LoadContextHooks struct {
	LoadContextWords func(addr address.Address, current []uint64) ([]uint64, error)
}

// ResolveCommitAddressRequest is the shell-visible address resolution request for one commit.
type ResolveCommitAddressRequest struct {
	Context *ParserContext
	Walker  *ParserWalker
	Commit  ContextSet
}

// ApplyCommitRequest is the shell-visible cache update request for one commit.
type ApplyCommitRequest struct {
	Context    *ParserContext
	Walker     *ParserWalker
	Commit     ContextSet
	CommitAddr address.Address
	NextAddr   address.Address
	HasNext    bool
}

// ApplyCommitsHooks supplies the unresolved address lookup and cache write boundaries.
type ApplyCommitsHooks struct {
	LookupOperandIndex   func(symbolID uint64) (int, bool)
	ResolveFixedHandle   func(symbolID uint64, walker *ParserWalker) (FixedHandle, bool, error)
	ResolveCommitAddress func(req ResolveCommitAddressRequest) (address.Address, error)
	ApplyCommit          func(req ApplyCommitRequest) error
}

type parserContextLoadState struct {
	mu      sync.Mutex
	commits []ContextSet
}

var parserContextLoadStateMap sync.Map

// LoadContext mirrors ParserContext::loadContext() behind an explicit cache hook.
func (ctx *ParserContext) LoadContext(hooks LoadContextHooks) error {
	if ctx == nil {
		return newUnimplError(ErrLoadContextUnimplemented, "parser context is nil")
	}
	if hooks.LoadContextWords == nil {
		return newUnimplError(ErrLoadContextUnimplemented, "load hook is nil")
	}
	words, err := hooks.LoadContextWords(ctx.GetAddr(), cloneContextWords(ctx.ContextWords))
	if err != nil {
		return err
	}
	ctx.SetContextWords(words)
	return nil
}

// ClearCommits mirrors ParserContext::clearCommits().
func (ctx *ParserContext) ClearCommits() {
	state := loadStateForParserContext(ctx)
	state.mu.Lock()
	state.commits = state.commits[:0]
	state.mu.Unlock()
}

// AddCommit mirrors ParserContext::addCommit() within the current shell scope.
func (ctx *ParserContext) AddCommit(commit ContextCommitBoundary, point *ConstructState) error {
	if ctx == nil {
		return fmt.Errorf("addCommit: parser context is nil")
	}
	num := int(commit.Number)
	if num < 0 || num >= len(ctx.ContextWords) {
		return fmt.Errorf("addCommit: context word %d is out of range", num)
	}
	set := ContextSet{
		SymbolID: commit.SymbolID,
		Point:    point,
		Number:   num,
		Mask:     commit.Mask,
		Value:    ctx.ContextWords[num] & commit.Mask,
		Flow:     commit.Flow,
	}
	state := loadStateForParserContext(ctx)
	state.mu.Lock()
	state.commits = append(state.commits, set)
	state.mu.Unlock()
	return nil
}

// PendingCommits returns a copy of the queued context commits.
func (ctx *ParserContext) PendingCommits() []ContextSet {
	state := loadStateForParserContext(ctx)
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.commits) == 0 {
		return nil
	}
	out := make([]ContextSet, len(state.commits))
	copy(out, state.commits)
	return out
}

// ApplyCommits mirrors ParserContext::applyCommits() up to the cache write boundary.
func (ctx *ParserContext) ApplyCommits(hooks ApplyCommitsHooks) error {
	if ctx == nil {
		return newUnimplError(ErrApplyCommitsUnimplemented, "parser context is nil")
	}
	if ctx.Symbols == nil && hooks.LookupOperandIndex == nil && hooks.ResolveFixedHandle == nil && hooks.ResolveCommitAddress == nil {
		return newUnimplError(ErrApplyCommitsUnimplemented, "commit address resolution is nil")
	}
	if hooks.ApplyCommit == nil {
		return newUnimplError(ErrApplyCommitsUnimplemented, "apply commit hook is nil")
	}

	commits := ctx.PendingCommits()
	if len(commits) == 0 {
		return nil
	}

	walker := NewParserWalker(ctx)
	walker.BaseState()

	for _, commit := range commits {
		commitAddr, err := resolveCommitAddress(ctx, walker, commit, hooks)
		if err != nil {
			return err
		}
		commitAddr, err = normalizeCommitAddress(ctx, commitAddr)
		if err != nil {
			return err
		}
		nextAddr, hasNext := nextCommitAddress(commitAddr, commit.Flow)
		if err := hooks.ApplyCommit(ApplyCommitRequest{
			Context:    ctx,
			Walker:     walker,
			Commit:     commit,
			CommitAddr: commitAddr,
			NextAddr:   nextAddr,
			HasNext:    hasNext,
		}); err != nil {
			return err
		}
	}
	return nil
}

func resolveCommitAddress(ctx *ParserContext, walker *ParserWalker, commit ContextSet, hooks ApplyCommitsHooks) (address.Address, error) {
	if commit.Point != nil {
		if ctx != nil && ctx.Symbols != nil {
			if operand, ok := ctx.Symbols.FindOperandSymbol(commit.SymbolID); ok {
				child, exists := commit.Point.Child(int(operand.Index))
				if !exists {
					return address.Address{}, fmt.Errorf("applyCommits: operand %d is not available on commit point", operand.Index)
				}
				if child.Handle.Space == nil {
					return address.Address{}, fmt.Errorf("applyCommits: operand %d handle has no space", operand.Index)
				}
				return address.Address{Space: child.Handle.Space, Offset: child.Handle.OffsetOffset}, nil
			}
		}
		if hooks.LookupOperandIndex != nil {
			if index, ok := hooks.LookupOperandIndex(commit.SymbolID); ok {
				child, exists := commit.Point.Child(index)
				if !exists {
					return address.Address{}, fmt.Errorf("applyCommits: operand %d is not available on commit point", index)
				}
				if child.Handle.Space == nil {
					return address.Address{}, fmt.Errorf("applyCommits: operand %d handle has no space", index)
				}
				return address.Address{Space: child.Handle.Space, Offset: child.Handle.OffsetOffset}, nil
			}
		}
	}
	if hooks.ResolveFixedHandle != nil {
		hand, handled, err := hooks.ResolveFixedHandle(commit.SymbolID, walker)
		if err != nil {
			return address.Address{}, err
		}
		if handled {
			if hand.Space == nil {
				return address.Address{}, fmt.Errorf("applyCommits: resolved handle has no space")
			}
			return address.Address{Space: hand.Space, Offset: hand.OffsetOffset}, nil
		}
	}
	if hooks.ResolveCommitAddress != nil {
		return hooks.ResolveCommitAddress(ResolveCommitAddressRequest{
			Context: ctx,
			Walker:  walker,
			Commit:  commit,
		})
	}
	return address.Address{}, newUnimplError(ErrApplyCommitsUnimplemented, fmt.Sprintf("unresolved commit symbol %d", commit.SymbolID))
}

func loadStateForParserContext(ctx *ParserContext) *parserContextLoadState {
	if ctx == nil {
		return &parserContextLoadState{}
	}
	if state, ok := parserContextLoadStateMap.Load(ctx); ok {
		return state.(*parserContextLoadState)
	}
	state := &parserContextLoadState{}
	actual, _ := parserContextLoadStateMap.LoadOrStore(ctx, state)
	return actual.(*parserContextLoadState)
}

func cloneContextWords(words []uint64) []uint64 {
	if len(words) == 0 {
		return nil
	}
	out := make([]uint64, len(words))
	copy(out, words)
	return out
}

func normalizeCommitAddress(ctx *ParserContext, commitAddr address.Address) (address.Address, error) {
	if err := commitAddr.Validate(); err != nil {
		return address.Address{}, fmt.Errorf("applyCommits: invalid commit address: %w", err)
	}
	if commitAddr.Space == nil || !commitAddr.Space.IsConstant() {
		return commitAddr, nil
	}
	current := ctx.GetCurSpace()
	if current == nil {
		return address.Address{}, fmt.Errorf("applyCommits: current instruction space is nil")
	}
	if current.WordSize == 0 {
		return address.Address{}, fmt.Errorf("applyCommits: current instruction word size is zero")
	}
	return address.Address{
		Space:  current,
		Offset: commitAddr.Offset * uint64(current.WordSize),
	}, nil
}

func nextCommitAddress(commitAddr address.Address, flow bool) (address.Address, bool) {
	if flow || commitAddr.Space == nil {
		return address.Address{}, false
	}
	if commitAddr.Offset == math.MaxUint64 {
		return address.Address{}, false
	}
	return commitAddr.Add(1), true
}

// ApplyContextOpsHooks carries the PatternExpression evaluation boundary for
// ContextOp application. ResolveOperandValue is optional; nil disables operand
// expression evaluation.
type ApplyContextOpsHooks struct {
	PatternHooks PatternExpressionValueHooks
}

// ApplyContextOps applies each ContextOpBoundary in ops to ctx, mirroring the
// loop in Constructor::applyContext() -> ContextOp::apply() in slghsymbol.cc/hh.
//
// Each op evaluates its PatternExpression via walker, shifts the result, then
// writes it into the matching context word using the stored mask:
//
//	val = expr.getValue(walker) << shift
//	ctx->setContextWord(num, val, mask)
//
// walker must already be positioned (BaseState or equivalent). If walker is nil
// a new one is created at BaseState of ctx.
func ApplyContextOps(ctx *ParserContext, ops []ContextOpBoundary, walker *ParserWalker, hooks ApplyContextOpsHooks) error {
	if ctx == nil {
		return newUnimplError(ErrApplyContextOpsUnimplemented, "parser context is nil")
	}
	if len(ops) == 0 {
		return nil
	}
	if walker == nil {
		walker = NewParserWalker(ctx)
		walker.BaseState()
	}
	for i := range ops {
		op := &ops[i]
		if op.Expression == nil {
			// No expression: nothing to evaluate; skip silently like C++ would if
			// patexp were null (defensive, should not happen in valid .sla data).
			continue
		}
		if op.Num < 0 || int(op.Num) >= len(ctx.ContextWords) {
			return fmt.Errorf("applyContextOps: op %d num %d out of range (len=%d)", i, op.Num, len(ctx.ContextWords))
		}
		// Mirrors ContextOp::apply(): val = patexp->getValue(walker); val <<= shift
		raw, err := GetPatternExpressionValue(op.Expression, walker, hooks.PatternHooks)
		if err != nil {
			return fmt.Errorf("applyContextOps: op %d expression eval: %w", i, err)
		}
		val := uint64(raw) << uint(op.Shift)
		ctx.SetContextWord(int(op.Num), val, op.Mask)
	}
	return nil
}
