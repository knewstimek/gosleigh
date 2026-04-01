package sla

import (
	"fmt"

	"gosleigh/pkg/address"
)

func (b *SleighBuilder) delaySlotFromWalker() (bool, error) {
	if b == nil || b.State.Walker == nil || b.State.Cache == nil {
		return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT requires active walker and cache", ErrBuilderUnimplemented))
	}

	sourceCtx, err := b.State.RequireWalkerPcodeParserContext()
	if err != nil {
		return true, normalizeBuilderUnimpl(err)
	}
	delaySlotByteCnt := sourceCtx.GetDelaySlot()
	if delaySlotByteCnt <= 0 {
		return true, nil
	}
	if sourceCtx.GetAddr().Space == nil {
		return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT source address has no space", ErrBuilderUnimplemented))
	}
	if sourceCtx.GetLength() <= 0 {
		return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT source length is not available", ErrBuilderUnimplemented))
	}

	prevWalker := b.State.Walker
	// Mirrors ghidra::SleighBuilder::delaySlot(): restore the outer walker only
	// after the recursive build returns normally so error rewriting can still
	// inspect the failing inner walker state.

	baseAddr := sourceCtx.GetAddr()
	fallOffset := uint64(sourceCtx.GetLength())
	consumed := 0
	for consumed < delaySlotByteCnt {
		targetAddr := address.Address{
			Space:  baseAddr.Space,
			Offset: baseAddr.Offset + fallOffset,
		}
		targetCtx, err := b.State.RequirePcodeParserContext(targetAddr)
		if err != nil {
			return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT target parser context %v", ErrBuilderUnimplemented, targetAddr))
		}
		if targetCtx.GetLength() <= 0 {
			return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT target length is not available for %v", ErrBuilderUnimplemented, targetAddr))
		}
		if targetCtx.BaseState == nil || targetCtx.BaseState.Constructor == nil {
			return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT target constructor state missing for %v", ErrBuilderUnimplemented, targetAddr))
		}

		crossWalker := NewParserWalker(targetCtx)
		crossWalker.BaseState()
		if crossWalker.Point == nil || crossWalker.Point.Constructor == nil {
			return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT target walker state missing for %v", ErrBuilderUnimplemented, targetAddr))
		}

		sectionID := int64(-1)
		if value, ok := crossWalker.Point.SectionValue(); ok {
			sectionID = value
		}
		selected, ok := crossWalker.Point.TemplateForSection(sectionID)
		if !ok {
			return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT target section %d missing for %v", ErrBuilderUnimplemented, sectionID, targetAddr))
		}

		b.State.Walker = crossWalker
		if err := b.Build(*selected, sectionID); err != nil {
			return true, normalizeBuilderUnimpl(err)
		}

		step := targetCtx.GetLength()
		if step <= 0 {
			return true, normalizeBuilderUnimpl(fmt.Errorf("%w: DELAY_SLOT target length is not available for %v", ErrBuilderUnimplemented, targetAddr))
		}
		fallOffset += uint64(step)
		consumed += step
	}

	b.State.Walker = prevWalker
	return true, nil
}
