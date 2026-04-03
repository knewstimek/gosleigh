package sla

import (
	"fmt"

	"gosleigh/pkg/address"
)

func (b *SleighBuilder) delaySlotFromWalker() (bool, error) {
	// Mirrors ghidra::SleighBuilder::delaySlot().
	// Infrastructure failures use plain errors (C++ throws LowlevelError which is NOT
	// caught by oneInstruction's catch(UnimplError&)). Only build() failures may propagate
	// as *UnimplError so that wrapTranslateUnimplError rewrites only pcode-level failures.
	if b == nil || b.State.Walker == nil || b.State.Cache == nil {
		return true, fmt.Errorf("DELAY_SLOT requires active walker and cache")
	}

	sourceCtx, err := b.State.RequireWalkerPcodeParserContext()
	if err != nil {
		return true, fmt.Errorf("DELAY_SLOT: %w", err)
	}
	delaySlotByteCnt := sourceCtx.GetDelaySlot()
	if delaySlotByteCnt <= 0 {
		return true, nil
	}
	if sourceCtx.GetAddr().Space == nil {
		return true, fmt.Errorf("DELAY_SLOT source address has no space")
	}
	if sourceCtx.GetLength() <= 0 {
		return true, fmt.Errorf("DELAY_SLOT source length is not available")
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
		targetCtx, err := b.State.requireOrObtainPcodeContext(targetAddr)
		if err != nil {
			// Mirrors C++ throw LowlevelError("Could not obtain cached delay slot instruction")
			return true, fmt.Errorf("Could not obtain cached delay slot instruction at %v: %w", targetAddr, err)
		}
		if targetCtx.GetLength() <= 0 {
			return true, fmt.Errorf("DELAY_SLOT target length is not available for %v", targetAddr)
		}
		if targetCtx.BaseState == nil || targetCtx.BaseState.Constructor == nil {
			return true, fmt.Errorf("DELAY_SLOT target constructor state missing for %v", targetAddr)
		}

		crossWalker := NewParserWalker(targetCtx)
		crossWalker.BaseState()
		if crossWalker.Point == nil || crossWalker.Point.Constructor == nil {
			return true, fmt.Errorf("DELAY_SLOT target walker state missing for %v", targetAddr)
		}

		sectionID := int64(-1)
		if value, ok := crossWalker.Point.SectionValue(); ok {
			sectionID = value
		}
		selected, ok := crossWalker.Point.TemplateForSection(sectionID)
		if !ok {
			// Mirrors PcodeBuilder::build(nullptr) -> throw UnimplError("",0):
			// the delay slot constructor has no pcode implementation.
			return true, newUnimplErrorWithInstructionLength(nil, "", 0)
		}

		b.State.Walker = crossWalker
		if err := b.Build(*selected, sectionID); err != nil {
			// build() errors propagate as-is; if *UnimplError, the caller's
			// wrapTranslateUnimplError will rewrite explain/instruction_length.
			return true, err
		}

		step := targetCtx.GetLength()
		if step <= 0 {
			return true, fmt.Errorf("DELAY_SLOT target length is not available for %v", targetAddr)
		}
		fallOffset += uint64(step)
		consumed += step
	}

	b.State.Walker = prevWalker
	return true, nil
}
