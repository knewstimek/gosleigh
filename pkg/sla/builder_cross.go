package sla

import (
	"fmt"

	"gosleigh/pkg/address"
)

func (b *SleighBuilder) appendCrossBuild(op OpTplBoundary, sectionID int64) error {
	// Mirrors ghidra::SleighBuilder::appendCrossBuild().
	// Infrastructure failures use plain errors (C++ throws LowlevelError which is NOT
	// caught by oneInstruction's catch(UnimplError&)). Only build()/buildEmpty() failures
	// may propagate as *UnimplError so that wrapTranslateUnimplError rewrites only
	// pcode-level failures.
	if b == nil {
		return fmt.Errorf("builder is nil")
	}
	if sectionID >= 0 {
		// Mirrors C++ throw LowlevelError("CROSSBUILD directive within a named section")
		return fmt.Errorf("CROSSBUILD directive within a named section")
	}
	if len(op.Inputs) < 2 {
		return fmt.Errorf("CROSSBUILD expects at least two inputs, got %d", len(op.Inputs))
	}
	if b.State.Walker == nil || b.State.Walker.ParserContext() == nil {
		return fmt.Errorf("CROSSBUILD requires an active parser walker")
	}
	if b.State.Cache == nil {
		return fmt.Errorf("CROSSBUILD requires a disassembly cache")
	}

	targetAddr, err := b.crossBuildTargetAddress(op.Inputs[0])
	if err != nil {
		return err
	}
	crossSectionID, err := realConstValue(op.Inputs[1].Offset, "CROSSBUILD section")
	if err != nil {
		return err
	}

	targetCtx, err := b.State.requireOrObtainPcodeContext(targetAddr)
	if err != nil {
		// Mirrors C++ throw LowlevelError("Could not obtain cached crossbuild instruction")
		return fmt.Errorf("Could not obtain cached crossbuild instruction at %v: %w", targetAddr, err)
	}

	crossWalker := NewCrossParserWalker(targetCtx, b.State.Walker.ParserContext())
	crossWalker.BaseState()
	if crossWalker.Point == nil || crossWalker.Point.Constructor == nil {
		return fmt.Errorf("CROSSBUILD target has no constructor state at %v", targetAddr)
	}

	prevWalker := b.State.Walker
	// Mirrors ghidra::SleighBuilder::appendCrossBuild(): restore the outer
	// walker only after the recursive build returns normally so error rewriting
	// can still inspect the failing inner walker state.
	b.State.Walker = crossWalker
	selected, ok := crossWalker.Point.TemplateForSection(crossSectionID)
	if !ok {
		// buildEmpty propagates *UnimplError from nested build() if applicable.
		if err := b.buildEmpty(crossSectionID); err != nil {
			return err
		}
		b.State.Walker = prevWalker
		return nil
	}
	// build() errors propagate as-is; *UnimplError from nested build() will be
	// rewritten by wrapTranslateUnimplError at the TranslateSubtable boundary.
	if err := b.Build(*selected, crossSectionID); err != nil {
		return err
	}
	b.State.Walker = prevWalker
	return nil
}

func (b *SleighBuilder) crossBuildTargetAddress(vn VarnodeTplBoundary) (address.Address, error) {
	space, err := fixConstSpace(vn.Space, b.State.Runtime)
	if err != nil {
		return address.Address{}, fmt.Errorf("resolve CROSSBUILD target space: %w", err)
	}
	offset, err := fixConstScalar(vn.Offset, b.State.Runtime)
	if err != nil {
		return address.Address{}, fmt.Errorf("resolve CROSSBUILD target offset: %w", err)
	}
	if space == nil {
		return address.Address{}, fmt.Errorf("resolve CROSSBUILD target space: nil")
	}
	return address.Address{Space: space, Offset: wrapSpaceOffset(space, offset)}, nil
}
