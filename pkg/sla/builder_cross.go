package sla

import (
	"fmt"

	"gosleigh/pkg/address"
)

func (b *SleighBuilder) appendCrossBuild(op OpTplBoundary, sectionID int64) error {
	if b == nil {
		return fmt.Errorf("builder is nil")
	}
	if sectionID >= 0 {
		return fmt.Errorf("CROSSBUILD directive within a named section")
	}
	if len(op.Inputs) < 2 {
		return fmt.Errorf("CROSSBUILD expects at least two inputs, got %d", len(op.Inputs))
	}
	if b.State.Walker == nil || b.State.Walker.ParserContext() == nil {
		return normalizeBuilderUnimpl(fmt.Errorf("%w: CROSSBUILD requires an active parser walker", ErrBuilderUnimplemented))
	}
	if b.State.Cache == nil {
		return normalizeBuilderUnimpl(fmt.Errorf("%w: CROSSBUILD requires a disassembly cache", ErrBuilderUnimplemented))
	}

	targetAddr, err := b.crossBuildTargetAddress(op.Inputs[0])
	if err != nil {
		return err
	}
	crossSectionID, err := realConstValue(op.Inputs[1].Offset, "CROSSBUILD section")
	if err != nil {
		return err
	}

	targetCtx, err := b.State.RequirePcodeParserContext(targetAddr)
	if err != nil {
		return normalizeBuilderUnimpl(fmt.Errorf("%w: CROSSBUILD target parser context %v", ErrBuilderUnimplemented, targetAddr))
	}

	crossWalker := NewCrossParserWalker(targetCtx, b.State.Walker.ParserContext())
	crossWalker.BaseState()
	if crossWalker.Point == nil || crossWalker.Point.Constructor == nil {
		return normalizeBuilderUnimpl(fmt.Errorf("%w: CROSSBUILD target has no constructor state", ErrBuilderUnimplemented))
	}

	prevWalker := b.State.Walker
	// Mirrors ghidra::SleighBuilder::appendCrossBuild(): restore the outer
	// walker only after the recursive build returns normally so error rewriting
	// can still inspect the failing inner walker state.
	b.State.Walker = crossWalker
	selected, ok := crossWalker.Point.TemplateForSection(crossSectionID)
	if !ok {
		if err := normalizeBuilderUnimpl(b.buildEmpty(crossSectionID)); err != nil {
			return err
		}
		b.State.Walker = prevWalker
		return nil
	}
	if err := normalizeBuilderUnimpl(b.Build(*selected, crossSectionID)); err != nil {
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
