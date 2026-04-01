package sla

import (
	"fmt"

	"gosleigh/pkg/pcode"
)

// buildEmpty is a conservative fallback used when walker state is unavailable.
func buildEmpty(sectionID int64) error {
	_ = sectionID
	return nil
}

// buildEmpty mirrors SleighBuilder::buildEmpty() for named sections.
// It walks subtable operands recursively, treating each as an implied BUILD.
func (b *SleighBuilder) buildEmpty(sectionID int64) error {
	if b == nil || b.State.Walker == nil || !b.State.Walker.IsState() {
		return normalizeBuilderUnimpl(fmt.Errorf("%w: BUILD empty section requires active walker state", ErrBuilderUnimplemented))
	}
	if sectionID < 0 {
		return fmt.Errorf("BUILD empty section requires non-negative section id, got %d", sectionID)
	}
	return b.buildEmptyFromState(b.State.Walker.Point, sectionID)
}

func (b *SleighBuilder) buildEmptyFromState(state *ConstructState, sectionID int64) error {
	if state == nil || state.Constructor == nil {
		return nil
	}
	ctx := b.State.Walker.ParserContext()
	if ctx == nil || ctx.GetSymbolTable() == nil {
		return normalizeBuilderUnimpl(fmt.Errorf("%w: BUILD empty section requires symbol table metadata", ErrBuilderUnimplemented))
	}
	symbols := ctx.GetSymbolTable()
	for i := range state.Constructor.OperandSymbolIDs {
		if !isSubtableOperand(symbols, state.Constructor, i) {
			continue
		}
		if err := b.State.Walker.PushOperand(i); err != nil {
			return err
		}
		err := func() error {
			if !b.State.Walker.IsState() || b.State.Walker.Point == nil || b.State.Walker.Point.Constructor == nil {
				return normalizeBuilderUnimpl(fmt.Errorf("%w: BUILD operand %d has no resolved child constructor", ErrBuilderUnimplemented, i))
			}
			if selected, ok := b.State.Walker.Point.TemplateForSection(sectionID); ok {
				return normalizeBuilderUnimpl(b.Build(*selected, sectionID))
			}
			return normalizeBuilderUnimpl(b.buildEmptyFromState(b.State.Walker.Point, sectionID))
		}()
		b.State.Walker.PopOperand()
		if err != nil {
			return err
		}
	}
	return nil
}

func isSubtableOperand(symbols *SymbolTableBoundary, constructor *ConstructorBoundary, index int) bool {
	operand, ok := symbols.FindOperandForConstructor(constructor, index)
	if !ok || operand == nil || !operand.HasDefiningSymbolID {
		return false
	}
	sym, ok := symbols.FindSymbol(operand.DefiningSymbolID)
	return ok && sym != nil && sym.Body.Subtable != nil
}

// RawLabelResolver mirrors the relative label backpatching shape used by
// PcodeCacher::addLabelRef(), addLabel(), and resolveRelatives().
// The tracked varnode offset is expected to carry the absolute label id
// (local label + builder label base), matching SleighBuilder::dump().
type RawLabelResolver struct {
	refs   []uint64
	labels map[uint64]uint64
}

func NewRawLabelResolver() RawLabelResolver {
	return RawLabelResolver{
		labels: make(map[uint64]uint64),
	}
}

func (r *RawLabelResolver) Clear() {
	if r == nil {
		return
	}
	r.refs = r.refs[:0]
	r.labels = make(map[uint64]uint64)
}

func (r *RawLabelResolver) AddRelativeRef(opIndex uint64) {
	if r == nil {
		return
	}
	r.refs = append(r.refs, opIndex)
}

func (r *RawLabelResolver) AddLabel(labelID uint64, opIndex uint64) {
	if r == nil {
		return
	}
	if r.labels == nil {
		r.labels = make(map[uint64]uint64)
	}
	r.labels[labelID] = opIndex
}

func (r *RawLabelResolver) Resolve(ops []pcode.RawOp) error {
	if r == nil || len(r.refs) == 0 {
		return nil
	}
	for _, refIndex := range r.refs {
		if refIndex >= uint64(len(ops)) {
			return fmt.Errorf("relative label ref index %d out of range", refIndex)
		}
		refOp := &ops[refIndex]
		if len(refOp.Inputs) == 0 {
			return fmt.Errorf("relative label ref at op %d has no input varnodes", refIndex)
		}
		size := refOp.Inputs[0].Size
		mask, err := labelMask(size)
		if err != nil {
			return fmt.Errorf("resolve relative label at op %d: %w", refIndex, err)
		}
		labelID := refOp.Inputs[0].Offset
		targetIndex, ok := r.labels[labelID]
		if !ok {
			return fmt.Errorf("relative label id %d at op %d is undefined", labelID, refIndex)
		}
		delta := (targetIndex - refIndex) & mask
		refOp.Inputs[0].Offset = delta
	}
	return nil
}

func labelMask(size uint32) (uint64, error) {
	if size == 0 {
		return 0, fmt.Errorf("relative label varnode size must be non-zero")
	}
	if size >= 8 {
		return ^uint64(0), nil
	}
	return (uint64(1) << (size * 8)) - 1, nil
}
