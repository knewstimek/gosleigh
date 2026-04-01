package sla

import "fmt"

// ParserWalkerChange mirrors the C++ mutation walker in shell form.
type ParserWalkerChange struct {
	Walker             *ParserWalker
	commitReservations []reservedContextCommit
}


type reservedContextCommit struct {
	commit ContextCommitBoundary
	point  *ConstructState
}

// NewParserWalkerChange creates a mutation shell for one active parser walker.
func NewParserWalkerChange(walker *ParserWalker) *ParserWalkerChange {
	return &ParserWalkerChange{Walker: walker}
}

// DeallocateState resets the walker to the root constructor state.
func (c *ParserWalkerChange) DeallocateState() error {
	if c == nil || c.Walker == nil {
		return fmt.Errorf("walker change has no active walker")
	}
	c.Walker.BaseState()
	return nil
}

// AllocateOperand creates or selects a child operand state and moves the walker to it.
func (c *ParserWalkerChange) AllocateOperand(index int) (*ConstructState, error) {
	if c == nil || c.Walker == nil || c.Walker.Point == nil {
		return nil, fmt.Errorf("walker change has no active state")
	}
	if err := c.Walker.PushOperand(index); err != nil {
		return nil, err
	}
	return c.Walker.Point, nil
}

// SetOffset records the current constructor-relative offset.
func (c *ParserWalkerChange) SetOffset(offset uint64) error {
	if c == nil || c.Walker == nil || c.Walker.Point == nil {
		return fmt.Errorf("walker change has no active state")
	}
	c.Walker.Point.Offset = offset
	return nil
}

// SetConstructor records the matched constructor boundary on the active state.
func (c *ParserWalkerChange) SetConstructor(constructor ConstructorBoundary) error {
	if c == nil || c.Walker == nil || c.Walker.Point == nil {
		return fmt.Errorf("walker change has no active state")
	}
	c.Walker.Point.SetConstructor(constructor)
	c.Walker.Point.ConstructorID = constructor.ConstructorID
	return nil
}

// SetCurrentLength records the current constructor length.
func (c *ParserWalkerChange) SetCurrentLength(length int) error {
	if c == nil || c.Walker == nil || c.Walker.Point == nil {
		return fmt.Errorf("walker change has no active state")
	}
	c.Walker.Point.Length = length
	return nil
}

// CalcCurrentLength computes the shell current length from the active state tree.
func (c *ParserWalkerChange) CalcCurrentLength() (int, error) {
	if c == nil || c.Walker == nil || c.Walker.Point == nil {
		return 0, fmt.Errorf("walker change has no active state")
	}
	end := currentStateEnd(c.Walker.Point)
	if end < c.Walker.Point.Offset {
		return 0, fmt.Errorf("invalid constructor length state")
	}
	return int(end - c.Walker.Point.Offset), nil
}

// ReserveCommit stores a commit request for later application on the active walker state.
func (c *ParserWalkerChange) ReserveCommit(commit ContextCommitBoundary) {
	if c == nil || c.Walker == nil || c.Walker.Point == nil {
		return
	}
	c.commitReservations = append(c.commitReservations, reservedContextCommit{commit: commit, point: c.Walker.Point})
}

// ApplyCommitReservations pushes reserved commits into the parser context queue.
func (c *ParserWalkerChange) ApplyCommitReservations(ctx *ParserContext) error {
	if c == nil || len(c.commitReservations) == 0 {
		return nil
	}
	for _, entry := range c.commitReservations {
		if err := ctx.AddCommit(entry.commit, entry.point); err != nil {
			return err
		}
	}
	return nil
}

// CommitReservations returns a copy of the pending commit requests.
func (c *ParserWalkerChange) CommitReservations() []ContextCommitBoundary {
	if c == nil || len(c.commitReservations) == 0 {
		return nil
	}
	out := make([]ContextCommitBoundary, 0, len(c.commitReservations))
	for _, entry := range c.commitReservations {
		out = append(out, entry.commit)
	}
	return out
}

// ClearCommitReservations drops all pending commit requests.
func (c *ParserWalkerChange) ClearCommitReservations() {
	if c == nil {
		return
	}
	c.commitReservations = c.commitReservations[:0]
}

func currentStateEnd(state *ConstructState) uint64 {
	if state == nil {
		return 0
	}
	end := state.Offset + uint64(state.Length)
	for _, child := range state.Children {
		childEnd := currentStateEnd(child)
		if childEnd > end {
			end = childEnd
		}
	}
	return end
}
