package pcode

import (
	"fmt"
	"strings"

	"gosleigh/pkg/address"
)

// SeqNum identifies a p-code op within the translation of a machine instruction.
type SeqNum struct {
	Address address.Address
	Time    uint64
	Order   uint64
}

func (s SeqNum) Validate() error {
	if err := s.Address.Validate(); err != nil {
		return fmt.Errorf("sequence address: %w", err)
	}
	return nil
}

// RawOp is the minimal p-code operation shape used between decode and later analysis.
type RawOp struct {
	SeqNum SeqNum
	OpCode OpCode
	Output *VarnodeData
	Inputs []VarnodeData
}

func (op RawOp) Validate() error {
	if err := op.SeqNum.Validate(); err != nil {
		return err
	}
	if op.OpCode == 0 {
		return fmt.Errorf("opcode is required")
	}
	if op.Output != nil {
		if err := op.Output.Validate(); err != nil {
			return fmt.Errorf("output: %w", err)
		}
	}
	for i, input := range op.Inputs {
		if err := input.Validate(); err != nil {
			return fmt.Errorf("input %d: %w", i, err)
		}
	}
	return nil
}

func (op RawOp) String() string {
	var sb strings.Builder
	sb.WriteString(op.SeqNum.Address.String())
	sb.WriteString(" ")
	sb.WriteString(op.OpCode.String())
	if op.Output != nil {
		sb.WriteString(" ")
		sb.WriteString(formatVarnode(*op.Output))
		sb.WriteString(" =")
	}
	for _, input := range op.Inputs {
		sb.WriteString(" ")
		sb.WriteString(formatVarnode(input))
	}
	return sb.String()
}

// RawEmitter is the minimal sink interface for emitted raw p-code ops.
type RawEmitter interface {
	EmitRaw(RawOp) error
}

func formatVarnode(v VarnodeData) string {
	if v.Space == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s:0x%x[%d]", v.Space.Name, v.Offset, v.Size)
}
