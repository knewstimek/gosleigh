package pcode

import (
	"fmt"

	"gosleigh/pkg/address"
)

// VarnodeData is the minimal storage triple used by raw p-code emission.
type VarnodeData struct {
	Space  *address.Space
	Offset uint64
	Size   uint32
}

func (v VarnodeData) Validate() error {
	if v.Space == nil {
		return fmt.Errorf("varnode space is nil")
	}
	if err := v.Space.Validate(); err != nil {
		return err
	}
	if v.Size == 0 {
		return fmt.Errorf("varnode size must be non-zero")
	}
	return nil
}

func (v VarnodeData) Address() address.Address {
	return address.Address{Space: v.Space, Offset: v.Offset}
}

func (v VarnodeData) Less(other VarnodeData) bool {
	switch {
	case v.Space == nil:
		return other.Space != nil
	case other.Space == nil:
		return false
	case v.Space.Index != other.Space.Index:
		return v.Space.Index < other.Space.Index
	case v.Offset != other.Offset:
		return v.Offset < other.Offset
	default:
		return v.Size > other.Size
	}
}
