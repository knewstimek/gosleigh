package pcode

import (
	"fmt"

	"github.com/knewstimek/gosleigh/pkg/address"
)

// VarnodeData is the minimal storage triple used by raw p-code emission.
type VarnodeData struct {
	Space  *address.Space
	Offset uint64
	Size   uint32
}

// VarnodeDataLess orders by space index, then offset, then larger size first.
// C++ parity: VarnodeData::operator<.
func VarnodeDataLess(a, b VarnodeData) bool {
	ai, bi := spaceIndexOf(a.Space), spaceIndexOf(b.Space)
	if ai != bi {
		return ai < bi
	}
	if a.Offset != b.Offset {
		return a.Offset < b.Offset
	}
	return a.Size > b.Size
}

func spaceIndexOf(sp *address.Space) int {
	if sp == nil {
		return -1
	}
	return int(sp.Index)
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
