package address

import "fmt"

// Address is the minimal pair of address space and offset.
type Address struct {
	Space  *Space
	Offset uint64
}

func (a Address) IsInvalid() bool {
	return a.Space == nil
}

func (a Address) Validate() error {
	if a.Space == nil {
		return fmt.Errorf("address space is nil")
	}
	return a.Space.Validate()
}

func (a Address) Less(other Address) bool {
	switch {
	case a.Space == nil:
		return other.Space != nil
	case other.Space == nil:
		return false
	case a.Space.Index != other.Space.Index:
		return a.Space.Index < other.Space.Index
	default:
		return a.Offset < other.Offset
	}
}

func (a Address) Add(delta uint64) Address {
	if a.Space == nil {
		return a
	}
	return Address{Space: a.Space, Offset: a.Offset + delta}
}

// C++ parity: address.cc Address::renormalize
func (a *Address) Renormalize(size int32) {
	// TODO known mismatch: Go currently has no join-space backing store.
	// The C++ version only adjusts join-space addresses here.
	_ = size
}

func (a Address) String() string {
	if a.Space == nil {
		return "<invalid>"
	}
	return fmt.Sprintf("%s:0x%x", a.Space.Name, a.Offset)
}
