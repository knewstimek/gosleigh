package address

import "fmt"

// SpaceKind identifies the role an address space plays in the p-code model.
type SpaceKind uint8

const (
	SpaceKindProcessor SpaceKind = iota
	SpaceKindConstant
	SpaceKindUnique
	SpaceKindJoin
	SpaceKindIop
	SpaceKindFspec
	SpaceKindStack
	SpaceKindOther
)

func (k SpaceKind) String() string {
	switch k {
	case SpaceKindProcessor:
		return "processor"
	case SpaceKindConstant:
		return "constant"
	case SpaceKindUnique:
		return "unique"
	case SpaceKindJoin:
		return "join"
	case SpaceKindIop:
		return "iop"
	case SpaceKindFspec:
		return "fspec"
	case SpaceKindStack:
		return "stack"
	case SpaceKindOther:
		return "other"
	default:
		return fmt.Sprintf("SpaceKind(%d)", uint8(k))
	}
}

// Space describes a p-code address space and the basic rules attached to it.
type Space struct {
	Name      string
	Kind      SpaceKind
	Index     uint16
	AddrSize  uint8
	WordSize  uint8
	BigEndian bool
	Physical  bool
	Delay     int32
	// Truncated marks a space whose usable pointer width is smaller than its
	// modelled address size. It is set from the pspec <space_base>/<space>
	// truncate_space attribute. All currently supported architectures
	// (x86/x64/aarch64) leave it false. C++ parity: AddrSpace::isTruncated.
	Truncated bool
}

// IsTruncated reports whether pointers into this space use a truncated width.
// C++ parity: AddrSpace::isTruncated (space.hh).
func (s *Space) IsTruncated() bool { return s != nil && s.Truncated }

func (s Space) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("address space name is required")
	}
	if s.AddrSize == 0 {
		return fmt.Errorf("address space %q must have non-zero address size", s.Name)
	}
	if s.WordSize == 0 {
		return fmt.Errorf("address space %q must have non-zero word size", s.Name)
	}
	if s.Delay < 0 {
		return fmt.Errorf("address space %q must have non-negative delay", s.Name)
	}
	return nil
}

func (s Space) IsConstant() bool {
	return s.Kind == SpaceKindConstant
}

func (s Space) IsUnique() bool {
	return s.Kind == SpaceKindUnique
}
