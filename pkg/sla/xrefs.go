package sla

import (
	"fmt"
	"sort"

	"gosleigh/pkg/address"
)

// VarnodeXrefEntry mirrors one entry in C++ SleighBase::varnode_xref.
// It maps a fixed varnode location (space index, offset, size) to a register name.
type VarnodeXrefEntry struct {
	SpaceIndex int64
	Offset     uint64
	Size       int64
	Name       string
}

// ContextFieldRegistration mirrors one registerContext() call from C++ buildXrefs.
// It records the context symbol name and the bit range from its backing ContextField.
type ContextFieldRegistration struct {
	Name     string
	StartBit int64
	EndBit   int64
	Flow     bool
}

// XRefs holds the runtime cross-reference data built by SleighBase::buildXrefs()
// after .sla decode completes. This includes the register name map, user-op name
// list, and context field registrations.
type XRefs struct {
	// VarnodeXref maps fixed varnode locations to register names.
	// Sorted by (SpaceIndex, Offset, Size) to match C++ std::map<VarnodeData,string> ordering.
	VarnodeXref []VarnodeXrefEntry

	// UserOpNames maps user-op indices to their names (mirrors C++ SleighBase::userop).
	// Index in the slice corresponds to UserOpSymbol::getIndex().
	UserOpNames []string

	// ContextFields lists all context field registrations derived from ContextSymbol
	// boundaries (mirrors C++ SleighBase::buildXrefs registerContext calls).
	ContextFields []ContextFieldRegistration
}

// GetRegisterName mirrors SleighBase::getRegisterName -- looks up a register name
// by space index, offset, and size using the sorted varnode xref table.
func (x *XRefs) GetRegisterName(spaceIndex int64, offset uint64, size int64) string {
	if x == nil || len(x.VarnodeXref) == 0 {
		return ""
	}
	// Binary search for upper_bound, then check predecessor(s) -- mirrors C++ logic.
	target := VarnodeXrefEntry{SpaceIndex: spaceIndex, Offset: offset, Size: size}
	idx := sort.Search(len(x.VarnodeXref), func(i int) bool {
		return varnodeXrefLess(target, x.VarnodeXref[i])
	})
	if idx == 0 {
		return ""
	}
	// Walk backward through entries at the same offset (like C++ SleighBase::getRegisterName).
	for i := idx - 1; i >= 0; i-- {
		entry := x.VarnodeXref[i]
		if entry.SpaceIndex != spaceIndex {
			return ""
		}
		if i < idx-1 && entry.Offset != x.VarnodeXref[idx-1].Offset {
			return ""
		}
		if entry.Offset+uint64(entry.Size) >= offset+uint64(size) {
			return entry.Name
		}
	}
	return ""
}

// GetExactRegisterName mirrors SleighBase::getExactRegisterName -- exact match lookup.
func (x *XRefs) GetExactRegisterName(spaceIndex int64, offset uint64, size int64) string {
	if x == nil {
		return ""
	}
	for _, entry := range x.VarnodeXref {
		if entry.SpaceIndex == spaceIndex && entry.Offset == offset && entry.Size == size {
			return entry.Name
		}
	}
	return ""
}

// GetUserOpName returns the name for a user-op at the given index.
func (x *XRefs) GetUserOpName(index int) string {
	if x == nil || index < 0 || index >= len(x.UserOpNames) {
		return ""
	}
	return x.UserOpNames[index]
}

// BuildXrefs mirrors SleighBase::buildXrefs() from sleighbase.cc.
// It iterates the global scope of the symbol table and collects:
//   - VarnodeSymbol entries into the register xref map
//   - UserOpSymbol entries into the user-op name list
//   - ContextSymbol entries into context field registrations
//
// Returns an error if duplicate register varnodes are found (mirrors C++ "Duplicate register pairs").
func BuildXrefs(symbols *SymbolTableBoundary) (*XRefs, error) {
	if symbols == nil {
		return &XRefs{}, nil
	}
	xrefs := &XRefs{}
	var duplicates []string

	for i := range symbols.Symbols {
		sym := &symbols.Symbols[i]
		// Mirrors C++ buildXrefs: only process global scope symbols.
		if sym.ScopeID != globalSymbolScopeID {
			continue
		}

		switch {
		// Mirrors: if (sym->getType() == SleighSymbol::varnode_symbol)
		case sym.HeaderElement == elemVarnodeSymHead && sym.Body.Varnode != nil:
			entry := VarnodeXrefEntry{
				SpaceIndex: sym.Body.Varnode.SpaceIndex,
				Offset:     sym.Body.Varnode.Offset,
				Size:       sym.Body.Varnode.Size,
				Name:       sym.Name,
			}
			// Check for duplicate (same space/offset/size).
			for _, existing := range xrefs.VarnodeXref {
				if existing.SpaceIndex == entry.SpaceIndex &&
					existing.Offset == entry.Offset &&
					existing.Size == entry.Size {
					duplicates = append(duplicates, sym.Name, existing.Name)
				}
			}
			xrefs.VarnodeXref = append(xrefs.VarnodeXref, entry)

		// Mirrors: if (sym->getType() == SleighSymbol::userop_symbol)
		case sym.HeaderElement == elemUserOpHead && sym.Body.UserOp != nil:
			idx := int(sym.Body.UserOp.Index)
			for len(xrefs.UserOpNames) <= idx {
				xrefs.UserOpNames = append(xrefs.UserOpNames, "")
			}
			xrefs.UserOpNames[idx] = sym.Name

		// Mirrors: if (sym->getType() == SleighSymbol::context_symbol)
		case sym.HeaderElement == elemContextSymHead && sym.Body.Context != nil:
			// In C++, buildXrefs gets startBit/endBit from the ContextField
			// (csym->getPatternValue()). The ContextField's bit range is stored
			// in the pattern expression attributes. We use the ContextSymbol's
			// low/high which correspond to the same bit range.
			reg := ContextFieldRegistration{
				Name:     sym.Name,
				StartBit: sym.Body.Context.Low,
				EndBit:   sym.Body.Context.High,
				Flow:     sym.Body.Context.Flow,
			}
			xrefs.ContextFields = append(xrefs.ContextFields, reg)
		}
	}

	// Sort varnode xref to match C++ std::map<VarnodeData,string> ordering.
	sort.Slice(xrefs.VarnodeXref, func(i, j int) bool {
		return varnodeXrefLess(xrefs.VarnodeXref[i], xrefs.VarnodeXref[j])
	})

	if len(duplicates) > 0 {
		return xrefs, fmt.Errorf("duplicate register pairs: %v", duplicates)
	}
	return xrefs, nil
}

// BuildXrefs is a convenience method on Boundaries.
func (b *Boundaries) BuildXrefs() (*XRefs, error) {
	if b == nil {
		return &XRefs{}, nil
	}
	return BuildXrefs(b.SymbolTable)
}

// varnodeXrefLess mirrors VarnodeData::operator< ordering used by std::map in C++.
// VarnodeData comparison order: space (by index), then offset, then size.
func varnodeXrefLess(a, b VarnodeXrefEntry) bool {
	if a.SpaceIndex != b.SpaceIndex {
		return a.SpaceIndex < b.SpaceIndex
	}
	if a.Offset != b.Offset {
		return a.Offset < b.Offset
	}
	return a.Size < b.Size
}

// RegisterByName returns the (spaceIndex, offset, size) of a named register,
// and whether the register was found in the xref table.
// C++ parity: SleighBase::getRegister (sleighbase.cc)
func (x *XRefs) RegisterByName(name string) (spaceIndex int64, offset uint64, size int64, ok bool) {
	if x == nil {
		return 0, 0, 0, false
	}
	for _, entry := range x.VarnodeXref {
		if entry.Name == name {
			return entry.SpaceIndex, entry.Offset, entry.Size, true
		}
	}
	return 0, 0, 0, false
}

// FindSpaceForVarnode resolves the address.Space for a VarnodeXrefEntry using metadata.
func FindSpaceForVarnode(entry VarnodeXrefEntry, metadata *Metadata) *address.Space {
	if metadata == nil {
		return nil
	}
	for i := range metadata.Spaces {
		if int64(metadata.Spaces[i].Index) == entry.SpaceIndex {
			return &metadata.Spaces[i]
		}
	}
	return nil
}
