package pcode

import "gosleigh/pkg/address"

// MarkNotMapped removes a stack range from the storage the local scope owns:
// symbols under it are dropped (unless type-locked) and no symbol is created
// there again, so a Varnode in it is neither mapped nor address-tied. Used for
// saved-register slots and the parameter area of locked calls.
// TODO known mismatch: minParamOffset/maxParamOffset (parameter=true) are not
// tracked; nothing reads them yet.
// C++ parity: varmap.cc ScopeLocal::markNotMapped.
func (sl *ScopeLocal) MarkNotMapped(spc *address.Space, first uint64, sz int32, parameter bool) {
	if sl == nil || spc == nil || spc != sl.SpaceID() || sz <= 0 {
		return
	}
	highest := spaceHighestOffset(spc)
	last := first + uint64(sz) - 1
	if last < first || last > highest {
		last = highest
	}
	addr := address.Address{Space: spc, Offset: first}
	for {
		overlap := sl.FindOverlap(addr, sz)
		if overlap == nil || overlap.Symbol() == nil {
			break
		}
		sym := overlap.Symbol()
		if sym.Flags()&VarnodeTypeLock != 0 {
			return
		}
		sl.RemoveSymbol(sym)
	}
	ext := sl.ext()
	ext.notMapped = append(ext.notMapped, [2]uint64{first, last})
}

// isNotMapped reports whether [off, off+size) touches a range removed by
// MarkNotMapped.
func (sl *ScopeLocal) isNotMapped(off uint64, size int32) bool {
	if sl == nil {
		return false
	}
	last := off + uint64(size) - 1
	for _, r := range sl.ext().notMapped {
		if off <= r[1] && last >= r[0] {
			return true
		}
	}
	return false
}

// ClearDeadVarnodes frees unlocked input Varnodes nothing reads any more.
// C++ parity: funcdata_varnode.cc Funcdata::clearDeadVarnodes.
func (fd *Funcdata) ClearDeadVarnodes() {
	for _, vn := range fd.vbank.AllVarnodes() {
		if vn == nil || !vn.HasNoDescend() {
			continue
		}
		// TODO known mismatch: C++ also destroys every free Varnode without
		// descendants; printc's stack declaration pass still reads such
		// leftovers (entryCoversVarnode).
		if vn.IsInput() && !vn.HasAddlFlags(VarnodeLockedInput) {
			fd.vbank.MakeFree(vn)
		}
	}
}

func spaceHighestOffset(spc *address.Space) uint64 {
	if spc.AddrSize >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (8 * uint(spc.AddrSize))) - 1
}
