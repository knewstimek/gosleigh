package pcode

import (
	"strings"

	"gosleigh/pkg/address"
)

// bitTransitions counts the 0/1 transitions in the low sz bytes of val.
// C++ parity: address.cc bit_transitions.
func bitTransitions(val uint64, sz int32) int {
	res := 0
	last := val & 1
	for i := 1; i < int(8*sz); i++ {
		val >>= 1
		cur := val & 1
		if cur != last {
			res++
			last = cur
		}
		if val == 0 {
			break
		}
	}
	return res
}

// constPtrIsPointer decides whether constant vn (read by op at slot) is a
// pointer into spc and returns the global symbol it points at.
// infer_pointers is on (the Ghidra default). Not ported: segmented
// resolveConstant.
// C++ parity: coreaction.cc ActionConstantPtr::isPointer.
func constPtrIsPointer(data *Funcdata, spc *address.Space, vn *Varnode, op *PcodeOp, slot int, scope *ScopeLocal) (*SymbolEntry, address.Address) {
	needExact := true
	if dt := vn.TypeReadFacing(op); dt != nil && dt.Metatype() == TYPE_PTR {
		needExact = false
	} else {
		if vn.IsTypeLock() {
			return nil, address.Address{}
		}
		switch op.Code() {
		case CPUI_CALL, CPUI_CALLIND:
			if slot == 0 {
				return nil, address.Address{}
			}
			// A locked parameter that is not a pointer vetoes.
			if fc := op.callSpec; fc != nil && fc.IsInputLocked() {
				if p, ok := fc.LockedParam(slot - 1); ok && p.Type != nil {
					if m := p.Type.Metatype(); m != TYPE_PTR && m != TYPE_UNKNOWN {
						return nil, address.Address{} // Definitely not passing a pointer
					}
				}
			}
		case CPUI_COPY:
			// A constant returned through a locked non-pointer output is no
			// pointer. C++ parity: ActionConstantPtr::checkCopy.
			if ret := op.Output().LoneDescend(); ret != nil && ret.Code() == CPUI_RETURN {
				if fp := data.GetFuncProto(); fp != nil && fp.IsOutputLocked() && fp.GetOutput() != nil && fp.GetOutput().Type() != nil {
					if m := fp.GetOutput().Type().Metatype(); m != TYPE_PTR && m != TYPE_UNKNOWN {
						return nil, address.Address{}
					}
				}
			}
		case CPUI_PIECE, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL:
		case CPUI_INT_ADD:
			if out := op.Output(); out != nil {
				if odt := out.TypeDefFacing(); odt != nil && odt.Metatype() == TYPE_PTR {
					if other := op.Input(1 - slot); other != nil {
						if t := other.TypeReadFacing(op); t != nil && t.Metatype() == TYPE_PTR {
							return nil, address.Address{}
						}
					}
					needExact = false
				}
			}
		case CPUI_STORE:
			if slot != 2 {
				return nil, address.Address{}
			}
		default:
			return nil, address.Address{}
		}
		// Pointers are not expected near either end of the space.
		// C++ parity: AddrSpace::calcScaleMask pointer bounds.
		buffer := uint64(0x1000)
		if spc.AddrSize < 3 {
			buffer = 0x100
		}
		if vn.Offset() < buffer || vn.Offset() > spaceHighestOffset(spc)-buffer {
			return nil, address.Address{}
		}
		if bitTransitions(vn.Offset(), vn.Size()) < 3 {
			return nil, address.Address{}
		}
	}
	rampoint := address.Address{Space: spc, Offset: vn.Offset()}
	entry := data.resolveGlobalSymbol(rampoint)
	if entry == nil && scope != nil {
		// Symbols injected into the local scope by the environment (kept
		// for the pre-host-scope behavior).
		entry = scope.QueryContainer(rampoint, 1, address.Address{})
	}
	if entry == nil {
		return nil, address.Address{}
	}
	if sym := entry.Symbol(); sym != nil {
		if arr, ok := sym.Type().(*Array); ok && isCharPrint(arr.Element()) {
			needExact = false // a pointer may point into the middle of a string
		}
	}
	if needExact && entry.Addr() != rampoint {
		return nil, address.Address{}
	}
	return entry, rampoint
}

// isCharPrint reports whether dt prints as a character.
// C++ parity: Datatype::isCharPrint.
func isCharPrint(dt Datatype) bool {
	if dt == nil {
		return false
	}
	switch dt.Name() {
	case "char", "wchar_t", "wchar16", "wchar32", "char16_t", "char32_t":
		return true
	}
	return false
}

// resolveGlobalSymbol returns any global symbol at addr: a data variable,
// a code label or a function. A label is an undefined1 at its address
// (LabSymbol::buildType); a function symbol has code type.
// C++ parity: Scope::queryContainer on the global (ScopeGhidra) scope.
func (fd *Funcdata) resolveGlobalSymbol(addr address.Address) *SymbolEntry {
	if e := fd.resolveGlobal(addr); e != nil {
		return e
	}
	if fd.hostScope == nil {
		return nil
	}
	gs := fd.globalScope
	if hs, ok := fd.hostScope.(HostDataScope); ok {
		if hd, ok := hs.QueryData(addr); ok && hd.Label && hd.Addr == addr {
			e := gs.AddSymbol(hd.Name, sharedTypeFactory.GetBase(1, TYPE_UNKNOWN, ""), hd.Addr, 1, VarnodeTypeLock|VarnodeNameLock)
			e.Symbol().namespace = hd.Namespace
			e.Symbol().nsPath = hd.NamespacePath
			return e
		}
	}
	if hf, ok := fd.hostScope.QueryFunction(addr); ok && hf.Name != "" {
		code := sharedTypeFactory.GetCode("", nil, nil, false)
		if hf.Namespace != "" && strings.HasPrefix(hf.Name, hf.Namespace+"::") {
			// The symbol lives in its scope, so printing keeps the scope raw
			// and cleans only the name. C++ parity: Symbol in its Scope.
			e := gs.AddSymbol(hf.Name[len(hf.Namespace)+2:], code, addr, 1, VarnodeTypeLock|VarnodeNameLock)
			e.Symbol().namespace = hf.Namespace
			return e
		}
		return gs.AddSymbol(hf.Name, code, addr, 1, VarnodeTypeLock|VarnodeNameLock)
	}
	return nil
}
