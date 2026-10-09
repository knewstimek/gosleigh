// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import (
	"fmt"
	"strings"

	"github.com/knewstimek/gosleigh/pkg/address"
)

// GlobalScope is the minimal stand-in for the parent (global) Scope that a
// ScopeLocal defers to. Ghidra models a full Database of nested Scopes; the Go
// port only needs the SymbolEntry container that ActionConstantPtr queries when
// promoting a constant to a global symbol pointer (getScopeLocal()->getParent()
// ->queryContainer). It holds a flat, address-keyed set of SymbolEntry records
// -- typically injected by the loader/bridge for symbols the analysis
// environment supplies (e.g. __ImageBase), the same way ScopeGhidra answers a
// query response into Ghidra's global scope.
//
// The default (uninjected) scope is empty, so every query misses and behavior
// is byte-identical to having no global scope at all.
//
// C++ parity: database.hh Scope / ScopeInternal (SymbolEntry storage subset,
// global-scope role).
type GlobalScope struct {
	entries []*SymbolEntry
	// vnMap links mapped global Varnodes to their entry (Varnode::mapentry).
	vnMap map[*Varnode]*SymbolEntry
}

// Attach links vn to entry. C++ parity: Varnode::setSymbolEntry.
func (g *GlobalScope) Attach(vn *Varnode, entry *SymbolEntry) {
	if g.vnMap == nil {
		g.vnMap = make(map[*Varnode]*SymbolEntry)
	}
	g.vnMap[vn] = entry
}

// EntryFor returns the entry vn is linked to, or nil.
func (g *GlobalScope) EntryFor(vn *Varnode) *SymbolEntry {
	if g == nil {
		return nil
	}
	return g.vnMap[vn]
}

// symbolAddr is the storage address of the symbol's first entry.
func symbolAddr(sym *Symbol) address.Address {
	if len(sym.mapEntry) == 0 {
		return address.Address{}
	}
	return sym.mapEntry[0].Addr()
}

// globalSymbolName is how a global symbol is referenced from the current
// function: qualified only as far as needed from the function's scope.
// C++ parity: PrintC::pushSymbolScope (minimal namespace strategy).
func (s *printCState) globalSymbolName(sym *Symbol) string {
	// The symbol name is a variable/function token (cleaned by the Java
	// PrettyPrinter); the scope is syntax and stays raw.
	name := cppDisplayName(sym.Name())
	q := sym.Name()
	if ns := sym.Namespace(); ns != "" {
		q = ns + "::" + q
	}
	q = s.minimalScopedNameAt(q, symbolAddr(sym))
	if i := strings.LastIndex(q, "::"); i >= 0 && strings.HasSuffix(q, "::"+sym.Name()) {
		return q[:i+2] + name
	}
	return name
}

// globalSymbolExpr is globalSymbolName as an expression whose scope names
// are separate tokens. C++ parity: PrintC::pushSymbolScope.
func (s *printCState) globalSymbolExpr(sym *Symbol) ExprFragment {
	if len(sym.nsPath) > 0 || sym.Namespace() == "" {
		var useScope []string
		fn := s.fd.DisplayName()
		if fn == "" {
			fn = s.fd.Name()
		}
		if up := splitScopePath(fn); len(up) > 1 {
			useScope = up[:len(up)-1]
		}
		base := cppDisplayName(sym.Name())
		symIDs, useIDs := s.namespaceIDs(symbolAddr(sym))
		depth := resolutionDepthIDs(sym.nsPath, useScope, symIDs, useIDs, sym.Name(), s.isNameUsed)
		if depth == 0 {
			return s.lang.Atom(base)
		}
		// pushOp(&scope) depth times, then the scope atoms outermost
		// first and the name: the operators nest to the left,
		// ((A::B)::name).
		scopeOp := func(l, r ExprFragment) ExprFragment {
			return ExprFragment{Text: l.Text + "::" + r.Text, Precedence: ExprPrecPrimary, node: &fragNode{
				kind: fragBinary, print1: "::", kids: []ExprFragment{l, r}, parens: []bool{false, false}}}
		}
		scopes := sym.nsPath[len(sym.nsPath)-min(depth, len(sym.nsPath)):]
		if depth > len(sym.nsPath) { // Up to the global scope, whose display name is empty
			scopes = append([]string{""}, scopes...)
		}
		expr := ExprFragment{Text: scopes[0], Precedence: ExprPrecPrimary}
		for _, sc := range scopes[1:] {
			expr = scopeOp(expr, ExprFragment{Text: sc, Precedence: ExprPrecPrimary})
		}
		return scopeOp(expr, ExprFragment{Text: base, Precedence: ExprPrecPrimary})
	}
	q := s.globalSymbolName(sym)
	base := cppDisplayName(sym.Name())
	if !strings.HasSuffix(q, "::"+base) {
		return s.lang.Atom(q)
	}
	return symbolNameExpr(q[:len(q)-len(base)]+sym.Name(), base)
}

// globalVarnodeName names vn through the global symbol entry it maps to:
// the symbol itself, a piece of it (field, element or ._off_size_) when vn
// lies inside the symbol, or the symbol name prefixed with '_' when vn
// starts at the symbol but runs past its end.
// C++ parity: PrintC::pushVnExplicit -> pushSymbol / pushPartialSymbol /
// pushMismatchSymbol.
// castTo is the read type when a truncating cast may stand in for the
// last piece step (allowCast); the cast type is returned when it is used.
func (s *printCState) globalVarnodeName(vn *Varnode, e *SymbolEntry, castTo Datatype, rop *PcodeOp, rslot int) (string, Datatype) {
	sym := e.Symbol()
	name := s.globalSymbolName(sym)
	ct := sym.Type()
	if ct == nil {
		return name, nil
	}
	// A varnode merged into the global's variable from other storage (a
	// register) sits where the high's global member sits.
	// C++ parity: PrintC::pushSymbolDetail (high->getSymbolOffset, vn size).
	at := vn
	if vn.Space() != e.Addr().Space {
		at = nil
		if hv := vn.High(); hv != nil {
			for _, w := range hv.Instances() {
				if w.Space() == e.Addr().Space {
					at = w
					break
				}
			}
		}
	}
	if at == nil || at.Offset() < e.Addr().Offset {
		return name, nil
	}
	off := int32(at.Offset() - e.Addr().Offset)
	if off == 0 && vn.Size() > ct.Size() {
		// A mismatch prints the bare name, without its scopes.
		// C++ parity: PrintC::pushMismatchSymbol ('_' + getDisplayName).
		return "_" + cppDisplayName(sym.Name()), nil
	}
	return symbolPieceName(name, ct, off, vn.Size(), castTo, e.Addr().Space.BigEndian, rop, rslot)
}

// symbolPieceName prints sz bytes at off within a symbol of type ct: the
// name for the whole symbol, "_"+name when it overruns it from the start,
// else a path of .field / [index] steps (._off_sz_ when nothing fits).
// For a read (castTo != nil) a step that is a plain truncation becomes a
// cast to castTo instead, which is returned.
// C++ parity: PrintC::pushSymbolDetail -> pushPartialSymbol /
// pushMismatchSymbol.
//
// rop/rslot is the op reading the Varnode (rslot >= 0) or writing it (-1): a
// structure whose single field fills it prints through the field when that
// use resolves to it.
func symbolPieceName(name string, ct Datatype, off, sz int32, castTo Datatype, bigEndian bool, rop *PcodeOp, rslot int) (string, Datatype) {
	// Without a use to resolve against, a whole symbol is its name.
	if off == 0 && sz == ct.Size() && (!ct.NeedsResolution() || rop == nil) {
		return name, nil
	}
	if off+sz > ct.Size() {
		if off == 0 {
			return "_" + name, nil
		}
		return name, nil
	}
	return partialSymbolName(name, ct, off, sz, castTo, bigEndian, rop, rslot)
}

// partialSymbolName is the pushPartialSymbol walk of symbolPieceName without
// the mismatch check: an access the symbol's type does not cover ends in
// an artificial ._off_sz_ step (or a truncating cast).
// C++ parity: PrintC::pushPartialSymbol.
func partialSymbolName(name string, ct Datatype, off, sz int32, castTo Datatype, bigEndian bool, rop *PcodeOp, rslot int) (string, Datatype) {
	var finalcast Datatype
	var sb strings.Builder
	sb.WriteString(name)
	for ct != nil {
		if off == 0 && sz == ct.Size() {
			if !ct.NeedsResolution() || ct.Metatype() == TYPE_PTR {
				break
			}
		}
		ok := false
		switch t := ct.(type) {
		case *Struct:
			if ct.NeedsResolution() && ct.Size() == sz && (rop == nil || findResolve(ct, rop, rslot) == ct) {
				break // Turns out we don't resolve to the field
			}
			for _, f := range t.Fields() {
				if f.Type != nil && f.Offset <= off && off+sz <= f.Offset+f.Type.Size() {
					sb.WriteString("." + f.Name)
					off -= f.Offset
					ct = f.Type
					ok = true
					break
				}
			}
		case *Union:
			// C++ parity: pushPartialSymbol TYPE_UNION (findTruncation reads
			// the cached resolution of this use).
			if rop != nil {
				if idx, newoff := unionFindTruncation(t, int64(off), sz, rop, rslot); idx >= 0 {
					f := t.fields[idx]
					sb.WriteString("." + f.Name)
					off = int32(newoff)
					ct = f.Type
					ok = true
					break
				}
			}
			if ct.Size() == sz {
				return sb.String(), finalcast // Turns out we don't need to resolve the field
			}
		case *Array:
			if el := t.Element(); el != nil && el.Size() > 0 {
				idx, rem := off/el.Size(), off%el.Size()
				if rem+sz <= el.Size() {
					// C++ parity: PrintC::push_integer (<= 10 decimal).
					sb.WriteString("[" + formatIntegerLiteral(uint64(idx), 4, false) + "]")
					off = rem
					ct = el
					ok = true
				}
			}
		}
		if !ok && off == 0 && sz == ct.Size() {
			break // A whole value that does not resolve to its component
		}
		if _, isStruct := ct.(*Struct); !ok && isStruct && rop != nil && (rop.Code() == CPUI_ZPULL || rop.Code() == CPUI_SPULL) {
			break // the final byte field cannot resolve: it is a bitfield
		}
		if !ok && castTo != nil {
			if _, isStruct := ct.(*Struct); !isStruct {
				if _, isArray := ct.(*Array); !isArray {
					tmpoff := off
					if bigEndian {
						tmpoff = ct.Size() - 1 - off
					}
					if sharedCastStrategyC.IsSubpieceCast(castTo, ct, uint32(tmpoff)) {
						finalcast = castTo
						break
					}
				}
			}
		}
		if !ok {
			fmt.Fprintf(&sb, "._%d_%d_", off, sz)
			break
		}
	}
	return sb.String(), finalcast
}

// globalEntryOf returns the global symbol entry a Varnode is linked to. A
// persistent Varnode created after ActionMapGlobals (rule rewrites) is linked
// on demand by address, as Funcdata::linkSymbol does in ActionNameVars.
func (fd *Funcdata) globalEntryOf(vn *Varnode) *SymbolEntry {
	gs := fd.globalScope
	if e := gs.EntryFor(vn); e != nil {
		return e
	}
	if gs == nil || vn.IsAnnotation() {
		return nil
	}
	if !vn.IsPersist() {
		// A temporary merged into a global's variable (a mergeIndirect COPY)
		// is that global. C++ parity: HighVariable::getSymbol.
		if hv := vn.High(); hv != nil {
			for _, w := range hv.Instances() {
				if e := gs.EntryFor(w); e != nil {
					return e
				}
			}
		}
		return nil
	}
	e := gs.QueryContainer(vn.Addr(), vn.Size(), address.Address{})
	if e != nil {
		gs.Attach(vn, e)
	}
	return e
}

// defaultGlobalName names a persistent location that has no symbol.
// C++ parity: ScopeInternal::buildVariableName, Varnode::persist branch
// (the caller tries the register name first).
func defaultGlobalName(addr address.Address, ct Datatype) string {
	sp := addr.Space.Name
	if sp != "" {
		sp = strings.ToUpper(sp[:1]) + sp[1:]
	}
	return fmt.Sprintf("%s%s%0*x", datatypeNameBase(ct), sp, 2*addr.Space.AddrSize, addr.Offset)
}

// resolveGlobal returns the global symbol entry covering addr, asking the
// host for it the first time (ScopeGhidra queries Java on a cache miss).
// A code label is a one-byte entry of unknown type, so a wider access at its
// address is a mismatch (_DAT_00000003). C++ parity: LabSymbol::buildType
// (getBase(1,TYPE_UNKNOWN)) found by Scope::queryProperties.
func (fd *Funcdata) resolveGlobal(addr address.Address) *SymbolEntry {
	if fd.globalScope == nil {
		fd.globalScope = NewGlobalScope()
	}
	gs := fd.globalScope
	if e := gs.QueryContainer(addr, 1, address.Address{}); e != nil {
		return e
	}
	hs, ok := fd.hostScope.(HostDataScope)
	if !ok {
		return nil
	}
	hd, ok := hs.QueryData(addr)
	// A code label recorded without a size (one the host made while printing
	// a goto) covers no storage: only queryCodeLabel finds it.
	// C++ parity: SymbolEntry::decode (size 0 range) vs Scope::queryContainer.
	if !ok || (hd.Label && hd.Size == 0) {
		return fd.externRefSymbol(addr)
	}
	if hd.Label {
		hd.Type, hd.Size = nil, 1
	}
	dt := hd.Type
	if dt == nil {
		dt = sharedTypeFactory.GetBase(hd.Size, TYPE_UNKNOWN, "")
	}
	fl := VarnodeTypeLock | VarnodeNameLock
	if hd.ReadOnly {
		fl |= VarnodeReadOnly
	}
	e := gs.AddSymbol(hd.Name, dt, hd.Addr, hd.Size, fl)
	e.Symbol().checkSizeTypeLock()
	// The Database outlives a restart: a size-locked type overridden by the
	// previous run is still in force.
	if ct := fd.sizeLockTypes[hd.Addr]; ct != nil && e.Symbol().IsSizeTypeLocked() && ct.Size() == dt.Size() {
		e.Symbol().SetType(ct)
	}
	e.Symbol().namespace = hd.Namespace
	e.Symbol().nsPath = hd.NamespacePath
	if hd.Isolate {
		e.Symbol().SetIsolated(true)
	}
	return e
}

// externRefSymbol maps an import slot to its external-reference Symbol: a
// type-locked code pointer named <function>_exref.
// C++ parity: ExternRefSymbol::buildNameType (Ghidra names it _exref).
func (fd *Funcdata) externRefSymbol(addr address.Address) *SymbolEntry {
	if fd.hostScope == nil || addr.Space == nil {
		return nil
	}
	name, ok := fd.hostScope.QueryExternalRef(addr)
	if !ok || name == "" {
		return nil
	}
	size := int32(addr.Space.AddrSize)
	if size <= 0 {
		return nil
	}
	ct := sharedTypeFactory.GetPointer(size, sharedTypeFactory.GetCode("code", nil, nil, false), uint32(addr.Space.WordSize))
	return fd.globalScope.AddSymbol(name+"_exref", ct, addr, size, VarnodeTypeLock|VarnodeNameLock|VarnodeExternRef)
}

// NewGlobalScope constructs an empty global scope.
func NewGlobalScope() *GlobalScope { return &GlobalScope{} }

// AddSymbol maps a named, typed storage location into the global scope and
// returns the created SymbolEntry. flags carries Varnode-style property bits
// (typelock / namelock) copied onto the Symbol so downstream passes see the
// same lock state Ghidra's injected symbol carries.
// C++ parity: ScopeInternal::addMapInternal + Scope::addSymbol.
func (g *GlobalScope) AddSymbol(name string, dt Datatype, addr address.Address, size int32, flags uint32) *SymbolEntry {
	if g == nil {
		return nil
	}
	sym := NewSymbol(name, dt)
	sym.SetFlags(flags)
	entry := NewSymbolEntry(sym, 0, addr, size, 0)
	sym.attachEntry(entry)
	g.entries = append(g.entries, entry)
	return entry
}

// Entries returns the live SymbolEntry records.
func (g *GlobalScope) Entries() []*SymbolEntry {
	if g == nil {
		return nil
	}
	return g.entries
}

// QueryContainer returns the smallest SymbolEntry that wholly contains the given
// address range, mirroring ScopeLocal.QueryContainer for the global container.
// C++ parity: Scope::queryContainer.
func (g *GlobalScope) QueryContainer(addr address.Address, size int32, usepoint address.Address) *SymbolEntry {
	if g == nil {
		return nil
	}
	var best *SymbolEntry
	for _, e := range g.entries {
		if e == nil || e.IsDynamic() {
			continue
		}
		if e.addr.Space != addr.Space {
			continue
		}
		if !containsRange(e, addr.Offset, size) {
			continue
		}
		if !e.InUse(usepoint) {
			continue
		}
		if best == nil || e.size < best.size {
			best = e
		}
	}
	return best
}
