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

	"gosleigh/pkg/address"
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

// globalSymbolName is how a global symbol is referenced from the current
// function: qualified by its namespace unless that is the function's own.
// C++ parity: PrintC::pushSymbolScope (minimal namespace strategy).
// TODO known mismatch: only the exact-namespace case is elided; C++ also
// elides a common prefix with the function's scope.
func (s *printCState) globalSymbolName(sym *Symbol) string {
	ns := sym.Namespace()
	if ns == "" {
		return sym.Name()
	}
	if fn := s.fd.Name(); strings.HasPrefix(fn, ns+"::") && !strings.Contains(fn[len(ns)+2:], "::") {
		return sym.Name()
	}
	return ns + "::" + sym.Name()
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
// (a register name if the location is one is not needed for ram).
func defaultGlobalName(addr address.Address, ct Datatype) string {
	sp := addr.Space.Name
	if sp != "" {
		sp = strings.ToUpper(sp[:1]) + sp[1:]
	}
	return fmt.Sprintf("%s%s%0*x", datatypeNameBase(ct), sp, 2*addr.Space.AddrSize, addr.Offset)
}

// resolveGlobal returns the global symbol entry covering addr, asking the
// host for it the first time (ScopeGhidra queries Java on a cache miss).
// Code labels are not storage and never back a variable.
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
	if !ok || hd.Label {
		return nil
	}
	dt := hd.Type
	if dt == nil {
		dt = sharedTypeFactory.GetBase(hd.Size, TYPE_UNKNOWN, "")
	}
	e := gs.AddSymbol(hd.Name, dt, hd.Addr, hd.Size, VarnodeTypeLock|VarnodeNameLock)
	e.Symbol().namespace = hd.Namespace
	return e
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
