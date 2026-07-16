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

import "gosleigh/pkg/address"

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
