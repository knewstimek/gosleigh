// Copyright 2026 The Gosleigh Authors. Apache 2.0.

// Package loader provides binary loading utilities.
package loader

import "sort"

// Symbol represents a named symbol in a binary.
type Symbol struct {
	Name    string
	Address uint64
	Size    uint64
}

// SymbolTable maps addresses to symbols.
type SymbolTable struct {
	byAddr map[uint64]Symbol
}

// NewSymbolTable creates an empty SymbolTable.
func NewSymbolTable() *SymbolTable {
	return &SymbolTable{byAddr: make(map[uint64]Symbol)}
}

// Add inserts or overwrites a symbol by address.
func (st *SymbolTable) Add(s Symbol) {
	st.byAddr[s.Address] = s
}

// Lookup returns the symbol at addr, if any.
func (st *SymbolTable) Lookup(addr uint64) (Symbol, bool) {
	s, ok := st.byAddr[addr]
	return s, ok
}

// All returns all symbols sorted by address.
func (st *SymbolTable) All() []Symbol {
	syms := make([]Symbol, 0, len(st.byAddr))
	for _, s := range st.byAddr {
		syms = append(syms, s)
	}
	sort.Slice(syms, func(i, j int) bool {
		return syms[i].Address < syms[j].Address
	})
	return syms
}

// Len returns the number of symbols.
func (st *SymbolTable) Len() int {
	return len(st.byAddr)
}
