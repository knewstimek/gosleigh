// Copyright 2026 The Gosleigh Authors. Apache 2.0.

// Package loader provides binary loading utilities.
package loader

import (
	"debug/dwarf"
	"debug/elf"
	"debug/pe"
	"fmt"
)

// LoadDWARFFunctions extracts function symbols from DWARF debug info in an ELF or PE binary.
// Returns an empty SymbolTable (not an error) when the file has no DWARF data.
// Returns an error only when the file cannot be parsed as ELF or PE.
func LoadDWARFFunctions(path string) (*SymbolTable, error) {
	st := NewSymbolTable()

	var dwarfData *dwarf.Data

	ef, elfErr := elf.Open(path)
	if elfErr == nil {
		defer ef.Close()
		d, err := ef.DWARF()
		if err != nil {
			// no DWARF -- return empty table, not an error
			return st, nil
		}
		dwarfData = d
	} else {
		pf, peErr := pe.Open(path)
		if peErr == nil {
			defer pf.Close()
			d, err := pf.DWARF()
			if err != nil {
				return st, nil
			}
			dwarfData = d
		} else {
			return nil, fmt.Errorf("LoadDWARFFunctions: not ELF (%v) and not PE (%v)", elfErr, peErr)
		}
	}

	r := dwarfData.Reader()
	for {
		entry, err := r.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag != dwarf.TagSubprogram {
			continue
		}
		nameVal := entry.Val(dwarf.AttrName)
		lowpcVal := entry.Val(dwarf.AttrLowpc)
		if nameVal == nil || lowpcVal == nil {
			continue
		}
		name, ok := nameVal.(string)
		if !ok || name == "" {
			continue
		}
		var addr uint64
		switch v := lowpcVal.(type) {
		case uint64:
			addr = v
		case int64:
			addr = uint64(v)
		default:
			continue
		}
		if addr == 0 {
			continue
		}
		st.Add(Symbol{Name: name, Address: addr})
	}

	return st, nil
}
