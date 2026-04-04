// Copyright 2026 The Gosleigh Authors. Apache 2.0.
// Corresponds to Ghidra's PeLoader / ImageSectionHeader handling.

package loader

import (
	"debug/pe"
	"fmt"
	"os"
)

// LoadPE32TextSection opens a PE32 (32-bit Windows executable) file and returns
// the raw bytes of the .text section along with the section's virtual memory address.
// Returns an error if the file is not PE32 (e.g. PE32+/64-bit), or has no .text section.
func LoadPE32TextSection(path string) ([]byte, uint64, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("pe.Open %s: %w", path, err)
	}
	defer f.Close()

	hdr32, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, 0, fmt.Errorf("%s: not a PE32 file (PE32+ or unknown optional header)", path)
	}

	for _, sec := range f.Sections {
		if sec.Name == ".text" {
			data, err := sec.Data()
			if err != nil {
				return nil, 0, fmt.Errorf("reading .text section from %s: %w", path, err)
			}
			// Trim to VirtualSize if smaller than raw data to match actual code size.
			if vs := int(sec.VirtualSize); vs > 0 && vs < len(data) {
				data = data[:vs]
			}
			vma := uint64(sec.VirtualAddress) + uint64(hdr32.ImageBase)
			return data, vma, nil
		}
	}

	return nil, 0, fmt.Errorf("%s: no .text section found", path)
}

// Ensure the file handle is closed even on early returns (used via defer above).
var _ = os.ErrClosed
