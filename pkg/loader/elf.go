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

package loader

import (
	"debug/elf"
	"fmt"
)

// LoadELF32TextSection opens an ELF32 file and returns the raw bytes of the
// .text section along with its virtual base address.
//
// The caller can pass the returned bytes and address directly to EngineBuilder:
//
//	data, base, err := LoadELF32TextSection(path)
//	engine, entry, err := (&EngineBuilder{Bytes: data, BaseAddr: base, ...}).Build()
func LoadELF32TextSection(path string) ([]byte, uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("LoadELF32TextSection: open %s: %w", path, err)
	}
	defer f.Close()

	sec := f.Section(".text")
	if sec == nil {
		return nil, 0, fmt.Errorf("LoadELF32TextSection: no .text section in %s", path)
	}

	data, err := sec.Data()
	if err != nil {
		return nil, 0, fmt.Errorf("LoadELF32TextSection: read .text: %w", err)
	}

	return data, sec.Addr, nil
}
