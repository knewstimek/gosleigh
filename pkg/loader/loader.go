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

// Package loader provides a high-level pipeline for building a translation
// Engine from .sla and optional .pspec files plus a raw binary image.
// It consolidates the steps that every caller must perform:
//   1. Read + decode the .sla container
//   2. Decode boundaries payload
//   3. Build cross-references (xrefs)
//   4. Locate the RAM/default address space
//   5. Create and configure the backend (context vars, pspec defaults)
//   6. Load binary bytes into the backend
//   7. Build the lowering context with the SpacesByIndex[0]=ConstantSpace fix
//   8. Create the Engine
package loader

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gosleigh/pkg/address"
	"gosleigh/pkg/sla"
)

// EngineBuilder holds all parameters needed to build a translation Engine.
// Zero-value fields use sensible defaults where possible.
type EngineBuilder struct {
	// SLAPath is the path to the packed or XML .sla file. Required.
	SLAPath string

	// PspecPath is the optional path to a .pspec XML file.
	// When non-empty, context_set defaults from the file are applied to the
	// backend before the Engine is built, matching the Java
	// SleighLanguage.setContextForProcessor behavior.
	PspecPath string

	// BinaryPath is the optional path to a raw binary image.
	// When non-empty, the file is opened via Backend.OpenRawInstructionFile.
	// BinaryPath and explicit Bytes are mutually exclusive; if both are set,
	// BinaryPath takes precedence.
	BinaryPath string

	// Bytes is optional raw instruction bytes to load via SetInstructionBytes
	// at the address {ram, BaseAddr}. Used when BinaryPath is empty.
	Bytes []byte

	// BaseAddr is the VMA of the first byte in Bytes (or the VMA for
	// OpenRawInstructionFile when BinaryPath is set). Default 0.
	BaseAddr uint64

	// BaseOffset is the file offset within BinaryPath to start reading from.
	// Ignored when using Bytes directly. Default 0 (start of file).
	BaseOffset uint64

	// ReadSize is the number of bytes to map from BinaryPath starting at
	// BaseOffset. A value of 0 maps the entire file. Ignored when Bytes is used.
	ReadSize uint64

	// Sections holds additional disjoint image sections, each mapped at its own
	// virtual memory address (PESection.VMA). This supports loading a fully
	// linked executable where code (.text) and jump tables / read-only data
	// (.rdata) live at distinct VMAs. Each section is written independently via
	// SetInstructionBytes into the backend's sparse image map, so sections at
	// different VMAs coexist. Sections are additive to (and independent of)
	// Bytes/BinaryPath; the returned entry address is still {ram, BaseAddr}, so
	// callers set BaseAddr to the target function VMA.
	Sections []PESection
}

// Build executes the full pipeline and returns a ready-to-use Engine and the
// entry address.Address in the default (RAM) space at offset BaseAddr.
//
// Pipeline (matches goldenEngineX86 in x86_golden_test.go):
//  1. os.ReadFile(SLAPath) -> sla.Read -> sla.DecodeBoundariesPayload
//  2. boundaries.BuildXrefs
//  3. locate default address space (RAM)
//  4. sla.NewBackend + RegisterContextVariable for every ContextField
//  5. optionally ParsePspec + SetVariableDefault
//  6. load binary bytes (BinaryPath or Bytes)
//  7. NewLoweringContext + SpacesByIndex[0] = ConstantSpace fix
//  8. NewEngineFromBoundaries
func (b *EngineBuilder) Build() (*sla.Engine, address.Address, error) {
	if b.SLAPath == "" {
		return nil, address.Address{}, fmt.Errorf("loader: SLAPath is required")
	}

	// --- Step 1: read and decode the .sla file ---
	rawData, err := os.ReadFile(b.SLAPath)
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("loader: read sla %q: %w", b.SLAPath, err)
	}
	container, err := sla.Read(bytes.NewReader(rawData))
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("loader: sla.Read: %w", err)
	}
	boundaries, err := sla.DecodeBoundariesPayload(container.Payload)
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("loader: DecodeBoundariesPayload: %w", err)
	}

	// --- Step 2: build cross-references ---
	xrefs, err := boundaries.BuildXrefs()
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("loader: BuildXrefs: %w", err)
	}

	// --- Step 3: locate default address space ---
	var ram *address.Space
	for i := range boundaries.Metadata.Spaces {
		if boundaries.Metadata.Spaces[i].Name == boundaries.Metadata.DefaultSpace {
			ram = &boundaries.Metadata.Spaces[i]
			break
		}
	}
	if ram == nil {
		return nil, address.Address{}, fmt.Errorf("loader: default address space %q not found in sla metadata", boundaries.Metadata.DefaultSpace)
	}

	// --- Step 4: create backend and register context variables ---
	backend := sla.NewBackend()
	for _, field := range xrefs.ContextFields {
		if regErr := backend.RegisterContextVariable(field.Name, int(field.StartBit), int(field.EndBit)); regErr != nil {
			return nil, address.Address{}, fmt.Errorf("loader: RegisterContextVariable(%q): %w", field.Name, regErr)
		}
	}

	// --- Step 5: apply pspec context defaults ---
	// Mirrors SleighLanguage.setContextForProcessor: only context_set entries
	// are applied as SetVariableDefault; tracked_set is not.
	if b.PspecPath != "" {
		pspecData, pspecErr := sla.ParsePspec(b.PspecPath)
		if pspecErr != nil {
			return nil, address.Address{}, fmt.Errorf("loader: ParsePspec(%q): %w", b.PspecPath, pspecErr)
		}
		for _, entry := range pspecData.ContextSet {
			if setErr := backend.SetVariableDefault(entry.Name, entry.Value); setErr != nil {
				return nil, address.Address{}, fmt.Errorf("loader: SetVariableDefault(%q): %w", entry.Name, setErr)
			}
		}
	}

	// --- Step 6: load binary bytes ---
	entryAddr := address.Address{Space: ram, Offset: b.BaseAddr}
	if b.BinaryPath != "" {
		// File-backed path: read bytes manually to support BaseOffset and ReadSize.
		// Using os.Open + Seek + Read (not OpenRawInstructionFile) so that we can
		// honor both the offset into the file and an optional byte count limit.
		f, openErr := os.Open(b.BinaryPath)
		if openErr != nil {
			return nil, address.Address{}, fmt.Errorf("loader: open binary %q: %w", b.BinaryPath, openErr)
		}
		defer f.Close()
		if b.BaseOffset > 0 {
			if _, seekErr := f.Seek(int64(b.BaseOffset), 0); seekErr != nil {
				return nil, address.Address{}, fmt.Errorf("loader: seek binary %q offset %d: %w", b.BinaryPath, b.BaseOffset, seekErr)
			}
		}
		var binBytes []byte
		if b.ReadSize > 0 {
			binBytes = make([]byte, b.ReadSize)
			if _, readErr := f.Read(binBytes); readErr != nil {
				return nil, address.Address{}, fmt.Errorf("loader: read binary %q: %w", b.BinaryPath, readErr)
			}
		} else {
			var readErr error
			binBytes, readErr = io.ReadAll(f)
			if readErr != nil {
				return nil, address.Address{}, fmt.Errorf("loader: readall binary %q: %w", b.BinaryPath, readErr)
			}
		}
		padded := binBytes
		if len(padded) < 16 {
			padded = make([]byte, 16)
			copy(padded, binBytes)
		}
		if setErr := backend.SetInstructionBytes(entryAddr, padded); setErr != nil {
			return nil, address.Address{}, fmt.Errorf("loader: SetInstructionBytes: %w", setErr)
		}
	} else if len(b.Bytes) > 0 {
		// In-memory path: pad to at least 16 bytes so the Sleigh pattern
		// matcher always has enough lookahead (mirrors goldenEngineX86 padding).
		padded := make([]byte, len(b.Bytes))
		if len(padded) < 16 {
			padded = make([]byte, 16)
		}
		copy(padded, b.Bytes)
		if setErr := backend.SetInstructionBytes(entryAddr, padded); setErr != nil {
			return nil, address.Address{}, fmt.Errorf("loader: SetInstructionBytes: %w", setErr)
		}
	}

	// --- Step 6b: map additional disjoint sections at their own VMAs ---
	// Each section is written independently into the backend's sparse
	// image[Address]byte map, so multiple sections at different virtual
	// addresses coexist without overlap. Used by the PE32+ loader path to place
	// .text and .rdata at their real VMAs (jump tables live in .rdata for the
	// general MSVC case; the switch corpus keeps the table inside .text).
	for _, sec := range b.Sections {
		if len(sec.Bytes) == 0 {
			continue
		}
		secAddr := address.Address{Space: ram, Offset: sec.VMA}
		if setErr := backend.SetInstructionBytes(secAddr, sec.Bytes); setErr != nil {
			return nil, address.Address{}, fmt.Errorf("loader: SetInstructionBytes section %q at 0x%x: %w", sec.Name, sec.VMA, setErr)
		}
	}

	// --- Step 7: build lowering context with SpacesByIndex[0] fix ---
	// Ghidra C++ IPTR_CONSTANT == 0 (space.hh): the const space must be
	// reachable at index 0.  NewLoweringContext inserts spaces from Metadata
	// but does NOT insert ConstantSpace into SpacesByIndex, causing
	// "space index 0 not found" errors when x86 p-code references const space
	// via ConstKindSpaceID.  This is the canonical fix applied in the golden
	// x86 test and must be present for any architecture that uses IPTR_CONSTANT.
	loweringCtx := sla.NewLoweringContext(boundaries.Metadata, entryAddr)
	if loweringCtx.ConstantSpace != nil {
		loweringCtx.SpacesByIndex[0] = loweringCtx.ConstantSpace
	}

	// --- Step 8: create engine ---
	engine, err := sla.NewEngineFromBoundaries(boundaries, sla.EngineConfig{
		LoweringTemplate: loweringCtx,
		XRefs:            xrefs,
		Backend: sla.EngineBackendAdapter{
			LoadMatchInput: backend.PayloadLoader(sla.BackendPayloadConfig{}),
			Commits:        backend.CommitHooks(),
		},
	})
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("loader: NewEngineFromBoundaries: %w", err)
	}
	return engine, entryAddr, nil
}
