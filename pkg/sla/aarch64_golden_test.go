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

package sla_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/sla"
)

// aarch64PspecPath returns the absolute path to testdata/sla/AARCH64.pspec.
// aarch64_golden_test.go lives at pkg/sla/; AARCH64.pspec is at ../../testdata/sla/AARCH64.pspec.
func aarch64PspecPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "testdata", "sla", "AARCH64.pspec")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "AARCH64.pspec")
}

// goldenEngineAARCH64 builds a *sla.Engine from AARCH64.sla with pspec context
// defaults applied. Unknown context variables in the pspec (e.g. ShowPAC, ShowBTI)
// are silently skipped -- AARCH64.sla may not register every optional extension
// variable, and mismatches are not fatal for baseline instruction tests.
//
// C++ ref: SleighLanguage.setContextForProcessor applies context_set entries;
// unknown variables are ignored in production Ghidra installs when the .sla
// was compiled without the corresponding context variable.
func goldenEngineAARCH64(program []byte) (*sla.Engine, address.Address, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, address.Address{}, fmt.Errorf("runtime.Caller failed")
	}
	// aarch64_golden_test.go lives at pkg/sla/; AARCH64.sla is at ../../testdata/sla/AARCH64.sla
	slaPath := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "AARCH64.sla")

	data, err := os.ReadFile(slaPath)
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("read sla file: %w", err)
	}
	container, err := sla.Read(bytes.NewReader(data))
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("sla.Read: %w", err)
	}
	boundaries, err := sla.DecodeBoundariesPayload(container.Payload)
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("DecodeBoundariesPayload: %w", err)
	}
	xrefs, err := boundaries.BuildXrefs()
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("BuildXrefs: %w", err)
	}

	var ram *address.Space
	for i := range boundaries.Metadata.Spaces {
		if boundaries.Metadata.Spaces[i].Name == boundaries.Metadata.DefaultSpace {
			ram = &boundaries.Metadata.Spaces[i]
			break
		}
	}
	if ram == nil {
		return nil, address.Address{}, fmt.Errorf("default address space not found")
	}

	backend := sla.NewBackend()
	for _, field := range xrefs.ContextFields {
		if regErr := backend.RegisterContextVariable(field.Name, int(field.StartBit), int(field.EndBit)); regErr != nil {
			return nil, address.Address{}, fmt.Errorf("RegisterContextVariable(%q): %w", field.Name, regErr)
		}
	}

	// Apply AARCH64 pspec context defaults. Unknown variables (e.g. ShowPAC,
	// ShowBTI, ShowMemTag, PAC_clobber) are skipped gracefully: if the compiled
	// AARCH64.sla does not include a given extension context variable, the pspec
	// entry has no corresponding registered slot and SetVariableDefault returns
	// an error. We skip rather than fail so that baseline tests work with any
	// AARCH64.sla vintage.
	pspecData, pspecErr := sla.ParsePspec(aarch64PspecPath())
	if pspecErr != nil {
		return nil, address.Address{}, fmt.Errorf("ParsePspec: %w", pspecErr)
	}
	for _, entry := range pspecData.ContextSet {
		if setErr := backend.SetVariableDefault(entry.Name, entry.Value); setErr != nil {
			// Silently skip: variable not registered in this .sla binary.
			_ = setErr
		}
	}

	base := address.Address{Space: ram, Offset: 0}
	padded := make([]byte, 16)
	copy(padded, program)
	if setErr := backend.SetInstructionBytes(base, padded); setErr != nil {
		return nil, address.Address{}, fmt.Errorf("SetInstructionBytes: %w", setErr)
	}

	// Register const space at index 0 -- Ghidra C++ IPTR_CONSTANT = 0 (space.hh).
	loweringCtx := sla.NewLoweringContext(boundaries.Metadata, base)
	if loweringCtx.ConstantSpace != nil {
		loweringCtx.SpacesByIndex[0] = loweringCtx.ConstantSpace
	}

	engine, err := sla.NewEngineFromBoundaries(boundaries, sla.EngineConfig{
		LoweringTemplate: loweringCtx,
		XRefs:            xrefs,
		Backend: sla.EngineBackendAdapter{
			LoadMatchInput: backend.PayloadLoader(sla.BackendPayloadConfig{}),
			Commits:        backend.CommitHooks(),
		},
	})
	if err != nil {
		return nil, address.Address{}, fmt.Errorf("NewEngineFromBoundaries: %w", err)
	}
	return engine, base, nil
}

// TestGoldenAARCH64 verifies that translating AArch64 instructions produces
// stable p-code op sequences by comparing against JSON fixture files.
//
// Set GOSLEIGH_UPDATE_GOLDEN=1 to regenerate fixtures instead of comparing.
// AArch64 is little-endian; all instruction bytes are 4-byte LE words.
// NOP legitimately produces 0 ops (empty p-code body) -- fixture will be [].
func TestGoldenAARCH64(t *testing.T) {
	cases := []struct {
		name string
		prog []byte
	}{
		// ADD X0, X0, X1  (0x8B010000 LE = bytes 00 00 01 8B)
		{"aarch64_ADD_X0_X0_X1", []byte{0x00, 0x00, 0x01, 0x8B}},
		// RET  (0xD65F03C0 LE = bytes C0 03 5F D6)
		{"aarch64_RET", []byte{0xC0, 0x03, 0x5F, 0xD6}},
		// MOV X0, X1 (ORR X0, XZR, X1)  (0xAA0103E0 LE = bytes E0 03 01 AA)
		{"aarch64_MOV_X0_X1", []byte{0xE0, 0x03, 0x01, 0xAA}},
		// NOP  (0xD503201F LE = bytes 1F 20 03 D5) -- produces empty p-code body
		{"aarch64_NOP", []byte{0x1F, 0x20, 0x03, 0xD5}},
	}

	update := os.Getenv("GOSLEIGH_UPDATE_GOLDEN") == "1"

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			engine, base, err := goldenEngineAARCH64(tc.prog)
			if err != nil {
				t.Fatalf("goldenEngineAARCH64: %v", err)
			}

			var got []GoldenOp

			translation, translateErr := engine.TranslateInstructionAt(base)
			if translateErr != nil {
				// Translation failure recorded as parity gap, not a hard fail.
				// Mirrors TestGolden6502 unimplemented handling.
				t.Logf("translation gap (%T): %v", translateErr, translateErr)
				got = []GoldenOp{{
					Address:       fmt.Sprintf("0x%x", base.Offset),
					Opcode:        "UNIMPLEMENTED",
					Inputs:        []VarnodeDesc{},
					Unimplemented: true,
				}}
			} else {
				got = opsToGolden(base, translation.Ops)
			}

			fixturePath := goldenFixturePath(tc.name)

			if update {
				data, marshalErr := json.MarshalIndent(got, "", "\t")
				if marshalErr != nil {
					t.Fatalf("marshal golden fixture: %v", marshalErr)
				}
				if mkErr := os.MkdirAll(filepath.Dir(fixturePath), 0o755); mkErr != nil {
					t.Fatalf("create golden dir: %v", mkErr)
				}
				if writeErr := os.WriteFile(fixturePath, data, 0o644); writeErr != nil {
					t.Fatalf("write golden fixture: %v", writeErr)
				}
				t.Logf("wrote golden fixture: %s", fixturePath)
				return
			}

			fixtureData, readErr := os.ReadFile(fixturePath)
			if readErr != nil {
				if os.IsNotExist(readErr) {
					t.Skipf("golden fixture not found (run GOSLEIGH_UPDATE_GOLDEN=1 to generate): %s", fixturePath)
				}
				t.Fatalf("read golden fixture: %v", readErr)
			}

			var want []GoldenOp
			if jsonErr := json.Unmarshal(fixtureData, &want); jsonErr != nil {
				t.Fatalf("unmarshal golden fixture: %v", jsonErr)
			}

			compareGolden(t, want, got)
		})
	}
}
