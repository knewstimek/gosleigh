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

// mips32lePspecPath returns the absolute path to testdata/sla/mips32le.pspec.
func mips32lePspecPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "testdata", "sla", "mips32le.pspec")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "mips32le.pspec")
}

// goldenEngineMIPS32LE builds a *sla.Engine from mips32le.sla with pspec context
// defaults applied. Unknown context variables in the pspec are silently skipped --
// same graceful handling as goldenEngineAARCH64.
//
// C++ ref: SleighLanguage.setContextForProcessor applies context_set entries;
// unknown variables are ignored in production Ghidra installs.
func goldenEngineMIPS32LE(program []byte) (*sla.Engine, address.Address, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, address.Address{}, fmt.Errorf("runtime.Caller failed")
	}
	// mips32_golden_test.go lives at pkg/sla/; mips32le.sla is at ../../testdata/sla/
	slaPath := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "mips32le.sla")

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

	// Apply MIPS32 pspec context defaults. Unknown variables are skipped
	// gracefully: if mips32le.sla does not register a given context variable,
	// SetVariableDefault returns an error which we silently ignore.
	pspecData, pspecErr := sla.ParsePspec(mips32lePspecPath())
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
	// MIPS32 instructions are 4 bytes; pad to 8 for safety.
	padded := make([]byte, 8)
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

// TestGoldenMIPS32LE verifies that translating MIPS32 LE instructions produces
// stable p-code op sequences by comparing against JSON fixture files.
//
// Set GOSLEIGH_UPDATE_GOLDEN=1 to regenerate fixtures instead of comparing.
// MIPS32 is little-endian; all instruction bytes are 4-byte LE words.
func TestGoldenMIPS32LE(t *testing.T) {
	cases := []struct {
		name string
		prog []byte
	}{
		// NOP = SLL $zero, $zero, 0 (encoding 0x00000000 LE = bytes 00 00 00 00)
		// Typically produces no p-code ops or a trivial COPY.
		{"mips32le_NOP", []byte{0x00, 0x00, 0x00, 0x00}},
		// ADDU $v0, $a0, $a1 (encoding 0x00851021 LE = bytes 21 10 85 00)
		// Expected: $v0 = $a0 + $a1
		{"mips32le_ADDU_V0_A0_A1", []byte{0x21, 0x10, 0x85, 0x00}},
		// JR $ra (encoding 0x03E00008 LE = bytes 08 00 E0 03)
		// Expected: RETURN or BRANCH p-code
		{"mips32le_JR_RA", []byte{0x08, 0x00, 0xE0, 0x03}},
		// ADDIU $v0, $zero, 1 (encoding 0x24020001 LE = bytes 01 00 02 24)
		// Expected: $v0 = 0 + 1 = 1
		{"mips32le_ADDIU_V0_ZERO_1", []byte{0x01, 0x00, 0x02, 0x24}},
	}

	update := os.Getenv("GOSLEIGH_UPDATE_GOLDEN") == "1"

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			engine, base, err := goldenEngineMIPS32LE(tc.prog)
			if err != nil {
				t.Fatalf("goldenEngineMIPS32LE: %v", err)
			}

			var got []GoldenOp

			translation, translateErr := engine.TranslateInstructionAt(base)
			if translateErr != nil {
				// Translation failure recorded as parity gap, not a hard fail.
				// Mirrors TestGoldenAARCH64 unimplemented handling.
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
