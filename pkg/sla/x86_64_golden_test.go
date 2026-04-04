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

// x8664PspecPath returns the absolute path to testdata/sla/x86-64.pspec.
func x8664PspecPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "testdata", "sla", "x86-64.pspec")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "x86-64.pspec")
}

// goldenEngineX8664 builds a *sla.Engine from x86-64-packed.sla with pspec
// context defaults applied (addrsize=2, opsize=1, longMode=1).
// C++ ref: SleighLanguage.setContextForProcessor applies pspec context_set defaults.
func goldenEngineX8664(program []byte) (*sla.Engine, address.Address, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, address.Address{}, fmt.Errorf("runtime.Caller failed")
	}
	// x86_64_golden_test.go lives at pkg/sla/; x86-64-packed.sla is at pkg/sla/testdata/
	slaPath := filepath.Join(filepath.Dir(file), "testdata", "x86-64-packed.sla")

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

	// Apply x86-64 pspec context defaults: addrsize=2, opsize=1, longMode=1.
	// C++ ref: SleighLanguage.setContextForProcessor applies context_set entries.
	pspecData, pspecErr := sla.ParsePspec(x8664PspecPath())
	if pspecErr != nil {
		return nil, address.Address{}, fmt.Errorf("ParsePspec: %w", pspecErr)
	}
	for _, entry := range pspecData.ContextSet {
		if setErr := backend.SetVariableDefault(entry.Name, entry.Value); setErr != nil {
			return nil, address.Address{}, fmt.Errorf("SetVariableDefault(%q): %w", entry.Name, setErr)
		}
	}

	base := address.Address{Space: ram, Offset: 0}
	padded := make([]byte, 16)
	copy(padded, program)
	if setErr := backend.SetInstructionBytes(base, padded); setErr != nil {
		return nil, address.Address{}, fmt.Errorf("SetInstructionBytes: %w", setErr)
	}

	// Build lowering context with SpacesByIndex[0]=ConstantSpace fix.
	// Ghidra C++ IPTR_CONSTANT=0: const space must be reachable at index 0.
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

// TestGoldenX8664 verifies that translating x86-64 instructions produces stable
// p-code op sequences with 64-bit context defaults applied (longMode=1).
//
// Set GOSLEIGH_UPDATE_GOLDEN=1 to regenerate fixtures.
func TestGoldenX8664(t *testing.T) {
	cases := []struct {
		name string
		prog []byte
	}{
		// REX.W + MOV RAX, imm64
		{"x86_64_MOV_RAX_imm64", []byte{0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		// REX.W + ADD RAX, RBX
		{"x86_64_ADD_RAX_RBX", []byte{0x48, 0x01, 0xD8}},
		// PUSH RBP (short encoding, no REX needed for default 64-bit push)
		{"x86_64_PUSH_RBP", []byte{0x55}},
		// REX.W + MOV RBP, RSP
		{"x86_64_MOV_RBP_RSP", []byte{0x48, 0x89, 0xE5}},
		// RET
		{"x86_64_RET", []byte{0xC3}},
		// MOV EAX, EDI (no REX: 32-bit zero-extends to RAX)
		{"x86_64_MOV_EAX_EDI", []byte{0x89, 0xF8}},
	}

	update := os.Getenv("GOSLEIGH_UPDATE_GOLDEN") == "1"

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			engine, base, err := goldenEngineX8664(tc.prog)
			if err != nil {
				t.Fatalf("goldenEngineX8664: %v", err)
			}

			translation, translateErr := engine.TranslateInstructionAt(base)
			if translateErr != nil {
				t.Fatalf("TranslateInstructionAt: %v", translateErr)
			}

			if len(translation.Ops) == 0 {
				t.Fatalf("0 ops returned for %s -- translation gap detected", tc.name)
			}

			got := opsToGolden(base, translation.Ops)
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
					t.Fatalf("golden fixture not found; run with GOSLEIGH_UPDATE_GOLDEN=1 to generate: %s", fixturePath)
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
