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

// x86PspecPath returns the absolute path to testdata/sla/x86.pspec.
// x86_golden_test.go lives at pkg/sla/; x86.pspec is at ../../testdata/sla/x86.pspec.
func x86PspecPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..", "testdata", "sla", "x86.pspec")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "x86.pspec")
}

// goldenEngineX86 builds a *sla.Engine from x86-packed.sla with pspec context defaults applied.
// Mirrors goldenEngine (6502) but uses packed SLA and applies addrsize=1, opsize=1 from x86.pspec.
// C++ ref: SleighLanguage.setContextForProcessor applies pspec context_set to context register defaults.
func goldenEngineX86(program []byte) (*sla.Engine, address.Address, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, address.Address{}, fmt.Errorf("runtime.Caller failed")
	}
	// x86_golden_test.go lives at pkg/sla/; x86-packed.sla is at pkg/sla/testdata/x86-packed.sla
	slaPath := filepath.Join(filepath.Dir(file), "testdata", "x86-packed.sla")

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

	// Apply pspec context defaults (addrsize=1, opsize=1) so Sleigh selects 32-bit constructors.
	// C++ ref: SleighLanguage.setContextForProcessor, applies context_set to context register defaults.
	pspecData, pspecErr := sla.ParsePspec(x86PspecPath())
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

	// Build the lowering context and register const space at index 0.
	// Ghidra C++ IPTR_CONSTANT = 0 (space.hh): the const space is always index 0.
	// NewLoweringContext allocates ConstantSpace but does not insert it into SpacesByIndex,
	// causing "space index 0 not found" when x86 p-code references const space via ConstKindSpaceID.
	loweringCtx := sla.NewLoweringContext(boundaries.Metadata, base)
	if loweringCtx.ConstantSpace != nil {
		loweringCtx.SpacesByIndex[0] = loweringCtx.ConstantSpace
	}

	engine, err := sla.NewEngineFromBoundaries(boundaries, sla.EngineConfig{
		LoweringTemplate: loweringCtx,
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

// TestGoldenX86 verifies that translating x86 32-bit instructions produces
// stable p-code op sequences with context defaults applied.
//
// Instructions chosen for coverage of key p-code paths:
//   - x86_NOP      (0x90):       no-op -- exercises zero-op / empty body path
//   - x86_RET      (0xC3):       near return via stack -- exercises LOAD+INT_ADD+RETURN
//   - x86_PUSH_EBP (0x55):       push EBP -- exercises VarnodeList (r32) operand resolution
//
// Set GOSLEIGH_UPDATE_GOLDEN=1 to regenerate fixtures.
// 0 ops is a non-fatal warning: NOP legitimately emits no ops.
func TestGoldenX86(t *testing.T) {
	cases := []struct {
		name string
		prog []byte
	}{
		{"x86_NOP",           []byte{0x90}},
		{"x86_RET",           []byte{0xC3}},
		{"x86_PUSH_EBP",      []byte{0x55}},
		{"x86_MOV_EBX_EAX",   []byte{0x89, 0xC3}},
		{"x86_MOV_EAX_imm32", []byte{0xB8, 0x01, 0x00, 0x00, 0x00}},
		{"x86_ADD_EAX_EBX",   []byte{0x01, 0xD8}},
		{"x86_SUB_EAX_EBX",   []byte{0x29, 0xD8}},
		{"x86_XOR_EAX_EAX",   []byte{0x31, 0xC0}},
		{"x86_POP_EBP",       []byte{0x5D}},
		{"x86_JMP_short",     []byte{0xEB, 0x00}},
		{"x86_DEC_ECX",       []byte{0x49}},
		{"x86_JNE_back",      []byte{0x75, 0xFE}},
		{"x86_CALL_rel32",    []byte{0xE8, 0x10, 0x00, 0x00, 0x00}},
		{"x86_JE_fwd",        []byte{0x74, 0x02}},
		{"x86_TEST_EAX_EAX",  []byte{0x85, 0xC0}},
		{"x86_JNS_fwd",       []byte{0x79, 0x04}},
		{"x86_NEG_EAX",       []byte{0xF7, 0xD8}},
		{"x86_IMUL_EAX_EBX",  []byte{0x0F, 0xAF, 0xC3}},
		{"x86_MUL_EBX",       []byte{0xF7, 0xE3}},
		{"x86_CDQ",           []byte{0x99}},
		{"x86_IDIV_ECX",      []byte{0xF7, 0xF9}},
		{"x86_DIV_ECX",       []byte{0xF7, 0xF1}},
		{"x86_SHL_EAX_imm8",  []byte{0xC1, 0xE0, 0x02}},
		{"x86_SHR_EAX_imm8",  []byte{0xC1, 0xE8, 0x02}},
		{"x86_SAR_EAX_imm8",  []byte{0xC1, 0xF8, 0x02}},
		{"x86_OR_EAX_EBX",   []byte{0x09, 0xD8}},
		{"x86_AND_EAX_EBX",  []byte{0x21, 0xD8}},
		{"x86_INC_EAX",      []byte{0x40}},
		{"x86_CMP_EAX_EBX",  []byte{0x39, 0xD8}},
		{"x86_MOVZX_EAX_AL", []byte{0x0F, 0xB6, 0xC0}},
		{"x86_MOVSX_EAX_AL", []byte{0x0F, 0xBE, 0xC0}},
		{"x86_LEA_EAX_disp8", []byte{0x8D, 0x43, 0x04}},
		{"x86_JGE_fwd",      []byte{0x7D, 0x02, 0x90}},
		{"x86_PUSH_EBX",     []byte{0x53}},
		{"x86_PUSH_ECX",     []byte{0x51}},
		{"x86_POP_EBX",      []byte{0x5B}},
		{"x86_DEC_EAX",      []byte{0x48}},
		{"x86_XCHG_EAX_ECX", []byte{0x91}},
		{"x86_JL_fwd",       []byte{0x7C, 0x02}},
		{"x86_JLE_fwd",      []byte{0x7E, 0x02}},
		{"x86_JG_fwd",       []byte{0x7F, 0x02}},
		{"x86_JB_fwd",       []byte{0x72, 0x02}},
		{"x86_JA_fwd",       []byte{0x77, 0x02}},
		{"x86_PUSH_imm8",          []byte{0x6A, 0x05}},
		{"x86_PUSH_imm32",         []byte{0x68, 0x78, 0x56, 0x34, 0x12}},
		{"x86_NOT_EAX",            []byte{0xF7, 0xD0}},
		{"x86_MOV_EBP_minus4_EAX", []byte{0x89, 0x45, 0xFC}},
		{"x86_MOV_EAX_EBP_minus4", []byte{0x8B, 0x45, 0xFC}},
		{"x86_SUB_ESP_imm8",       []byte{0x83, 0xEC, 0x04}},
		{"x86_SHL_EAX_1",          []byte{0xD1, 0xE0}},
	}

	update := os.Getenv("GOSLEIGH_UPDATE_GOLDEN") == "1"

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			engine, base, err := goldenEngineX86(tc.prog)
			if err != nil {
				t.Fatalf("goldenEngineX86: %v", err)
			}

			translation, translateErr := engine.TranslateInstructionAt(base)
			if translateErr != nil {
				t.Fatalf("TranslateInstructionAt: %v", translateErr)
			}

			// NOP legitimately emits 0 ops; all other subtests must produce at least 1 op.
			if len(translation.Ops) == 0 {
				if tc.name == "x86_NOP" {
					t.Logf("WARNING: 0 ops returned for %s -- intentional no-op", tc.name)
				} else {
					t.Fatalf("0 ops returned for %s -- translation gap detected", tc.name)
				}
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
