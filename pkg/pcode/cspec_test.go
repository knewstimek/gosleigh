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

import (
	"strings"
	"testing"
)

// minimalCdeclXML is an inline cspec XML that covers stack input pentry,
// register output pentry, unaffected list, and killedbycall list -- the
// minimal set needed to exercise ABI-aware variable naming.
const minimalCdeclXML = `<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
  <stackpointer register="ESP" space="ram"/>
  <returnaddress>
    <varnode space="stack" offset="0" size="4"/>
  </returnaddress>
  <default_proto>
    <prototype name="__cdecl" extrapop="4" stackshift="4">
      <input>
        <pentry minsize="1" maxsize="500" align="4">
          <addr space="stack" offset="4"/>
        </pentry>
      </input>
      <output>
        <pentry minsize="1" maxsize="4">
          <register name="EAX"/>
        </pentry>
      </output>
      <unaffected>
        <register name="ESP"/>
        <register name="EBP"/>
        <register name="ESI"/>
      </unaffected>
      <killedbycall>
        <register name="EAX"/>
        <register name="ECX"/>
        <register name="EDX"/>
      </killedbycall>
    </prototype>
  </default_proto>
</compiler_spec>`

// TestParseCspec verifies that a well-formed cdecl cspec parses all fields
// correctly: stack pointer, return address offset, default prototype name,
// extrapop, stack input pentry, register output pentry, unaffected list,
// killedbycall list, and the derived helpers StackParamBaseOffset/StackParamAlign.
func TestParseCspec(t *testing.T) {
	cs, err := ParseCspecBytes([]byte(minimalCdeclXML))
	if err != nil {
		t.Fatalf("ParseCspecBytes error: %v", err)
	}
	if cs == nil {
		t.Fatal("expected non-nil CspecData")
	}

	// Stack pointer.
	if cs.StackPointerReg != "ESP" {
		t.Errorf("StackPointerReg = %q, want ESP", cs.StackPointerReg)
	}
	if cs.StackPointerSpace != "ram" {
		t.Errorf("StackPointerSpace = %q, want ram", cs.StackPointerSpace)
	}

	// Return address stack offset (varnode space="stack" offset="0").
	if cs.ReturnAddressOffset != 0 {
		t.Errorf("ReturnAddressOffset = %d, want 0", cs.ReturnAddressOffset)
	}

	// Default prototype.
	if cs.DefaultProto == nil {
		t.Fatal("expected DefaultProto to be set")
	}
	if cs.DefaultProto.Name != "__cdecl" {
		t.Errorf("DefaultProto.Name = %q, want __cdecl", cs.DefaultProto.Name)
	}
	if cs.DefaultProto.ExtraPop != 4 {
		t.Errorf("DefaultProto.ExtraPop = %d, want 4", cs.DefaultProto.ExtraPop)
	}
	if cs.DefaultProto.StackShift != 4 {
		t.Errorf("DefaultProto.StackShift = %d, want 4", cs.DefaultProto.StackShift)
	}

	// Stack input pentry: space="stack", offset=4, align=4.
	inputs := cs.DefaultProto.Input.Pentries
	if len(inputs) != 1 {
		t.Fatalf("input pentry count = %d, want 1", len(inputs))
	}
	pe := inputs[0]
	if pe.Addr == nil {
		t.Fatal("expected input pentry to have Addr sub-element")
	}
	if pe.Addr.Space != "stack" {
		t.Errorf("input pentry addr space = %q, want stack", pe.Addr.Space)
	}
	if pe.Addr.Offset != 4 {
		t.Errorf("input pentry addr offset = %d, want 4", pe.Addr.Offset)
	}
	if pe.Align != 4 {
		t.Errorf("input pentry align = %d, want 4", pe.Align)
	}
	if pe.MinSize != 1 || pe.MaxSize != 500 {
		t.Errorf("input pentry size range = [%d,%d], want [1,500]", pe.MinSize, pe.MaxSize)
	}

	// Register output pentry: register name="EAX".
	outputs := cs.DefaultProto.Output.Pentries
	if len(outputs) != 1 {
		t.Fatalf("output pentry count = %d, want 1", len(outputs))
	}
	outPe := outputs[0]
	if outPe.Register == nil {
		t.Fatal("expected output pentry to have Register sub-element")
	}
	if outPe.Register.Name != "EAX" {
		t.Errorf("output register name = %q, want EAX", outPe.Register.Name)
	}

	// Unaffected (callee-saved) list: ESP, EBP, ESI.
	unaffected := cs.DefaultProto.Unaffected.Registers
	if len(unaffected) != 3 {
		t.Errorf("unaffected register count = %d, want 3", len(unaffected))
	} else {
		seen := make(map[string]bool, 3)
		for _, r := range unaffected {
			seen[r.Name] = true
		}
		for _, name := range []string{"ESP", "EBP", "ESI"} {
			if !seen[name] {
				t.Errorf("unaffected list missing %q", name)
			}
		}
	}

	// KilledByCall (caller-saved) list: EAX, ECX, EDX.
	killed := cs.DefaultProto.KilledByCall.Registers
	if len(killed) != 3 {
		t.Errorf("killedbycall register count = %d, want 3", len(killed))
	} else {
		seen := make(map[string]bool, 3)
		for _, r := range killed {
			seen[r.Name] = true
		}
		for _, name := range []string{"EAX", "ECX", "EDX"} {
			if !seen[name] {
				t.Errorf("killedbycall list missing %q", name)
			}
		}
	}

	// Derived helpers.
	if off := cs.StackParamBaseOffset(); off != 4 {
		t.Errorf("StackParamBaseOffset() = %d, want 4", off)
	}
	if align := cs.StackParamAlign(); align != 4 {
		t.Errorf("StackParamAlign() = %d, want 4", align)
	}

	// No extra named prototypes.
	if len(cs.ExtraProtos) != 0 {
		t.Errorf("ExtraProtos count = %d, want 0", len(cs.ExtraProtos))
	}
}

// TestParseCspecEmpty verifies that an empty <compiler_spec/> produces no error
// and leaves DefaultProto nil (empty protos map semantics).
func TestParseCspecEmpty(t *testing.T) {
	const emptyXML = `<compiler_spec></compiler_spec>`
	cs, err := ParseCspecBytes([]byte(emptyXML))
	if err != nil {
		t.Fatalf("unexpected error for empty XML: %v", err)
	}
	if cs == nil {
		t.Fatal("expected non-nil CspecData")
	}
	// No prototype name means the default_proto block is empty -> nil.
	if cs.DefaultProto != nil {
		t.Errorf("expected nil DefaultProto for empty XML, got %+v", cs.DefaultProto)
	}
	if len(cs.ExtraProtos) != 0 {
		t.Errorf("expected zero ExtraProtos, got %d", len(cs.ExtraProtos))
	}
}

// TestParseCspecMalformed verifies that structurally broken XML returns a
// non-nil error that mentions "cspec" (matching our error-wrapping convention).
func TestParseCspecMalformed(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"unclosed tag", `<compiler_spec`},
		{"double angle bracket", `<<compiler_spec>>`},
		{"truncated attribute value", `<compiler_spec><stackpointer register=`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCspecBytes([]byte(tc.input))
			if err == nil {
				t.Errorf("expected error for malformed input %q, got nil", tc.input)
				return
			}
			if !strings.Contains(err.Error(), "cspec") {
				t.Errorf("error %q should mention 'cspec'", err.Error())
			}
		})
	}
}
