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

package sla

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
)

// PspecContextEntry holds a single context variable default from a pspec context_set.
// Mirrors SleighLanguage.setContextForProcessor (Java), which applies context_set entries
// to the context register defaults.
type PspecContextEntry struct {
	Name  string
	Value uint64
}

// PspecData holds the parsed result of a .pspec file.
// Only ContextSet entries are context register defaults; TrackedSet entries
// must not be passed to SetVariableDefault.
type PspecData struct {
	ContextSet []PspecContextEntry
	// LanedRegisters lists the registers carrying vector_lane_sizes.
	// C++ parity: Architecture::decodeProcessorSpec register_data.
	LanedRegisters []PspecLanedRegister
	// IncidentalCopy names the registers copied to incidentally (the x87
	// stack). C++ parity: Architecture::decodeIncidentalCopy.
	IncidentalCopy []string
	// TrackedSet holds the tracked_set register values known at every function
	// entry (x86: DF=0). They are not context defaults; a host passes them to
	// the core as the function's tracked registers. C++ parity:
	// ContextDatabase::decodeFromSpec (ELEM_TRACKED_SET), read back through
	// ContextDatabase::getTrackedSet by ActionConstbase.
	TrackedSet []PspecContextEntry
}

// PspecLanedRegister is a register_data entry with preferred lane sizes.
type PspecLanedRegister struct {
	Name      string
	LaneSizes string
}

type pspecXMLRegister struct {
	Name      string `xml:"name,attr"`
	LaneSizes string `xml:"vector_lane_sizes,attr"`
}

type pspecXMLRegisterData struct {
	Registers []pspecXMLRegister `xml:"register"`
}

// pspecXMLSet is the XML shape of a <set> element inside context_set or tracked_set.
type pspecXMLSet struct {
	Name string `xml:"name,attr"`
	Val  string `xml:"val,attr"`
}

// pspecXMLContextSet is the XML shape of a <context_set> element.
type pspecXMLContextSet struct {
	Sets []pspecXMLSet `xml:"set"`
}

// pspecXMLContextData is the XML shape of the <context_data> element.
// tracked_set is kept apart from context_set: only context_set becomes context
// register defaults.
type pspecXMLContextData struct {
	ContextSet []pspecXMLContextSet `xml:"context_set"`
	TrackedSet []pspecXMLContextSet `xml:"tracked_set"`
}

// pspecXMLRoot is the XML shape of the top-level <processor_spec> element.
type pspecXMLRoot struct {
	ContextData    pspecXMLContextData  `xml:"context_data"`
	RegisterData   pspecXMLRegisterData `xml:"register_data"`
	IncidentalCopy pspecXMLRegisterData `xml:"incidentalcopy"`
}

// ParsePspec reads a .pspec XML file and returns the context_set defaults.
// val attributes are decimal integers (e.g., "1"); parsed with strconv.ParseUint.
// Returns an error if the file cannot be read or the XML is malformed.
func ParsePspec(path string) (PspecData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PspecData{}, fmt.Errorf("ParsePspec read %q: %w", path, err)
	}
	result, err := ParsePspecBytes(data)
	if err != nil {
		return PspecData{}, fmt.Errorf("%w (file %q)", err, path)
	}
	return result, nil
}

// ParsePspecBytes parses .pspec XML from in-memory bytes (an embedded spec).
func ParsePspecBytes(data []byte) (PspecData, error) {
	var root pspecXMLRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return PspecData{}, fmt.Errorf("ParsePspec unmarshal: %w", err)
	}

	var result PspecData
	for _, cs := range root.ContextData.ContextSet {
		for _, s := range cs.Sets {
			v, err := strconv.ParseUint(s.Val, 10, 64)
			if err != nil {
				return PspecData{}, fmt.Errorf("ParsePspec: invalid val %q for %q: %w", s.Val, s.Name, err)
			}
			result.ContextSet = append(result.ContextSet, PspecContextEntry{Name: s.Name, Value: v})
		}
	}
	for _, ts := range root.ContextData.TrackedSet {
		for _, s := range ts.Sets {
			// Base 0: the C++ decoder (decodeUnsignedInteger) accepts 0x-prefixed values.
			v, err := strconv.ParseUint(s.Val, 0, 64)
			if err != nil {
				return PspecData{}, fmt.Errorf("ParsePspec: invalid tracked val %q for %q: %w", s.Val, s.Name, err)
			}
			result.TrackedSet = append(result.TrackedSet, PspecContextEntry{Name: s.Name, Value: v})
		}
	}
	for _, r := range root.RegisterData.Registers {
		if r.LaneSizes != "" {
			result.LanedRegisters = append(result.LanedRegisters, PspecLanedRegister{Name: r.Name, LaneSizes: r.LaneSizes})
		}
	}
	for _, r := range root.IncidentalCopy.Registers {
		result.IncidentalCopy = append(result.IncidentalCopy, r.Name)
	}
	return result, nil
}
