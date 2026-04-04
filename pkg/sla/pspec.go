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
// Only context_set entries are included -- tracked_set entries are NOT context register
// defaults in Ghidra and must not be passed to SetVariableDefault.
type PspecData struct {
	ContextSet []PspecContextEntry
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
// tracked_set is deliberately not mapped -- we ignore it.
type pspecXMLContextData struct {
	ContextSet []pspecXMLContextSet `xml:"context_set"`
}

// pspecXMLRoot is the XML shape of the top-level <processor_spec> element.
type pspecXMLRoot struct {
	ContextData pspecXMLContextData `xml:"context_data"`
}

// ParsePspec reads a .pspec XML file and returns the context_set defaults.
// val attributes are decimal integers (e.g., "1"); parsed with strconv.ParseUint.
// Returns an error if the file cannot be read or the XML is malformed.
func ParsePspec(path string) (PspecData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PspecData{}, fmt.Errorf("ParsePspec read %q: %w", path, err)
	}

	var root pspecXMLRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return PspecData{}, fmt.Errorf("ParsePspec unmarshal %q: %w", path, err)
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
	return result, nil
}
