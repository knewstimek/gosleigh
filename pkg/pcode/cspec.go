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
	"encoding/xml"
	"fmt"
	"os"
)

// CspecPentry describes a single parameter entry slot in a calling convention.
// C++ parity: compiler.hh ParamEntry
type CspecPentry struct {
	MinSize  int    `xml:"minsize,attr"`
	MaxSize  int    `xml:"maxsize,attr"`
	Align    int    `xml:"align,attr"`
	Metatype string `xml:"metatype,attr"`
	// Addr sub-element: space + offset, or register name
	Addr     *CspecAddr     `xml:"addr"`
	Register *CspecRegister `xml:"register"`
}

// CspecAddr is the <addr> sub-element of <pentry>.
type CspecAddr struct {
	Space  string `xml:"space,attr"`
	Offset int64  `xml:"offset,attr"`
}

// CspecRegister is the <register> sub-element of <pentry>.
type CspecRegister struct {
	Name string `xml:"name,attr"`
}

// CspecInput holds the <input> block of a prototype.
type CspecInput struct {
	Pentries []CspecPentry `xml:"pentry"`
}

// CspecOutput holds the <output> block of a prototype.
type CspecOutput struct {
	Pentries []CspecPentry `xml:"pentry"`
}

// CspecRegList holds a list of <register> elements (for unaffected/killedbycall).
type CspecRegList struct {
	Registers []CspecRegister `xml:"register"`
}

// CspecPrototype is a single calling convention prototype.
// C++ parity: compiler.hh PrototypeModel
type CspecPrototype struct {
	Name       string       `xml:"name,attr"`
	ExtraPop   int          `xml:"extrapop,attr"`
	StackShift int          `xml:"stackshift,attr"`
	Input      CspecInput   `xml:"input"`
	Output     CspecOutput  `xml:"output"`
	Unaffected CspecRegList `xml:"unaffected"`
	KilledByCall CspecRegList `xml:"killedbycall"`
}

// CspecDefaultProto wraps the <default_proto> element containing one <prototype>.
type CspecDefaultProto struct {
	Prototype CspecPrototype `xml:"prototype"`
}

// CspecStackPointer describes the <stackpointer> element.
type CspecStackPointer struct {
	Register string `xml:"register,attr"`
	Space    string `xml:"space,attr"`
}

// CspecReturnAddress describes the <returnaddress> element.
type CspecReturnAddress struct {
	Varnode *CspecVarnodeRef `xml:"varnode"`
}

// CspecVarnodeRef is a <varnode> element with space/offset/size attributes.
type CspecVarnodeRef struct {
	Space  string `xml:"space,attr"`
	Offset int64  `xml:"offset,attr"`
	Size   int    `xml:"size,attr"`
}

// CspecData is the parsed contents of a .cspec XML file.
// C++ parity: Architecture::parseBuildSpec (compiler.cc)
type CspecData struct {
	// DefaultProto is the default calling convention prototype.
	DefaultProto *CspecPrototype
	// ExtraProtos are all named non-default prototypes.
	ExtraProtos []*CspecPrototype
	// StackPointer register name (e.g. "ESP").
	StackPointerReg string
	// StackPointerSpace is the backing address space for the stack pointer (e.g. "ram").
	StackPointerSpace string
	// ReturnAddressStack is the stack offset of the return address (0 for x86 cdecl).
	ReturnAddressOffset int64
}

// xmlCompilerSpec mirrors the top-level <compiler_spec> XML element.
type xmlCompilerSpec struct {
	XMLName      xml.Name           `xml:"compiler_spec"`
	StackPointer CspecStackPointer  `xml:"stackpointer"`
	ReturnAddr   CspecReturnAddress `xml:"returnaddress"`
	DefaultProto CspecDefaultProto  `xml:"default_proto"`
	Prototypes   []CspecPrototype   `xml:"prototype"`
}

// ParseCspec reads and parses a .cspec XML file.
// Only the fields needed for ABI-aware variable naming are extracted.
// C++ parity: Architecture::parseBuildSpec / CompilerSpec construction
func ParseCspec(path string) (*CspecData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cspec: read %q: %w", path, err)
	}
	return ParseCspecBytes(data)
}

// ParseCspecBytes parses .cspec XML from in-memory bytes.
func ParseCspecBytes(data []byte) (*CspecData, error) {
	var raw xmlCompilerSpec
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cspec: xml parse: %w", err)
	}

	cs := &CspecData{
		StackPointerReg:   raw.StackPointer.Register,
		StackPointerSpace: raw.StackPointer.Space,
	}
	if raw.ReturnAddr.Varnode != nil {
		cs.ReturnAddressOffset = raw.ReturnAddr.Varnode.Offset
	}

	proto := raw.DefaultProto.Prototype
	if proto.Name != "" {
		cs.DefaultProto = &proto
	}

	for i := range raw.Prototypes {
		p := raw.Prototypes[i]
		cs.ExtraProtos = append(cs.ExtraProtos, &p)
	}

	return cs, nil
}

// StackParamBaseOffset returns the stack offset of the first parameter.
// For x86 __cdecl with 4-byte return address this is 4.
// Returns 0 if the calling convention has no stack-based inputs.
func (cs *CspecData) StackParamBaseOffset() int64 {
	if cs == nil || cs.DefaultProto == nil {
		return 4 // safe default for x86 cdecl
	}
	for _, pe := range cs.DefaultProto.Input.Pentries {
		if pe.Addr != nil && pe.Addr.Space == "stack" {
			return pe.Addr.Offset
		}
	}
	return 4
}

// StackParamAlign returns the stack alignment for parameters (bytes).
func (cs *CspecData) StackParamAlign() int64 {
	if cs == nil || cs.DefaultProto == nil {
		return 4
	}
	for _, pe := range cs.DefaultProto.Input.Pentries {
		if pe.Addr != nil && pe.Addr.Space == "stack" {
			if pe.Align > 0 {
				return int64(pe.Align)
			}
		}
	}
	return 4
}
