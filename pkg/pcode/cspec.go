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
	// Storage carries the AArch64-style class attribute ("float", "hiddenret").
	// Older x86 cspecs use Metatype instead; both are checked when classifying a
	// pentry as an integer register slot. C++ parity: ParamEntry type class.
	Storage string `xml:"storage,attr"`
	// Addr sub-element: space + offset, or register name
	Addr     *CspecAddr     `xml:"addr"`
	Register *CspecRegister `xml:"register"`
}

// isIntegerRegPentry reports whether a pentry assigns an integer/pointer value to
// a single register (not a stack addr, not a float slot, not a hidden-return
// pointer slot). These are exactly the pentries that define register-passed
// parameters and the integer return slot, across x86-64 SysV (metatype="float"
// excluded) and AArch64 (storage="float"/"hiddenret" excluded).
// C++ parity: ParamEntry float/hiddenret filtering in ProtoModel::assignMap.
func isIntegerRegPentry(pe CspecPentry) bool {
	return pe.Register != nil && pe.Addr == nil &&
		pe.Metatype != "float" &&
		pe.Storage != "float" && pe.Storage != "hiddenret"
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

// CspecGroup holds a <group> element inside an <input> block.
// C++ parity: compiler.hh ParamEntryGroup (Windows x64 ABI grouped registers)
type CspecGroup struct {
	Pentries []CspecPentry `xml:"pentry"`
}

// CspecInput holds the <input> block of a prototype.
// Groups are flattened into Pentries during XML unmarshalling.
type CspecInput struct {
	Pentries []CspecPentry `xml:"pentry"`
	Groups   []CspecGroup  `xml:"group"`
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
	Name         string       `xml:"name,attr"`
	ExtraPop     int          `xml:"extrapop,attr"`
	StackShift   int          `xml:"stackshift,attr"`
	Input        CspecInput   `xml:"input"`
	Output       CspecOutput  `xml:"output"`
	Unaffected   CspecRegList `xml:"unaffected"`
	KilledByCall CspecRegList `xml:"killedbycall"`
	// LikelyTrash mirrors the <likelytrash> register list. Hosts call
	// LikelyTrashRegs() to extract the names and then push them into each
	// per-call FuncProto via FuncProto.SetLikelyTrash (declared in
	// action_extras.go side-map style because funcproto.go's struct list is
	// frozen for this slice).
	// C++ parity: compiler.hh ProtoModel::likelytrash
	LikelyTrash CspecRegList `xml:"likelytrash"`
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

// xmlDataOrg mirrors the <data_organization> XML element.
type xmlDataOrg struct {
	PointerSize xmlPointerSize `xml:"pointer_size"`
	LongSize    xmlLongSize    `xml:"long_size"`
}

// xmlPointerSize mirrors the <pointer_size> element inside <data_organization>.
type xmlPointerSize struct {
	Value int `xml:"value,attr"`
}

// xmlLongSize mirrors the <long_size> element inside <data_organization>.
type xmlLongSize struct {
	Value int `xml:"value,attr"`
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
	// PointerSizeVal is the pointer size in bytes from <data_organization><pointer_size/>.
	// 0 means unset (use default 4).
	PointerSizeVal int
	// LongSizeVal is the size of the C "long" type in bytes from
	// <data_organization><long_size/>.  0 means unset (use default 8, LP64).
	// Determines whether an 8-byte signed integer is named "long" (long_size==8,
	// LP64) or "longlong" (long_size==4, LLP64 / Windows x64).
	// C++ parity: TypeFactory::sizeOfLong (type.cc decodeDataOrganization/setupSizes).
	LongSizeVal int
}

// xmlCompilerSpec mirrors the top-level <compiler_spec> XML element.
type xmlCompilerSpec struct {
	XMLName      xml.Name           `xml:"compiler_spec"`
	StackPointer CspecStackPointer  `xml:"stackpointer"`
	ReturnAddr   CspecReturnAddress `xml:"returnaddress"`
	DefaultProto CspecDefaultProto  `xml:"default_proto"`
	Prototypes   []CspecPrototype   `xml:"prototype"`
	DataOrg      *xmlDataOrg        `xml:"data_organization"`
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
	if raw.DataOrg != nil && raw.DataOrg.PointerSize.Value > 0 {
		cs.PointerSizeVal = raw.DataOrg.PointerSize.Value
	}
	if raw.DataOrg != nil && raw.DataOrg.LongSize.Value > 0 {
		cs.LongSizeVal = raw.DataOrg.LongSize.Value
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

// PointerSize returns the pointer size in bytes from <data_organization>.
// Returns 4 if unset (default for x86-32 cdecl).
func (cs *CspecData) PointerSize() int {
	if cs == nil || cs.PointerSizeVal == 0 {
		return 4
	}
	return cs.PointerSizeVal
}

// LongSize returns the size of the C "long" type in bytes from <data_organization>.
// Returns 8 when unset. C++ parity: TypeFactory::setupSizes defaults sizeOfLong to 8
// when sizeOfInt is 4 (the common case), so LP64 "long" is the safe default.
func (cs *CspecData) LongSize() int {
	if cs == nil || cs.LongSizeVal == 0 {
		return 8
	}
	return cs.LongSizeVal
}

// allInputPentries returns all pentry elements from the default proto's input,
// including those nested inside <group> elements.
// C++ parity: ProtoModel::getPentries -- groups flatten into the pentry list.
func (cs *CspecData) allInputPentries() []CspecPentry {
	if cs == nil || cs.DefaultProto == nil {
		return nil
	}
	// Start with top-level pentries (direct children of <input>).
	result := make([]CspecPentry, 0, len(cs.DefaultProto.Input.Pentries))
	result = append(result, cs.DefaultProto.Input.Pentries...)
	// Append pentries nested inside <group> elements.
	for _, g := range cs.DefaultProto.Input.Groups {
		result = append(result, g.Pentries...)
	}
	return result
}

// LikelyTrashRegs returns the names of registers declared inside the
// <likelytrash> block of the default prototype. Empty when the cspec does not
// declare any. Hosts wire each per-call FuncProto via
// FuncProto.SetLikelyTrash (action_extras.go) -- the parser exposes the raw
// data here so loaders can resolve register names to VarnodeData on their
// own schedule.
// C++ parity: compiler.cc ProtoModel::decode parsing the <likelytrash> tag.
func (cs *CspecData) LikelyTrashRegs() []string {
	if cs == nil || cs.DefaultProto == nil {
		return nil
	}
	regs := cs.DefaultProto.LikelyTrash.Registers
	if len(regs) == 0 {
		return nil
	}
	out := make([]string, 0, len(regs))
	for _, r := range regs {
		out = append(out, r.Name)
	}
	return out
}

// IntegerRegParams returns the ordered list of integer/pointer register parameter
// names from the default calling convention prototype. Float-metatype and stack
// pentries are excluded. For grouped entries (Windows x64 ABI), only non-float
// registers within groups are included.
//
// Examples:
//   - x86-64 gcc (SysV):  ["RDI","RSI","RDX","RCX","R8","R9"]
//   - x86-64 win (__fastcall):  ["RCX","RDX","R8","R9"]
//   - x86-32 (no register params): nil
//
// C++ parity: ProtoModel::assignMap / ParamActive::isParamable (register subset)
func (cs *CspecData) IntegerRegParams() []string {
	if cs == nil || cs.DefaultProto == nil {
		return nil
	}
	var regs []string
	for _, pe := range cs.allInputPentries() {
		if isIntegerRegPentry(pe) {
			regs = append(regs, pe.Register.Name)
		}
	}
	return regs
}

// IntegerReturnReg returns the name of the integer/pointer return register from
// the default prototype's <output> block: the first register pentry that is not
// a float slot or hidden-return pointer slot. Empty when the convention returns
// via stack/join or declares no register output.
//
// Examples:
//   - x86-32 cdecl:  "EAX"
//   - x86-64 SysV:   "RAX" (after the float XMM0/XMM1 output pentries)
//   - AArch64:       "x0"  (after the float q0..q3 output pentries)
//
// C++ parity: ProtoModel output ParamList -- first integer register slot.
func (cs *CspecData) IntegerReturnReg() string {
	if cs == nil || cs.DefaultProto == nil {
		return ""
	}
	for _, pe := range cs.DefaultProto.Output.Pentries {
		if isIntegerRegPentry(pe) {
			return pe.Register.Name
		}
	}
	return ""
}
