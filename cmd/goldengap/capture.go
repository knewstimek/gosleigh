package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/pcode"
)

// xnode is a generic XML element tree for reading Ghidra decompiler savefiles.
type xnode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Kids    []xnode    `xml:",any"`
	text    string
}

// UnmarshalXML keeps the element's character data (comment text) as well.
func (n *xnode) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type plain struct {
		Attrs []xml.Attr `xml:",any,attr"`
		Kids  []xnode    `xml:",any"`
		Text  string     `xml:",chardata"`
	}
	var p plain
	if err := d.DecodeElement(&p, &start); err != nil {
		return err
	}
	n.XMLName, n.Attrs, n.Kids, n.text = start.Name, p.Attrs, p.Kids, p.Text
	return nil
}

func (n *xnode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n *xnode) child(name string) *xnode {
	for i := range n.Kids {
		if n.Kids[i].XMLName.Local == name {
			return &n.Kids[i]
		}
	}
	return nil
}

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if !strings.HasPrefix(s, "0x") {
		v, _ = strconv.ParseUint(s, 10, 64)
	}
	return v
}

// captureData is the global data symbol table of one decompiler savefile:
// exactly the <mapsym> answers the Java host gave the C++ core for that
// function (DecompileCallback.getMappedSymbols), sorted by address.
type captureData struct {
	syms []pcode.HostData
}

// loadCaptureData reads the <db> scopes of a savefile written by
// DecompInterface.enableDebug (tools/realexe/GenCapture.java).
func loadCaptureData(path string, ram *address.Space) (*captureData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root xnode
	if err := xml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	state := root.child("save_state")
	if state == nil {
		return nil, fmt.Errorf("%s: no save_state", path)
	}
	types := map[string]*xnode{}
	collectTypes := func(n *xnode) {
		if n == nil {
			return
		}
		for i := range n.Kids {
			if k := &n.Kids[i]; k.XMLName.Local == "type" {
				types[k.attr("name")] = k
			}
		}
	}
	collectTypes(root.child("coretypes"))
	collectTypes(state.child("typegrp"))
	db := state.child("db")
	if db == nil {
		return &captureData{}, nil
	}
	// Scope id -> namespace path.
	scopes := map[string]*xnode{}
	for i := range db.Kids {
		if s := &db.Kids[i]; s.XMLName.Local == "scope" {
			scopes[s.attr("id")] = s
		}
	}
	var nsPath func(id string) string
	nsPath = func(id string) string {
		s := scopes[id]
		if s == nil || s.attr("name") == "" {
			return ""
		}
		parent := ""
		if p := s.child("parent"); p != nil {
			parent = nsPath(p.attr("id"))
		}
		if parent == "" {
			return s.attr("name")
		}
		return parent + "::" + s.attr("name")
	}
	cd := &captureData{}
	for id, s := range scopes {
		ns := nsPath(id)
		list := s.child("symbollist")
		if list == nil {
			continue
		}
		for i := range list.Kids {
			ms := &list.Kids[i]
			if ms.XMLName.Local != "mapsym" || len(ms.Kids) < 2 {
				continue
			}
			sym, at := &ms.Kids[0], ms.child("addr")
			if at == nil || at.attr("space") != ram.Name {
				continue
			}
			hd := pcode.HostData{
				Name:      sym.attr("name"),
				Namespace: ns,
				Addr:      address.Address{Space: ram, Offset: parseUint(at.attr("offset"))},
				Size:      int32(parseUint(at.attr("size"))),
				ReadOnly:  sym.attr("readonly") == "true",
			}
			switch sym.XMLName.Local {
			case "symbol":
				if len(sym.Kids) > 0 {
					hd.Type = pcode.ResolveHostType(typeDesc(&sym.Kids[0], types, 0))
				}
			case "labelsym":
				hd.Label = true
			default:
				continue // functions come from the symbol table; externrefs too
			}
			cd.syms = append(cd.syms, hd)
		}
	}
	sort.Slice(cd.syms, func(i, j int) bool { return cd.syms[i].Addr.Offset < cd.syms[j].Addr.Offset })
	return cd, nil
}

// typeDesc converts a <type>/<typeref> element into a host type description,
// resolving references through the savefile's core types and type group.
func typeDesc(n *xnode, types map[string]*xnode, depth int) *pcode.HostTypeDesc {
	if n == nil || depth > 16 {
		return nil
	}
	switch n.XMLName.Local {
	case "typeref":
		if t := types[n.attr("name")]; t != nil {
			return typeDesc(t, types, depth+1)
		}
		return nil
	case "void":
		return &pcode.HostTypeDesc{Meta: "void"}
	case "type":
	default:
		return nil
	}
	d := &pcode.HostTypeDesc{
		Name:  n.attr("name"),
		Meta:  n.attr("metatype"),
		Size:  int32(parseUint(n.attr("size"))),
		Count: int32(parseUint(n.attr("arraysize"))),
	}
	if len(n.Kids) > 0 && (d.Meta == "ptr" || d.Meta == "array") {
		d.Elem = typeDesc(&n.Kids[0], types, depth+1)
	}
	return d
}

// captureDir is the -host-captures directory: <entry as %08x>.xml per golden.
var captureDir string

// hostWithData layers a function's captured data symbols over the program
// symbol table.
type hostWithData struct {
	pcode.HostScope
	*captureData
}

// withCapture returns host extended with fn's captured data symbols, or host
// unchanged when there is no capture for fn.
func withCapture(host pcode.HostScope, fn goldenEntry, ram *address.Space) pcode.HostScope {
	if captureDir == "" || host == nil || ram == nil {
		return host
	}
	cd, err := loadCaptureData(fmt.Sprintf("%s/%08x.xml", captureDir, fn.Entry), ram)
	if err != nil {
		return host
	}
	return hostWithData{host, cd}
}

// captureComments returns fn's comment database from its capture, or nil.
func captureComments(fn goldenEntry) []bridge.HostComment {
	if captureDir == "" {
		return nil
	}
	raw, err := os.ReadFile(fmt.Sprintf("%s/%08x.xml", captureDir, fn.Entry))
	if err != nil {
		return nil
	}
	var root xnode
	if xml.Unmarshal(raw, &root) != nil {
		return nil
	}
	state := root.child("save_state")
	if state == nil {
		return nil
	}
	db := state.child("commentdb")
	if db == nil {
		return nil
	}
	var out []bridge.HostComment
	for i := range db.Kids {
		c := &db.Kids[i]
		if c.XMLName.Local != "comment" {
			continue
		}
		// <comment type=..><addr func/><addr at/><text>..</text></comment>
		var addrs []*xnode
		var text string
		for j := range c.Kids {
			switch k := &c.Kids[j]; k.XMLName.Local {
			case "addr":
				addrs = append(addrs, k)
			case "text":
				text = k.text
			}
		}
		if len(addrs) < 2 {
			continue
		}
		out = append(out, bridge.HostComment{Type: c.attr("type"), Addr: parseUint(addrs[1].attr("offset")), Text: text})
	}
	return out
}

// QueryData returns the symbol whose storage contains addr (a label matches
// its address only).
func (cd *captureData) QueryData(addr address.Address) (pcode.HostData, bool) {
	if cd == nil {
		return pcode.HostData{}, false
	}
	i := sort.Search(len(cd.syms), func(i int) bool { return cd.syms[i].Addr.Offset > addr.Offset })
	for j := i - 1; j >= 0; j-- {
		s := cd.syms[j]
		size := uint64(s.Size)
		if size == 0 {
			size = 1
		}
		if addr.Offset < s.Addr.Offset+size {
			return s, true
		}
		if j < i-1 {
			break
		}
	}
	return pcode.HostData{}, false
}
