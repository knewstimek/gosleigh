package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	// typeWarnings are the TypeFactory warnings of the capture's types, in
	// the order the core decoded them (<entry>.typeorder from GenCapture).
	typeWarnings []string
	syms         []pcode.HostData
	// protos are the callee prototypes the core received, by entry offset.
	protos map[uint64]captureProto
}

// captureProto is the locked part of a host function prototype.
type captureProto struct {
	name, model            string
	extraPop               int32
	noReturn               bool
	inputLocked, outLocked bool
	modelLock              bool
	params                 []pcode.HostParam
	output                 *pcode.HostParam
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
			if k := &n.Kids[i]; k.XMLName.Local == "type" || k.XMLName.Local == "def" {
				// Types are found by id: one short name can stand for several
				// template instances (ForElementType<unsigned_int>). A forward
				// declaration never replaces a full definition.
				// C++ parity: TypeFactory::findById.
				for _, key := range []string{"id:" + k.attr("id"), k.attr("name")} {
					if old := types[key]; old != nil && old.attr("incomplete") != "true" && k.attr("incomplete") == "true" {
						continue
					}
					types[key] = k
				}
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
			case "function":
				if cd.protos == nil {
					cd.protos = map[uint64]captureProto{}
				}
				cd.protos[hd.Addr.Offset] = parseCaptureProto(sym, types)
				continue
			default:
				continue // externrefs come from the symbol table
			}
			cd.syms = append(cd.syms, hd)
		}
	}
	sort.Slice(cd.syms, func(i, j int) bool { return cd.syms[i].Addr.Offset < cd.syms[j].Addr.Offset })
	return cd, nil
}

// parseCaptureProto reads a <function> element's prototype: its locked
// parameters (localdb symbols of category 0, by index) and locked return.
// C++ parity: FuncProto::decode + ProtoStoreSymbol (isInputLocked is a void
// lock or a type-locked first parameter).
func parseCaptureProto(fn *xnode, types map[string]*xnode) captureProto {
	cp := captureProto{name: fn.attr("name"), noReturn: fn.attr("noreturn") == "true", extraPop: pcode.ExtrapopUnknown}
	slot := func(sym, at *xnode) pcode.HostParam {
		p := pcode.HostParam{Space: at.attr("space"), Offset: parseUint(at.attr("offset")),
			Size: int32(parseUint(at.attr("size"))), Name: sym.attr("name"), ThisPtr: sym.attr("thisptr") == "true"}
		for i := range sym.Kids {
			if t := typeDesc(&sym.Kids[i], types, 0); t != nil {
				p.Type = pcode.ResolveHostType(t)
				break
			}
		}
		return p
	}
	type indexed struct {
		idx    uint64
		locked bool
		p      pcode.HostParam
	}
	var ins []indexed
	if ldb := fn.child("localdb"); ldb != nil {
		if sc := ldb.child("scope"); sc != nil {
			if list := sc.child("symbollist"); list != nil {
				for i := range list.Kids {
					ms := &list.Kids[i]
					if ms.XMLName.Local != "mapsym" || len(ms.Kids) < 2 {
						continue
					}
					sym, at := &ms.Kids[0], ms.child("addr")
					if at == nil || sym.attr("cat") != "0" {
						continue
					}
					ins = append(ins, indexed{parseUint(sym.attr("index")), sym.attr("typelock") == "true", slot(sym, at)})
				}
			}
		}
	}
	sort.Slice(ins, func(i, j int) bool { return ins[i].idx < ins[j].idx })
	proto := fn.child("prototype")
	if proto == nil {
		return cp
	}
	cp.model = proto.attr("model")
	cp.modelLock = proto.attr("modellock") == "true"
	if ep := proto.attr("extrapop"); ep != "" && ep != "unknown" {
		cp.extraPop = int32(parseUint(ep))
	}
	cp.inputLocked = proto.attr("voidlock") == "true" || (len(ins) > 0 && ins[0].locked)
	if cp.inputLocked {
		for _, in := range ins {
			cp.params = append(cp.params, in.p)
		}
	}
	if ret := proto.child("returnsym"); ret != nil && ret.attr("typelock") == "true" {
		cp.outLocked = true
		out := pcode.HostParam{}
		if at := ret.child("addr"); at != nil {
			out.Space, out.Offset, out.Size = at.attr("space"), parseUint(at.attr("offset")), int32(parseUint(at.attr("size")))
		}
		for i := range ret.Kids {
			if t := typeDesc(&ret.Kids[i], types, 0); t != nil {
				out.Type = pcode.ResolveHostType(t)
				break
			}
		}
		cp.output = &out
	}
	return cp
}

// QueryFunction adds the captured locked prototype to the symbol table's
// answer for a callee the core asked about.
func (h hostWithData) QueryFunction(addr address.Address) (pcode.HostFunction, bool) {
	hf, ok := h.HostScope.QueryFunction(addr)
	if h.captureData == nil {
		return hf, ok
	}
	if cp, found := h.captureData.protos[addr.Offset]; found {
		if !ok {
			// A function the symbol table lacks (an external one behind an
			// import slot): the capture holds all the core received.
			hf = pcode.HostFunction{Name: cp.name, Model: cp.model, ExtraPop: cp.extraPop}
			ok = true
		}
		hf.NoReturn = hf.NoReturn || cp.noReturn
		hf.InputLocked, hf.OutputLocked = cp.inputLocked, cp.outLocked
		if cp.modelLock {
			hf.Model, hf.ModelLock = cp.model, true
		}
		hf.Params, hf.Output = cp.params, cp.output
	}
	return hf, ok
}

// typeDesc converts a <type>/<typeref> element into a host type description,
// resolving references through the savefile's core types and type group.
// structDescs memoizes structure descriptions by their capture element.
var structDescs sync.Map

func typeDesc(n *xnode, types map[string]*xnode, depth int) *pcode.HostTypeDesc {
	if n == nil || depth > 16 {
		return nil
	}
	switch n.XMLName.Local {
	case "typeref":
		if id := n.attr("id"); id != "" {
			if t := types["id:"+id]; t != nil {
				return typeDesc(t, types, depth+1)
			}
		}
		if t := types[n.attr("name")]; t != nil {
			return typeDesc(t, types, depth+1)
		}
		// Java's DefaultDataType: a 1-byte unknown named plainly "undefined"
		// (distinct from the core undefined1); it is never listed in the save.
		if n.attr("name") == "undefined" {
			return &pcode.HostTypeDesc{Name: "undefined", Meta: "unknown", Size: 1}
		}
		return nil
	case "void":
		return &pcode.HostTypeDesc{Meta: "void"}
	case "def": // typedef: the base type under the typedef's name
		if len(n.Kids) == 0 {
			return nil
		}
		base := typeDesc(&n.Kids[0], types, depth+1)
		if base == nil {
			return nil
		}
		td := *base
		td.Typedef = n.attr("name")
		return &td
	case "type":
	default:
		return nil
	}
	d := &pcode.HostTypeDesc{
		Name:  n.attr("name"),
		Meta:  n.attr("metatype"),
		Size:  int32(parseUint(n.attr("size"))),
		Count: int32(parseUint(n.attr("arraysize"))),
		Char:  n.attr("char") == "true",
		Utf:   n.attr("utf") == "true",
	}
	if d.Meta == "enum_uint" || d.Meta == "enum_int" {
		d.EnumValues = map[uint64]string{}
		mask := ^uint64(0)
		if d.Size > 0 && d.Size < 8 {
			mask = uint64(1)<<(8*uint(d.Size)) - 1
		}
		for i := range n.Kids {
			v := &n.Kids[i]
			if v.XMLName.Local != "val" {
				continue
			}
			val, err := strconv.ParseInt(v.attr("value"), 0, 64)
			if err != nil {
				u, uerr := strconv.ParseUint(v.attr("value"), 0, 64)
				if uerr != nil {
					continue
				}
				val = int64(u)
			}
			key := uint64(val) & mask // The value might be negative
			if _, dup := d.EnumValues[key]; !dup {
				d.EnumValues[key] = v.attr("name")
			}
		}
	}
	if len(n.Kids) > 0 && (d.Meta == "ptr" || d.Meta == "array") {
		d.Elem = typeDesc(&n.Kids[0], types, depth+1)
	}
	if d.Meta == "struct" {
		// One description per host structure, shared before its fields are
		// read so a field pointing back to it closes the cycle.
		if id := n.attr("id"); id != "" && id != "0x0" {
			if old, ok := structDescs.Load(n); ok {
				return old.(*pcode.HostTypeDesc)
			}
			d.ID = id
			structDescs.Store(n, d)
		}
		for i := range n.Kids {
			f := &n.Kids[i]
			if f.XMLName.Local != "field" || len(f.Kids) == 0 {
				continue
			}
			d.Fields = append(d.Fields, pcode.HostFieldDesc{Name: f.attr("name"),
				Offset: int32(parseUint(f.attr("offset"))), Type: typeDesc(&f.Kids[0], types, depth+1)})
		}
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
	if raw, err := os.ReadFile(fmt.Sprintf("%s/%08x.typeorder", captureDir, fn.Entry)); err == nil {
		for _, ln := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
			if ln = strings.TrimSpace(ln); ln != "" {
				cd.typeWarnings = append(cd.typeWarnings, "Enum \""+ln+"\": Some values do not have unique names")
			}
		}
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

// captureInjections returns fn's call-fixup payloads from the capture's
// <injectdebug> (the payload the Java host compiled at each call site).
func captureInjections(fn goldenEntry, host pcode.HostScope, ram *address.Space) map[uint64]bridge.HostInjection {
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
	dbg := state.child("injectdebug")
	if dbg == nil {
		return nil
	}
	out := map[uint64]bridge.HostInjection{}
	for i := range dbg.Kids {
		in := &dbg.Kids[i]
		if in.XMLName.Local != "inject" || in.attr("type") != "1" { // 1 = call fixup
			continue
		}
		at, pl := in.child("addr"), in.child("payload")
		if at == nil || pl == nil {
			continue
		}
		var payload xnode
		if xml.Unmarshal([]byte("<p>"+pl.text+"</p>"), &payload) != nil {
			continue
		}
		inj := bridge.HostInjection{Name: in.attr("name")}
		for j := range payload.Kids {
			inst := &payload.Kids[j]
			for k := range inst.Kids {
				op := &inst.Kids[k]
				if op.XMLName.Local != "op" || len(op.Kids) == 0 {
					continue
				}
				hop := bridge.HostInjectOp{Code: pcode.OpCode(parseUint(op.attr("code")))}
				vn := func(n *xnode) bridge.HostVarnode {
					return bridge.HostVarnode{Space: n.attr("space"), Offset: parseUint(n.attr("offset")), Size: int32(parseUint(n.attr("size")))}
				}
				if first := &op.Kids[0]; first.XMLName.Local == "addr" {
					v := vn(first)
					hop.Out = &v
				}
				for _, n := range op.Kids[1:] {
					if n.XMLName.Local == "addr" {
						hop.In = append(hop.In, vn(&n))
					}
				}
				inj.Ops = append(inj.Ops, hop)
			}
		}
		addr := parseUint(at.attr("offset"))
		inj.Callee = calleeAt(raw, addr, host, ram)
		out[addr] = inj
	}
	return out
}

// calleeAt names the function a call fixup replaced: the call target of the
// instruction at addr is not decoded here, so the capture's own function list
// is used -- the injected callee is the one carrying an <inject> prototype.
func calleeAt(raw []byte, _ uint64, host pcode.HostScope, ram *address.Space) string {
	var root xnode
	if xml.Unmarshal(raw, &root) != nil {
		return ""
	}
	db := root.child("save_state").child("db")
	if db == nil {
		return ""
	}
	for i := range db.Kids {
		sc := &db.Kids[i]
		list := sc.child("symbollist")
		if sc.XMLName.Local != "scope" || list == nil {
			continue
		}
		for j := range list.Kids {
			ms := &list.Kids[j]
			if len(ms.Kids) == 0 || ms.Kids[0].XMLName.Local != "function" {
				continue
			}
			fnode := &ms.Kids[0]
			if p := fnode.child("prototype"); p == nil || p.child("inject") == nil {
				continue
			}
			if at := ms.child("addr"); at != nil && host != nil && ram != nil {
				if hf, ok := host.QueryFunction(address.Address{Space: ram, Offset: parseUint(at.attr("offset"))}); ok {
					return hf.Name
				}
			}
			return fnode.attr("name")
		}
	}
	return ""
}

// QueryData returns the symbol whose storage contains addr (a label matches
// its address only).
func (cd *captureData) QueryData(addr address.Address) (pcode.HostData, bool) {
	if cd == nil || len(cd.syms) == 0 || addr.Space != cd.syms[0].Addr.Space {
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

// DatatypeWarnings implements pcode.HostTypeWarnings.
func (cd *captureData) DatatypeWarnings() []string { return cd.typeWarnings }
