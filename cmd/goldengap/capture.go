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
	// namesUsed maps a symbol name to the depths of the function's namespace
	// path that use it (-1: more symbols carry it than the host checks),
	// from <entry>.names (GenNames).
	namesUsed map[string][]int
	// nsIDs maps a symbol address to its scope-id path (outermost first).
	nsIDs map[uint64][]uint64
	// nsNames maps a symbol address to its scope-name path (outermost first).
	nsNames map[uint64][]string
	syms      []pcode.HostData
	// readonly are the ram ranges with the read-only property: the load
	// image's read-only chunks and the read-only symbols' storage.
	// C++ parity: Database::setPropertyRange (Architecture::fillinReadOnly
	// FromLoader, ScopeGhidra::dump2Cache).
	readonly [][2]uint64
	// protos are the callee prototypes the core received, by entry offset.
	protos map[uint64]captureProto
}

// captureProto is the locked part of a host function prototype.
type captureProto struct {
	name, model            string
	namespace              string // scope path of the function symbol
	extraPop               int32
	noReturn               bool
	inputLocked, outLocked bool
	modelLock              bool
	dotdotdot              bool
	inline                 bool
	params                 []pcode.HostParam
	unlockedParams         []pcode.HostParam
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
	var nsList func(id string) []string
	nsList = func(id string) []string {
		s := scopes[id]
		if s == nil || s.attr("name") == "" {
			return nil
		}
		var parent []string
		if p := s.child("parent"); p != nil {
			parent = nsList(p.attr("id"))
		}
		return append(append([]string(nil), parent...), s.attr("name"))
	}
	var idList func(id string) []uint64
	idList = func(id string) []uint64 {
		s := scopes[id]
		if s == nil || s.attr("name") == "" {
			return nil
		}
		var parent []uint64
		if p := s.child("parent"); p != nil {
			parent = idList(p.attr("id"))
		}
		return append(append([]uint64(nil), parent...), parseUint(id))
	}
	cd := &captureData{nsIDs: map[uint64][]uint64{}, nsNames: map[uint64][]string{}}
	for id, s := range scopes {
		ns := nsPath(id)
		nsl := nsList(id)
		ids := idList(id)
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
			// An external reference shares its function's address from the
			// global scope; it must not hide the function's own scope path.
			if sym.XMLName.Local != "externrefsymbol" {
				cd.nsIDs[parseUint(at.attr("offset"))] = ids
				cd.nsNames[parseUint(at.attr("offset"))] = nsl
			}
			hd := pcode.HostData{
				Name:          sym.attr("name"),
				Namespace:     ns,
				NamespacePath: nsl,
				Addr:          address.Address{Space: ram, Offset: parseUint(at.attr("offset"))},
				Size:          int32(parseUint(at.attr("size"))),
				ReadOnly:      sym.attr("readonly") == "true",
				Isolate:       sym.attr("merge") == "false",
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
				cp := parseCaptureProto(sym, types)
				cp.namespace = ns
				cd.protos[hd.Addr.Offset] = cp
				continue
			default:
				continue // externrefs come from the symbol table
			}
			cd.syms = append(cd.syms, hd)
		}
	}
	sort.Slice(cd.syms, func(i, j int) bool { return cd.syms[i].Addr.Offset < cd.syms[j].Addr.Offset })
	for _, hd := range cd.syms {
		if hd.ReadOnly && hd.Size > 0 {
			cd.readonly = append(cd.readonly, [2]uint64{hd.Addr.Offset, hd.Addr.Offset + uint64(hd.Size) - 1})
		}
	}
	if img := root.child("binaryimage"); img != nil {
		for i := range img.Kids {
			k := &img.Kids[i]
			if k.XMLName.Local != "bytechunk" || k.attr("readonly") != "true" || k.attr("space") != ram.Name {
				continue
			}
			n := uint64(len(strings.Join(strings.Fields(k.text), "")) / 2)
			if n > 0 {
				first := parseUint(k.attr("offset"))
				cd.readonly = append(cd.readonly, [2]uint64{first, first + n - 1})
			}
		}
	}
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
			Size: int32(parseUint(at.attr("size"))), Name: sym.attr("name"), ThisPtr: sym.attr("thisptr") == "true",
			NameLock: sym.attr("namelock") == "true", Isolate: sym.attr("merge") == "false"}
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
	cp.dotdotdot = proto.attr("dotdotdot") == "true"
	// An inline attribute or a call-fixup <inject> marks the prototype
	// inline. C++ parity: FuncProto::decode (ATTRIB_INLINE, ELEM_INJECT).
	cp.inline = proto.attr("inline") == "true" || proto.child("inject") != nil
	if ep := proto.attr("extrapop"); ep != "" && ep != "unknown" {
		cp.extraPop = int32(parseUint(ep))
	}
	cp.inputLocked = proto.attr("voidlock") == "true" || (len(ins) > 0 && ins[0].locked)
	for _, in := range ins {
		if cp.inputLocked {
			cp.params = append(cp.params, in.p)
		} else {
			cp.unlockedParams = append(cp.unlockedParams, in.p)
		}
	}
	if ret := proto.child("returnsym"); ret != nil && ret.attr("typelock") == "true" {
		cp.outLocked = true
		out := pcode.HostParam{}
		if at := ret.child("addr"); at != nil {
			out.Space, out.Offset, out.Size = at.attr("space"), parseUint(at.attr("offset")), int32(parseUint(at.attr("size")))
			// A single-piece join is that piece, truncated to the logical
			// size (an 8-byte value in the 10-byte ST0).
			// C++ parity: AddrSpaceManager::findAddJoin (one piece).
			if out.Space == "join" && at.attr("piece2") != "" {
				// A multi-piece join: the pieces, most significant first.
				// C++ parity: JoinSpace::decodeAttributes.
				for k := 1; ; k++ {
					parts := strings.Split(at.attr(fmt.Sprintf("piece%d", k)), ":")
					if len(parts) != 3 {
						break
					}
					out.JoinPieces = append(out.JoinPieces, pcode.HostStorage{Space: parts[0], Offset: parseUint(parts[1]), Size: int32(parseUint(parts[2]))})
					out.Size += int32(parseUint(parts[2]))
				}
			}
			if out.Space == "join" && at.attr("piece2") == "" {
				if parts := strings.Split(at.attr("piece1"), ":"); len(parts) == 3 {
					out.Space, out.Offset, out.Size = parts[0], parseUint(parts[1]), int32(parseUint(parts[2]))
					if ls := int32(parseUint(at.attr("logicalsize"))); ls > 0 && ls < out.Size {
						out.Size = ls
					}
				}
			}
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
		// The callee is the function symbol the core finds at the address,
		// named within its own scope (a thunk's target class).
		// C++ parity: FuncCallSpecs takes the FunctionSymbol's name and scope.
		if cp.name != "" {
			hf.Name, hf.Namespace = cp.name, cp.namespace
			if cp.namespace != "" {
				hf.Name = cp.namespace + "::" + cp.name
			}
		}
		hf.NoReturn = hf.NoReturn || cp.noReturn
		hf.InputLocked, hf.OutputLocked = cp.inputLocked, cp.outLocked
		hf.Dotdotdot = hf.Dotdotdot || cp.dotdotdot
		hf.Inline = hf.Inline || cp.inline
		if cp.modelLock {
			hf.Model, hf.ModelLock = cp.model, true
		}
		hf.Params, hf.Output = cp.params, cp.output
		hf.UnlockedParams = cp.unlockedParams
	}
	return hf, ok
}

// typeDesc converts a <type>/<typeref> element into a host type description,
// resolving references through the savefile's core types and type group.
// structDescs memoizes structure descriptions by their capture element.
var structDescs sync.Map

func typeDesc(n *xnode, types map[string]*xnode, depth int) *pcode.HostTypeDesc {
	// Structures close cycles through structDescs, so the depth bound only
	// guards against malformed input. A low bound cut deep acyclic chains
	// (a pointer field reached 16 levels down became undefined1 *), and the
	// host-id struct stub then kept that wrong field for every later function.
	if n == nil || depth > 4096 {
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
	if d.Meta == "ptr" {
		d.WordSize = uint32(parseUint(n.attr("wordsize")))
		d.Space = n.attr("space")
	}
	if len(n.Kids) > 0 && (d.Meta == "ptr" || d.Meta == "array") {
		d.Elem = typeDesc(&n.Kids[0], types, depth+1)
	}
	if d.Meta == "code" {
		if proto := n.child("prototype"); proto != nil {
			d.Proto = codeTypeProto(proto, types, depth+1)
		}
	}
	if d.Meta == "struct" || d.Meta == "union" {
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

// codeTypeProto reads the <prototype> of a function data-type: typed
// parameters without storage and the return type.
// C++ parity: TypeCode::decodeStub/decodePrototype -> FuncProto::decode.
func codeTypeProto(proto *xnode, types map[string]*xnode, depth int) *pcode.HostCodeProto {
	cp := &pcode.HostCodeProto{Model: proto.attr("model"), ModelLock: proto.attr("modellock") == "true",
		ExtraPop: pcode.ExtrapopUnknown, NoReturn: proto.attr("noreturn") == "true",
		Dotdotdot: proto.attr("dotdotdot") == "true"}
	if ep := proto.attr("extrapop"); ep != "" && ep != "unknown" {
		cp.ExtraPop = int32(parseUint(ep))
	}
	firstType := func(n *xnode) *pcode.HostTypeDesc {
		for i := range n.Kids {
			if n.Kids[i].XMLName.Local == "addr" {
				continue
			}
			if t := typeDesc(&n.Kids[i], types, depth+1); t != nil {
				return t
			}
		}
		return nil
	}
	if ret := proto.child("returnsym"); ret != nil && ret.attr("typelock") == "true" {
		cp.OutLocked = true
		if t := firstType(ret); t != nil && t.Meta != "void" {
			cp.Ret = t
		}
	}
	cp.InputLocked = proto.attr("voidlock") == "true"
	if list := proto.child("internallist"); list != nil {
		for i := range list.Kids {
			pn := &list.Kids[i]
			if pn.XMLName.Local != "param" {
				continue
			}
			t := firstType(pn)
			if t == nil {
				return nil
			}
			if i == 0 && pn.attr("typelock") == "true" {
				cp.InputLocked = true
			}
			cp.Params = append(cp.Params, t)
		}
	}
	return cp
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
	if raw, err := os.ReadFile(fmt.Sprintf("%s/%08x.names", captureDir, fn.Entry)); err == nil {
		cd.namesUsed = map[string][]int{}
		for _, ln := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
			nm, d, ok := strings.Cut(ln, "\t")
			if !ok {
				continue
			}
			depth := -1
			if d != "*" {
				if depth, err = strconv.Atoi(d); err != nil {
					continue
				}
			}
			cd.namesUsed[nm] = append(cd.namesUsed[nm], depth)
		}
	}
	return hostWithData{host, cd}
}

// captureComments returns fn's comment database from its capture, or nil.
// captureFlowOverrides reads the savefile's <flowoverridelist>: the flow
// overrides the C++ core receives for the function, which may be more than
// the golden records. C++ parity: Override::decode (ELEM_FLOW).
func captureFlowOverrides(fn goldenEntry) map[uint64]string {
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
	var list *xnode
	var find func(n *xnode)
	find = func(n *xnode) {
		for i := range n.Kids {
			if list != nil {
				return
			}
			if n.Kids[i].XMLName.Local == "flowoverridelist" {
				list = &n.Kids[i]
				return
			}
			find(&n.Kids[i])
		}
	}
	find(&root)
	if list == nil {
		return nil
	}
	names := map[string]string{"branch": "BRANCH", "call": "CALL", "callreturn": "CALL_RETURN", "return": "RETURN"}
	m := map[uint64]string{}
	for i := range list.Kids {
		f := &list.Kids[i]
		var addrs []*xnode
		for j := range f.Kids {
			if f.Kids[j].XMLName.Local == "addr" {
				addrs = append(addrs, &f.Kids[j])
			}
		}
		if f.XMLName.Local != "flow" || len(addrs) < 2 || names[f.attr("type")] == "" {
			continue
		}
		m[parseUint(addrs[1].attr("offset"))] = names[f.attr("type")]
	}
	return m
}

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
					switch n.XMLName.Local {
					case "addr":
						hop.In = append(hop.In, vn(&n))
					case "spaceid": // LOAD/STORE space operand
						hop.In = append(hop.In, bridge.HostVarnode{SpaceRef: n.attr("name")})
					}
				}
				inj.Ops = append(inj.Ops, hop)
			}
		}
		addr := parseUint(at.attr("offset"))
		inj.Callee = calleeAt(raw, inj.Name, host, ram)
		out[addr] = inj
	}
	return out
}

// calleeAt names the function a call fixup replaced: the call target of the
// instruction at addr is not decoded here, so the capture's own function list
// is used -- the injected callee is the one carrying an <inject> prototype.
func calleeAt(raw []byte, injName string, host pcode.HostScope, ram *address.Space) string {
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
			// The function whose prototype names this injection.
			p := fnode.child("prototype")
			if p == nil || p.child("inject") == nil || strings.TrimSpace(p.child("inject").text) != injName {
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

// Property implements pcode.HostProperties.
func (cd *captureData) Property(addr address.Address) uint32 {
	for _, r := range cd.readonly {
		if addr.Offset >= r[0] && addr.Offset <= r[1] {
			return pcode.VarnodeReadOnly
		}
	}
	return 0
}

// IsNameUsed implements pcode.HostNameUsed.
// Java parity: DecompileCallback.isNameUsed.
// NamespaceIDsAt implements pcode.HostNamespaceIDs.
func (cd *captureData) NamespaceIDsAt(addr address.Address) []uint64 {
	return cd.nsIDs[addr.Offset]
}

// NamespacePathAt implements pcode.HostNamespacePath.
func (cd *captureData) NamespacePathAt(addr address.Address) []string {
	return cd.nsNames[addr.Offset]
}

func (cd *captureData) IsNameUsed(name string, depth int) bool {
	for _, d := range cd.namesUsed[name] {
		if d < 0 || d >= depth {
			return true
		}
	}
	return false
}

// DatatypeWarnings implements pcode.HostTypeWarnings.
func (cd *captureData) DatatypeWarnings() []string { return cd.typeWarnings }
