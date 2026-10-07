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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gosleigh/pkg/address"
)

// This file ports modelrules.cc: the <rule> elements of a cspec parameter
// list (data-type filters, qualifiers and assignment actions) and the
// PrimitiveExtractor they use.

// assignResponse is the outcome of assigning storage to one parameter.
// C++ parity: AssignAction response codes (modelrules.hh).
type assignResponse int

const (
	assignSuccess assignResponse = iota
	assignFail
	assignNoAssignment
	assignHiddenretPtrparam
	assignHiddenretSpecialreg
	assignHiddenretSpecialregVoid
)

// ParameterPieces flags. C++ parity: ParameterPieces::indirectstorage,
// ParameterPieces::hiddenretparm.
const (
	pieceIndirectStorage uint32 = 1 << iota
	pieceHiddenRetParm
)

// parameterPieces is the storage and data-type given to one parameter or the
// return value. C++ parity: ParameterPieces.
type parameterPieces struct {
	addr  address.Address
	typ   Datatype
	flags uint32
}

// prototypePieces is the high-level description of a prototype the rules are
// evaluated against. C++ parity: PrototypePieces (outtype, intypes,
// firstVarArgSlot).
type prototypePieces struct {
	outtype         Datatype
	intypes         []Datatype
	firstVarArgSlot int // -1 when there are no varargs
}

// assignAddressFromPieces gives res the storage made of the pieces: one piece
// is its own address, several become a join. mostToLeast tells whether the
// pieces are ordered most significant first.
// C++ parity: ParameterPieces::assignAddressFromPieces.
func (pl *ParamListStandard) assignAddressFromPieces(pieces []address.VarnodeData, mostToLeast bool, res *parameterPieces) bool {
	if !mostToLeast && len(pieces) > 1 {
		rev := make([]address.VarnodeData, len(pieces))
		for i := range pieces {
			rev[len(pieces)-1-i] = pieces[i]
		}
		pieces = rev
	}
	pieces = pl.mergeSequence(pieces)
	if len(pieces) == 1 {
		res.addr = pieces[0].Addr()
		return true
	}
	if pl.joinSpace == nil {
		return false
	}
	rec := address.FindAddJoin(pl.joinSpace, pieces, 0)
	res.addr = rec.Unified.Addr()
	return true
}

// mergeSequence merges contiguous pieces (most significant first), unless a
// merge produces storage that is not a named register.
// C++ parity: JoinRecord::mergeSequence.
func (pl *ParamListStandard) mergeSequence(seq []address.VarnodeData) []address.VarnodeData {
	i := 1
	for ; i < len(seq); i++ {
		if varnodeContiguous(seq[i-1], seq[i]) {
			break
		}
	}
	if i >= len(seq) {
		return seq
	}
	res := []address.VarnodeData{seq[0]}
	lastIsInformal := false
	for i = 1; i < len(seq); i++ {
		hi := &res[len(res)-1]
		lo := seq[i]
		if varnodeContiguous(*hi, lo) {
			if !hi.Space.BigEndian {
				hi.Offset = lo.Offset
			}
			hi.Size += lo.Size
			if hi.Space.Kind != address.SpaceKindStack {
				lastIsInformal = pl.regName == nil || pl.regName(hi.Space, hi.Offset, hi.Size) == ""
			}
		} else {
			if lastIsInformal {
				break
			}
			res = append(res, lo)
		}
	}
	if lastIsInformal { // The merge contains an informal register
		return seq
	}
	return res
}

// varnodeContiguous reports whether lo immediately follows hi in significance.
// C++ parity: VarnodeData::isContiguous.
func varnodeContiguous(hi, lo address.VarnodeData) bool {
	if hi.Space != lo.Space {
		return false
	}
	if hi.Space.BigEndian {
		return hi.Offset+uint64(hi.Size) == lo.Offset
	}
	return lo.Offset+uint64(lo.Size) == hi.Offset
}

// justifyPieces removes offset padding bytes from one end of a tiling.
// C++ parity: AssignAction::justifyPieces.
func justifyPieces(pieces []address.VarnodeData, offset int32, isBigEndian, consumeMostSig, justifyRight bool) {
	addOffset := isBigEndian != consumeMostSig != justifyRight
	pos := len(pieces) - 1
	if justifyRight {
		pos = 0
	}
	if addOffset {
		pieces[pos].Offset += uint64(offset)
	}
	pieces[pos].Size -= offset
}

// --- PrimitiveExtractor ---

// primitive is one primitive data-type at an offset within a composite.
type primitive struct {
	dt     Datatype
	offset int32
}

const (
	primInvalid        uint32 = 1
	primUnionInvalid   uint32 = 2
	primUnknownElement uint32 = 4
	primExtraSpace     uint32 = 8
	primUnaligned      uint32 = 0x10
)

// primitiveExtractor lists the primitive data-types making up a data-type.
// C++ parity: PrimitiveExtractor.
type primitiveExtractor struct {
	primitives []primitive
	flags      uint32
}

func newPrimitiveExtractor(dt Datatype, unionIllegal bool, offset int32, max int) *primitiveExtractor {
	p := &primitiveExtractor{}
	if unionIllegal {
		p.flags = primUnionInvalid
	}
	if !p.extract(dt, max, offset) {
		p.flags |= primInvalid
	}
	return p
}

func (p *primitiveExtractor) isValid() bool         { return p.flags&primInvalid == 0 }
func (p *primitiveExtractor) containsUnknown() bool { return p.flags&primUnknownElement != 0 }
func (p *primitiveExtractor) isAligned() bool       { return p.flags&primUnaligned == 0 }
func (p *primitiveExtractor) containsHoles() bool   { return p.flags&primExtraSpace != 0 }

// checkOverlap folds the primitives of small overlapped by big into res.
// C++ parity: PrimitiveExtractor::checkOverlap.
func checkOverlap(res *[]primitive, small []primitive, point int, big primitive) int {
	endOff := big.offset + big.dt.AlignSize()
	// A big float lets the smaller primitives override it
	useSmall := big.dt.Metatype() == TYPE_FLOAT
	for point < len(small) {
		curOff := small[point].offset
		if curOff >= endOff {
			break
		}
		curOff += small[point].dt.AlignSize()
		if curOff > endOff {
			return -1 // Improper overlap of the end of big
		}
		if useSmall {
			*res = append(*res, small[point])
		}
		point++
	}
	if !useSmall {
		*res = append(*res, big)
	}
	return point
}

// commonRefinement replaces first with the common refinement of the lists.
// C++ parity: PrimitiveExtractor::commonRefinement.
func commonRefinement(first *[]primitive, second []primitive) bool {
	f := *first
	firstPoint, secondPoint := 0, 0
	var common []primitive
	for firstPoint < len(f) && secondPoint < len(second) {
		fe, se := f[firstPoint], second[secondPoint]
		if fe.offset < se.offset && fe.offset+fe.dt.AlignSize() <= se.offset {
			common = append(common, fe)
			firstPoint++
			continue
		}
		if se.offset < fe.offset && se.offset+se.dt.AlignSize() <= fe.offset {
			common = append(common, se)
			secondPoint++
			continue
		}
		if fe.dt.AlignSize() >= se.dt.AlignSize() {
			secondPoint = checkOverlap(&common, second, secondPoint, fe)
			if secondPoint < 0 {
				return false
			}
			firstPoint++
		} else {
			firstPoint = checkOverlap(&common, f, firstPoint, se)
			if firstPoint < 0 {
				return false
			}
			secondPoint++
		}
	}
	common = append(common, f[firstPoint:]...)
	common = append(common, second[secondPoint:]...)
	*first = common
	return true
}

// handleUnion appends the common refinement of a union's fields.
// C++ parity: PrimitiveExtractor::handleUnion.
func (p *primitiveExtractor) handleUnion(u *Union, max int, offset int32) bool {
	if p.flags&primUnionInvalid != 0 {
		return false
	}
	fields := u.Fields()
	if len(fields) == 0 {
		return false
	}
	common := newPrimitiveExtractor(fields[0].Type, false, offset+fields[0].Offset, max)
	if !common.isValid() {
		return false
	}
	for _, f := range fields[1:] {
		next := newPrimitiveExtractor(f.Type, false, offset+f.Offset, max)
		if !next.isValid() {
			return false
		}
		if !commonRefinement(&common.primitives, next.primitives) {
			return false
		}
	}
	if len(p.primitives)+len(common.primitives) > max {
		return false
	}
	p.primitives = append(p.primitives, common.primitives...)
	return true
}

// extract adds the primitives of dt at offset, false when there are too many
// or an illegal data-type is met. C++ parity: PrimitiveExtractor::extract.
func (p *primitiveExtractor) extract(dt Datatype, max int, offset int32) bool {
	switch dt.Metatype() {
	case TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_CODE, TYPE_FLOAT, TYPE_PTR, TYPE_PTRREL:
		if dt.Metatype() == TYPE_UNKNOWN {
			p.flags |= primUnknownElement
		}
		if len(p.primitives) >= max {
			return false
		}
		p.primitives = append(p.primitives, primitive{dt, offset})
		return true
	case TYPE_ARRAY:
		a, ok := dt.(*Array)
		if !ok {
			return false
		}
		base := a.Element()
		for i := int32(0); i < a.Count(); i++ {
			if !p.extract(base, max, offset) {
				return false
			}
			offset += base.AlignSize()
		}
		return true
	case TYPE_UNION:
		u, ok := dt.(*Union)
		if !ok {
			return false
		}
		return p.handleUnion(u, max, offset)
	case TYPE_STRUCT:
	default:
		return false
	}
	st, ok := dt.(*Struct)
	if !ok {
		return false
	}
	expectedOff := offset
	for _, f := range st.Fields() {
		compDt := f.Type
		curOff := f.Offset + offset
		align := compDt.Alignment()
		if align > 0 && curOff%align != 0 {
			p.flags |= primUnaligned
		}
		if align > 0 {
			if rem := expectedOff % align; rem != 0 {
				expectedOff += align - rem
			}
		}
		if expectedOff != curOff {
			p.flags |= primExtraSpace
		}
		if !p.extract(compDt, max, curOff) {
			return false
		}
		expectedOff = curOff + compDt.AlignSize()
	}
	return true
}

// --- Data-type filters ---

// datatypeFilter decides whether a data-type takes a rule.
// C++ parity: DatatypeFilter.
type datatypeFilter interface {
	filter(dt Datatype) bool
}

// sizeRestrictedFilter passes data-types within a size range or set; it is the
// "any" filter. C++ parity: SizeRestrictedFilter.
type sizeRestrictedFilter struct {
	minSize, maxSize int32
	sizes            map[int32]bool
}

func (f *sizeRestrictedFilter) filterOnSize(dt Datatype) bool {
	if f.maxSize == 0 {
		return true // No size filtering
	}
	if len(f.sizes) != 0 {
		return f.sizes[dt.Size()]
	}
	return dt.Size() >= f.minSize && dt.Size() <= f.maxSize
}

func (f *sizeRestrictedFilter) filter(dt Datatype) bool { return f.filterOnSize(dt) }

// decode reads minsize/maxsize/sizes. C++ parity: SizeRestrictedFilter::decode.
func (f *sizeRestrictedFilter) decode(e *CspecElem) error {
	for _, a := range e.Attrs {
		switch a.Name.Local {
		case "minsize", "maxsize":
			if len(f.sizes) != 0 {
				return fmt.Errorf("mixing sizes with minsize and maxsize")
			}
			v, err := strconv.ParseUint(a.Value, 0, 32)
			if err != nil {
				return err
			}
			if a.Name.Local == "minsize" {
				f.minSize = int32(v)
			} else {
				f.maxSize = int32(v)
			}
		case "sizes":
			if f.minSize != 0 || f.maxSize != 0 {
				return fmt.Errorf("mixing sizes with minsize and maxsize")
			}
			if err := f.initFromSizeList(a.Value); err != nil {
				return err
			}
		}
	}
	if f.maxSize == 0 && f.minSize >= 0 {
		f.maxSize = 0x7fffffff // No maxsize means no upper bound
	}
	return nil
}

// initFromSizeList parses a comma or space separated size list.
// C++ parity: SizeRestrictedFilter::initFromSizeList.
func (f *sizeRestrictedFilter) initFromSizeList(str string) error {
	f.sizes = map[int32]bool{}
	var vals []int32
	for _, tok := range strings.FieldsFunc(str, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
		v, err := strconv.Atoi(tok)
		if err != nil || v <= 0 {
			return fmt.Errorf("bad filter size")
		}
		f.sizes[int32(v)] = true
		vals = append(vals, int32(v))
	}
	if len(vals) != 0 {
		sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
		f.minSize, f.maxSize = vals[0], vals[len(vals)-1]
	}
	return nil
}

// metaTypeFilter passes one metatype within the size restriction.
// C++ parity: MetaTypeFilter.
type metaTypeFilter struct {
	sizeRestrictedFilter
	meta metatype
}

func (f *metaTypeFilter) filter(dt Datatype) bool {
	return dt.Metatype() == f.meta && f.filterOnSize(dt)
}

// homogeneousAggregate passes an array or structure made of at most
// maxPrimitives copies of one primitive of the metatype.
// C++ parity: HomogeneousAggregate.
type homogeneousAggregate struct {
	sizeRestrictedFilter
	meta          metatype
	maxPrimitives int
}

func (f *homogeneousAggregate) filter(dt Datatype) bool {
	if m := dt.Metatype(); m != TYPE_ARRAY && m != TYPE_STRUCT {
		return false
	}
	prims := newPrimitiveExtractor(dt, true, 0, f.maxPrimitives)
	if !prims.isValid() || len(prims.primitives) == 0 || prims.containsUnknown() || !prims.isAligned() || prims.containsHoles() {
		return false
	}
	base := prims.primitives[0].dt
	if base.Metatype() != f.meta {
		return false
	}
	for _, pr := range prims.primitives[1:] {
		if pr.dt != base {
			return false
		}
	}
	return true
}

// decodeDatatypeFilter reads a <datatype> element.
// C++ parity: DatatypeFilter::decodeFilter.
func decodeDatatypeFilter(e *CspecElem) (datatypeFilter, error) {
	if e.XMLName.Local != "datatype" {
		return nil, fmt.Errorf("expecting <datatype>")
	}
	nm, _ := e.Attr("name")
	switch nm {
	case "any":
		f := &sizeRestrictedFilter{}
		return f, f.decode(e)
	case "homogeneous-float-aggregate":
		f := &homogeneousAggregate{meta: TYPE_FLOAT, maxPrimitives: 4}
		if err := f.decode(e); err != nil {
			return nil, err
		}
		if v, ok := e.Attr("max_primitives"); ok {
			if n, err := strconv.ParseUint(v, 0, 32); err == nil && n > 0 {
				f.maxPrimitives = int(n)
			}
		}
		return f, nil
	}
	m, ok := metatypeFromString(nm)
	if !ok {
		return nil, fmt.Errorf("unknown metatype %q", nm)
	}
	f := &metaTypeFilter{meta: m}
	return f, f.decode(e)
}

// metatypeFromString is string2metatype. C++ parity: type.cc string2metatype.
func metatypeFromString(s string) (metatype, bool) {
	m, ok := map[string]metatype{
		"code": TYPE_CODE, "void": TYPE_VOID, "union": TYPE_UNION, "struct": TYPE_STRUCT,
		"partunion": TYPE_PARTIALUNION, "partstruct": TYPE_PARTIALSTRUCT, "array": TYPE_ARRAY,
		"ptrrel": TYPE_PTRREL, "ptr": TYPE_PTR, "float": TYPE_FLOAT, "spacebase": TYPE_SPACEBASE,
		"unknown": TYPE_UNKNOWN, "uint": TYPE_UINT, "int": TYPE_INT, "bool": TYPE_BOOL,
		"enum_int": TYPE_ENUM_INT, "enum_uint": TYPE_ENUM_UINT,
	}[s]
	return m, ok
}

// typeclassFromString is string2typeclass. C++ parity: type.cc string2typeclass.
func typeclassFromString(s string) (typeClass, error) {
	switch s {
	case "class1":
		return 100, nil
	case "class2":
		return 101, nil
	case "class3":
		return 102, nil
	case "class4":
		return typeclassClass4, nil
	case "general", "unknown":
		return typeclassGeneral, nil
	case "hiddenret":
		return typeclassHiddenret, nil
	case "float":
		return typeclassFloat, nil
	case "ptr", "pointer":
		return typeclassPtr, nil
	case "vector":
		return 4, nil
	}
	return 0, fmt.Errorf("unknown data-type class: %s", s)
}

// --- Qualifiers ---

// qualifierFilter decides from the prototype and position whether a rule
// applies. C++ parity: QualifierFilter.
type qualifierFilter interface {
	filter(proto *prototypePieces, pos int) bool
}

// andFilter passes when every sub-qualifier passes. C++ parity: AndFilter.
type andFilter []qualifierFilter

func (f andFilter) filter(proto *prototypePieces, pos int) bool {
	for _, q := range f {
		if !q.filter(proto, pos) {
			return false
		}
	}
	return true
}

// varargsFilter passes a position within [first,last] past the first
// variable argument. C++ parity: VarargsFilter.
type varargsFilter struct{ firstPos, lastPos int }

func (f *varargsFilter) filter(proto *prototypePieces, pos int) bool {
	if proto.firstVarArgSlot < 0 {
		return false
	}
	pos -= proto.firstVarArgSlot
	return pos >= f.firstPos && pos <= f.lastPos
}

// positionMatchFilter passes one position. C++ parity: PositionMatchFilter.
type positionMatchFilter struct{ position int }

func (f *positionMatchFilter) filter(_ *prototypePieces, pos int) bool { return pos == f.position }

// datatypeMatchFilter passes when the data-type at a fixed position (the
// return value for -1) passes a data-type filter. C++ parity: DatatypeMatchFilter.
type datatypeMatchFilter struct {
	position   int
	typeFilter datatypeFilter
}

func (f *datatypeMatchFilter) filter(proto *prototypePieces, _ int) bool {
	var dt Datatype
	if f.position < 0 {
		dt = proto.outtype
	} else {
		if f.position >= len(proto.intypes) {
			return false
		}
		dt = proto.intypes[f.position]
	}
	return dt != nil && f.typeFilter.filter(dt)
}

func attrInt(e *CspecElem, name string, def int) int {
	if v, ok := e.Attr(name); ok {
		if n, err := strconv.ParseInt(v, 0, 32); err == nil {
			return int(n)
		}
	}
	return def
}

func attrBool(e *CspecElem, name string) (bool, bool) {
	v, ok := e.Attr(name)
	if !ok {
		return false, false
	}
	return v == "true" || v == "1", true
}

// decodeQualifier reads a qualifier element, nil if e is not one.
// C++ parity: QualifierFilter::decodeFilter.
func decodeQualifier(e *CspecElem) (qualifierFilter, error) {
	switch e.XMLName.Local {
	case "varargs":
		// C++ VarargsFilter defaults: firstPos = minimum, lastPos = maximum.
		return &varargsFilter{firstPos: attrInt(e, "first", -1<<31), lastPos: attrInt(e, "last", 1<<31-1)}, nil
	case "position":
		return &positionMatchFilter{position: attrInt(e, "index", -1)}, nil
	case "datatype_at":
		if len(e.Kids) == 0 {
			return nil, fmt.Errorf("<datatype_at> needs a <datatype>")
		}
		tf, err := decodeDatatypeFilter(&e.Kids[0])
		if err != nil {
			return nil, err
		}
		return &datatypeMatchFilter{position: attrInt(e, "index", -1), typeFilter: tf}, nil
	}
	return nil, nil
}

// --- Assignment actions ---

// assignAction assigns storage to a parameter, or acts as a precondition or
// side-effect consuming resources. C++ parity: AssignAction.
type assignAction interface {
	assignAddress(dt Datatype, proto *prototypePieces, pos int, status []int32, res *parameterPieces) assignResponse
	// fillinOutputMap decides the return storage from the active trials.
	fillinOutputMap(active *ParamActive) bool
	// canAffectFillinOutput: the action takes part in deciding the return
	// storage. C++ parity: AssignAction::fillinOutputActive.
	canAffectFillinOutput() bool
}

// gotoStack assigns the parameter to the stack. C++ parity: GotoStack.
type gotoStack struct {
	resource   *ParamListStandard
	stackEntry *paramEntry
}

func (a *gotoStack) assignAddress(dt Datatype, _ *prototypePieces, _ int, status []int32, res *parameterPieces) assignResponse {
	grp := a.stackEntry.getGroup()
	res.typ = dt
	res.addr = a.stackEntry.getAddrBySlot(&status[grp], dt.Size(), dt.Alignment())
	res.flags = 0
	return assignSuccess
}

func (a *gotoStack) fillinOutputMap(active *ParamActive) bool {
	count := 0
	for i := 0; i < active.NumTrials(); i++ {
		entry := active.Trial(i).GetEntry()
		if entry == nil {
			break
		}
		if entry != a.stackEntry {
			return false
		}
		count++
		if count > 1 {
			return false
		}
	}
	return count == 1
}

func (a *gotoStack) canAffectFillinOutput() bool { return true }

// convertToPointer passes the parameter as a pointer to it.
// C++ parity: ConvertToPointer.
type convertToPointer struct{ resource *ParamListStandard }

func (a *convertToPointer) assignAddress(dt Datatype, proto *prototypePieces, pos int, status []int32, res *parameterPieces) assignResponse {
	pointertp := sharedTypeFactory.GetPointer(a.resource.pointerSize, dt, 1)
	response := a.resource.assignAddress(pointertp, proto, pos, status, res) // (Recursively) assign storage
	res.flags = pieceIndirectStorage
	return response
}

func (a *convertToPointer) fillinOutputMap(*ParamActive) bool { return false }
func (a *convertToPointer) canAffectFillinOutput() bool       { return false }

// multiSlotAssign spreads the parameter over consecutive registers of a
// storage class, then the stack. C++ parity: MultiSlotAssign.
type multiSlotAssign struct {
	resource         *ParamListStandard
	resourceType     typeClass
	consumeFromStack bool
	consumeMostSig   bool
	enforceAlign     bool
	justifyRight     bool
	tiles            []*paramEntry
	stackEntry       *paramEntry
}

func newMultiSlotAssign(res *ParamListStandard) *multiSlotAssign {
	a := &multiSlotAssign{resource: res, resourceType: typeclassGeneral}
	// Consume from stack on input parameters by default
	a.consumeFromStack = !res.isOutput
	if res.isBigEndian() {
		a.consumeMostSig, a.justifyRight = true, true
	}
	return a
}

func (a *multiSlotAssign) initializeEntries() error {
	a.tiles = a.resource.extractTiles(a.resourceType)
	a.stackEntry = a.resource.getStackEntry()
	if len(a.tiles) == 0 {
		return fmt.Errorf("could not find matching resources for action: join")
	}
	if a.consumeFromStack && a.stackEntry == nil {
		return fmt.Errorf("cannot find matching <pentry> for action: join")
	}
	return nil
}

func (a *multiSlotAssign) assignAddress(dt Datatype, _ *prototypePieces, _ int, status []int32, res *parameterPieces) assignResponse {
	tmpStatus := append([]int32(nil), status...)
	var pieces []address.VarnodeData
	sizeLeft := dt.Size()
	align := dt.Alignment()
	iter := 0
	if a.enforceAlign {
		resourcesConsumed := int32(0)
		for iter != len(a.tiles) {
			entry := a.tiles[iter]
			if tmpStatus[entry.getGroup()] == 0 { // Not consumed
				regSize := entry.getSize()
				if align <= regSize || (align > 0 && resourcesConsumed%align == 0) {
					break
				}
				tmpStatus[entry.getGroup()] = -1 // Consume unaligned register
			}
			resourcesConsumed += entry.getSize()
			iter++
		}
	}
	for sizeLeft > 0 && iter != len(a.tiles) {
		entry := a.tiles[iter]
		iter++
		if tmpStatus[entry.getGroup()] != 0 {
			continue // Already consumed
		}
		trialSize := entry.getSize()
		addr := entry.getAddrBySlot(&tmpStatus[entry.getGroup()], trialSize, align)
		tmpStatus[entry.getGroup()] = -1 // Consume the register
		pieces = append(pieces, address.VarnodeData{Space: addr.Space, Offset: addr.Offset, Size: trialSize})
		sizeLeft -= trialSize
		align = 1 // Remaining partial pieces have no alignment requirement
	}
	if sizeLeft > 0 { // Use the stack to get enough bytes
		if !a.consumeFromStack {
			return assignFail
		}
		grp := a.stackEntry.getGroup()
		addr := a.stackEntry.getAddrBySlotJustify(&tmpStatus[grp], sizeLeft, align, a.justifyRight)
		if addr.Space == nil {
			return assignFail
		}
		pieces = append(pieces, address.VarnodeData{Space: addr.Space, Offset: addr.Offset, Size: sizeLeft})
	} else if sizeLeft < 0 { // Odd data-type size
		if a.resourceType == typeclassFloat && len(pieces) == 1 {
			// A float register holding a smaller value is a float extension.
			// C++ parity: AddrSpaceManager::constructFloatExtensionAddress.
			if a.resource.joinSpace == nil {
				return assignFail
			}
			rec := address.FindAddJoin(a.resource.joinSpace, pieces[:1], dt.Size())
			copy(status, tmpStatus)
			res.flags, res.typ, res.addr = 0, dt, rec.Unified.Addr()
			return assignSuccess
		}
		justifyPieces(pieces, -sizeLeft, a.resource.isBigEndian(), a.consumeMostSig, a.justifyRight)
	}
	var piece parameterPieces
	if !a.resource.assignAddressFromPieces(pieces, a.consumeMostSig, &piece) {
		return assignFail
	}
	copy(status, tmpStatus) // Commit resource usage for all the pieces
	res.flags, res.typ, res.addr = 0, dt, piece.addr
	return assignSuccess
}

func (a *multiSlotAssign) fillinOutputMap(active *ParamActive) bool {
	return fillinJoinOutput(active, func(t typeClass, first bool) bool { return t == a.resourceType }, a.justifyRight, a.consumeMostSig)
}

func (a *multiSlotAssign) canAffectFillinOutput() bool { return true }

// fillinJoinOutput is the shared trial check of the join actions: trials come
// from consecutive entries of one accepted storage class starting at its
// first entry, and at most one trial, at the justified end, is partial.
// C++ parity: MultiSlotAssign::fillinOutputMap / MultiSlotDualAssign::fillinOutputMap.
func fillinJoinOutput(active *ParamActive, accept func(t typeClass, first bool) bool, justifyRight, consumeMostSig bool) bool {
	count := 0
	curGroup := int32(-1)
	partial := -1
	var resourceType typeClass
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		entry := trial.GetEntry()
		if entry == nil {
			break
		}
		if count == 0 {
			resourceType = entry.getType()
			if !accept(resourceType, true) {
				return false
			}
			if !entry.isFirstInClass() {
				return false // Trials must start on the first entry of the class
			}
		} else {
			if entry.getType() != resourceType {
				return false // Trials must come from the action's class
			}
			if entry.getGroup() != curGroup+1 {
				return false // Trials must be consecutive
			}
		}
		curGroup = entry.getGroup()
		if trial.GetSize() != entry.getSize() {
			if partial != -1 {
				return false // At most one trial can be partial
			}
			partial = i
		}
		count++
	}
	if partial != -1 {
		if justifyRight {
			if partial != 0 {
				return false
			}
		} else if partial != count-1 {
			return false
		}
		trial := active.Trial(partial)
		if justifyRight == consumeMostSig {
			if trial.GetOffset() != 0 {
				return false // Partial entry must be least significant bytes
			}
		} else if trial.GetOffset()+trial.GetSize() != trial.GetEntry().getSize() {
			return false // Partial entry must be most significant bytes
		}
	}
	if count == 0 {
		return false
	}
	if consumeMostSig {
		active.SetJoinReverse()
	}
	return true
}

// multiMemberAssign gives each primitive of the parameter its own register.
// C++ parity: MultiMemberAssign.
type multiMemberAssign struct {
	resource         *ParamListStandard
	resourceType     typeClass
	consumeFromStack bool
	consumeMostSig   bool
}

func (a *multiMemberAssign) assignAddress(dt Datatype, _ *prototypePieces, _ int, status []int32, res *parameterPieces) assignResponse {
	tmpStatus := append([]int32(nil), status...)
	var pieces []address.VarnodeData
	prims := newPrimitiveExtractor(dt, false, 0, 16)
	if !prims.isValid() || len(prims.primitives) == 0 || prims.containsUnknown() || !prims.isAligned() || prims.containsHoles() {
		return assignFail
	}
	for _, pr := range prims.primitives {
		addr, ok := a.resource.assignAddressFallback(a.resourceType, pr.dt, !a.consumeFromStack, tmpStatus)
		if !ok {
			return assignFail
		}
		pieces = append(pieces, address.VarnodeData{Space: addr.Space, Offset: addr.Offset, Size: pr.dt.Size()})
	}
	var piece parameterPieces
	if !a.resource.assignAddressFromPieces(pieces, a.consumeMostSig, &piece) {
		return assignFail
	}
	copy(status, tmpStatus) // Commit resource usage for all the pieces
	res.flags, res.typ, res.addr = 0, dt, piece.addr
	return assignSuccess
}

func (a *multiMemberAssign) fillinOutputMap(active *ParamActive) bool {
	count := 0
	curGroup := int32(-1)
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		entry := trial.GetEntry()
		if entry == nil {
			break
		}
		if entry.getType() != a.resourceType {
			return false
		}
		if count == 0 {
			if !entry.isFirstInClass() {
				return false
			}
		} else if entry.getGroup() != curGroup+1 {
			return false // Trials must be consecutive
		}
		curGroup = entry.getGroup()
		if trial.GetOffset() != 0 {
			return false // Entry must be justified
		}
		count++
	}
	if count == 0 {
		return false
	}
	if a.consumeMostSig {
		active.SetJoinReverse()
	}
	return true
}

func (a *multiMemberAssign) canAffectFillinOutput() bool { return true }

// multiSlotDualAssign tiles the parameter over registers of two storage
// classes, choosing per tile by the primitives it holds.
// C++ parity: MultiSlotDualAssign.
type multiSlotDualAssign struct {
	resource         *ParamListStandard
	baseType         typeClass
	altType          typeClass
	consumeFromStack bool
	consumeMostSig   bool
	justifyRight     bool
	fillAlternate    bool
	tileSize         int32
	baseTiles        []*paramEntry
	altTiles         []*paramEntry
	stackEntry       *paramEntry
}

func newMultiSlotDualAssign(res *ParamListStandard) *multiSlotDualAssign {
	a := &multiSlotDualAssign{resource: res, baseType: typeclassGeneral, altType: typeclassFloat}
	if res.isBigEndian() {
		a.consumeMostSig, a.justifyRight = true, true
	}
	return a
}

func (a *multiSlotDualAssign) initializeEntries() error {
	a.baseTiles = a.resource.extractTiles(a.baseType)
	a.altTiles = a.resource.extractTiles(a.altType)
	a.stackEntry = a.resource.getStackEntry()
	if len(a.baseTiles) == 0 || len(a.altTiles) == 0 {
		return fmt.Errorf("could not find matching resources for action: join_dual_class")
	}
	a.tileSize = a.baseTiles[0].getSize()
	if a.tileSize != a.altTiles[0].getSize() {
		return fmt.Errorf("storage class register sizes do not match for action: join_dual_class")
	}
	if a.consumeFromStack && a.stackEntry == nil {
		return fmt.Errorf("cannot find matching stack resource for action: join_dual_class")
	}
	return nil
}

// getFirstUnused is the index of the first unconsumed tile from iter.
func getFirstUnused(iter int, tiles []*paramEntry, status []int32) int {
	for ; iter != len(tiles); iter++ {
		if status[tiles[iter].getGroup()] == 0 {
			return iter
		}
	}
	return len(tiles)
}

// getTileClass is 1 when the primitives of the section at off all take the
// alternate class, 0 when any does not, -1 when a primitive crosses the
// section. C++ parity: MultiSlotDualAssign::getTileClass.
func (a *multiSlotDualAssign) getTileClass(prims *primitiveExtractor, off int32, index *int) int {
	res := 1
	count := 0
	endBoundary := off + a.tileSize
	if *index >= len(prims.primitives) {
		return -1
	}
	first := prims.primitives[*index]
	for *index < len(prims.primitives) {
		el := prims.primitives[*index]
		if el.offset < off {
			return -1
		}
		if el.offset >= endBoundary {
			break
		}
		if el.offset+el.dt.Size() > endBoundary {
			return -1
		}
		count++
		*index++
		if metatypeTypeClass(el.dt.Metatype()) != a.altType {
			res = 0
		}
	}
	if count == 0 {
		return -1 // At least one primitive in the section
	}
	if a.fillAlternate { // Only one primitive of exactly the tile size takes altType
		if count > 1 {
			res = 0
		}
		if first.dt.Size() != a.tileSize {
			res = 0
		}
	}
	return res
}

func (a *multiSlotDualAssign) assignAddress(dt Datatype, _ *prototypePieces, _ int, status []int32, res *parameterPieces) assignResponse {
	prims := newPrimitiveExtractor(dt, false, 0, 1024)
	if !prims.isValid() || len(prims.primitives) == 0 || prims.containsHoles() {
		return assignFail
	}
	primitiveIndex := 0
	tmpStatus := append([]int32(nil), status...)
	var pieces []address.VarnodeData
	typeSize := dt.Size()
	align := dt.Alignment()
	sizeLeft := typeSize
	iterBase, iterAlt := 0, 0
	for sizeLeft > 0 {
		var entry *paramEntry
		iterType := a.getTileClass(prims, typeSize-sizeLeft, &primitiveIndex)
		if iterType < 0 {
			return assignFail
		}
		if iterType == 0 {
			iterBase = getFirstUnused(iterBase, a.baseTiles, tmpStatus)
			if iterBase == len(a.baseTiles) {
				if !a.consumeFromStack {
					return assignFail // Out of general purpose registers
				}
				break
			}
			entry = a.baseTiles[iterBase]
		} else {
			iterAlt = getFirstUnused(iterAlt, a.altTiles, tmpStatus)
			if iterAlt == len(a.altTiles) {
				if !a.consumeFromStack {
					return assignFail // Out of alternate registers
				}
				break
			}
			entry = a.altTiles[iterAlt]
		}
		trialSize := entry.getSize()
		addr := entry.getAddrBySlot(&tmpStatus[entry.getGroup()], trialSize, 1)
		tmpStatus[entry.getGroup()] = -1 // Consume the register
		pieces = append(pieces, address.VarnodeData{Space: addr.Space, Offset: addr.Offset, Size: trialSize})
		sizeLeft -= trialSize
	}
	if sizeLeft > 0 {
		if !a.consumeFromStack {
			return assignFail
		}
		grp := a.stackEntry.getGroup()
		addr := a.stackEntry.getAddrBySlotJustify(&tmpStatus[grp], sizeLeft, align, a.justifyRight)
		if addr.Space == nil {
			return assignFail
		}
		pieces = append(pieces, address.VarnodeData{Space: addr.Space, Offset: addr.Offset, Size: sizeLeft})
	}
	if sizeLeft < 0 { // Odd data-type size
		justifyPieces(pieces, -sizeLeft, a.resource.isBigEndian(), a.consumeMostSig, a.justifyRight)
	}
	var piece parameterPieces
	if !a.resource.assignAddressFromPieces(pieces, a.consumeMostSig, &piece) {
		return assignFail
	}
	copy(status, tmpStatus) // Commit resource usage for all the pieces
	res.flags, res.typ, res.addr = 0, dt, piece.addr
	return assignSuccess
}

func (a *multiSlotDualAssign) fillinOutputMap(active *ParamActive) bool {
	return fillinJoinOutput(active, func(t typeClass, _ bool) bool { return t == a.baseType || t == a.altType }, a.justifyRight, a.consumeMostSig)
}

func (a *multiSlotDualAssign) canAffectFillinOutput() bool { return true }

// consumeAs assigns from one storage class only. C++ parity: ConsumeAs.
type consumeAs struct {
	resource     *ParamListStandard
	resourceType typeClass
}

func (a *consumeAs) assignAddress(dt Datatype, _ *prototypePieces, _ int, status []int32, res *parameterPieces) assignResponse {
	addr, ok := a.resource.assignAddressFallback(a.resourceType, dt, true, status)
	if !ok {
		return assignFail
	}
	res.addr, res.typ, res.flags = addr, dt, 0
	return assignSuccess
}

func (a *consumeAs) fillinOutputMap(active *ParamActive) bool {
	count := 0
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		entry := trial.GetEntry()
		if entry == nil {
			break
		}
		if entry.getType() != a.resourceType || !entry.isFirstInClass() {
			return false
		}
		count++
		if count > 1 {
			return false
		}
		if trial.GetOffset() != 0 {
			return false // Entry must be justified
		}
	}
	return count > 0
}

func (a *consumeAs) canAffectFillinOutput() bool { return true }

// hiddenReturnAssign signals that the return value goes through a hidden
// pointer. C++ parity: HiddenReturnAssign.
type hiddenReturnAssign struct{ retCode assignResponse }

func (a *hiddenReturnAssign) assignAddress(Datatype, *prototypePieces, int, []int32, *parameterPieces) assignResponse {
	return a.retCode
}
func (a *hiddenReturnAssign) fillinOutputMap(*ParamActive) bool { return false }
func (a *hiddenReturnAssign) canAffectFillinOutput() bool       { return false }

// consumeExtra consumes registers of a class covering the data-type's size
// (or one register). C++ parity: ConsumeExtra.
type consumeExtra struct {
	resourceType typeClass
	matchSize    bool
	tiles        []*paramEntry
}

func (a *consumeExtra) assignAddress(dt Datatype, _ *prototypePieces, _ int, status []int32, _ *parameterPieces) assignResponse {
	iter := 0
	sizeLeft := dt.Size()
	for sizeLeft > 0 && iter != len(a.tiles) {
		entry := a.tiles[iter]
		iter++
		if status[entry.getGroup()] != 0 {
			continue // Already consumed
		}
		status[entry.getGroup()] = -1 // Consume the slot/register
		sizeLeft -= entry.getSize()
		if !a.matchSize {
			break // Only consume a single register
		}
	}
	return assignSuccess
}
func (a *consumeExtra) fillinOutputMap(*ParamActive) bool { return false }
func (a *consumeExtra) canAffectFillinOutput() bool       { return false }

// consumeRemaining consumes every register of a class.
// C++ parity: ConsumeRemaining.
type consumeRemaining struct{ tiles []*paramEntry }

func (a *consumeRemaining) assignAddress(_ Datatype, _ *prototypePieces, _ int, status []int32, _ *parameterPieces) assignResponse {
	for _, entry := range a.tiles {
		if status[entry.getGroup()] != 0 {
			continue // Already consumed
		}
		status[entry.getGroup()] = -1 // Consume the slot/register
	}
	return assignSuccess
}
func (a *consumeRemaining) fillinOutputMap(*ParamActive) bool { return false }
func (a *consumeRemaining) canAffectFillinOutput() bool       { return false }

// extraStack consumes stack space as well, once enough of a class has been
// consumed. C++ parity: ExtraStack.
type extraStack struct {
	resource     *ParamListStandard
	afterBytes   int32
	afterStorage typeClass
	stackEntry   *paramEntry
}

func (a *extraStack) assignAddress(dt Datatype, _ *prototypePieces, _ int, status []int32, res *parameterPieces) assignResponse {
	if res.addr.Space == a.stackEntry.space {
		return assignSuccess // Parameter was already assigned to the stack
	}
	grp := a.stackEntry.getGroup()
	if a.afterBytes > 0 { // Enough storage consumed to adjust the stack yet?
		bytesConsumed := int32(0)
		for _, entry := range a.resource.entry {
			if entry.getGroup() == grp || entry.getType() != a.afterStorage {
				continue
			}
			if status[entry.getGroup()] != 0 {
				bytesConsumed += entry.getSize()
			}
		}
		if bytesConsumed < a.afterBytes {
			return assignSuccess
		}
	}
	// Assign (and ignore) a stack address, consuming the stack resources
	a.stackEntry.getAddrBySlot(&status[grp], dt.Size(), dt.Alignment())
	return assignSuccess
}
func (a *extraStack) fillinOutputMap(*ParamActive) bool { return false }
func (a *extraStack) canAffectFillinOutput() bool       { return false }

// decodeAction reads the action element of a rule.
// C++ parity: AssignAction::decodeAction.
func decodeAction(e *CspecElem, res *ParamListStandard) (assignAction, error) {
	switch e.XMLName.Local {
	case "goto_stack":
		a := &gotoStack{resource: res, stackEntry: res.getStackEntry()}
		if a.stackEntry == nil {
			return nil, fmt.Errorf("cannot find matching <pentry> for action: goto_stack")
		}
		return a, nil
	case "join":
		a := newMultiSlotAssign(res)
		for _, at := range e.Attrs {
			v := at.Value == "true" || at.Value == "1"
			switch at.Name.Local {
			case "reversejustify":
				if v {
					a.justifyRight = !a.justifyRight
				}
			case "reversesignif":
				if v {
					a.consumeMostSig = !a.consumeMostSig
				}
			case "storage":
				tc, err := typeclassFromString(at.Value)
				if err != nil {
					return nil, err
				}
				a.resourceType = tc
			case "align":
				a.enforceAlign = v
			case "stackspill":
				a.consumeFromStack = v
			}
		}
		return a, a.initializeEntries()
	case "consume":
		s, _ := e.Attr("storage")
		tc, err := typeclassFromString(s)
		if err != nil {
			return nil, err
		}
		return &consumeAs{resource: res, resourceType: tc}, nil
	case "convert_to_ptr":
		return &convertToPointer{resource: res}, nil
	case "hidden_return":
		// C++ parity: HiddenReturnAssign::decode (a voidlock attribute of any
		// value selects the void form).
		a := &hiddenReturnAssign{retCode: assignHiddenretSpecialreg}
		for _, at := range e.Attrs {
			switch at.Name.Local {
			case "voidlock":
				a.retCode = assignHiddenretSpecialregVoid
			case "strategy":
				switch at.Value {
				case "normalparam":
					a.retCode = assignHiddenretPtrparam
				case "special":
					a.retCode = assignHiddenretSpecialreg
				default:
					return nil, fmt.Errorf("bad <hidden_return> strategy: %s", at.Value)
				}
			}
		}
		return a, nil
	case "join_per_primitive":
		a := &multiMemberAssign{resource: res, resourceType: typeclassGeneral, consumeMostSig: res.isBigEndian()}
		if s, ok := e.Attr("storage"); ok {
			tc, err := typeclassFromString(s)
			if err != nil {
				return nil, err
			}
			a.resourceType = tc
		}
		return a, nil
	case "join_dual_class":
		a := newMultiSlotDualAssign(res)
		for _, at := range e.Attrs {
			v := at.Value == "true" || at.Value == "1"
			switch at.Name.Local {
			case "reversejustify":
				if v {
					a.justifyRight = !a.justifyRight
				}
			case "reversesignif":
				if v {
					a.consumeMostSig = !a.consumeMostSig
				}
			case "storage", "a":
				tc, err := typeclassFromString(at.Value)
				if err != nil {
					return nil, err
				}
				a.baseType = tc
			case "b":
				tc, err := typeclassFromString(at.Value)
				if err != nil {
					return nil, err
				}
				a.altType = tc
			case "stackspill":
				a.consumeFromStack = v
			case "fillalternate":
				a.fillAlternate = v
			}
		}
		return a, a.initializeEntries()
	}
	return nil, fmt.Errorf("expecting model rule action, got <%s>", e.XMLName.Local)
}

// decodeConsumeExtra reads <consume_extra>. C++ parity: ConsumeExtra::decode.
func decodeConsumeExtra(e *CspecElem, res *ParamListStandard) (assignAction, error) {
	a := &consumeExtra{resourceType: typeclassGeneral, matchSize: true}
	if s, ok := e.Attr("storage"); ok {
		tc, err := typeclassFromString(s)
		if err != nil {
			return nil, err
		}
		a.resourceType = tc
	}
	if v, ok := attrBool(e, "matchsize"); ok {
		a.matchSize = v
	}
	a.tiles = res.extractTiles(a.resourceType)
	if len(a.tiles) == 0 {
		return nil, fmt.Errorf("could not find matching resources for action: consume_extra")
	}
	return a, nil
}

// decodeSideeffect reads a side-effect element.
// C++ parity: AssignAction::decodeSideeffect.
func decodeSideeffect(e *CspecElem, res *ParamListStandard) (assignAction, error) {
	switch e.XMLName.Local {
	case "consume_extra":
		return decodeConsumeExtra(e, res)
	case "extra_stack":
		a := &extraStack{resource: res, afterBytes: -1, afterStorage: typeclassGeneral, stackEntry: res.getStackEntry()}
		if v, ok := e.Attr("afterbytes"); ok {
			n, err := strconv.ParseUint(v, 0, 32)
			if err != nil {
				return nil, err
			}
			a.afterBytes = int32(n)
		}
		if s, ok := e.Attr("afterstorage"); ok {
			tc, err := typeclassFromString(s)
			if err != nil {
				return nil, err
			}
			a.afterStorage = tc
		}
		if a.stackEntry == nil {
			return nil, fmt.Errorf("cannot find matching <pentry> for action: extra_stack")
		}
		return a, nil
	case "consume_remaining":
		s, _ := e.Attr("storage")
		tc, err := typeclassFromString(s)
		if err != nil {
			return nil, err
		}
		a := &consumeRemaining{tiles: res.extractTiles(tc)}
		if len(a.tiles) == 0 {
			return nil, fmt.Errorf("could not find matching resources for action: consume_remaining")
		}
		return a, nil
	}
	return nil, fmt.Errorf("expecting model rule sideeffect, got <%s>", e.XMLName.Local)
}

// --- ModelRule ---

// modelRule is one <rule> of a parameter list.
// C++ parity: ModelRule.
type modelRule struct {
	filter        datatypeFilter
	qualifier     qualifierFilter
	preconditions []assignAction
	assign        assignAction
	sideeffects   []assignAction
}

// assignAddress applies the rule when the filters pass.
// C++ parity: ModelRule::assignAddress.
func (r *modelRule) assignAddress(dt Datatype, proto *prototypePieces, pos int, status []int32, res *parameterPieces) assignResponse {
	if !r.filter.filter(dt) {
		return assignFail
	}
	if r.qualifier != nil && !r.qualifier.filter(proto, pos) {
		return assignFail
	}
	tmpStatus := append([]int32(nil), status...)
	for _, pre := range r.preconditions {
		pre.assignAddress(dt, proto, pos, tmpStatus, res)
	}
	response := r.assign.assignAddress(dt, proto, pos, tmpStatus, res)
	if response != assignFail {
		copy(status, tmpStatus)
		for _, se := range r.sideeffects {
			se.assignAddress(dt, proto, pos, status, res)
		}
	}
	return response
}

// decodeModelRule reads one <rule>. C++ parity: ModelRule::decode.
func decodeModelRule(rule *CspecRule, res *ParamListStandard) (*modelRule, error) {
	els := rule.Elems
	if len(els) == 0 {
		return nil, fmt.Errorf("empty <rule>")
	}
	r := &modelRule{}
	f, err := decodeDatatypeFilter(&els[0])
	if err != nil {
		return nil, err
	}
	r.filter = f
	i := 1
	var quals andFilter
	for ; i < len(els); i++ {
		q, err := decodeQualifier(&els[i])
		if err != nil {
			return nil, err
		}
		if q == nil {
			break
		}
		quals = append(quals, q)
	}
	switch len(quals) {
	case 0:
	case 1:
		r.qualifier = quals[0]
	default:
		r.qualifier = quals
	}
	for ; i < len(els) && els[i].XMLName.Local == "consume_extra"; i++ {
		pre, err := decodeConsumeExtra(&els[i], res)
		if err != nil {
			return nil, err
		}
		r.preconditions = append(r.preconditions, pre)
	}
	if i >= len(els) {
		return nil, fmt.Errorf("expecting model rule action")
	}
	if r.assign, err = decodeAction(&els[i], res); err != nil {
		return nil, err
	}
	for i++; i < len(els); i++ {
		se, err := decodeSideeffect(&els[i], res)
		if err != nil {
			return nil, err
		}
		r.sideeffects = append(r.sideeffects, se)
	}
	return r, nil
}

// SetModelRules installs the list's <rule> elements and, when pointermax is
// set, the trailing rule converting larger data-types to pointers. output
// marks a return-value list, whose fillinMap then follows the rules that can
// decide the return storage.
// C++ parity: ParamListStandard::decode (ModelRule::decode, pointermax rule)
// and ParamListStandardOut::initialize.
// A rule C++ would reject while decoding (an unknown element, an action
// without its storage) fails the whole model there; it is dropped here.
func (pl *ParamListStandard) SetModelRules(rules []CspecRule, pointerMax int32, pointerSize int32, output bool) {
	pl.pointerSize = pointerSize
	pl.isOutput = output
	pl.modelRules = nil
	for i := range rules {
		r, err := decodeModelRule(&rules[i], pl)
		if err != nil {
			continue
		}
		pl.modelRules = append(pl.modelRules, *r)
	}
	if pointerMax > 0 {
		f := &sizeRestrictedFilter{minSize: pointerMax + 1}
		f.maxSize = 0x7fffffff
		pl.modelRules = append(pl.modelRules, modelRule{filter: f, assign: &convertToPointer{resource: pl}})
	}
	pl.useFillinFallback = true
	for i := range pl.modelRules {
		if pl.modelRules[i].assign.canAffectFillinOutput() {
			pl.useFillinFallback = false
			break
		}
	}
}

// AutoKilledByCallLegacy: a return list with no rule deciding the return
// storage marks every return location killed by a call.
// C++ parity: ParamListStandardOut::initialize (autoKilledByCall = true).
func (pl *ParamListStandard) AutoKilledByCallLegacy() bool {
	return pl.isOutput && pl.useFillinFallback
}

// assignAddress tries every model rule, then the fallback assignment.
// C++ parity: ParamListStandard::assignAddress.
func (pl *ParamListStandard) assignAddress(dt Datatype, proto *prototypePieces, pos int, status []int32, res *parameterPieces) assignResponse {
	for i := range pl.modelRules {
		if code := pl.modelRules[i].assignAddress(dt, proto, pos, status, res); code != assignFail {
			return code
		}
	}
	return pl.assignAddressFallbackPiece(metatypeTypeClass(dt.Metatype()), dt, false, status, res)
}

func (pl *ParamListStandard) assignAddressFallbackPiece(resource typeClass, dt Datatype, matchExact bool, status []int32, res *parameterPieces) assignResponse {
	addr, ok := pl.assignAddressFallback(resource, dt, matchExact, status)
	if !ok {
		return assignFail
	}
	res.addr, res.typ, res.flags = addr, dt, 0
	return assignSuccess
}

// assignOutput gives the return value its storage, switching to a hidden
// pointer when it cannot be returned directly. The second piece, when
// present, is the hidden input pointer still to be placed by assignInputs.
// C++ parity: ParamListStandardOut::assignMap.
func (pl *ParamListStandard) assignOutput(proto *prototypePieces) ([]parameterPieces, bool) {
	outtype := proto.outtype
	status := make([]int32, pl.numgroup)
	res := []parameterPieces{{}}
	if outtype.Metatype() == TYPE_VOID {
		res[0].typ = outtype
		return res, true // Leave the address invalid
	}
	code := pl.assignAddress(outtype, proto, -1, status, &res[0])
	if code == assignFail {
		code = assignHiddenretPtrparam // Default hidden return input assignment
	}
	if code == assignHiddenretPtrparam || code == assignHiddenretSpecialreg || code == assignHiddenretSpecialregVoid {
		pointertp := sharedTypeFactory.GetPointer(pl.pointerSize, outtype, 1)
		if code == assignHiddenretSpecialregVoid {
			res[0].typ = sharedTypeFactory.GetVoid()
		} else {
			res[0].typ = pointertp
			if pl.assignAddress(pointertp, proto, -1, status, &res[0]) == assignFail {
				return nil, false // Cannot assign return value as a pointer
			}
		}
		res[0].flags = pieceIndirectStorage
		hidden := parameterPieces{typ: pointertp}
		if code != assignHiddenretPtrparam {
			hidden.flags = pieceHiddenRetParm
		}
		res = append(res, hidden)
	}
	return res, true
}

// assignInputs places the hidden return pointer (if res holds one) and then
// every input type. C++ parity: ParamListStandard::assignMap.
func (pl *ParamListStandard) assignInputs(proto *prototypePieces, res []parameterPieces) ([]parameterPieces, bool) {
	status := make([]int32, pl.numgroup)
	if len(res) == 2 {
		last := &res[1]
		if last.flags&pieceHiddenRetParm != 0 {
			if pl.assignAddressFallbackPiece(typeclassHiddenret, last.typ, false, status, last) == assignFail {
				return nil, false
			}
		} else if pl.assignAddress(last.typ, proto, 0, status, last) == assignFail {
			return nil, false
		}
		last.flags |= pieceHiddenRetParm
	}
	for i, dt := range proto.intypes {
		var p parameterPieces
		code := pl.assignAddress(dt, proto, i, status, &p)
		if code == assignFail || code == assignNoAssignment {
			return nil, false // ParamUnassignedError
		}
		res = append(res, p)
	}
	return res, true
}

// assignParameterStorage assigns storage to the return value and all inputs.
// An output that cannot be placed becomes an unlocked void.
// C++ parity: ProtoModel::assignParameterStorage (ignoreOutputError).
func (pm *ProtoModel) assignParameterStorage(proto *prototypePieces) ([]parameterPieces, bool) {
	var res []parameterPieces
	if pm.OutputParams != nil && proto.outtype != nil {
		if out, ok := pm.OutputParams.assignOutput(proto); ok {
			res = out
		}
	}
	if res == nil {
		res = []parameterPieces{{typ: sharedTypeFactory.GetVoid()}}
	}
	return pm.InputParams.assignInputs(proto, res)
}
