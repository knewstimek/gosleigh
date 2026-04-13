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

// C++ parity: transform.hh LaneDescription
type LaneDescription struct {
	wholeSize    int32
	laneSize     []int32
	lanePosition []int32
}

// C++ parity: transform.hh LaneDescription::LaneDescription(const LaneDescription &)
func NewLaneDescriptionCopy(op2 *LaneDescription) *LaneDescription {
	if op2 == nil {
		return nil
	}
	return &LaneDescription{
		wholeSize:    op2.wholeSize,
		laneSize:     append([]int32(nil), op2.laneSize...),
		lanePosition: append([]int32(nil), op2.lanePosition...),
	}
}

// C++ parity: transform.hh LaneDescription::LaneDescription(int4 origSize, int4 sz)
func NewLaneDescriptionUniform(origSize, sz int32) *LaneDescription {
	ld := &LaneDescription{wholeSize: origSize}
	if sz <= 0 || origSize <= 0 {
		return ld
	}
	numLanes := origSize / sz
	ld.laneSize = make([]int32, numLanes)
	ld.lanePosition = make([]int32, numLanes)
	pos := int32(0)
	for i := int32(0); i < numLanes; i++ {
		ld.laneSize[i] = sz
		ld.lanePosition[i] = pos
		pos += sz
	}
	return ld
}

// C++ parity: transform.hh LaneDescription::LaneDescription(int4 origSize, int4 lo, int4 hi)
func NewLaneDescriptionTwoLanes(origSize, lo, hi int32) *LaneDescription {
	return &LaneDescription{
		wholeSize:    origSize,
		laneSize:     []int32{lo, hi},
		lanePosition: []int32{0, lo},
	}
}

// C++ parity: transform.cc LaneDescription::subset
func (ld *LaneDescription) Subset(lsbOffset, size int32) bool {
	if ld == nil {
		return false
	}
	if lsbOffset == 0 && size == ld.wholeSize {
		return true
	}
	firstLane := ld.GetBoundary(lsbOffset)
	if firstLane < 0 {
		return false
	}
	lastLane := ld.GetBoundary(lsbOffset + size)
	if lastLane < 0 {
		return false
	}
	newLaneSize := make([]int32, 0, lastLane-firstLane)
	newLanePosition := make([]int32, 0, lastLane-firstLane)
	newPosition := int32(0)
	for i := firstLane; i < lastLane; i++ {
		sz := ld.laneSize[i]
		newLanePosition = append(newLanePosition, newPosition)
		newLaneSize = append(newLaneSize, sz)
		newPosition += sz
	}
	ld.wholeSize = size
	ld.laneSize = newLaneSize
	ld.lanePosition = newLanePosition
	return true
}

// C++ parity: transform.hh LaneDescription::getNumLanes
func (ld *LaneDescription) GetNumLanes() int32 {
	if ld == nil {
		return 0
	}
	return int32(len(ld.laneSize))
}

// C++ parity: transform.hh LaneDescription::getWholeSize
func (ld *LaneDescription) GetWholeSize() int32 {
	if ld == nil {
		return 0
	}
	return ld.wholeSize
}

// C++ parity: transform.hh LaneDescription::getSize
func (ld *LaneDescription) GetSize(i int32) int32 {
	return ld.laneSize[i]
}

// C++ parity: transform.hh LaneDescription::getPosition
func (ld *LaneDescription) GetPosition(i int32) int32 {
	return ld.lanePosition[i]
}

// C++ parity: transform.cc LaneDescription::getBoundary
func (ld *LaneDescription) GetBoundary(bytePos int32) int32 {
	if ld == nil {
		return -1
	}
	if bytePos < 0 || bytePos > ld.wholeSize {
		return -1
	}
	if bytePos == ld.wholeSize {
		return int32(len(ld.lanePosition))
	}
	min := int32(0)
	max := int32(len(ld.lanePosition) - 1)
	for min <= max {
		index := (min + max) / 2
		pos := ld.lanePosition[index]
		if pos == bytePos {
			return index
		}
		if pos < bytePos {
			min = index + 1
		} else {
			max = index - 1
		}
	}
	return -1
}

// C++ parity: transform.cc LaneDescription::restriction
func (ld *LaneDescription) Restriction(numLanes, skipLanes, bytePos, size int32) (bool, int32, int32) {
	if ld == nil || skipLanes < 0 || skipLanes >= int32(len(ld.lanePosition)) {
		return false, 0, 0
	}
	resSkipLanes := ld.GetBoundary(ld.lanePosition[skipLanes] + bytePos)
	if resSkipLanes < 0 {
		return false, 0, 0
	}
	finalIndex := ld.GetBoundary(ld.lanePosition[skipLanes] + bytePos + size)
	if finalIndex < 0 {
		return false, 0, 0
	}
	resNumLanes := finalIndex - resSkipLanes
	if resNumLanes == 0 {
		return false, 0, 0
	}
	return true, resNumLanes, resSkipLanes
}

// C++ parity: transform.cc LaneDescription::extension
func (ld *LaneDescription) Extension(numLanes, skipLanes, bytePos, size int32) (bool, int32, int32) {
	if ld == nil || skipLanes < 0 || skipLanes >= int32(len(ld.lanePosition)) {
		return false, 0, 0
	}
	resSkipLanes := ld.GetBoundary(ld.lanePosition[skipLanes] - bytePos)
	if resSkipLanes < 0 {
		return false, 0, 0
	}
	finalIndex := ld.GetBoundary(ld.lanePosition[skipLanes] - bytePos + size)
	if finalIndex < 0 {
		return false, 0, 0
	}
	resNumLanes := finalIndex - resSkipLanes
	if resNumLanes == 0 {
		return false, 0, 0
	}
	return true, resNumLanes, resSkipLanes
}

// C++ parity: transform.hh LanedRegister
type LanedRegister struct {
	wholeSize   int32
	sizeBitMask uint32
}

// C++ parity: transform.hh LanedRegister::LanedRegister(void)
func NewLanedRegister() LanedRegister {
	return LanedRegister{}
}

// C++ parity: transform.hh LanedRegister::LanedRegister(int4 sz, uint4 mask)
func NewLanedRegisterWithMask(sz int32, mask uint32) LanedRegister {
	return LanedRegister{wholeSize: sz, sizeBitMask: mask}
}

// C++ parity: transform.cc LanedRegister::parseSizes
func (lr *LanedRegister) ParseSizes(registerSize int32, laneSizes string) error {
	lr.wholeSize = registerSize
	lr.sizeBitMask = 0
	for _, raw := range strings.Split(laneSizes, ",") {
		value := strings.TrimSpace(raw)
		if value == "" {
			return fmt.Errorf("bad lane size: %q", raw)
		}
		sz64, err := strconv.ParseInt(value, 0, 32)
		if err != nil {
			return fmt.Errorf("bad lane size: %s", value)
		}
		sz := int32(sz64)
		if sz < 0 || sz > 16 {
			return fmt.Errorf("bad lane size: %s", value)
		}
		lr.AddLaneSize(sz)
	}
	return nil
}

// C++ parity: transform.hh LanedRegister::getWholeSize
func (lr *LanedRegister) GetWholeSize() int32 {
	if lr == nil {
		return 0
	}
	return lr.wholeSize
}

// C++ parity: transform.hh LanedRegister::getSizeBitMask
func (lr *LanedRegister) GetSizeBitMask() uint32 {
	if lr == nil {
		return 0
	}
	return lr.sizeBitMask
}

// C++ parity: transform.hh LanedRegister::addLaneSize
func (lr *LanedRegister) AddLaneSize(size int32) {
	if size < 0 || size >= 32 {
		return
	}
	lr.sizeBitMask |= uint32(1) << uint(size)
}

// C++ parity: transform.hh LanedRegister::allowedLane
func (lr *LanedRegister) AllowedLane(size int32) bool {
	if lr == nil || size < 0 || size >= 32 {
		return false
	}
	return ((lr.sizeBitMask >> uint(size)) & 1) != 0
}

// C++ parity: transform.hh LanedRegister::begin
func (lr *LanedRegister) Begin() LanedIterator {
	return NewLanedIterator(lr)
}

// C++ parity: transform.hh LanedRegister::end
func (lr *LanedRegister) End() LanedIterator {
	return NewLanedIteratorEnd()
}

// C++ parity: transform.hh LanedRegister::LanedIterator
type LanedIterator struct {
	size int32
	mask uint32
}

// C++ parity: transform.hh LanedRegister::LanedIterator(const LanedRegister *)
func NewLanedIterator(lanedR *LanedRegister) LanedIterator {
	if lanedR == nil {
		return NewLanedIteratorEnd()
	}
	it := LanedIterator{size: 0, mask: lanedR.sizeBitMask}
	it.normalize()
	return it
}

// C++ parity: transform.hh LanedRegister::LanedIterator(void)
func NewLanedIteratorEnd() LanedIterator {
	return LanedIterator{size: -1}
}

// C++ parity: transform.cc LanedRegister::LanedIterator::normalize
func (it *LanedIterator) normalize() {
	if it == nil {
		return
	}
	flag := uint32(1)
	if it.size >= 0 && it.size < 32 {
		flag <<= uint(it.size)
	} else {
		flag = 0
	}
	for flag != 0 && flag <= it.mask {
		if flag&it.mask != 0 {
			return
		}
		it.size++
		if it.size >= 32 {
			break
		}
		flag <<= 1
	}
	it.size = -1
	it.mask = 0
}

// C++ parity: transform.hh LanedRegister::LanedIterator::operator++
func (it *LanedIterator) Next() bool {
	if it == nil || it.size < 0 {
		return false
	}
	it.size++
	it.normalize()
	return it.size >= 0
}

// C++ parity: transform.hh LanedRegister::LanedIterator::operator*
func (it *LanedIterator) Value() int32 {
	if it == nil {
		return -1
	}
	return it.size
}

// C++ parity: transform.hh LanedRegister::LanedIterator::operator==
func (it *LanedIterator) Equal(other LanedIterator) bool {
	if it == nil {
		return other.size < 0
	}
	return it.size == other.size
}

// C++ parity: transform.hh LanedRegister::LanedIterator::operator!=
func (it *LanedIterator) NotEqual(other LanedIterator) bool {
	return !it.Equal(other)
}

// C++ parity: transform.hh TransformVar
type TransformVar struct {
	vn          *Varnode
	replacement *Varnode
	typeCode    uint32
	flags       uint32
	byteSize    int32
	bitSize     int32
	val         uint64
	def         *TransformOp
}

const (
	// C++ parity: transform.hh TransformVar::piece / preexisting / normal_temp / piece_temp / constant / constant_iop
	TVarPiece       uint32 = 1
	TVarPreexisting uint32 = 2
	TVarNormalTemp  uint32 = 3
	TVarPieceTemp   uint32 = 4
	TVarConstant    uint32 = 5
	TVarConstantIOP uint32 = 6
)

const (
	// C++ parity: transform.hh TransformVar::split_terminator / input_duplicate
	TVarSplitTerminator uint32 = 1
	TVarInputDuplicate  uint32 = 2
)

// C++ parity: transform.hh TransformVar::initialize
func (tv *TransformVar) initialize(tp uint32, v *Varnode, bits, bytes int32, value uint64) {
	tv.typeCode = tp
	tv.vn = v
	tv.val = value
	tv.bitSize = bits
	tv.byteSize = bytes
	tv.flags = 0
	tv.def = nil
	tv.replacement = nil
}

// C++ parity: transform.cc TransformVar::createReplacement
func (tv *TransformVar) createReplacement(fd *Funcdata) {
	if tv == nil || tv.replacement != nil {
		return
	}
	switch tv.typeCode {
	case TVarPreexisting:
		tv.replacement = tv.vn
	case TVarConstant:
		tv.replacement = fd.NewConstant(tv.byteSize, tv.val)
	case TVarNormalTemp, TVarPieceTemp:
		if tv.def == nil {
			tv.replacement = fd.GetVarnodeBank().CreateUnique(tv.byteSize)
		} else {
			tv.replacement = fd.NewUniqueOut(tv.byteSize, tv.def.replacement)
		}
	case TVarPiece:
		bytePos := int32(tv.val)
		if bytePos&7 != 0 {
			panic("Varnode piece is not byte aligned")
		}
		bytePos >>= 3
		if tv.vn != nil && tv.vn.Space() != nil && tv.vn.Space().BigEndian {
			bytePos = tv.vn.Size() - bytePos - tv.byteSize
		}
		addr := tv.vn.Addr().Add(uint64(bytePos))
		addr.Renormalize(tv.byteSize)
		if tv.def == nil {
			tv.replacement = fd.NewVarnode(tv.byteSize, addr)
		} else {
			tv.replacement = fd.NewVarnodeOut(tv.byteSize, addr, tv.def.replacement)
		}
		fd.TransferVarnodeProperties(tv.vn, tv.replacement, bytePos)
	case TVarConstantIOP:
		// TODO known mismatch: Go repo has no IopSpace-backed pointer encoding yet.
		// Preserve the encoded offset as a constant placeholder so later batches can
		// still recover the reference value if needed.
		tv.replacement = fd.NewConstant(tv.byteSize, tv.val)
	default:
		panic("bad TransformVar type")
	}
}

// C++ parity: transform.hh TransformVar::getOriginal
func (tv *TransformVar) GetOriginal() *Varnode {
	if tv == nil {
		return nil
	}
	return tv.vn
}

// C++ parity: transform.hh TransformVar::getDef
func (tv *TransformVar) GetDef() *TransformOp {
	if tv == nil {
		return nil
	}
	return tv.def
}

// C++ parity: transform.hh TransformOp
type TransformOp struct {
	op          *PcodeOp
	replacement *PcodeOp
	opc         OpCode
	special     uint32
	output      *TransformVar
	input       []*TransformVar
	follow      *TransformOp
}

const (
	// C++ parity: transform.hh TransformOp::op_replacement / op_preexisting / indirect_creation / indirect_creation_possible_out
	TOpReplacement                 uint32 = 1
	TOpPreexisting                 uint32 = 2
	TOpIndirectCreation            uint32 = 4
	TOpIndirectCreationPossibleOut uint32 = 8
)

// C++ parity: transform.hh TransformOp::createReplacement
func (to *TransformOp) createReplacement(fd *Funcdata) {
	if to == nil || to.replacement != nil {
		return
	}
	if to.special&TOpPreexisting != 0 {
		to.replacement = to.op
		fd.OpSetOpcode(to.op, to.opc)
		for to.op.NumInput() > len(to.input) {
			fd.OpUnsetInput(to.op, to.op.NumInput()-1)
			to.op.RemoveInput(to.op.NumInput() - 1)
		}
		for i := 0; i < to.op.NumInput(); i++ {
			fd.OpUnsetInput(to.op, i)
		}
		for to.op.NumInput() < len(to.input) {
			to.op.InsertInput(to.op.NumInput())
		}
		return
	}
	to.replacement = fd.NewOp(len(to.input), to.op.Addr())
	fd.OpSetOpcode(to.replacement, to.opc)
	if to.output != nil {
		to.output.createReplacement(fd)
	}
	if to.follow == nil {
		if to.opc == CPUI_MULTIEQUAL {
			fd.OpInsertBegin(to.replacement, to.op.Parent())
		} else {
			fd.OpInsertBefore(to.replacement, to.op)
		}
	}
}

// C++ parity: transform.hh TransformOp::attemptInsertion
func (to *TransformOp) attemptInsertion(fd *Funcdata) bool {
	if to == nil {
		return true
	}
	if to.follow != nil {
		if to.follow.follow == nil {
			if to.opc == CPUI_MULTIEQUAL {
				fd.OpInsertBegin(to.replacement, to.follow.replacement.Parent())
			} else {
				fd.OpInsertBefore(to.replacement, to.follow.replacement)
			}
			to.follow = nil
			return true
		}
		return false
	}
	return true
}

// C++ parity: transform.hh TransformOp::inheritIndirect
func (to *TransformOp) inheritIndirect(indOp *PcodeOp) {
	if to == nil || indOp == nil || !indOp.IsIndirectCreation() {
		return
	}
	if in0 := indOp.Input(0); in0 != nil && in0.IsIndirectZero() {
		to.special |= TOpIndirectCreation
	} else {
		to.special |= TOpIndirectCreationPossibleOut
	}
}

// C++ parity: transform.hh TransformOp::getOut
func (to *TransformOp) GetOut() *TransformVar {
	if to == nil {
		return nil
	}
	return to.output
}

// C++ parity: transform.hh TransformOp::getIn
func (to *TransformOp) GetIn(i int) *TransformVar {
	return to.input[i]
}

// C++ parity: transform.hh TransformManager
type TransformManager struct {
	fd          *Funcdata
	pieceMap    map[uint32][]*TransformVar
	newVarnodes []*TransformVar
	newOps      []*TransformOp
}

// C++ parity: transform.hh TransformManager::TransformManager
func NewTransformManager(f *Funcdata) *TransformManager {
	return &TransformManager{fd: f, pieceMap: make(map[uint32][]*TransformVar)}
}

// C++ parity: transform.hh TransformManager::preserveAddress
func (tm *TransformManager) PreserveAddress(vn *Varnode, bitSize, lsbOffset int32) bool {
	if vn == nil || vn.Space() == nil {
		return false
	}
	if lsbOffset&7 != 0 {
		return false
	}
	if vn.Space().Kind == address.SpaceKindUnique {
		return false
	}
	return true
}

// C++ parity: transform.hh TransformManager::getFunction
func (tm *TransformManager) GetFunction() *Funcdata {
	if tm == nil {
		return nil
	}
	return tm.fd
}

// C++ parity: transform.hh TransformManager::clearVarnodeMarks
func (tm *TransformManager) ClearVarnodeMarks() {
	if tm == nil {
		return
	}
	keys := make([]uint32, 0, len(tm.pieceMap))
	for key := range tm.pieceMap {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		vars := tm.pieceMap[key]
		for _, tv := range vars {
			if tv != nil && tv.vn != nil {
				tv.vn.ClearMark()
			}
		}
	}
}

// C++ parity: transform.hh TransformManager::newPreexistingVarnode
func (tm *TransformManager) NewPreexistingVarnode(vn *Varnode) *TransformVar {
	tv := &TransformVar{}
	tm.pieceMap[vn.CreateIndex()] = []*TransformVar{tv}
	tv.initialize(TVarPreexisting, vn, vn.Size()*8, vn.Size(), 0)
	tv.flags = TVarSplitTerminator
	return tv
}

// C++ parity: transform.hh TransformManager::newUnique
func (tm *TransformManager) NewUnique(size int32) *TransformVar {
	tv := &TransformVar{}
	tm.newVarnodes = append(tm.newVarnodes, tv)
	tv.initialize(TVarNormalTemp, nil, size*8, size, 0)
	return tv
}

// C++ parity: transform.hh TransformManager::newConstant
func (tm *TransformManager) NewConstant(size, lsbOffset int32, val uint64) *TransformVar {
	tv := &TransformVar{}
	tm.newVarnodes = append(tm.newVarnodes, tv)
	tv.initialize(TVarConstant, nil, size*8, size, (val>>uint(lsbOffset))&maskForSize(size))
	return tv
}

// C++ parity: transform.hh TransformManager::newIop
func (tm *TransformManager) NewIop(vn *Varnode) *TransformVar {
	tv := &TransformVar{}
	tm.newVarnodes = append(tm.newVarnodes, tv)
	tv.initialize(TVarConstantIOP, nil, vn.Size()*8, vn.Size(), vn.Offset())
	return tv
}

// C++ parity: transform.hh TransformManager::newPiece
func (tm *TransformManager) NewPiece(vn *Varnode, bitSize, lsbOffset int32) *TransformVar {
	tv := &TransformVar{}
	tm.pieceMap[vn.CreateIndex()] = []*TransformVar{tv}
	byteSize := (bitSize + 7) / 8
	tp := TVarPieceTemp
	if tm.PreserveAddress(vn, bitSize, lsbOffset) {
		tp = TVarPiece
	}
	tv.initialize(tp, vn, bitSize, byteSize, uint64(lsbOffset))
	tv.flags = TVarSplitTerminator
	return tv
}

// C++ parity: transform.hh TransformManager::newSplit
func (tm *TransformManager) NewSplit(vn *Varnode, description *LaneDescription) []*TransformVar {
	if vn == nil || description == nil {
		return nil
	}
	return tm.NewSplitRange(vn, description, description.GetNumLanes(), 0)
}

// C++ parity: transform.hh TransformManager::newSplit
func (tm *TransformManager) NewSplitRange(vn *Varnode, description *LaneDescription, numLanes, startLane int32) []*TransformVar {
	if vn == nil || description == nil || numLanes <= 0 {
		return nil
	}
	res := make([]*TransformVar, numLanes)
	tm.pieceMap[vn.CreateIndex()] = res
	baseBitPos := description.GetPosition(startLane) * 8
	for i := int32(0); i < numLanes; i++ {
		byteSize := description.GetSize(startLane + i)
		tv := &TransformVar{}
		res[i] = tv
		bitpos := description.GetPosition(startLane+i)*8 - baseBitPos
		if vn.IsConstant() {
			var val uint64
			if bitpos < 64 {
				val = (vn.Offset() >> uint(bitpos)) & maskForSize(byteSize)
			}
			tv.initialize(TVarConstant, vn, byteSize*8, byteSize, val)
		} else {
			tp := TVarPieceTemp
			if tm.PreserveAddress(vn, byteSize*8, bitpos) {
				tp = TVarPiece
			}
			tv.initialize(tp, vn, byteSize*8, byteSize, uint64(bitpos))
		}
	}
	res[numLanes-1].flags = TVarSplitTerminator
	return res
}

// C++ parity: transform.hh TransformManager::newOpReplace
func (tm *TransformManager) NewOpReplace(numParams int, opc OpCode, replace *PcodeOp) *TransformOp {
	rop := &TransformOp{
		op:      replace,
		opc:     opc,
		special: TOpReplacement,
		input:   make([]*TransformVar, numParams),
		follow:  nil,
		output:  nil,
	}
	tm.newOps = append(tm.newOps, rop)
	return rop
}

// C++ parity: transform.hh TransformManager::newOp
func (tm *TransformManager) NewOp(numParams int, opc OpCode, follow *TransformOp) *TransformOp {
	if follow == nil {
		panic("TransformManager.NewOp requires a follow op")
	}
	rop := &TransformOp{
		op:     follow.op,
		opc:    opc,
		follow: follow,
		input:  make([]*TransformVar, numParams),
		output: nil,
	}
	tm.newOps = append(tm.newOps, rop)
	return rop
}

// C++ parity: transform.hh TransformManager::newPreexistingOp
func (tm *TransformManager) NewPreexistingOp(numParams int, opc OpCode, originalOp *PcodeOp) *TransformOp {
	rop := &TransformOp{
		op:      originalOp,
		opc:     opc,
		special: TOpPreexisting,
		input:   make([]*TransformVar, numParams),
		follow:  nil,
		output:  nil,
	}
	tm.newOps = append(tm.newOps, rop)
	return rop
}

// C++ parity: transform.hh TransformManager::getPreexistingVarnode
func (tm *TransformManager) GetPreexistingVarnode(vn *Varnode) *TransformVar {
	if vn == nil {
		return nil
	}
	if vn.IsConstant() {
		return tm.NewConstant(vn.Size(), 0, vn.Offset())
	}
	if vars, ok := tm.pieceMap[vn.CreateIndex()]; ok && len(vars) > 0 {
		return vars[0]
	}
	return tm.NewPreexistingVarnode(vn)
}

// C++ parity: transform.hh TransformManager::getPiece
func (tm *TransformManager) GetPiece(vn *Varnode, bitSize, lsbOffset int32) *TransformVar {
	if vn == nil {
		return nil
	}
	if vars, ok := tm.pieceMap[vn.CreateIndex()]; ok && len(vars) > 0 {
		tv := vars[0]
		if tv.bitSize != bitSize || tv.val != uint64(lsbOffset) {
			panic("cannot create multiple pieces for one Varnode through GetPiece")
		}
		return tv
	}
	return tm.NewPiece(vn, bitSize, lsbOffset)
}

// C++ parity: transform.hh TransformManager::getSplit
func (tm *TransformManager) GetSplit(vn *Varnode, description *LaneDescription) []*TransformVar {
	if vn == nil || description == nil {
		return nil
	}
	if vars, ok := tm.pieceMap[vn.CreateIndex()]; ok {
		return vars
	}
	return tm.NewSplit(vn, description)
}

// C++ parity: transform.hh TransformManager::getSplit
func (tm *TransformManager) GetSplitRange(vn *Varnode, description *LaneDescription, numLanes, startLane int32) []*TransformVar {
	if vn == nil || description == nil {
		return nil
	}
	if vars, ok := tm.pieceMap[vn.CreateIndex()]; ok {
		return vars
	}
	return tm.NewSplitRange(vn, description, numLanes, startLane)
}

// C++ parity: transform.hh TransformManager::opSetInput
func (tm *TransformManager) OpSetInput(rop *TransformOp, rvn *TransformVar, slot int) {
	if rop == nil || rvn == nil || slot < 0 || slot >= len(rop.input) {
		return
	}
	rop.input[slot] = rvn
}

// C++ parity: transform.hh TransformManager::opSetOutput
func (tm *TransformManager) OpSetOutput(rop *TransformOp, rvn *TransformVar) {
	if rop == nil || rvn == nil {
		return
	}
	rop.output = rvn
	rvn.def = rop
}

// C++ parity: transform.hh TransformManager::preexistingGuard
func (tm *TransformManager) PreexistingGuard(slot int, rvn *TransformVar) bool {
	if slot == 0 {
		return true
	}
	if rvn != nil && (rvn.typeCode == TVarPiece || rvn.typeCode == TVarPieceTemp) {
		return false
	}
	return true
}

// C++ parity: transform.cc TransformManager::specialHandling
func (tm *TransformManager) specialHandling(rop *TransformOp) {
	if tm == nil || tm.fd == nil || rop == nil || rop.replacement == nil {
		return
	}
	if rop.special&TOpIndirectCreation != 0 {
		tm.fd.MarkIndirectCreation(rop.replacement, false)
	} else if rop.special&TOpIndirectCreationPossibleOut != 0 {
		tm.fd.MarkIndirectCreation(rop.replacement, true)
	}
}

// C++ parity: transform.cc TransformManager::createOps
func (tm *TransformManager) createOps() {
	for _, rop := range tm.newOps {
		rop.createReplacement(tm.fd)
	}
	for {
		followCount := 0
		for _, rop := range tm.newOps {
			if !rop.attemptInsertion(tm.fd) {
				followCount++
			}
		}
		if followCount == 0 {
			return
		}
	}
}

// C++ parity: transform.cc TransformManager::createVarnodes
func (tm *TransformManager) createVarnodes(inputList *[]*TransformVar) {
	keys := make([]uint32, 0, len(tm.pieceMap))
	for key := range tm.pieceMap {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		vars := tm.pieceMap[key]
		for _, rvn := range vars {
			if rvn == nil {
				continue
			}
			if rvn.typeCode == TVarPiece {
				vn := rvn.vn
				if vn != nil && vn.IsInput() {
					*inputList = append(*inputList, rvn)
					if vn.IsMark() {
						rvn.flags |= TVarInputDuplicate
					} else {
						vn.SetMark()
					}
				}
			}
			rvn.createReplacement(tm.fd)
			if rvn.flags&TVarSplitTerminator != 0 {
				break
			}
		}
	}
	for _, rvn := range tm.newVarnodes {
		rvn.createReplacement(tm.fd)
	}
}

// C++ parity: transform.cc TransformManager::removeOld
func (tm *TransformManager) removeOld() {
	for _, rop := range tm.newOps {
		if rop.special&TOpReplacement != 0 && rop.op != nil && !rop.op.IsDead() {
			tm.fd.OpDestroy(rop.op)
		}
	}
}

// C++ parity: transform.cc TransformManager::transformInputVarnodes
func (tm *TransformManager) transformInputVarnodes(inputList []*TransformVar) {
	for _, rvn := range inputList {
		if rvn == nil || rvn.replacement == nil {
			continue
		}
		if rvn.flags&TVarInputDuplicate == 0 && rvn.vn != nil {
			tm.fd.DeleteVarnode(rvn.vn)
		}
		rvn.replacement = tm.fd.SetInputVarnode(rvn.replacement)
	}
}

// C++ parity: transform.cc TransformManager::placeInputs
func (tm *TransformManager) placeInputs() {
	for _, rop := range tm.newOps {
		if rop == nil || rop.replacement == nil {
			continue
		}
		for i, rvn := range rop.input {
			if rvn == nil || rvn.replacement == nil {
				continue
			}
			tm.fd.OpSetInput(rop.replacement, rvn.replacement, i)
		}
		tm.specialHandling(rop)
	}
}

// C++ parity: transform.hh TransformManager::apply
func (tm *TransformManager) Apply() {
	inputList := make([]*TransformVar, 0)
	tm.createOps()
	tm.createVarnodes(&inputList)
	tm.removeOld()
	tm.transformInputVarnodes(inputList)
	tm.placeInputs()
}
