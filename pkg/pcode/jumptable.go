/*
 * Copyright 2024 The Gosleigh Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pcode

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"

	"gosleigh/pkg/address"
)

// This file ports the JumpTable / JumpModel infrastructure from Ghidra's
// jumptable.hh / jumptable.cc into Go. It is the Keystone 3 landing: the
// JumpTable container itself, LoadTable, PathMeld / GuardRecord data
// skeletons, JumpModel interface, JumpModelTrivial, and a JumpBasic struct
// with the method surface needed by downstream callers. Several of the deeper
// recovery methods depend on C++ infrastructure that is not yet ported
// (CircleRange / EmulateFunction / CFG pullback analysis); those bodies are
// marked with explicit TODO notes citing the upstream C++ function so a
// follow-up batch can fill them in without having to rediscover scope.
//
// Intentional deviations from direct C++ translation:
//   - Go's error return replaces C++ exceptions (JumptableThunkError etc.).
//   - EmulateFunction is declared but its Execute path is a stub.
//   - PathMeld stores Varnode/PcodeOp pointers; the meld algorithm relies on
//     PcodeOpNode path descriptors which are also not ported yet.
//
// Special-circumstance note: this file was written directly by the
// orchestrator (instead of a subagent) because every dependency read for
// scope analysis was already hot in context, and re-dispatching would have
// duplicated the C++ read budget on a file whose realistic landing surface
// is primarily data structures + stubs. See project CLAUDE.md note on
// subagent overhead vs. direct work.

// -----------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------

// JumptableThunkError is returned when a putative jump table looks more
// like a thunk than a real switch.
// C++ parity: jumptable.hh JumptableThunkError
var JumptableThunkError = errors.New("jumptable looks like a thunk")

// JumptableRecoveryError is the generic recovery failure, replacing the
// C++ LowlevelError path used throughout jumptable.cc.
// C++ parity: jumptable.cc LowlevelError raises in JumpTable::recoverAddresses
var JumptableRecoveryError = errors.New("jumptable recovery failure")

// -----------------------------------------------------------------------
// LoadTable
// -----------------------------------------------------------------------

// LoadTable describes a table of memory load addresses produced by
// emulating a computed jump. Each entry is a contiguous run of Num slots
// of Size bytes starting at Addr.
// C++ parity: jumptable.hh LoadTable
type LoadTable struct {
	Addr address.Address
	Size int32
	Num  int32
}

// NewLoadTableSingle builds a single-entry table at ad with entry size sz.
// C++ parity: jumptable.hh LoadTable::LoadTable(const Address&,int4)
func NewLoadTableSingle(ad address.Address, sz int32) LoadTable {
	return LoadTable{Addr: ad, Size: sz, Num: 1}
}

// NewLoadTable builds a full LoadTable entry.
// C++ parity: jumptable.hh LoadTable::LoadTable(const Address&,int4,int4)
func NewLoadTable(ad address.Address, sz, num int32) LoadTable {
	return LoadTable{Addr: ad, Size: sz, Num: num}
}

// Less orders LoadTable values by starting address.
// C++ parity: jumptable.hh LoadTable::operator<
func (lt LoadTable) Less(other LoadTable) bool {
	return lt.Addr.Less(other.Addr)
}

// CollapseLoadTables merges adjacent load table entries that are contiguous
// in memory and share an entry size. The slice is sorted in place and then
// compacted. C++ parity: jumptable.cc LoadTable::collapseTable
func CollapseLoadTables(table []LoadTable) []LoadTable {
	if len(table) < 2 {
		return table
	}
	sort.Slice(table, func(i, j int) bool { return table[i].Less(table[j]) })
	out := table[:1]
	for i := 1; i < len(table); i++ {
		last := &out[len(out)-1]
		cur := table[i]
		// Entries are mergeable when same size and contiguous offsets in
		// the same space. C++ walks the full set rather than adjacent
		// pairs but the effect is identical for sorted, non-overlapping
		// tables produced by the emulator.
		if last.Size == cur.Size &&
			last.Addr.Space == cur.Addr.Space &&
			last.Addr.Offset+uint64(last.Size)*uint64(last.Num) == cur.Addr.Offset {
			last.Num += cur.Num
			continue
		}
		out = append(out, cur)
	}
	return out
}

// -----------------------------------------------------------------------
// PathMeld
// -----------------------------------------------------------------------

// PathMeld collects every PcodeOp and Varnode on the set of data-flow paths
// from a putative switch variable to a BRANCHIND. The Varnodes in commonVn
// are shared by every path and are the candidate switch variables.
// C++ parity: jumptable.hh PathMeld
type PathMeld struct {
	commonVn []*Varnode
	opMeld   []pathMeldRootedOp
}

// pathMeldRootedOp pairs a PcodeOp with the index (in commonVn) of the
// shared Varnode at which its path diverged.
// C++ parity: jumptable.hh PathMeld::RootedOp
type pathMeldRootedOp struct {
	op     *PcodeOp
	rootVn int
}

// CopyFrom clones another PathMeld's contents into the receiver.
// C++ parity: jumptable.cc PathMeld::set(const PathMeld&)
func (pm *PathMeld) CopyFrom(other *PathMeld) {
	if other == nil {
		pm.commonVn = nil
		pm.opMeld = nil
		return
	}
	pm.commonVn = append(pm.commonVn[:0], other.commonVn...)
	pm.opMeld = append(pm.opMeld[:0], other.opMeld...)
}

// SetSingle initialises the container as a single node "path" holding op
// rooted at vn. C++ parity: jumptable.cc PathMeld::set(PcodeOp*,Varnode*)
func (pm *PathMeld) SetSingle(op *PcodeOp, vn *Varnode) {
	pm.commonVn = pm.commonVn[:0]
	pm.opMeld = pm.opMeld[:0]
	if vn != nil {
		pm.commonVn = append(pm.commonVn, vn)
	}
	if op != nil {
		pm.opMeld = append(pm.opMeld, pathMeldRootedOp{op: op, rootVn: 0})
	}
}

// Clear empties the PathMeld container.
// C++ parity: jumptable.cc PathMeld::clear
func (pm *PathMeld) Clear() {
	pm.commonVn = pm.commonVn[:0]
	pm.opMeld = pm.opMeld[:0]
}

// NumCommonVarnode returns the number of Varnodes shared by every tracked
// path. C++ parity: jumptable.hh PathMeld::numCommonVarnode
func (pm *PathMeld) NumCommonVarnode() int { return len(pm.commonVn) }

// NumOps returns the number of PcodeOps across all tracked paths.
// C++ parity: jumptable.hh PathMeld::numOps
func (pm *PathMeld) NumOps() int { return len(pm.opMeld) }

// Varnode returns the i-th common Varnode.
// C++ parity: jumptable.hh PathMeld::getVarnode
func (pm *PathMeld) Varnode(i int) *Varnode { return pm.commonVn[i] }

// Op returns the i-th PcodeOp in the meld.
// C++ parity: jumptable.hh PathMeld::getOp
func (pm *PathMeld) Op(i int) *PcodeOp { return pm.opMeld[i].op }

// OpParent returns the split-point common Varnode for the i-th PcodeOp.
// C++ parity: jumptable.hh PathMeld::getOpParent
func (pm *PathMeld) OpParent(i int) *Varnode { return pm.commonVn[pm.opMeld[i].rootVn] }

// Empty reports whether the PathMeld has been populated.
// C++ parity: jumptable.hh PathMeld::empty
func (pm *PathMeld) Empty() bool { return len(pm.commonVn) == 0 }

// Meld folds another path into the receiver.
// C++ parity: jumptable.cc PathMeld::meld
//
// TODO: depends on PcodeOpNode (not yet ported) and internalIntersect.
// Follow-up batch: port jumptable.cc PathMeld::internalIntersect,
// PathMeld::meldOps, PathMeld::truncatePaths in a single pass.
func (pm *PathMeld) Meld(_ []*PcodeOp) {
	// TODO mismatch: PathMeld::meld full intersection logic is stubbed;
	// JumpBasic::findDeterminingVarnodes cannot currently consume multi
	// path switches without this.
}

// MarkPaths walks back from startVarnode and toggles a mark bit on every
// PcodeOp reachable through the common Varnodes.
// C++ parity: jumptable.cc PathMeld::markPaths
//
// TODO: depends on PcodeOp mark flags being wired into the rest of the
// switch recovery pipeline; no caller exists yet in Go.
func (pm *PathMeld) MarkPaths(_ bool, _ int) {
	// TODO mismatch: PathMeld::markPaths not yet needed; added as stub
	// to match the C++ API surface.
}

// -----------------------------------------------------------------------
// GuardRecord
// -----------------------------------------------------------------------

// GuardRecord describes a CBRANCH that constrains the range of a candidate
// switch variable on the path reaching the BRANCHIND.
// C++ parity: jumptable.hh GuardRecord
//
// The Range field normally holds a rangeutil.hh CircleRange, but CircleRange
// has not been ported to Go yet. The field is typed as RawCircleRange, a
// stub that stores the range bounds as raw uintb values so downstream code
// can read them once CircleRange lands.
type GuardRecord struct {
	CBranch        *PcodeOp // the CBRANCH whose taken-path reaches the switch
	ReadOp         *PcodeOp // the immediate PcodeOp causing the restriction
	Vn             *Varnode // the Varnode being restricted
	BaseVn         *Varnode // value being (quasi)copied into Vn
	IndPath        int32    // which CBRANCH out-edge reaches the switch
	BitsPreserved  int32    // number of low bits copied (others are zero)
	Range          RawCircleRange
	Unrolled       bool // guarding CBRANCH duplicated across multiple blocks
}

// RawCircleRange is a placeholder for rangeutil.hh CircleRange. It holds
// minimal inclusive bounds so guard records can round-trip through the
// JumpTable container until the real CircleRange port lands.
// C++ parity: rangeutil.hh CircleRange (not yet ported)
//
// TODO mismatch: CircleRange supports wrap-around arcs, step counting, and
// pullBackOp bit-width arithmetic. RawCircleRange captures none of that.
type RawCircleRange struct {
	Min  uint64
	Max  uint64
	Mask uint64
	Step uint32
}

// NewGuardRecord builds a GuardRecord with the given fields.
// C++ parity: jumptable.cc GuardRecord::GuardRecord
func NewGuardRecord(bOp, rOp *PcodeOp, path int32, rng RawCircleRange, vn *Varnode, unrolled bool) *GuardRecord {
	return &GuardRecord{
		CBranch:  bOp,
		ReadOp:   rOp,
		IndPath:  path,
		Range:    rng,
		Vn:       vn,
		Unrolled: unrolled,
	}
}

// IsUnrolled reports whether the guarding CBRANCH is duplicated across
// multiple blocks. C++ parity: jumptable.hh GuardRecord::isUnrolled
func (g *GuardRecord) IsUnrolled() bool { return g.Unrolled }

// Clear marks the guard as unused (the clear-by-null pattern from C++).
// C++ parity: jumptable.hh GuardRecord::clear
func (g *GuardRecord) Clear() { g.CBranch = nil }

// -----------------------------------------------------------------------
// EmulateFunction (stub)
// -----------------------------------------------------------------------

// EmulateFunction is the light-weight emulator used by JumpBasic to walk a
// jump-table computation: it flows a single switch value through the p-code
// ops on the meld path to the final BRANCHIND input. It merges Ghidra's
// EmulatePcodeOp (single-op execution over a local varnode value map) and
// EmulateFunction (path stepping + load-point collection); the opcode dispatch
// and per-op execution live in emulate.go.
// C++ parity: emulateutil.hh EmulatePcodeOp + jumptable.hh EmulateFunction.
type EmulateFunction struct {
	fd         *Funcdata
	loadPoints *[]LoadTable
	// varnodeMap holds emulated values for tree Varnodes. Within a syntax tree
	// a memory location is just a label, so values cannot be keyed by address.
	// C++ parity: EmulateFunction::varnodeMap.
	varnodeMap map[*Varnode]uint64
	currentOp  *PcodeOp // op currently being executed
	lastOp     *PcodeOp // previously executed op (for MULTIEQUAL edge selection)
}

// NewEmulateFunction creates an emulator tied to fd.
// C++ parity: jumptable.cc EmulateFunction::EmulateFunction
func NewEmulateFunction(fd *Funcdata) *EmulateFunction {
	return &EmulateFunction{fd: fd}
}

// SetLoadCollect attaches (or detaches) a LoadTable sink.
// C++ parity: jumptable.hh EmulateFunction::setLoadCollect
func (e *EmulateFunction) SetLoadCollect(dst *[]LoadTable) { e.loadPoints = dst }

// -----------------------------------------------------------------------
// JumpValues / JumpValuesRange
// -----------------------------------------------------------------------

// JumpValueNoLabel is reserved to mean "no label available" in JumpValues
// iteration. C++ parity: jumptable.hh JumpValues::NO_LABEL
const JumpValueNoLabel uint64 = 0xBAD1ABE1

// JumpValues iterates the candidate values a (normalized) switch variable
// can take. Implementations produce the start Varnode / PcodeOp for each
// value so the emulator can seed its state.
// C++ parity: jumptable.hh JumpValues
type JumpValues interface {
	Truncate(n int32)
	Size() uint64
	Contains(v uint64) bool
	InitializeForReading() bool
	Next() bool
	Value() uint64
	StartVarnode() *Varnode
	StartOp() *PcodeOp
	IsReversible() bool
	Clone() JumpValues
}

// JumpValuesRange is the single-entry switch variable iterator backed by a
// CircleRange. It is the common case used by JumpBasic.
// C++ parity: jumptable.hh JumpValuesRange
type JumpValuesRange struct {
	Range      circleRange
	NormVn     *Varnode
	StartOpPtr *PcodeOp
	cur        uint64
}

// NewJumpValuesRange constructs an iterator whose range starts out empty. The
// empty seed mirrors the C++ default-constructed CircleRange (isempty=true);
// without it the Go zero-value circleRange would be a non-empty, step-0 range
// and getSize would divide by zero.
func NewJumpValuesRange() *JumpValuesRange {
	return &JumpValuesRange{Range: circleRange{isempty: true}}
}

// SetRange assigns the normalized range.
// C++ parity: jumptable.hh JumpValuesRange::setRange
func (jv *JumpValuesRange) SetRange(r circleRange) { jv.Range = r }

// SetStartVn assigns the normalized switch Varnode.
// C++ parity: jumptable.hh JumpValuesRange::setStartVn
func (jv *JumpValuesRange) SetStartVn(vn *Varnode) { jv.NormVn = vn }

// SetStartOp assigns the starting PcodeOp.
// C++ parity: jumptable.hh JumpValuesRange::setStartOp
func (jv *JumpValuesRange) SetStartOp(op *PcodeOp) { jv.StartOpPtr = op }

// Truncate shortens the range so it holds exactly nm elements, preserving the
// start value and step. C++ parity: jumptable.cc JumpValuesRange::truncate.
func (jv *JumpValuesRange) Truncate(nm int32) {
	rangeSize := int32(64 - bits.LeadingZeros64(jv.Range.getMask()))
	rangeSize >>= 3
	left := jv.Range.getMin()
	step := jv.Range.getStep()
	right := (left + uint64(step)*uint64(nm)) & jv.Range.getMask()
	jv.Range.setRange(left, right, rangeSize, int32(step))
}

// Size returns the number of reachable values.
// C++ parity: jumptable.cc JumpValuesRange::getSize
func (jv *JumpValuesRange) Size() uint64 {
	return jv.Range.getSize()
}

// Contains tests whether v is inside the current range.
// C++ parity: jumptable.cc JumpValuesRange::contains
func (jv *JumpValuesRange) Contains(v uint64) bool {
	return jv.Range.contains(v)
}

// InitializeForReading starts an iteration over the range.
// C++ parity: jumptable.cc JumpValuesRange::initializeForReading
func (jv *JumpValuesRange) InitializeForReading() bool {
	if jv.Range.getSize() == 0 {
		return false
	}
	jv.cur = jv.Range.getMin()
	return true
}

// Next advances the iterator, returning false once the end is reached.
// C++ parity: jumptable.cc JumpValuesRange::next
func (jv *JumpValuesRange) Next() bool {
	next, ok := jv.Range.getNext(jv.cur)
	jv.cur = next
	return ok
}

// Value returns the current iterator value.
// C++ parity: jumptable.cc JumpValuesRange::getValue
func (jv *JumpValuesRange) Value() uint64 { return jv.cur }

// StartVarnode returns the starting Varnode for the current value.
// C++ parity: jumptable.cc JumpValuesRange::getStartVarnode
func (jv *JumpValuesRange) StartVarnode() *Varnode { return jv.NormVn }

// StartOp returns the starting PcodeOp for the current value.
// C++ parity: jumptable.cc JumpValuesRange::getStartOp
func (jv *JumpValuesRange) StartOp() *PcodeOp { return jv.StartOpPtr }

// IsReversible reports whether the current value can be back-propagated
// to a label. C++ parity: jumptable.hh JumpValuesRange::isReversible
func (jv *JumpValuesRange) IsReversible() bool { return true }

// Clone returns a shallow copy of the iterator.
// C++ parity: jumptable.cc JumpValuesRange::clone
func (jv *JumpValuesRange) Clone() JumpValues {
	cp := *jv
	return &cp
}

// -----------------------------------------------------------------------
// JumpModel interface
// -----------------------------------------------------------------------

// JumpModel is the interface implemented by every jump-table execution
// model. The C++ class hierarchy is translated to a Go interface plus
// concrete types.
// C++ parity: jumptable.hh JumpModel
type JumpModel interface {
	IsOverride() bool
	TableSize() int
	RecoverModel(fd *Funcdata, indop *PcodeOp, matchSize, maxTableSize uint32) bool
	BuildAddresses(fd *Funcdata, indop *PcodeOp, addressTable *[]address.Address,
		loadPoints *[]LoadTable, loadCounts *[]int32)
	FindUnnormalized(maxAddSub, maxLeftRight, maxExt uint32)
	BuildLabels(fd *Funcdata, addressTable []address.Address, labels *[]uint64, orig JumpModel)
	FoldInNormalization(fd *Funcdata, indop *PcodeOp) *Varnode
	FoldInGuards(fd *Funcdata, jt *JumpTable) bool
	SanityCheck(fd *Funcdata, indop *PcodeOp, addressTable *[]address.Address,
		loadPoints *[]LoadTable, loadCounts *[]int32) bool
	Clone(jt *JumpTable) JumpModel
	Clear()
}

// -----------------------------------------------------------------------
// JumpModelTrivial
// -----------------------------------------------------------------------

// JumpModelTrivial treats the BRANCHIND input as the switch variable and
// uses the existing block structure to enumerate destinations. It is the
// fallback when the normalisation pipeline could not recover a model.
// C++ parity: jumptable.hh JumpModelTrivial
type JumpModelTrivial struct {
	jt   *JumpTable
	size uint32
}

// NewJumpModelTrivial constructs a trivial model under the given table.
// C++ parity: jumptable.hh JumpModelTrivial::JumpModelTrivial
func NewJumpModelTrivial(jt *JumpTable) *JumpModelTrivial {
	return &JumpModelTrivial{jt: jt}
}

// IsOverride reports whether the model was manually overridden.
// C++ parity: jumptable.hh JumpModelTrivial::isOverride
func (m *JumpModelTrivial) IsOverride() bool { return false }

// TableSize returns the reported address table size.
// C++ parity: jumptable.hh JumpModelTrivial::getTableSize
func (m *JumpModelTrivial) TableSize() int { return int(m.size) }

// RecoverModel inspects the BRANCHIND's parent block and stores the out
// edge count as the reachable table size.
// C++ parity: jumptable.cc JumpModelTrivial::recoverModel
func (m *JumpModelTrivial) RecoverModel(_ *Funcdata, indop *PcodeOp, _ uint32, maxTableSize uint32) bool {
	if indop == nil {
		return false
	}
	parent := indop.Parent()
	if parent == nil {
		return false
	}
	sz := uint32(parent.SizeOut())
	if sz > maxTableSize {
		return false
	}
	m.size = sz
	return sz > 0
}

// BuildAddresses appends the starting address of each out-edge basic block.
// C++ parity: jumptable.cc JumpModelTrivial::buildAddresses
func (m *JumpModelTrivial) BuildAddresses(_ *Funcdata, indop *PcodeOp, addressTable *[]address.Address,
	_ *[]LoadTable, loadCounts *[]int32) {
	*addressTable = (*addressTable)[:0]
	if indop == nil {
		return
	}
	parent := indop.Parent()
	if parent == nil {
		return
	}
	for i := 0; i < parent.SizeOut(); i++ {
		out := parent.OutEdge(i).Point
		if out == nil {
			continue
		}
		// Use the concrete BlockBasic's first op address as the block
		// start; this mirrors FlowBlock::getStart() for basic blocks.
		if bb, ok := out.Concrete().(*BlockBasic); ok && bb.FirstOp() != nil {
			*addressTable = append(*addressTable, bb.FirstOp().Addr())
		} else {
			*addressTable = append(*addressTable, address.Address{})
		}
		if loadCounts != nil {
			*loadCounts = append(*loadCounts, 0)
		}
	}
}

// FindUnnormalized is a no-op for the trivial model.
// C++ parity: jumptable.hh JumpModelTrivial::findUnnormalized
func (m *JumpModelTrivial) FindUnnormalized(_, _, _ uint32) {}

// BuildLabels assigns sequential labels.
// C++ parity: jumptable.cc JumpModelTrivial::buildLabels
func (m *JumpModelTrivial) BuildLabels(_ *Funcdata, addressTable []address.Address, labels *[]uint64, _ JumpModel) {
	*labels = (*labels)[:0]
	for i := range addressTable {
		*labels = append(*labels, uint64(i))
	}
}

// FoldInNormalization returns nil; trivial model has nothing to fold.
// C++ parity: jumptable.hh JumpModelTrivial::foldInNormalization
func (m *JumpModelTrivial) FoldInNormalization(_ *Funcdata, _ *PcodeOp) *Varnode { return nil }

// FoldInGuards returns false; trivial model has no guards.
// C++ parity: jumptable.hh JumpModelTrivial::foldInGuards
func (m *JumpModelTrivial) FoldInGuards(_ *Funcdata, _ *JumpTable) bool { return false }

// SanityCheck always passes for the trivial model.
// C++ parity: jumptable.hh JumpModelTrivial::sanityCheck
func (m *JumpModelTrivial) SanityCheck(_ *Funcdata, _ *PcodeOp, _ *[]address.Address,
	_ *[]LoadTable, _ *[]int32) bool {
	return true
}

// Clone produces an independent copy bound to jt.
// C++ parity: jumptable.cc JumpModelTrivial::clone
func (m *JumpModelTrivial) Clone(jt *JumpTable) JumpModel {
	return &JumpModelTrivial{jt: jt, size: m.size}
}

// Clear is a no-op for the trivial model.
// C++ parity: jumptable.hh JumpModelTrivial::clear
func (m *JumpModelTrivial) Clear() {}

// -----------------------------------------------------------------------
// JumpBasic
// -----------------------------------------------------------------------

// JumpBasic is the common straight-line switch model: one guarded range
// check feeds a straight-line computation that ends in the BRANCHIND.
// C++ parity: jumptable.hh JumpBasic
//
// Method bodies that require CircleRange / PathMeld.meld /
// EmulateFunction are TODO stubs. The struct layout and the interface
// wiring are fully real so downstream code (ActionSwitchNorm) can be
// upgraded in a follow-up batch without needing to re-plumb the JumpTable
// container.
type JumpBasic struct {
	jt            *JumpTable
	Range         *JumpValuesRange
	PathMeld      PathMeld
	SelectGuards  []*GuardRecord
	VarnodeIndex  int
	NormalVn      *Varnode
	SwitchVn      *Varnode
}

// NewJumpBasic constructs a JumpBasic bound to jt.
// C++ parity: jumptable.hh JumpBasic::JumpBasic
func NewJumpBasic(jt *JumpTable) *JumpBasic {
	return &JumpBasic{jt: jt}
}

// IsOverride is always false for JumpBasic.
// C++ parity: jumptable.hh JumpBasic::isOverride
func (m *JumpBasic) IsOverride() bool { return false }

// TableSize returns the range iterator's reported size.
// C++ parity: jumptable.hh JumpBasic::getTableSize
func (m *JumpBasic) TableSize() int {
	if m.Range == nil {
		return 0
	}
	return int(m.Range.Size())
}

// GetPathMeld returns the pointer to this model's PathMeld.
// C++ parity: jumptable.hh JumpBasic::getPathMeld
func (m *JumpBasic) GetPathMeld() *PathMeld { return &m.PathMeld }

// GetValueRange returns the normalized value iterator.
// C++ parity: jumptable.hh JumpBasic::getValueRange
func (m *JumpBasic) GetValueRange() *JumpValuesRange { return m.Range }

// RecoverModel walks back from indop to identify the normalized switch
// variable and the guards that constrain it.
// C++ parity: jumptable.cc JumpBasic::recoverModel
//
// TODO mismatch: findDeterminingVarnodes + findNormalized +
// markFoldableGuards require PathMeld.meld, CircleRange pull-back
// arithmetic, and CBRANCH guard analysis which are not yet ported.
// The method currently returns false so the outer JumpTable falls back
// to the trivial path.
func (m *JumpBasic) RecoverModel(_ *Funcdata, indop *PcodeOp, _ uint32, _ uint32) bool {
	if indop == nil || indop.NumInput() == 0 {
		return false
	}
	// Seed the PathMeld with the BRANCHIND input so downstream code
	// that only needs the entry Varnode still functions.
	m.PathMeld.SetSingle(indop, indop.Input(0))
	m.Range = NewJumpValuesRange()
	return false
}

// BuildAddresses is the emulation step that turns normalized switch
// values into actual target addresses.
// C++ parity: jumptable.cc JumpBasic::buildAddresses
//
// TODO mismatch: depends on EmulateFunction.EmulatePath, which is a stub.
func (m *JumpBasic) BuildAddresses(fd *Funcdata, _ *PcodeOp, addressTable *[]address.Address,
	loadPoints *[]LoadTable, loadCounts *[]int32) {
	*addressTable = (*addressTable)[:0]
	if m.Range == nil {
		return
	}
	emul := NewEmulateFunction(fd)
	emul.SetLoadCollect(loadPoints)
	notDone := m.Range.InitializeForReading()
	for notDone {
		_, err := emul.EmulatePath(m.Range.Value(), &m.PathMeld, m.Range.StartOp(), m.Range.StartVarnode())
		if err != nil {
			// Stub emulator: stop so we report an empty table and the
			// outer JumpTable falls through to the trivial path.
			return
		}
		// Real path would append the resulting address here.
		if loadCounts != nil && loadPoints != nil {
			*loadCounts = append(*loadCounts, int32(len(*loadPoints)))
		}
		notDone = m.Range.Next()
	}
}

// FindUnnormalized walks the PathMeld chain of common Varnodes to recover
// the "user-visible" switch variable (as opposed to the normalized form).
// C++ parity: jumptable.cc JumpBasic::findUnnormalized
//
// TODO mismatch: requires PathMeld population by findDeterminingVarnodes
// which is not yet functional.
func (m *JumpBasic) FindUnnormalized(_, _, _ uint32) {
	if m.PathMeld.NumCommonVarnode() == 0 {
		return
	}
	m.NormalVn = m.PathMeld.Varnode(m.VarnodeIndex)
	m.SwitchVn = m.NormalVn
}

// BuildLabels materialises the case label values.
// C++ parity: jumptable.cc JumpBasic::buildLabels
//
// TODO mismatch: requires CircleRange reverse walking for label inversion.
func (m *JumpBasic) BuildLabels(_ *Funcdata, addressTable []address.Address, labels *[]uint64, _ JumpModel) {
	*labels = (*labels)[:0]
	for i := range addressTable {
		*labels = append(*labels, uint64(i))
	}
}

// FoldInNormalization removes the normalisation ops from the data flow so
// the BRANCHIND appears to consume the switch variable directly.
// C++ parity: jumptable.cc JumpBasic::foldInNormalization
//
// TODO mismatch: requires Funcdata.opSetInput / opUnlink primitives to be
// audited for JumpTable usage. Returns the switch variable if recovered
// or nil otherwise.
func (m *JumpBasic) FoldInNormalization(_ *Funcdata, _ *PcodeOp) *Varnode {
	return m.SwitchVn
}

// FoldInGuards removes the guard branches from the CFG.
// C++ parity: jumptable.cc JumpBasic::foldInGuards
//
// TODO mismatch: requires foldInOneGuard which in turn drops CBRANCHes.
func (m *JumpBasic) FoldInGuards(_ *Funcdata, _ *JumpTable) bool { return false }

// SanityCheck asks the model to prune obviously-bad addresses.
// C++ parity: jumptable.cc JumpBasic::sanityCheck
func (m *JumpBasic) SanityCheck(_ *Funcdata, _ *PcodeOp, addressTable *[]address.Address,
	_ *[]LoadTable, _ *[]int32) bool {
	return len(*addressTable) > 0
}

// Clone copies this model into jt.
// C++ parity: jumptable.cc JumpBasic::clone
func (m *JumpBasic) Clone(jt *JumpTable) JumpModel {
	cp := &JumpBasic{jt: jt, VarnodeIndex: m.VarnodeIndex, NormalVn: m.NormalVn, SwitchVn: m.SwitchVn}
	if m.Range != nil {
		r := *m.Range
		cp.Range = &r
	}
	cp.PathMeld.CopyFrom(&m.PathMeld)
	cp.SelectGuards = append([]*GuardRecord(nil), m.SelectGuards...)
	return cp
}

// Clear drops the range, PathMeld, and guard list.
// C++ parity: jumptable.cc JumpBasic::clear
func (m *JumpBasic) Clear() {
	m.Range = nil
	m.PathMeld.Clear()
	m.SelectGuards = nil
	m.VarnodeIndex = 0
	m.NormalVn = nil
	m.SwitchVn = nil
}

// -----------------------------------------------------------------------
// JumpBasic2 (stub)
// -----------------------------------------------------------------------

// JumpBasic2 extends JumpBasic with a default-value path.
// C++ parity: jumptable.hh JumpBasic2
//
// TODO mismatch: the initializeStart/recoverModel/findUnnormalized logic
// needs CircleRange + PathMeld.meld to be real. The struct and interface
// wiring are present so downstream code can reference it without the port
// being complete.
type JumpBasic2 struct {
	JumpBasic
	ExtraVn      *Varnode
	OrigPathMeld PathMeld
}

// NewJumpBasic2 constructs an empty JumpBasic2.
// C++ parity: jumptable.hh JumpBasic2::JumpBasic2
func NewJumpBasic2(jt *JumpTable) *JumpBasic2 {
	return &JumpBasic2{JumpBasic: JumpBasic{jt: jt}}
}

// InitializeStart reuses a PathMeld computed by a previous JumpBasic.
// C++ parity: jumptable.cc JumpBasic2::initializeStart
func (m *JumpBasic2) InitializeStart(pm *PathMeld) { m.OrigPathMeld.CopyFrom(pm) }

// RecoverModel is a TODO stub.
// C++ parity: jumptable.cc JumpBasic2::recoverModel
func (m *JumpBasic2) RecoverModel(_ *Funcdata, _ *PcodeOp, _ uint32, _ uint32) bool {
	// TODO mismatch: JumpBasic2::recoverModel depends on checkNormalDominance
	// and CircleRange-aware path inspection.
	return false
}

// FindUnnormalized is a TODO stub.
// C++ parity: jumptable.cc JumpBasic2::findUnnormalized
func (m *JumpBasic2) FindUnnormalized(_, _, _ uint32) {
	// TODO mismatch: needs real JumpBasic.FindUnnormalized first.
}

// Clone copies this model into jt.
// C++ parity: jumptable.cc JumpBasic2::clone
func (m *JumpBasic2) Clone(jt *JumpTable) JumpModel {
	cp := &JumpBasic2{JumpBasic: JumpBasic{jt: jt}}
	cp.OrigPathMeld.CopyFrom(&m.OrigPathMeld)
	cp.ExtraVn = m.ExtraVn
	return cp
}

// Clear resets the extra-path state.
// C++ parity: jumptable.cc JumpBasic2::clear
func (m *JumpBasic2) Clear() {
	m.JumpBasic.Clear()
	m.ExtraVn = nil
	m.OrigPathMeld.Clear()
}

// -----------------------------------------------------------------------
// JumpBasicOverride (stub)
// -----------------------------------------------------------------------

// JumpBasicOverride is the manual-override variant. The destination set is
// provided externally (via JumpTable.SetOverride), not recovered from the
// function.
// C++ parity: jumptable.hh JumpBasicOverride
//
// TODO mismatch: findLikelyNorm / trialNorm / setupTrivial all need
// CircleRange and hash-based Varnode identification.
type JumpBasicOverride struct {
	JumpBasic
	AddrSet       map[address.Address]struct{}
	Values        []uint64
	AddrTable     []address.Address
	StartingValue uint64
	NormAddress   address.Address
	Hash          uint64
	IsTrivial     bool
}

// NewJumpBasicOverride constructs an empty override model.
// C++ parity: jumptable.cc JumpBasicOverride::JumpBasicOverride
func NewJumpBasicOverride(jt *JumpTable) *JumpBasicOverride {
	return &JumpBasicOverride{
		JumpBasic: JumpBasic{jt: jt},
		AddrSet:   make(map[address.Address]struct{}),
	}
}

// SetAddresses fixes the address table.
// C++ parity: jumptable.cc JumpBasicOverride::setAddresses
func (m *JumpBasicOverride) SetAddresses(addrs []address.Address) {
	m.AddrTable = append(m.AddrTable[:0], addrs...)
	m.AddrSet = make(map[address.Address]struct{}, len(addrs))
	for _, a := range addrs {
		m.AddrSet[a] = struct{}{}
	}
}

// SetNorm stores the normalised switch variable address and hash.
// C++ parity: jumptable.hh JumpBasicOverride::setNorm
func (m *JumpBasicOverride) SetNorm(addr address.Address, hash uint64) {
	m.NormAddress = addr
	m.Hash = hash
}

// SetStartingValue records the starting value for the normalised range.
// C++ parity: jumptable.hh JumpBasicOverride::setStartingValue
func (m *JumpBasicOverride) SetStartingValue(v uint64) { m.StartingValue = v }

// IsOverride is always true.
// C++ parity: jumptable.hh JumpBasicOverride::isOverride
func (m *JumpBasicOverride) IsOverride() bool { return true }

// TableSize returns the number of overridden addresses.
// C++ parity: jumptable.hh JumpBasicOverride::getTableSize
func (m *JumpBasicOverride) TableSize() int { return len(m.AddrTable) }

// RecoverModel is a TODO stub.
// C++ parity: jumptable.cc JumpBasicOverride::recoverModel
func (m *JumpBasicOverride) RecoverModel(_ *Funcdata, _ *PcodeOp, _ uint32, _ uint32) bool {
	// TODO mismatch: requires findLikelyNorm + trialNorm port.
	return len(m.AddrTable) > 0
}

// BuildAddresses copies the pre-populated table.
// C++ parity: jumptable.cc JumpBasicOverride::buildAddresses
func (m *JumpBasicOverride) BuildAddresses(_ *Funcdata, _ *PcodeOp, addressTable *[]address.Address,
	_ *[]LoadTable, _ *[]int32) {
	*addressTable = append((*addressTable)[:0], m.AddrTable...)
}

// BuildLabels reuses the stored values as labels.
// C++ parity: jumptable.cc JumpBasicOverride::buildLabels
func (m *JumpBasicOverride) BuildLabels(_ *Funcdata, _ []address.Address, labels *[]uint64, _ JumpModel) {
	*labels = append((*labels)[:0], m.Values...)
}

// FoldInGuards is always false for overrides.
// C++ parity: jumptable.hh JumpBasicOverride::foldInGuards
func (m *JumpBasicOverride) FoldInGuards(_ *Funcdata, _ *JumpTable) bool { return false }

// SanityCheck always passes for overrides.
// C++ parity: jumptable.hh JumpBasicOverride::sanityCheck
func (m *JumpBasicOverride) SanityCheck(_ *Funcdata, _ *PcodeOp, _ *[]address.Address,
	_ *[]LoadTable, _ *[]int32) bool {
	return true
}

// Clone copies this override into jt.
// C++ parity: jumptable.cc JumpBasicOverride::clone
func (m *JumpBasicOverride) Clone(jt *JumpTable) JumpModel {
	cp := NewJumpBasicOverride(jt)
	cp.SetAddresses(m.AddrTable)
	cp.Values = append(cp.Values[:0], m.Values...)
	cp.StartingValue = m.StartingValue
	cp.NormAddress = m.NormAddress
	cp.Hash = m.Hash
	cp.IsTrivial = m.IsTrivial
	return cp
}

// Clear drops state produced during recovery.
// C++ parity: jumptable.cc JumpBasicOverride::clear
func (m *JumpBasicOverride) Clear() {
	m.JumpBasic.Clear()
	m.Values = nil
}

// -----------------------------------------------------------------------
// JumpAssisted (stub)
// -----------------------------------------------------------------------

// JumpAssisted is driven by a `jumpassist` CALLOTHER pseudo-op that
// documents the case2index and index2address transforms.
// C++ parity: jumptable.hh JumpAssisted
//
// TODO mismatch: requires JumpAssistOp (userop.hh) and executable p-code
// exemplar interpretation. Unused by current downstream code.
type JumpAssisted struct {
	jt          *JumpTable
	AssistOp    *PcodeOp
	SwitchVn    *Varnode
	SizeIndices int32
}

// NewJumpAssisted constructs an empty assisted model.
// C++ parity: jumptable.hh JumpAssisted::JumpAssisted
func NewJumpAssisted(jt *JumpTable) *JumpAssisted { return &JumpAssisted{jt: jt} }

// IsOverride always returns false.
// C++ parity: jumptable.hh JumpAssisted::isOverride
func (m *JumpAssisted) IsOverride() bool { return false }

// TableSize reports the assisted table size.
// C++ parity: jumptable.hh JumpAssisted::getTableSize
func (m *JumpAssisted) TableSize() int { return int(m.SizeIndices + 1) }

// RecoverModel is a TODO stub.
// C++ parity: jumptable.cc JumpAssisted::recoverModel
func (m *JumpAssisted) RecoverModel(_ *Funcdata, _ *PcodeOp, _ uint32, _ uint32) bool {
	// TODO mismatch: requires JumpAssistOp lookup via userop manager.
	return false
}

// BuildAddresses is a TODO stub.
// C++ parity: jumptable.cc JumpAssisted::buildAddresses
func (m *JumpAssisted) BuildAddresses(_ *Funcdata, _ *PcodeOp, addressTable *[]address.Address,
	_ *[]LoadTable, _ *[]int32) {
	*addressTable = (*addressTable)[:0]
}

// FindUnnormalized is a no-op.
// C++ parity: jumptable.hh JumpAssisted::findUnnormalized
func (m *JumpAssisted) FindUnnormalized(_, _, _ uint32) {}

// BuildLabels is a TODO stub.
// C++ parity: jumptable.cc JumpAssisted::buildLabels
func (m *JumpAssisted) BuildLabels(_ *Funcdata, addressTable []address.Address, labels *[]uint64, _ JumpModel) {
	*labels = (*labels)[:0]
	for i := range addressTable {
		*labels = append(*labels, uint64(i))
	}
}

// FoldInNormalization is a TODO stub.
// C++ parity: jumptable.cc JumpAssisted::foldInNormalization
func (m *JumpAssisted) FoldInNormalization(_ *Funcdata, _ *PcodeOp) *Varnode { return m.SwitchVn }

// FoldInGuards is a TODO stub.
// C++ parity: jumptable.cc JumpAssisted::foldInGuards
func (m *JumpAssisted) FoldInGuards(_ *Funcdata, _ *JumpTable) bool { return false }

// SanityCheck always passes.
// C++ parity: jumptable.hh JumpAssisted::sanityCheck
func (m *JumpAssisted) SanityCheck(_ *Funcdata, _ *PcodeOp, _ *[]address.Address,
	_ *[]LoadTable, _ *[]int32) bool {
	return true
}

// Clone copies this assisted model into jt.
// C++ parity: jumptable.cc JumpAssisted::clone
func (m *JumpAssisted) Clone(jt *JumpTable) JumpModel {
	return &JumpAssisted{jt: jt, AssistOp: m.AssistOp, SwitchVn: m.SwitchVn, SizeIndices: m.SizeIndices}
}

// Clear drops cached lookups.
// C++ parity: jumptable.hh JumpAssisted::clear
func (m *JumpAssisted) Clear() {
	m.AssistOp = nil
	m.SwitchVn = nil
}

// -----------------------------------------------------------------------
// JumpTable recovery mode
// -----------------------------------------------------------------------

// JumpTableRecoveryMode mirrors JumpTable::RecoveryMode for the outer
// drive loop. C++ parity: jumptable.hh JumpTable::RecoveryMode
type JumpTableRecoveryMode int

const (
	JumpTableSuccess       JumpTableRecoveryMode = iota // RecoveryMode::success
	JumpTableFailNormal                                 // RecoveryMode::fail_normal
	JumpTableFailThunk                                  // RecoveryMode::fail_thunk
	JumpTableFailReturn                                 // RecoveryMode::fail_return
	JumpTableFailCallOther                              // RecoveryMode::fail_callother
)

// -----------------------------------------------------------------------
// JumpTable
// -----------------------------------------------------------------------

// IndexPair associates an out-edge position with an address table index.
// C++ parity: jumptable.hh JumpTable::IndexPair
type IndexPair struct {
	BlockPosition int32
	AddressIndex  int32
}

// indexPairLess implements JumpTable::IndexPair::operator<.
// C++ parity: jumptable.hh JumpTable::IndexPair::operator<
func indexPairLess(a, b IndexPair) bool {
	if a.BlockPosition != b.BlockPosition {
		return a.BlockPosition < b.BlockPosition
	}
	return a.AddressIndex < b.AddressIndex
}

// JumpTable maps computed-jump values to control flow targets.
// C++ parity: jumptable.hh JumpTable
type JumpTable struct {
	jmodel           JumpModel
	origModel        JumpModel
	addressTable     []address.Address
	block2Addr       []IndexPair
	label            []uint64
	loadPoints       []LoadTable
	opAddress        address.Address
	indirect         *PcodeOp
	switchVarConsume uint64
	defaultBlock     int32
	lastBlock        int32
	maxAddSub        uint32
	maxLeftRight     uint32
	maxExt           uint32
	displayFormat    uint32
	partialTable     bool
	collectLoads     bool
	defaultIsFolded  bool
}

// NewJumpTable constructs an empty jump-table tied to the BRANCHIND at ad.
// C++ parity: jumptable.cc JumpTable::JumpTable(Address)
func NewJumpTable(ad address.Address) *JumpTable {
	return &JumpTable{
		opAddress:        ad,
		switchVarConsume: ^uint64(0),
		defaultBlock:     -1,
		lastBlock:        -1,
		maxAddSub:        1,
		maxLeftRight:     1,
		maxExt:           1,
	}
}

// CloneJumpTable is the "partial clone" constructor used during multistage
// recovery: the address table and load points are copied, but anything
// tied to a specific Funcdata is reset.
// C++ parity: jumptable.cc JumpTable::JumpTable(const JumpTable*)
func CloneJumpTable(op2 *JumpTable) *JumpTable {
	jt := &JumpTable{
		switchVarConsume: ^uint64(0),
		defaultBlock:     -1,
		lastBlock:        op2.lastBlock,
		maxAddSub:        op2.maxAddSub,
		maxLeftRight:     op2.maxLeftRight,
		maxExt:           op2.maxExt,
		displayFormat:    op2.displayFormat,
		partialTable:     op2.partialTable,
		collectLoads:     op2.collectLoads,
		addressTable:     append([]address.Address(nil), op2.addressTable...),
		loadPoints:       append([]LoadTable(nil), op2.loadPoints...),
		opAddress:        op2.opAddress,
	}
	if op2.jmodel != nil {
		jt.jmodel = op2.jmodel.Clone(jt)
	}
	return jt
}

// IsRecovered reports whether the address table has been populated.
// C++ parity: jumptable.hh JumpTable::isRecovered
func (jt *JumpTable) IsRecovered() bool { return len(jt.addressTable) > 0 }

// IsLabelled reports whether the case labels have been computed.
// C++ parity: jumptable.hh JumpTable::isLabelled
func (jt *JumpTable) IsLabelled() bool { return len(jt.label) > 0 }

// IsOverride reports whether the model is an override variant.
// C++ parity: jumptable.cc JumpTable::isOverride
func (jt *JumpTable) IsOverride() bool {
	if jt.jmodel == nil {
		return false
	}
	return jt.jmodel.IsOverride()
}

// IsPartial reports whether the table is still marked incomplete.
// C++ parity: jumptable.hh JumpTable::isPartial
func (jt *JumpTable) IsPartial() bool { return jt.partialTable }

// MarkComplete flips the partial flag off.
// C++ parity: jumptable.hh JumpTable::markComplete
func (jt *JumpTable) MarkComplete() { jt.partialTable = false }

// NumEntries returns the address table size.
// C++ parity: jumptable.hh JumpTable::numEntries
func (jt *JumpTable) NumEntries() int { return len(jt.addressTable) }

// SwitchVarConsume returns the mask of bits actually consumed.
// C++ parity: jumptable.hh JumpTable::getSwitchVarConsume
func (jt *JumpTable) SwitchVarConsume() uint64 { return jt.switchVarConsume }

// DefaultBlock returns the default out-edge index (or -1).
// C++ parity: jumptable.hh JumpTable::getDefaultBlock
func (jt *JumpTable) DefaultBlock() int32 { return jt.defaultBlock }

// OpAddress returns the address of the BRANCHIND being modelled.
// C++ parity: jumptable.hh JumpTable::getOpAddress
func (jt *JumpTable) OpAddress() address.Address { return jt.opAddress }

// IndirectOp returns the linked BRANCHIND PcodeOp.
// C++ parity: jumptable.hh JumpTable::getIndirectOp
func (jt *JumpTable) IndirectOp() *PcodeOp { return jt.indirect }

// SetIndirectOp binds a BRANCHIND and takes its address.
// C++ parity: jumptable.hh JumpTable::setIndirectOp
func (jt *JumpTable) SetIndirectOp(op *PcodeOp) {
	if op == nil {
		return
	}
	jt.opAddress = op.Addr()
	jt.indirect = op
}

// SetNormMax sets the normalisation arithmetic budget.
// C++ parity: jumptable.hh JumpTable::setNormMax
func (jt *JumpTable) SetNormMax(addSub, leftRight, ext uint32) {
	jt.maxAddSub = addSub
	jt.maxLeftRight = leftRight
	jt.maxExt = ext
}

// DisplayFormat returns the integer case display format.
// C++ parity: jumptable.hh JumpTable::getDisplayFormat
func (jt *JumpTable) DisplayFormat() uint32 { return jt.displayFormat }

// SetDisplayFormat assigns the integer case display format.
// C++ parity: jumptable.hh JumpTable::setDisplayFormat
func (jt *JumpTable) SetDisplayFormat(f uint32) { jt.displayFormat = f }

// AddressByIndex returns the i-th address table entry.
// C++ parity: jumptable.hh JumpTable::getAddressByIndex
func (jt *JumpTable) AddressByIndex(i int) address.Address { return jt.addressTable[i] }

// SetLastAsDefault marks the last out-edge as the default target.
// C++ parity: jumptable.cc JumpTable::setLastAsDefault
func (jt *JumpTable) SetLastAsDefault() { jt.defaultBlock = jt.lastBlock }

// SetDefaultBlock assigns the default out-edge explicitly.
// C++ parity: jumptable.hh JumpTable::setDefaultBlock
func (jt *JumpTable) SetDefaultBlock(b int32) { jt.defaultBlock = b }

// SetLoadCollect toggles LOAD tracking.
// C++ parity: jumptable.hh JumpTable::setLoadCollect
func (jt *JumpTable) SetLoadCollect(v bool) { jt.collectLoads = v }

// SetFoldedDefault flags the default block as folded CBRANCH target.
// C++ parity: jumptable.hh JumpTable::setFoldedDefault
func (jt *JumpTable) SetFoldedDefault() { jt.defaultIsFolded = true }

// HasFoldedDefault reports the folded-default flag.
// C++ parity: jumptable.hh JumpTable::hasFoldedDefault
func (jt *JumpTable) HasFoldedDefault() bool { return jt.defaultIsFolded }

// LabelByIndex returns the case label stored for index i.
// C++ parity: jumptable.hh JumpTable::getLabelByIndex
func (jt *JumpTable) LabelByIndex(i int) uint64 { return jt.label[i] }

// LoadPoints returns the collected LoadTable slice (read-only view).
// C++ parity accessor complementing the JumpTable encoder path.
func (jt *JumpTable) LoadPoints() []LoadTable { return jt.loadPoints }

// JumpModel returns the current model (may be nil).
// C++ parity accessor for jumptable.cc code that reads jmodel directly.
func (jt *JumpTable) JumpModel() JumpModel { return jt.jmodel }

// AddBlockToSwitch appends a synthetic destination (used when a guard
// block should also be recorded as a switch target).
// C++ parity: jumptable.cc JumpTable::addBlockToSwitch
func (jt *JumpTable) AddBlockToSwitch(bl *BlockBasic, lab uint64) {
	if bl == nil || jt.indirect == nil {
		return
	}
	start := address.Address{}
	if bl.FirstOp() != nil {
		start = bl.FirstOp().Addr()
	}
	jt.addressTable = append(jt.addressTable, start)
	parent := jt.indirect.Parent()
	if parent != nil {
		jt.lastBlock = int32(parent.SizeOut())
	}
	jt.block2Addr = append(jt.block2Addr, IndexPair{BlockPosition: jt.lastBlock, AddressIndex: int32(len(jt.addressTable) - 1)})
	jt.label = append(jt.label, lab)
}

// NumIndicesByBlock counts the address table entries that target bl.
// C++ parity: jumptable.cc JumpTable::numIndicesByBlock
func (jt *JumpTable) NumIndicesByBlock(bl *FlowBlock) int {
	pos, err := jt.block2Position(bl)
	if err != nil {
		return 0
	}
	count := 0
	for _, ip := range jt.block2Addr {
		if ip.BlockPosition == pos {
			count++
		}
	}
	return count
}

// IndexByBlock returns the i-th address table index that targets bl.
// C++ parity: jumptable.cc JumpTable::getIndexByBlock
func (jt *JumpTable) IndexByBlock(bl *FlowBlock, i int) (int32, error) {
	pos, err := jt.block2Position(bl)
	if err != nil {
		return -1, err
	}
	count := 0
	for _, ip := range jt.block2Addr {
		if ip.BlockPosition != pos {
			continue
		}
		if count == i {
			return ip.AddressIndex, nil
		}
		count++
	}
	return -1, fmt.Errorf("%w: block has no jumptable entry", JumptableRecoveryError)
}

// block2Position walks the parent block's out-edges to find which edge
// hits bl. C++ parity: jumptable.cc JumpTable::block2Position
func (jt *JumpTable) block2Position(bl *FlowBlock) (int32, error) {
	if jt.indirect == nil || bl == nil {
		return -1, fmt.Errorf("%w: block2Position called before indirect bound", JumptableRecoveryError)
	}
	parent := jt.indirect.Parent()
	if parent == nil {
		return -1, fmt.Errorf("%w: BRANCHIND has no parent block", JumptableRecoveryError)
	}
	// parent is *BlockBasic whose FlowBlock is embedded; compare pointers
	// through the BlockEdge.Point field on bl's incoming edges.
	for pos := 0; pos < bl.SizeIn(); pos++ {
		if bl.InEdge(pos).Point == &parent.FlowBlock {
			return int32(bl.InRevIndex(pos)), nil
		}
	}
	return -1, fmt.Errorf("%w: requested block not in jumptable", JumptableRecoveryError)
}

// isReachable is the shallow reachability check from C++: follow single
// predecessors up to two levels looking for a collapsed guard.
// C++ parity: jumptable.cc JumpTable::isReachable
func jumpTableIsReachable(op *PcodeOp) bool {
	if op == nil {
		return false
	}
	parent := op.Parent()
	for depth := 0; depth < 2; depth++ {
		if parent == nil || parent.SizeIn() != 1 {
			return true
		}
		predEdge := parent.InEdge(0).Point
		if predEdge == nil {
			return true
		}
		predBB, ok := predEdge.Concrete().(*BlockBasic)
		if !ok || predBB.SizeOut() != 2 {
			if predBB != nil {
				parent = predBB
			}
			continue
		}
		cbranch := predBB.LastOp()
		if cbranch == nil || cbranch.Code() != CPUI_CBRANCH {
			parent = predBB
			continue
		}
		cond := cbranch.Input(1)
		if cond == nil || !cond.IsConstant() {
			parent = predBB
			continue
		}
		trueSlot := 1
		if cbranch.HasFlag(PcodeOpBooleanFlip) {
			trueSlot = 0
		}
		if cond.Offset() == 0 {
			trueSlot = 1 - trueSlot
		}
		takenEdge := predBB.OutEdge(trueSlot).Point
		if takenEdge != &parent.FlowBlock {
			return false
		}
		parent = predBB
	}
	return true
}

// IsReachable exposes the shallow reachability helper.
// C++ parity: jumptable.cc JumpTable::isReachable
func (jt *JumpTable) IsReachable() bool { return jumpTableIsReachable(jt.indirect) }

// RecoverModel runs through the model candidates in order until one
// accepts the BRANCHIND.
// C++ parity: jumptable.cc JumpTable::recoverModel
func (jt *JumpTable) RecoverModel(fd *Funcdata) {
	const defaultMaxTable = 1024 // C++ uses Architecture::max_jumptable_size
	if jt.jmodel != nil {
		if jt.jmodel.IsOverride() {
			jt.jmodel.RecoverModel(fd, jt.indirect, 0, defaultMaxTable)
			return
		}
		jt.jmodel = nil
	}
	if jt.indirect == nil || jt.indirect.NumInput() == 0 {
		return
	}
	vn := jt.indirect.Input(0)
	if vn != nil && vn.IsWritten() {
		op := vn.Def()
		if op != nil && op.Code() == CPUI_CALLOTHER {
			jassist := NewJumpAssisted(jt)
			jt.jmodel = jassist
			if jassist.RecoverModel(fd, jt.indirect, uint32(len(jt.addressTable)), defaultMaxTable) {
				return
			}
		}
	}
	jbasic := NewJumpBasic(jt)
	jt.jmodel = jbasic
	if jbasic.RecoverModel(fd, jt.indirect, uint32(len(jt.addressTable)), defaultMaxTable) {
		return
	}
	j2 := NewJumpBasic2(jt)
	j2.InitializeStart(jbasic.GetPathMeld())
	jt.jmodel = j2
	if j2.RecoverModel(fd, jt.indirect, uint32(len(jt.addressTable)), defaultMaxTable) {
		return
	}
	// Fall back to trivial so downstream code can at least enumerate
	// out-edges until the JumpBasic body is ported.
	triv := NewJumpModelTrivial(jt)
	if triv.RecoverModel(fd, jt.indirect, 0, defaultMaxTable) {
		jt.jmodel = triv
		return
	}
	jt.jmodel = nil
}

// RecoverAddresses runs the first-stage recovery (model + address table +
// sanity check). The heavy lifting in buildAddresses and sanityCheck is
// delegated to the current model.
// C++ parity: jumptable.cc JumpTable::recoverAddresses
func (jt *JumpTable) RecoverAddresses(fd *Funcdata) error {
	jt.RecoverModel(fd)
	if jt.jmodel == nil {
		return fmt.Errorf("%w: could not recover jumptable at %s (too many branches)",
			JumptableRecoveryError, jt.opAddress)
	}
	if jt.jmodel.TableSize() == 0 {
		return fmt.Errorf("%w: jumptable with 0 entries at %s",
			JumptableRecoveryError, jt.opAddress)
	}
	var loadCounts []int32
	if jt.collectLoads {
		jt.jmodel.BuildAddresses(fd, jt.indirect, &jt.addressTable, &jt.loadPoints, &loadCounts)
		if err := jt.sanityCheck(fd, &loadCounts); err != nil {
			return err
		}
		jt.loadPoints = CollapseLoadTables(jt.loadPoints)
	} else {
		jt.jmodel.BuildAddresses(fd, jt.indirect, &jt.addressTable, nil, nil)
		if err := jt.sanityCheck(fd, nil); err != nil {
			return err
		}
	}
	return nil
}

// RecoverMultistage retries recovery while preserving a prior model so
// second-stage failures can roll back. C++ parity: jumptable.cc
// JumpTable::recoverMultistage
func (jt *JumpTable) RecoverMultistage(fd *Funcdata) {
	jt.saveModel()
	oldTable := append([]address.Address(nil), jt.addressTable...)
	jt.addressTable = jt.addressTable[:0]
	jt.loadPoints = jt.loadPoints[:0]
	if err := jt.RecoverAddresses(fd); err != nil {
		if errors.Is(err, JumptableThunkError) || errors.Is(err, JumptableRecoveryError) {
			jt.restoreSavedModel()
			jt.addressTable = oldTable
		}
	}
	jt.partialTable = false
	jt.clearSavedModel()
}

// sanityCheck runs the shallow reachability test, the thunk heuristic,
// and delegates to the current model's sanityCheck.
// C++ parity: jumptable.cc JumpTable::sanityCheck
func (jt *JumpTable) sanityCheck(fd *Funcdata, loadCounts *[]int32) error {
	if jt.jmodel.IsOverride() {
		return nil
	}
	if !jumpTableIsReachable(jt.indirect) {
		jt.partialTable = true
	}
	if len(jt.addressTable) == 1 {
		addr := jt.addressTable[0]
		isThunk := false
		if addr.Offset == 0 {
			isThunk = true
		} else if jt.indirect != nil {
			jumpAddr := jt.indirect.Addr()
			var diff uint64
			if addr.Offset < jumpAddr.Offset {
				diff = jumpAddr.Offset - addr.Offset
			} else {
				diff = addr.Offset - jumpAddr.Offset
			}
			if diff > 0xffff {
				isThunk = true
			}
		}
		if isThunk {
			return fmt.Errorf("%w: likely thunk", JumptableThunkError)
		}
	}
	if !jt.jmodel.SanityCheck(fd, jt.indirect, &jt.addressTable, &jt.loadPoints, loadCounts) {
		return fmt.Errorf("%w: jumptable at %s failed sanity check",
			JumptableRecoveryError, jt.opAddress)
	}
	return nil
}

// SwitchOver converts absolute addresses to block indices relative to the
// BRANCHIND parent block. Replaces the C++ FlowInfo::target lookup with a
// caller-supplied resolver because FlowInfo is not yet ported.
// C++ parity: jumptable.cc JumpTable::switchOver
//
// resolver maps an address to the PcodeOp starting the target basic block.
// A nil resolver forces the trivial switch-over path.
func (jt *JumpTable) SwitchOver(resolver func(address.Address) *PcodeOp) error {
	if resolver == nil {
		jt.trivialSwitchOver()
		return nil
	}
	if jt.indirect == nil {
		return fmt.Errorf("%w: SwitchOver before SetIndirectOp", JumptableRecoveryError)
	}
	parent := jt.indirect.Parent()
	if parent == nil {
		return fmt.Errorf("%w: BRANCHIND has no parent", JumptableRecoveryError)
	}
	jt.block2Addr = jt.block2Addr[:0]
	for i, addr := range jt.addressTable {
		op := resolver(addr)
		if op == nil {
			return fmt.Errorf("%w: jumptable destination %s not linked",
				JumptableRecoveryError, addr)
		}
		target := op.Parent()
		if target == nil {
			return fmt.Errorf("%w: jumptable destination op has no parent", JumptableRecoveryError)
		}
		pos := -1
		for p := 0; p < parent.SizeOut(); p++ {
			if parent.OutEdge(p).Point == &target.FlowBlock {
				pos = p
				break
			}
		}
		if pos < 0 {
			return fmt.Errorf("%w: jumptable destination not linked", JumptableRecoveryError)
		}
		jt.block2Addr = append(jt.block2Addr, IndexPair{BlockPosition: int32(pos), AddressIndex: int32(i)})
	}
	if len(jt.block2Addr) > 0 {
		jt.lastBlock = jt.block2Addr[len(jt.block2Addr)-1].BlockPosition
	}
	sort.Slice(jt.block2Addr, func(i, j int) bool { return indexPairLess(jt.block2Addr[i], jt.block2Addr[j]) })

	jt.defaultBlock = -1
	maxCount := 1
	for i := 0; i < len(jt.block2Addr); {
		cur := jt.block2Addr[i].BlockPosition
		j := i
		count := 0
		for j < len(jt.block2Addr) && jt.block2Addr[j].BlockPosition == cur {
			count++
			j++
		}
		if count > maxCount {
			maxCount = count
			jt.defaultBlock = cur
		}
		i = j
	}
	return nil
}

// trivialSwitchOver is the fallback path that pairs each out-edge of the
// BRANCHIND parent to one address table entry.
// C++ parity: jumptable.cc JumpTable::trivialSwitchOver
func (jt *JumpTable) trivialSwitchOver() {
	jt.block2Addr = jt.block2Addr[:0]
	if jt.indirect == nil {
		return
	}
	parent := jt.indirect.Parent()
	if parent == nil {
		return
	}
	if parent.SizeOut() != len(jt.addressTable) {
		// Diverging from C++ which throws here: we leave block2Addr empty
		// and rely on callers (ActionSwitchNorm) to detect the empty set.
		// TODO mismatch: should emit a Funcdata warning once those land.
		return
	}
	for i := 0; i < parent.SizeOut(); i++ {
		jt.block2Addr = append(jt.block2Addr, IndexPair{BlockPosition: int32(i), AddressIndex: int32(i)})
	}
	jt.lastBlock = int32(parent.SizeOut() - 1)
	jt.defaultBlock = -1
}

// FoldInNormalization hides the normalisation pcode from the CFG view.
// C++ parity: jumptable.cc JumpTable::foldInNormalization
func (jt *JumpTable) FoldInNormalization(fd *Funcdata) {
	if jt.jmodel == nil {
		return
	}
	switchVn := jt.jmodel.FoldInNormalization(fd, jt.indirect)
	if switchVn == nil {
		return
	}
	// C++ uses minimalmask/calc_mask to compute switchVarConsume. Those
	// helpers live in pcode support code; until they are wired up we
	// default to "all bits" which matches the C++ fallback arm.
	jt.switchVarConsume = ^uint64(0)
	_ = switchVn
	// TODO mismatch: minimalmask + calc_mask integration for
	// subvariable-flow hints after INT_SEXT is not implemented yet.
}

// FoldInGuards hides guard code paths.
// C++ parity: jumptable.hh JumpTable::foldInGuards
func (jt *JumpTable) FoldInGuards(fd *Funcdata) bool {
	if jt.jmodel == nil {
		return false
	}
	return jt.jmodel.FoldInGuards(fd, jt)
}

// Clear drops instance-specific recovery state.
// C++ parity: jumptable.cc JumpTable::clear
func (jt *JumpTable) Clear() {
	if jt.jmodel != nil {
		jt.jmodel.Clear()
	}
	jt.addressTable = nil
	jt.block2Addr = nil
	jt.label = nil
	jt.loadPoints = nil
	jt.switchVarConsume = ^uint64(0)
	jt.defaultBlock = -1
	jt.lastBlock = -1
	jt.partialTable = false
	jt.defaultIsFolded = false
}

// saveModel stashes the current model so a re-run can roll back.
// C++ parity: jumptable.cc JumpTable::saveModel
func (jt *JumpTable) saveModel() {
	jt.origModel = jt.jmodel
	jt.jmodel = nil
}

// restoreSavedModel reinstates a previously saved model.
// C++ parity: jumptable.cc JumpTable::restoreSavedModel
func (jt *JumpTable) restoreSavedModel() {
	if jt.origModel != nil {
		jt.jmodel = jt.origModel
		jt.origModel = nil
	}
}

// clearSavedModel drops any saved model pointer.
// C++ parity: jumptable.cc JumpTable::clearSavedModel
func (jt *JumpTable) clearSavedModel() { jt.origModel = nil }

// SetOverride installs a JumpBasicOverride with an externally provided
// address list. C++ parity: jumptable.cc JumpTable::setOverride
func (jt *JumpTable) SetOverride(addrTable []address.Address, normAddr address.Address, hash, startVal uint64) {
	ov := NewJumpBasicOverride(jt)
	ov.SetAddresses(addrTable)
	ov.SetNorm(normAddr, hash)
	ov.SetStartingValue(startVal)
	jt.jmodel = ov
}

// MatchModel attempts to recover the case labels now that the address
// table has been produced. C++ parity: jumptable.cc JumpTable::matchModel
//
// TODO mismatch: full matchModel depends on JumpBasic.findUnnormalized
// being real; until then we just ensure the model has a table size and
// leave label/unnormalized recovery to the follow-up batch.
func (jt *JumpTable) MatchModel(fd *Funcdata) {
	if jt.jmodel == nil {
		jt.RecoverModel(fd)
	}
}

// RecoverLabels builds case labels from the current model.
// C++ parity: jumptable.cc JumpTable::recoverLabels
func (jt *JumpTable) RecoverLabels(fd *Funcdata) {
	if jt.jmodel == nil {
		return
	}
	jt.jmodel.FindUnnormalized(jt.maxAddSub, jt.maxLeftRight, jt.maxExt)
	jt.jmodel.BuildLabels(fd, jt.addressTable, &jt.label, jt.jmodel)
}

// CheckForMultistage reports whether this table still needs another
// recovery pass. C++ parity: jumptable.cc JumpTable::checkForMultistage
//
// TODO mismatch: the C++ version inspects the switch block to decide
// whether a second-stage pass would help. We currently return the
// partialTable flag, which is the conservative approximation.
func (jt *JumpTable) CheckForMultistage(_ *Funcdata) bool { return jt.partialTable }
