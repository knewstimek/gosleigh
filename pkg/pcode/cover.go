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

// cover.go -- live-range tracking for Varnodes across basic blocks.
// C++ parity: cover.hh / cover.cc Cover, CoverBlock

// Special index values used in place of C++ pointer sentinels.
// C++ uses (uintm)0 for block-begin, ~(uintm)0 for block-end, (uintm)2 for input.
// We encode these as uint64 constants instead.
const (
	coverIndexBegin uint64 = 0              // block-start sentinel  (C++: ptr==0)
	coverIndexEnd   uint64 = ^uint64(0)     // block-end sentinel    (C++: ptr==1)
	coverIndexInput uint64 = 0              // function-input mark   (C++: ptr==2, same index as begin)
)

// getOpUIndex returns the comparison index of a PcodeOp for cover intersection.
// Mirrors CoverBlock::getUIndex from cover.cc.
//
// Rules (matching C++ semantics):
//   - nil op (representing "block begin") -> 0
//   - end sentinel (blockEndSentinel) -> MaxUint64
//   - MULTIEQUAL is considered block-begin (index 0)
//   - INDIRECT has the index of its causing op
//   - otherwise: op.Seq().Order
func getOpUIndex(op *PcodeOp) uint64 {
	if op == nil {
		return coverIndexBegin
	}
	if op == blockEndSentinel {
		return coverIndexEnd
	}
	if op.IsMarker() {
		if op.Code() == CPUI_MULTIEQUAL {
			return coverIndexBegin
		}
	}
	return op.Seq().Order
}

// blockEndSentinel is a package-level sentinel PcodeOp pointer used to mark
// "to the end of the block". It is never inserted into any live data structure.
// C++ parity: (PcodeOp *)1 sentinel in cover.hh CoverBlock::setAll / setEnd.
var blockEndSentinel = &PcodeOp{}

// CoverBlock tracks the live range of a variable within a single basic block.
// The range is from start (inclusive) to stop (inclusive).
// nil start means "from block beginning"; blockEndSentinel stop means "to block end".
//
// C++ parity: cover.hh CoverBlock
type CoverBlock struct {
	start *PcodeOp // nil = block start
	stop  *PcodeOp // blockEndSentinel = block end
}

// Empty returns true if the block has no coverage.
// C++ parity: CoverBlock::empty
func (cb *CoverBlock) Empty() bool {
	return cb.start == nil && cb.stop == nil
}

// SetAll marks the entire block as covered.
// C++ parity: CoverBlock::setAll
func (cb *CoverBlock) SetAll() {
	cb.start = nil
	cb.stop = blockEndSentinel
}

// SetBegin resets the start of the range; if stop is nil (empty), sets stop to end sentinel.
// C++ parity: CoverBlock::setBegin
func (cb *CoverBlock) SetBegin(begin *PcodeOp) {
	cb.start = begin
	if cb.stop == nil {
		cb.stop = blockEndSentinel
	}
}

// SetEnd resets the end of the range.
// C++ parity: CoverBlock::setEnd
func (cb *CoverBlock) SetEnd(end *PcodeOp) {
	cb.stop = end
}

// Contain returns true if the given op falls within this range.
// C++ parity: CoverBlock::contain
func (cb *CoverBlock) Contain(op *PcodeOp) bool {
	if cb.Empty() {
		return false
	}
	upoint := getOpUIndex(op)
	ustart := getOpUIndex(cb.start)
	ustop := getOpUIndex(cb.stop)
	if ustart <= ustop {
		return upoint >= ustart && upoint <= ustop
	}
	return upoint <= ustop || upoint >= ustart
}

// Boundary characterizes whether op is on a boundary of this range.
// Returns 0 if not on boundary, 1 if on tail (stop), 2 if on defining point (start).
// C++ parity: CoverBlock::boundary
func (cb *CoverBlock) Boundary(op *PcodeOp) int {
	if cb.Empty() {
		return 0
	}
	val := getOpUIndex(op)
	if getOpUIndex(cb.start) == val {
		if cb.start != nil {
			return 2
		}
	}
	if getOpUIndex(cb.stop) == val {
		return 1
	}
	return 0
}

// Intersect returns the intersection type with another CoverBlock.
// Returns 0 (no intersection), 1 (boundary only), or 2 (range intersection).
// C++ parity: CoverBlock::intersect
func (cb *CoverBlock) Intersect(op2 *CoverBlock) int {
	if cb.Empty() {
		return 0
	}
	if op2.Empty() {
		return 0
	}
	ustart := getOpUIndex(cb.start)
	ustop := getOpUIndex(cb.stop)
	u2start := getOpUIndex(op2.start)
	u2stop := getOpUIndex(op2.stop)

	if ustart <= ustop {
		if u2start <= u2stop {
			// Both one-piece
			if ustop <= u2start || u2stop <= ustart {
				if ustart == u2stop || ustop == u2start {
					return 1
				}
				return 0
			}
		} else {
			// They are two-piece, we are one-piece
			if ustart >= u2stop && ustop <= u2start {
				if ustart == u2stop || ustop == u2start {
					return 1
				}
				return 0
			}
		}
	} else {
		if u2start <= u2stop {
			// They are one-piece, we are two-piece
			if u2start >= ustop && u2stop <= ustart {
				if u2start == ustop || u2stop == ustart {
					return 1
				}
				return 0
			}
		}
		// Both two-piece: must be an interval intersection
	}
	return 2
}

// Merge computes the union of this CoverBlock with op2, replacing this in place.
// C++ parity: CoverBlock::merge
func (cb *CoverBlock) Merge(op2 *CoverBlock) {
	if op2.Empty() {
		return
	}
	if cb.Empty() {
		cb.start = op2.start
		cb.stop = op2.stop
		return
	}
	ustart := getOpUIndex(cb.start)
	u2start := getOpUIndex(op2.start)

	// Is our start inside op2?
	internal4 := ustart == 0 && op2.stop == blockEndSentinel
	internal1 := internal4 || op2.Contain(cb.start)
	// Is op2.start inside us?
	internal3 := u2start == 0 && cb.stop == blockEndSentinel
	internal2 := internal3 || cb.Contain(op2.start)

	if internal1 && internal2 {
		if ustart != u2start || internal3 || internal4 {
			cb.SetAll()
			return
		}
	}
	if internal1 {
		cb.start = op2.start // pick non-internal start
	} else if !internal1 && !internal2 {
		// Disjoint intervals: pick earliest start, take other stop
		if ustart < u2start {
			cb.stop = op2.stop
		} else {
			cb.start = op2.start
		}
		return
	}
	if internal3 || op2.Contain(cb.stop) {
		cb.stop = op2.stop
	}
}

// ---------------------------------------------------------------------------
// Cover
// ---------------------------------------------------------------------------

// Cover tracks the live range of a variable across all basic blocks.
// Internally stored as block-index -> CoverBlock map (sparse, only non-empty blocks present).
//
// C++ parity: cover.hh Cover
type Cover struct {
	blocks map[int32]*CoverBlock // block Index -> CoverBlock (nil map = empty)
}

// ensureMap initialises the map lazily.
func (c *Cover) ensureMap() {
	if c.blocks == nil {
		c.blocks = make(map[int32]*CoverBlock)
	}
}

// Clear removes all cover data.
// C++ parity: Cover::clear
func (c *Cover) Clear() {
	c.blocks = nil
}

// GetCoverBlock returns the CoverBlock for block i, or an empty one if absent.
// C++ parity: Cover::getCoverBlock
func (c *Cover) GetCoverBlock(i int32) *CoverBlock {
	if c.blocks == nil {
		return &CoverBlock{}
	}
	cb, ok := c.blocks[i]
	if !ok {
		return &CoverBlock{}
	}
	return cb
}

// getOrCreate returns the existing CoverBlock for block i, creating it if needed.
func (c *Cover) getOrCreate(i int32) *CoverBlock {
	c.ensureMap()
	cb, ok := c.blocks[i]
	if !ok {
		cb = &CoverBlock{}
		c.blocks[i] = cb
	}
	return cb
}

// Intersect returns the intersection type between this Cover and op2.
// Returns 0 (none), 1 (boundary only), or 2 (range overlap).
// C++ parity: Cover::intersect(const Cover&)
func (c *Cover) Intersect(op2 *Cover) int {
	res := 0
	if c.blocks == nil || op2.blocks == nil {
		return 0
	}
	// Parallel scan over sorted block indices.
	// For efficiency, iterate over the smaller map and look up in the larger.
	for idx, cb := range c.blocks {
		cb2, ok := op2.blocks[idx]
		if !ok {
			continue
		}
		newres := cb.Intersect(cb2)
		if newres == 2 {
			return 2
		}
		if newres == 1 {
			res = 1
		}
	}
	return res
}

// IntersectByBlock checks intersection only on a specific block.
// C++ parity: Cover::intersectByBlock
func (c *Cover) IntersectByBlock(blk int32, op2 *Cover) int {
	if c.blocks == nil || op2.blocks == nil {
		return 0
	}
	cb, ok := c.blocks[blk]
	if !ok {
		return 0
	}
	cb2, ok := op2.blocks[blk]
	if !ok {
		return 0
	}
	return cb.Intersect(cb2)
}

// Merge combines op2 into this Cover (union), block by block.
// C++ parity: Cover::merge
func (c *Cover) Merge(op2 *Cover) {
	if op2.blocks == nil {
		return
	}
	c.ensureMap()
	for idx, cb2 := range op2.blocks {
		cb, ok := c.blocks[idx]
		if !ok {
			// Copy the CoverBlock by value.
			copied := *cb2
			c.blocks[idx] = &copied
		} else {
			cb.Merge(cb2)
		}
	}
}

// AddDefPoint sets this Cover to the single-point where vn is defined.
// Clears any previous cover first.
// C++ parity: Cover::addDefPoint
func (c *Cover) AddDefPoint(vn *Varnode) {
	c.blocks = make(map[int32]*CoverBlock)
	def := vn.Def()
	if def != nil {
		bb := def.Parent()
		if bb == nil {
			return
		}
		cb := c.getOrCreate(bb.Index())
		cb.SetBegin(def)
		cb.SetEnd(def)
	} else if vn.IsInput() {
		// Input varnode: cover starts at the very beginning of block 0.
		// C++ uses special pointer value 2 to mark "input"; we use nil (same index 0).
		cb := c.getOrCreate(0)
		cb.SetBegin(nil)
		cb.SetEnd(nil)
	}
}

// addRefRecurse fills coverage backwards from bl until existing cover is found.
// C++ parity: Cover::addRefRecurse
func (c *Cover) addRefRecurse(bl *FlowBlock) {
	cb := c.getOrCreate(bl.Index())
	if cb.Empty() {
		cb.SetAll()
		for j := 0; j < bl.SizeIn(); j++ {
			c.addRefRecurse(bl.InEdge(j).Point)
		}
	} else {
		op := cb.stop
		ustart := getOpUIndex(cb.start)
		ustop := getOpUIndex(op)
		if ustop != coverIndexEnd && ustop >= ustart {
			cb.SetEnd(blockEndSentinel)
		}
		// If this block contains only an infinitesimal tip through a MULTIEQUAL branch,
		// recurse through predecessors.
		if ustop == 0 && cb.start == nil {
			if op != nil && op != blockEndSentinel && op.Code() == CPUI_MULTIEQUAL {
				for j := 0; j < bl.SizeIn(); j++ {
					c.addRefRecurse(bl.InEdge(j).Point)
				}
			}
		}
	}
}

// AddRefPoint adds the point where vn is read (by ref op) and fills coverage backwards.
// C++ parity: Cover::addRefPoint
func (c *Cover) AddRefPoint(ref *PcodeOp, vn *Varnode) {
	bl := ref.Parent()
	if bl == nil {
		return
	}
	cb := c.getOrCreate(bl.Index())
	if cb.Empty() {
		cb.SetEnd(ref)
	} else {
		if cb.Contain(ref) {
			if ref.Code() != CPUI_MULTIEQUAL {
				return
			}
			// MULTIEQUAL: may be adding new cover via a different branch, don't return.
		} else {
			startop := cb.start
			cb.SetEnd(ref)
			ustop := getOpUIndex(cb.stop)
			if ustop >= getOpUIndex(startop) {
				// Check the infinitesimal-tip case
				origStop := cb.stop
				_ = origStop
				if cb.stop != nil && cb.stop != blockEndSentinel &&
					cb.stop.Code() == CPUI_MULTIEQUAL && cb.start == nil {
					for j := 0; j < bl.SizeIn(); j++ {
						c.addRefRecurse(bl.InEdge(j).Point)
					}
				}
				return
			}
		}
	}
	if ref.Code() == CPUI_MULTIEQUAL {
		// Only recurse through the predecessor corresponding to our input slot.
		for j := 0; j < ref.NumInput(); j++ {
			if ref.Input(j) == vn {
				if j < bl.SizeIn() {
					c.addRefRecurse(bl.InEdge(j).Point)
				}
			}
		}
	} else {
		for j := 0; j < bl.SizeIn(); j++ {
			c.addRefRecurse(bl.InEdge(j).Point)
		}
	}
}

// Rebuild rebuilds this Cover from the def-use range of a single Varnode.
// C++ parity: Cover::rebuild
func (c *Cover) Rebuild(vn *Varnode) {
	c.AddDefPoint(vn)
	for _, op := range vn.DescendIter() {
		c.AddRefPoint(op, vn)
	}
}
