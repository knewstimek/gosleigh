package pcode

import (
	"sort"

	"gosleigh/pkg/address"
)

// ---------------------------------------------------------------------------
// SizePass -- records the size and pass number of a heritaged range.
// C++ parity: heritage.hh LocationMap inner type
// ---------------------------------------------------------------------------

// SizePass records the size and pass number of a heritaged range.
type SizePass struct {
	Size int32
	Pass int32
}

// ---------------------------------------------------------------------------
// LocationMap -- tracks disjoint address ranges processed into SSA form.
// C++ parity: heritage.hh LocationMap
// ---------------------------------------------------------------------------

type locationEntry struct {
	Addr address.Address
	SP   SizePass
}

// LocationMap tracks disjoint address ranges processed into SSA form.
// Uses a sorted slice keyed by start address.
type LocationMap struct {
	entries []locationEntry // sorted by address
}

// Len returns the number of entries.
func (lm *LocationMap) Len() int { return len(lm.entries) }

// Clear removes all entries.
func (lm *LocationMap) Clear() { lm.entries = lm.entries[:0] }

// findIdx finds the first entry >= addr using binary search.
func (lm *LocationMap) findIdx(addr address.Address) int {
	return sort.Search(len(lm.entries), func(i int) bool {
		return !lm.entries[i].Addr.Less(addr)
	})
}

// Find finds the entry index containing addr, returns -1 if not found.
// An entry at entries[i] contains addr if:
//
//	entries[i].Addr <= addr < entries[i].Addr + entries[i].SP.Size
func (lm *LocationMap) Find(addr address.Address) int {
	idx := lm.findIdx(addr)
	// Check exact match at idx
	if idx < len(lm.entries) {
		e := &lm.entries[idx]
		if e.Addr.Space == addr.Space && e.Addr.Offset == addr.Offset {
			return idx
		}
	}
	// Check if previous entry contains addr
	if idx > 0 {
		prev := &lm.entries[idx-1]
		if prev.Addr.Space == addr.Space {
			end := prev.Addr.Offset + uint64(prev.SP.Size)
			if addr.Offset < end {
				return idx - 1
			}
		}
	}
	return -1
}

// FindPass returns the pass number for the entry containing addr, or -1.
func (lm *LocationMap) FindPass(addr address.Address) int32 {
	idx := lm.Find(addr)
	if idx < 0 {
		return -1
	}
	return lm.entries[idx].SP.Pass
}

// Add merges the range [addr, addr+size) into the map with the given pass.
// Returns (index of containing/new entry, intersect code):
//
//	0 = new range or same-pass extension
//	1 = partial overlap with older pass
//	2 = fully contained in older pass entry
//
// C++ parity: heritage.cc LocationMap::add
func (lm *LocationMap) Add(addr address.Address, size int32, pass int32) (int, int) {
	endOff := addr.Offset + uint64(size)

	idx := lm.findIdx(addr)

	// Check if previous entry overlaps or is adjacent
	startIdx := idx
	if idx > 0 {
		prev := &lm.entries[idx-1]
		if prev.Addr.Space == addr.Space {
			prevEnd := prev.Addr.Offset + uint64(prev.SP.Size)
			if prevEnd >= addr.Offset {
				// Previous entry overlaps or is adjacent
				startIdx = idx - 1
			}
		}
	}

	// Find all overlapping entries from startIdx forward
	endIdx := startIdx
	for endIdx < len(lm.entries) {
		e := &lm.entries[endIdx]
		if e.Addr.Space != addr.Space || e.Addr.Offset > endOff {
			break
		}
		endIdx++
	}

	// No overlaps at all -- insert new entry
	if startIdx == endIdx {
		entry := locationEntry{
			Addr: addr,
			SP:   SizePass{Size: size, Pass: pass},
		}
		lm.entries = append(lm.entries, locationEntry{})
		copy(lm.entries[idx+1:], lm.entries[idx:])
		lm.entries[idx] = entry
		return idx, 0
	}

	// Check if fully contained in an existing entry with same or older pass
	first := &lm.entries[startIdx]
	if startIdx+1 == endIdx &&
		first.Addr.Space == addr.Space &&
		first.Addr.Offset <= addr.Offset {
		firstEnd := first.Addr.Offset + uint64(first.SP.Size)
		if firstEnd >= endOff {
			if first.SP.Pass <= pass {
				// Fully contained in existing entry, same or older pass
				return startIdx, 2
			}
		}
	}

	// Merge: compute unified range
	mergeStart := addr.Offset
	mergeEnd := endOff
	minPass := pass
	intersectCode := 0

	for i := startIdx; i < endIdx; i++ {
		e := &lm.entries[i]
		if e.Addr.Offset < mergeStart {
			mergeStart = e.Addr.Offset
		}
		eEnd := e.Addr.Offset + uint64(e.SP.Size)
		if eEnd > mergeEnd {
			mergeEnd = eEnd
		}
		if e.SP.Pass < minPass {
			minPass = e.SP.Pass
			intersectCode = 1
		}
	}

	// Replace overlapping entries with merged entry
	merged := locationEntry{
		Addr: address.Address{Space: addr.Space, Offset: mergeStart},
		SP:   SizePass{Size: int32(mergeEnd - mergeStart), Pass: minPass},
	}
	lm.entries[startIdx] = merged
	if endIdx > startIdx+1 {
		lm.entries = append(lm.entries[:startIdx+1], lm.entries[endIdx:]...)
	}

	return startIdx, intersectCode
}

// ---------------------------------------------------------------------------
// MemRange -- a single address range for heritage processing.
// C++ parity: heritage.hh MemRange (simplified -- no union struct)
// ---------------------------------------------------------------------------

const (
	MemRangeNewAddresses uint32 = 1
	MemRangeOldAddresses uint32 = 2
)

// MemRange is an address range with flags for heritage processing.
type MemRange struct {
	Addr  address.Address
	Size  int32
	Flags uint32
}

// NewAddresses returns true if this range contains new (unheritaged) addresses.
func (m *MemRange) NewAddresses() bool { return m.Flags&MemRangeNewAddresses != 0 }

// OldAddresses returns true if this range contains previously heritaged addresses.
func (m *MemRange) OldAddresses() bool { return m.Flags&MemRangeOldAddresses != 0 }

// ---------------------------------------------------------------------------
// TaskList -- ordered list of disjoint ranges for current heritage pass.
// C++ parity: heritage.hh TaskList (simplified)
// ---------------------------------------------------------------------------

// TaskList is an ordered list of disjoint address ranges for heritage processing.
type TaskList struct {
	tasks []MemRange
}

// Add appends a range to the task list. If the last entry overlaps or is
// adjacent in the same space, extends it and ORs the flags.
func (tl *TaskList) Add(addr address.Address, size int32, flags uint32) {
	if len(tl.tasks) > 0 {
		last := &tl.tasks[len(tl.tasks)-1]
		if last.Addr.Space == addr.Space {
			lastEnd := last.Addr.Offset + uint64(last.Size)
			if lastEnd >= addr.Offset {
				// Overlapping or adjacent -- extend
				newEnd := addr.Offset + uint64(size)
				if newEnd > lastEnd {
					last.Size = int32(newEnd - last.Addr.Offset)
				}
				last.Flags |= flags
				return
			}
		}
	}
	tl.tasks = append(tl.tasks, MemRange{
		Addr:  addr,
		Size:  size,
		Flags: flags,
	})
}

// Clear removes all tasks.
func (tl *TaskList) Clear() { tl.tasks = tl.tasks[:0] }

// Len returns the number of tasks.
func (tl *TaskList) Len() int { return len(tl.tasks) }

// Get returns the i-th task.
func (tl *TaskList) Get(i int) MemRange { return tl.tasks[i] }

// Tasks returns a snapshot copy of all tasks.
func (tl *TaskList) Tasks() []MemRange {
	out := make([]MemRange, len(tl.tasks))
	copy(out, tl.tasks)
	return out
}

// ---------------------------------------------------------------------------
// PriorityQueue -- depth-indexed priority stacks for phi-node placement.
// C++ parity: heritage.hh PriorityQueue
// ---------------------------------------------------------------------------

// PriorityQueue is a depth-indexed priority queue used in the
// Bilardi-Pingali algorithm for phi-node placement.
type PriorityQueue struct {
	queue    [][]int32 // queue[depth] = stack of block indices
	curDepth int32
}

// Reset allocates stacks for depths [0, maxDepth] and sets curDepth=-1.
func (pq *PriorityQueue) Reset(maxDepth int32) {
	pq.queue = make([][]int32, maxDepth+1)
	pq.curDepth = -1
}

// Insert pushes blockIndex onto the stack at the given depth.
func (pq *PriorityQueue) Insert(blockIndex int32, depth int32) {
	pq.queue[depth] = append(pq.queue[depth], blockIndex)
	if depth > pq.curDepth {
		pq.curDepth = depth
	}
}

// Extract pops a block index from the deepest non-empty stack.
// Panics if called on an empty queue.
func (pq *PriorityQueue) Extract() int32 {
	stk := pq.queue[pq.curDepth]
	val := stk[len(stk)-1]
	pq.queue[pq.curDepth] = stk[:len(stk)-1]
	// Scan down for next non-empty depth
	for pq.curDepth >= 0 && len(pq.queue[pq.curDepth]) == 0 {
		pq.curDepth--
	}
	return val
}

// Empty returns true if the queue has no elements.
func (pq *PriorityQueue) Empty() bool {
	return pq.curDepth < 0
}

// ---------------------------------------------------------------------------
// HeritageInfo -- per-address-space heritage bookkeeping.
// C++ parity: heritage.hh HeritageInfo
// ---------------------------------------------------------------------------

// HeritageInfo tracks per-space heritage state.
type HeritageInfo struct {
	Space         *address.Space
	Delay         int32 // passes to wait before first heritage
	DeadCodeDelay int32
	DeadRemoved   int32
	LoadGuardDone bool
	WarningIssued bool
}

// NewHeritageInfo creates HeritageInfo for a space. If spc is nil or
// is not a heritaged space (constant/iop/fspec), Space is set to nil.
// C++ parity: heritage.cc HeritageInfo constructor
func NewHeritageInfo(spc *address.Space) HeritageInfo {
	if spc == nil {
		return HeritageInfo{}
	}
	switch spc.Kind {
	case address.SpaceKindConstant, address.SpaceKindIop, address.SpaceKindFspec:
		return HeritageInfo{}
	default:
		return HeritageInfo{
			Space: spc,
			Delay: spc.Delay,
		}
	}
}

// IsHeritaged returns true if this space participates in heritage.
func (hi *HeritageInfo) IsHeritaged() bool { return hi.Space != nil }

// Reset clears all state except the space pointer.
func (hi *HeritageInfo) Reset() {
	if hi.Space != nil {
		hi.Delay = hi.Space.Delay
	}
	hi.DeadCodeDelay = 0
	hi.DeadRemoved = 0
	hi.LoadGuardDone = false
	hi.WarningIssued = false
}

// ---------------------------------------------------------------------------
// LoadGuard -- guard for guarded loads/stores.
// C++ parity: heritage.hh LoadGuard (simplified for Phase 3)
// ---------------------------------------------------------------------------

// LoadGuard tracks a guarded load or store operation.
type LoadGuard struct {
	Op            *PcodeOp
	Spc           *address.Space
	PointerBase   uint64
	MinimumOffset uint64
	MaximumOffset uint64
	Step          int32
	AnalysisState int32 // 0=unanalyzed, 1=partial, 2=locked
}

// IsGuarded returns true if addr falls within the guard range.
func (lg *LoadGuard) IsGuarded(addr address.Address) bool {
	if addr.Space != lg.Spc {
		return false
	}
	return addr.Offset >= lg.MinimumOffset && addr.Offset <= lg.MaximumOffset
}

// IsRangeLocked returns true if analysis is complete.
func (lg *LoadGuard) IsRangeLocked() bool { return lg.AnalysisState == 2 }

// IsValid returns true if the underlying op is alive and has the expected opcode.
func (lg *LoadGuard) IsValid(opc OpCode) bool {
	if lg.Op == nil || lg.Op.IsDead() {
		return false
	}
	return lg.Op.Code() == opc
}

// ---------------------------------------------------------------------------
// addressKey -- comparable key for varnode address lookups during renaming.
// C++ parity: used internally in heritage rename algorithm
// ---------------------------------------------------------------------------

type addressKey struct {
	spaceIndex uint16
	offset     uint64
}

func makeAddressKey(addr address.Address) addressKey {
	idx := uint16(0)
	if addr.Space != nil {
		idx = addr.Space.Index
	}
	return addressKey{spaceIndex: idx, offset: addr.Offset}
}
