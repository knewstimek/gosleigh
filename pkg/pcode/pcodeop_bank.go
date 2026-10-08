package pcode

import (
	"sort"

	"gosleigh/pkg/address"
)

// PcodeOpBank manages all PcodeOps within a function.
// C++ parity: op.hh PcodeOpBank
type PcodeOpBank struct {
	opTree    map[SeqNum]*PcodeOp // primary index by SeqNum
	deadList  []*PcodeOp          // dead ops (not in CFG)
	aliveList []*PcodeOp          // alive ops (in CFG)
	uniqID    uint64              // monotonic sequence counter
	// sorted holds every op in SeqNum order (C++ optree is a std::map keyed
	// by SeqNum), maintained on create/destroy. Iterating the Go map would
	// make the order, and so the output, vary from run to run.
	sorted []*PcodeOp
	// codeCounter stamps each opcode change, so CodeList can rebuild the
	// C++ per-opcode lists, which append an op whenever its opcode is set.
	codeCounter uint64
}

// NewPcodeOpBank creates an empty PcodeOpBank.
func NewPcodeOpBank() *PcodeOpBank {
	return &PcodeOpBank{
		opTree: make(map[SeqNum]*PcodeOp),
	}
}

// Create allocates a new PcodeOp at the given address, assigns it a unique
// sequence number, marks it dead, and adds it to the bank.
// C++ parity: PcodeOpBank::create
func (b *PcodeOpBank) Create(numInputs int, addr address.Address) *PcodeOp {
	seq := SeqNum{
		Address: addr,
		Time:    b.uniqID,
		Order:   b.uniqID,
	}
	b.uniqID++
	return b.createInternal(numInputs, seq)
}

// CreateWithSeq allocates a new PcodeOp with an explicit SeqNum.
func (b *PcodeOpBank) CreateWithSeq(numInputs int, seq SeqNum) *PcodeOp {
	if seq.Time >= b.uniqID {
		b.uniqID = seq.Time + 1
	}
	return b.createInternal(numInputs, seq)
}

func (b *PcodeOpBank) createInternal(numInputs int, seq SeqNum) *PcodeOp {
	op := NewPcodeOp(numInputs, seq)
	op.SetFlag(PcodeOpDead)
	b.opTree[seq] = op
	i := b.searchSeq(seq)
	b.sorted = append(b.sorted, nil)
	copy(b.sorted[i+1:], b.sorted[i:])
	b.sorted[i] = op
	b.deadList = append(b.deadList, op)
	return op
}

// MarkAlive moves an op from the dead list to the alive list.
// C++ parity: PcodeOpBank::markAlive
func (b *PcodeOpBank) MarkAlive(op *PcodeOp) {
	b.deadList = removeFromSlice(b.deadList, op)
	op.ClearFlag(PcodeOpDead)
	b.aliveList = append(b.aliveList, op)
}

// MarkDead moves an op from the alive list to the dead list.
// C++ parity: PcodeOpBank::markDead
func (b *PcodeOpBank) MarkDead(op *PcodeOp) {
	b.aliveList = removeFromSlice(b.aliveList, op)
	op.SetFlag(PcodeOpDead)
	b.deadList = append(b.deadList, op)
}

// Destroy removes an op from all indices.
// C++ parity: PcodeOpBank::destroy
func (b *PcodeOpBank) Destroy(op *PcodeOp) {
	delete(b.opTree, op.seq)
	for i := b.searchSeq(op.seq); i < len(b.sorted) && SeqNumEqual(b.sorted[i].seq, op.seq); i++ {
		if b.sorted[i] == op {
			b.sorted = append(b.sorted[:i], b.sorted[i+1:]...)
			break
		}
	}
	if op.IsDead() {
		b.deadList = removeFromSlice(b.deadList, op)
	} else {
		b.aliveList = removeFromSlice(b.aliveList, op)
	}
}

// FindOp looks up an op by its SeqNum.
func (b *PcodeOpBank) FindOp(seq SeqNum) *PcodeOp {
	return b.opTree[seq]
}

// Target returns the first op (in SeqNum order) at addr, or nil.
// C++ parity: PcodeOpBank::target.
func (b *PcodeOpBank) Target(addr address.Address) *PcodeOp {
	for _, op := range b.sorted {
		if op.seq.Address == addr {
			return op
		}
	}
	return nil
}

// NumOps returns the total number of ops in the bank.
func (b *PcodeOpBank) NumOps() int { return len(b.opTree) }

// Clear removes all ops from the bank.
func (b *PcodeOpBank) Clear() {
	b.opTree = make(map[SeqNum]*PcodeOp)
	b.sorted = nil
	b.deadList = nil
	b.aliveList = nil
	// uniqID is not reset -- matches C++ behavior
}

// AllOps returns a snapshot of all ops in the bank in SeqNum order.
// C++ parity: PcodeOpBank::beginAll/endAll (optree iteration).
func (b *PcodeOpBank) AllOps() []*PcodeOp {
	return append([]*PcodeOp(nil), b.sorted...)
}

// searchSeq is the index of the first op whose SeqNum is not before seq.
func (b *PcodeOpBank) searchSeq(seq SeqNum) int {
	return sort.Search(len(b.sorted), func(i int) bool { return !SeqNumLess(b.sorted[i].seq, seq) })
}

// NextAfter returns the first op at or after seq (strictly after when
// strict), or nil. C++ parity: optree.lower_bound / upper_bound.
func (b *PcodeOpBank) NextAfter(seq SeqNum, strict bool) *PcodeOp {
	i := b.searchSeq(seq)
	for strict && i < len(b.sorted) && SeqNumEqual(b.sorted[i].seq, seq) {
		i++ // ops can share a SeqNum (CreateWithSeq); skip them all
	}
	if i < len(b.sorted) {
		return b.sorted[i]
	}
	return nil
}

// ChangeOpcode sets op's opcode and moves it to the end of its opcode
// list. C++ parity: PcodeOpBank::changeOpcode (removeFromCodeList, then
// addToCodeList, even for an unchanged opcode).
func (b *PcodeOpBank) ChangeOpcode(op *PcodeOp, t TypeOp) {
	op.SetOpcode(t)
	op.codeOrder = b.codeCounter
	b.codeCounter++
}

// CodeList returns the ops with opcode opc, dead ones included, in the
// order they joined that opcode. C++ parity: PcodeOpBank::begin(opc) over
// returnlist / storelist / loadlist / useroplist.
func (b *PcodeOpBank) CodeList(opc OpCode) []*PcodeOp {
	var out []*PcodeOp
	for _, op := range b.sorted {
		if op.Code() == opc {
			out = append(out, op)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].codeOrder < out[j].codeOrder })
	return out
}

// AliveOps returns a copy of the alive list.
func (b *PcodeOpBank) AliveOps() []*PcodeOp {
	out := make([]*PcodeOp, len(b.aliveList))
	copy(out, b.aliveList)
	return out
}

// SortAliveByTime orders the alive list by op creation time.
// C++ parity: FlowInfo::splitBasic inserts the ops into their blocks walking
// the dead list, which flow fills in generation (time) order, so the alive
// list starts out in that order.
func (b *PcodeOpBank) SortAliveByTime() {
	sort.SliceStable(b.aliveList, func(i, j int) bool {
		return b.aliveList[i].seq.Time < b.aliveList[j].seq.Time
	})
}

// DeadOps returns a copy of the dead list.
func (b *PcodeOpBank) DeadOps() []*PcodeOp {
	out := make([]*PcodeOp, len(b.deadList))
	copy(out, b.deadList)
	return out
}

// removeFromSlice removes the first occurrence of target from s.
func removeFromSlice(s []*PcodeOp, target *PcodeOp) []*PcodeOp {
	for i, op := range s {
		if op == target {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}
