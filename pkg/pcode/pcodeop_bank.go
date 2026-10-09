package pcode

import (
	"sort"

	"github.com/knewstimek/gosleigh/pkg/address"
)

// PcodeOpBank manages all PcodeOps within a function.
// C++ parity: op.hh PcodeOpBank
type PcodeOpBank struct {
	opTree    map[SeqNum]*PcodeOp // primary index by SeqNum
	deadList  opList              // dead ops (not in CFG)
	aliveList opList              // alive ops (in CFG)
	uniqID    uint64              // monotonic sequence counter
	// sorted holds every op in SeqNum order (C++ optree is a std::map keyed
	// by SeqNum), maintained on create/destroy. Iterating the Go map would
	// make the order, and so the output, vary from run to run.
	sorted chunkList[*PcodeOp]
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
	b.sorted.insertAt(b.searchSeq(seq), op)
	b.deadList.push(op)
	return op
}

// MarkAlive moves an op from the dead list to the alive list.
// C++ parity: PcodeOpBank::markAlive
func (b *PcodeOpBank) MarkAlive(op *PcodeOp) {
	b.deadList.remove(op)
	op.ClearFlag(PcodeOpDead)
	b.aliveList.push(op)
}

// MarkDead moves an op from the alive list to the dead list.
// C++ parity: PcodeOpBank::markDead
func (b *PcodeOpBank) MarkDead(op *PcodeOp) {
	b.aliveList.remove(op)
	op.SetFlag(PcodeOpDead)
	b.deadList.push(op)
}

// Destroy removes an op from all indices.
// C++ parity: PcodeOpBank::destroy
func (b *PcodeOpBank) Destroy(op *PcodeOp) {
	delete(b.opTree, op.seq)
	for p := b.searchSeq(op.seq); ; p = b.sorted.next(p) {
		o := b.sorted.at(p)
		if o == nil || !SeqNumEqual(o.seq, op.seq) {
			break
		}
		if o == op {
			b.sorted.removeAt(p)
			break
		}
	}
	if op.IsDead() {
		b.deadList.remove(op)
	} else {
		b.aliveList.remove(op)
	}
}

// FindOp looks up an op by its SeqNum.
func (b *PcodeOpBank) FindOp(seq SeqNum) *PcodeOp {
	return b.opTree[seq]
}

// Target returns the first op (in SeqNum order) at addr, or nil.
// C++ parity: PcodeOpBank::target.
func (b *PcodeOpBank) Target(addr address.Address) *PcodeOp {
	for _, op := range b.sorted.all() {
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
	b.sorted.clear()
	b.deadList = opList{}
	b.aliveList = opList{}
	// uniqID is not reset -- matches C++ behavior
}

// AllOps returns a snapshot of all ops in the bank in SeqNum order.
// C++ parity: PcodeOpBank::beginAll/endAll (optree iteration).
func (b *PcodeOpBank) AllOps() []*PcodeOp {
	return b.sorted.all()
}

// searchSeq is the position of the first op whose SeqNum is not before seq.
func (b *PcodeOpBank) searchSeq(seq SeqNum) vnPos {
	return b.sorted.search(func(op *PcodeOp) bool { return !SeqNumLess(op.seq, seq) })
}

// NextAfter returns the first op at or after seq (strictly after when
// strict), or nil. C++ parity: optree.lower_bound / upper_bound.
func (b *PcodeOpBank) NextAfter(seq SeqNum, strict bool) *PcodeOp {
	p := b.searchSeq(seq)
	for strict {
		op := b.sorted.at(p)
		if op == nil || !SeqNumEqual(op.seq, seq) {
			break
		}
		p = b.sorted.next(p) // ops can share a SeqNum (CreateWithSeq); skip them all
	}
	return b.sorted.at(p)
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
	for _, op := range b.sorted.all() {
		if op.Code() == opc {
			out = append(out, op)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].codeOrder < out[j].codeOrder })
	return out
}

// AliveOps returns a copy of the alive list.
func (b *PcodeOpBank) AliveOps() []*PcodeOp { return b.aliveList.snapshot() }

// SortAliveByTime orders the alive list by op creation time.
// C++ parity: FlowInfo::splitBasic inserts the ops into their blocks walking
// the dead list, which flow fills in generation (time) order, so the alive
// list starts out in that order.
func (b *PcodeOpBank) SortAliveByTime() {
	b.aliveList.compact()
	ops := b.aliveList.ops
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].seq.Time < ops[j].seq.Time })
	b.aliveList.renumber()
}

// DeadOps returns a copy of the dead list.
func (b *PcodeOpBank) DeadOps() []*PcodeOp { return b.deadList.snapshot() }

// opList is the alive or dead op list in its insertion order. A removal
// leaves a hole (each op knows its slot) that a later compaction closes, so
// it is O(1) like the C++ std::list erase through the op's stored iterator.
type opList struct {
	ops   []*PcodeOp
	holes int
}

func (l *opList) push(op *PcodeOp) {
	op.listPos = len(l.ops)
	l.ops = append(l.ops, op)
}

func (l *opList) remove(op *PcodeOp) {
	i := op.listPos
	if i < 0 || i >= len(l.ops) || l.ops[i] != op {
		i = -1
		for k, o := range l.ops {
			if o == op {
				i = k
				break
			}
		}
		if i < 0 {
			return
		}
	}
	l.ops[i] = nil
	l.holes++
	if l.holes > 64 && 2*l.holes > len(l.ops) {
		l.compact()
	}
}

// compact closes the holes, keeping the order.
func (l *opList) compact() {
	if l.holes == 0 {
		return
	}
	kept := l.ops[:0]
	for _, op := range l.ops {
		if op != nil {
			kept = append(kept, op)
		}
	}
	clear(l.ops[len(kept):])
	l.ops = kept
	l.holes = 0
	l.renumber()
}

func (l *opList) renumber() {
	for i, op := range l.ops {
		op.listPos = i
	}
}

func (l *opList) snapshot() []*PcodeOp {
	out := make([]*PcodeOp, 0, len(l.ops)-l.holes)
	for _, op := range l.ops {
		if op != nil {
			out = append(out, op)
		}
	}
	return out
}
