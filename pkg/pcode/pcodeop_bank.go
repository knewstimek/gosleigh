package pcode

import "gosleigh/pkg/address"

// PcodeOpBank manages all PcodeOps within a function.
// C++ parity: op.hh PcodeOpBank
type PcodeOpBank struct {
	opTree    map[SeqNum]*PcodeOp // primary index by SeqNum
	deadList  []*PcodeOp          // dead ops (not in CFG)
	aliveList []*PcodeOp          // alive ops (in CFG)
	uniqID    uint64              // monotonic sequence counter
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

// Target returns the first op whose address matches addr, or nil.
// C++ uses a tree iterator; we do a linear scan for now.
func (b *PcodeOpBank) Target(addr address.Address) *PcodeOp {
	for _, op := range b.opTree {
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
	b.deadList = nil
	b.aliveList = nil
	// uniqID is not reset -- matches C++ behavior
}

// AllOps returns a snapshot of all ops in the bank.
func (b *PcodeOpBank) AllOps() []*PcodeOp {
	result := make([]*PcodeOp, 0, len(b.opTree))
	for _, op := range b.opTree {
		result = append(result, op)
	}
	return result
}

// AliveOps returns a copy of the alive list.
func (b *PcodeOpBank) AliveOps() []*PcodeOp {
	out := make([]*PcodeOp, len(b.aliveList))
	copy(out, b.aliveList)
	return out
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
