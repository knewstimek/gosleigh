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

import "sort"

// CseHash is the primary common-subexpression key of op: opcode, output
// size and input identities. 0 means the op does not take part.
// C++ parity: op.cc PcodeOp::getCseHash (uintm is 32 bits).
func (op *PcodeOp) CseHash() uint32 {
	if op.EvalType()&(PcodeOpUnary|PcodeOpBinary) == 0 || op.Code() == CPUI_COPY {
		return 0
	}
	hash := uint32(op.Output().Size())<<8 | uint32(op.Code())
	for i := 0; i < op.NumInput(); i++ {
		vn := op.Input(i)
		hash = hash<<8 | hash>>24
		if vn.IsConstant() {
			hash ^= uint32(vn.Offset())
		} else {
			hash ^= uint32(vn.CreateIndex())
		}
	}
	return hash
}

type cseEntry struct {
	hash uint32
	op   *PcodeOp
}

// isHeritaged reports whether vn's storage has been through heritage.
// C++ parity: Funcdata::isHeritaged.
func (fd *Funcdata) isHeritaged(vn *Varnode) bool {
	if vn.Space() != nil && vn.Space().IsUnique() {
		return true
	}
	h := fd.heritage
	return h != nil && h.globalDisjoint.FindPass(vn.Addr()) >= 0
}

// cseEliminateList merges hash-equal, CSE-matching ops of the list and
// returns the surviving outputs.
// C++ parity: Funcdata::cseEliminateList.
func (fd *Funcdata) cseEliminateList(list []cseEntry) []*Varnode {
	var out []*Varnode
	sort.SliceStable(list, func(i, j int) bool { return list[i].hash < list[j].hash })
	for i := 0; i+1 < len(list); i++ {
		if list[i].hash != list[i+1].hash {
			continue
		}
		op1, op2 := list[i].op, list[i+1].op
		if op1.IsDead() || op2.IsDead() || !op1.IsCseMatch(op2) {
			continue
		}
		out1, out2 := op1.Output(), op2.Output()
		if (out1 == nil || fd.isHeritaged(out1)) && (out2 == nil || fd.isHeritaged(out2)) {
			out = append(out, fd.cseElimination(op1, op2).Output())
		}
	}
	return out
}

// cseElimination keeps the op that dominates the other (or a new copy in
// their common dominator) and redirects the other's readers to it.
// C++ parity: Funcdata::cseElimination.
func (fd *Funcdata) cseElimination(op1, op2 *PcodeOp) *PcodeOp {
	var replace *PcodeOp
	if op1.Parent() == op2.Parent() {
		replace = op2
		if op1.Seq().Order < op2.Seq().Order {
			replace = op1
		}
	} else {
		common := asBasic(FindCommonBlock(&op1.Parent().FlowBlock, &op2.Parent().FlowBlock))
		switch common {
		case op1.Parent():
			replace = op1
		case op2.Parent():
			replace = op2
		default:
			// C++ places the new op at common->getStop(); Gosleigh blocks keep no
			// address range, so the common block's last op address stands in.
			addr := op1.Addr()
			if last := common.LastOp(); last != nil {
				addr = last.Addr()
			}
			replace = fd.NewOp(op1.NumInput(), addr)
			fd.OpSetOpcode(replace, op1.Code())
			fd.NewVarnodeOut(op1.Output().Size(), op1.Output().Addr(), replace)
			for i := 0; i < op1.NumInput(); i++ {
				in := op1.Input(i)
				if in.IsConstant() {
					fd.OpSetInput(replace, fd.NewConstant(in.Size(), in.Offset()), i)
				} else {
					fd.OpSetInput(replace, in, i)
				}
			}
			fd.OpInsertEnd(replace, common)
		}
	}
	if replace != op1 {
		fd.TotalReplace(op1.Output(), replace.Output())
		fd.OpDestroy(op1)
	}
	if replace != op2 {
		fd.TotalReplace(op2.Output(), replace.Output())
		fd.OpDestroy(op2)
	}
	return replace
}

// apply merges duplicate SUBPIECE / INT_SRIGHT computations of one Varnode.
// C++ parity: ruleaction.cc RuleSelectCse::applyOp.
func (r *RuleSelectCse) apply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(0)
	var list []cseEntry
	for _, other := range vn.DescendIter() {
		if other.Code() != op.Code() {
			continue
		}
		if h := other.CseHash(); h != 0 {
			list = append(list, cseEntry{h, other})
		}
	}
	if len(list) <= 1 {
		return 0
	}
	if len(data.cseEliminateList(list)) == 0 {
		return 0
	}
	return 1
}
