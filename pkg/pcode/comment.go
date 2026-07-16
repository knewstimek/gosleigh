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

	"gosleigh/pkg/address"
)

// This file ports Ghidra's high-level comment subsystem (comment.hh/comment.cc)
// and the slice of PrintC/CommentSorter needed to render warning comments in the
// function body. Only the pieces exercised by decompiler warnings are ported:
// a per-function comment database, the addCommentNoDuplicate placement rule, and
// the CommentSorter position calculation that maps a comment's address to the
// basic block and intra-block order where PrintC emits it.

// Comment property flags. A comment carries a set of these; PrintC selects which
// sets to render in the body vs the header.
// C++ parity: comment.hh Comment::comment_type.
const (
	CommentUser1         uint32 = 1
	CommentUser2         uint32 = 2
	CommentUser3         uint32 = 4
	CommentHeader        uint32 = 8
	CommentWarning       uint32 = 16
	CommentWarningHeader uint32 = 32
)

// instrCommentType selects the comment properties PrintC renders as inline body
// comments (before the statement they attach to).
// C++ parity: printlanguage.cc PrintLanguage::resetDefaultsInternal
// (instr_comment_type = Comment::user2 | Comment::warning, printlanguage.cc:586).
const instrCommentType = CommentUser2 | CommentWarning

// Comment is a single high-level comment attached to a function and to the
// address of an instruction within that function's body.
// C++ parity: comment.hh Comment.
type Comment struct {
	Type     uint32
	Uniq     int
	FuncAddr address.Address
	Addr     address.Address
	Text     string
}

// CommentDatabase is the in-memory store of comments for one function. Ghidra
// keeps a single global CommentDatabaseInternal indexed by function address;
// Gosleigh decompiles one function at a time, so a per-Funcdata store holds the
// same information without the funcaddr keying.
// C++ parity: comment.hh CommentDatabaseInternal.
type CommentDatabase struct {
	comments []*Comment
}

// addCommentNoDuplicate adds a comment unless an identical-text comment already
// exists at the same (function, address). The sub-sort index (uniq) is assigned
// so that comments at the same address keep insertion order: a new comment gets
// one past the highest existing uniq at that address.
// C++ parity: comment.cc CommentDatabaseInternal::addCommentNoDuplicate.
func (db *CommentDatabase) addCommentNoDuplicate(tp uint32, fad, ad address.Address, txt string) bool {
	uniq := 0
	for _, c := range db.comments {
		if c.FuncAddr == fad && c.Addr == ad {
			if c.Text == txt {
				return false // matching text, don't store it
			}
			if c.Uniq >= uniq {
				uniq = c.Uniq + 1
			}
		}
	}
	db.comments = append(db.comments, &Comment{Type: tp, Uniq: uniq, FuncAddr: fad, Addr: ad, Text: txt})
	return true
}

// PrintRawAddr renders an address the way Ghidra streams it (ostream << Address
// -> AddrSpace::printRaw). It is used to build the warning text that embeds an
// op address (e.g. "Could not emulate address calculation at 0x000024e0"), so
// the digits and zero-padding match Ghidra byte-for-byte.
// C++ parity: space.cc AddrSpace::printRaw (space.cc:206).
func PrintRawAddr(a address.Address) string {
	if a.Space == nil {
		return "<invalid>"
	}
	sz := int(a.Space.AddrSize)
	off := a.Offset
	ws := uint64(a.Space.WordSize)
	if ws == 0 {
		ws = 1
	}
	// Don't print a bunch of leading zeroes for wide spaces holding small offsets.
	if sz > 4 {
		if off>>32 == 0 {
			sz = 4
		} else if off>>48 == 0 {
			sz = 6
		}
	}
	s := fmt.Sprintf("0x%0*x", 2*sz, off/ws) // byteToAddress: off/wordsize
	if ws > 1 {
		if cut := off % ws; cut != 0 {
			s += fmt.Sprintf("+%d", cut)
		}
	}
	return s
}

// positionedComment is a comment that has been assigned to a basic block at a
// specific intra-block position (the index, within the block's op list, of the
// op it should precede). It is the flattened result of CommentSorter::findPosition
// for a single comment.
//
// Ghidra keys the intra-block sort on PcodeOp::getSeqNum().getOrder(), a value it
// makes block-monotonic when it linearizes the block. Gosleigh's SeqNum.Order is
// per-instruction (it resets at each machine address), so it is NOT a usable
// intra-block key; the position of the op within BlockBasic.Ops() is the faithful
// equivalent -- it reflects the same execution order Ghidra's getOrder encodes.
type positionedComment struct {
	order int    // index of the target op within its block's Ops() list
	uniq  int    // sub-sort within the same address, preserves insertion order
	text  string // wrapped comment text (already includes the "/* ... */")
}

// spaceKey orders address spaces the way Ghidra's AddrSpace comparison does
// (by unique index). All function ops share one space in the current corpus, so
// this only matters as a tiebreaker.
func spaceKey(s *address.Space) int {
	if s == nil {
		return -1
	}
	return int(s.Index)
}

// addrLess reports whether address a sorts before b (space, then offset).
func addrLess(a, b address.Address) bool {
	if a.Space != b.Space {
		return spaceKey(a.Space) < spaceKey(b.Space)
	}
	return a.Offset < b.Offset
}

// seqLess reports whether op a sorts before op b in Ghidra's PcodeOpTree order:
// by address, then by intra-instruction order.
// C++ parity: op.hh SeqNum::operator< (address then order).
func seqLess(a, b *PcodeOp) bool {
	if a.Addr() != b.Addr() {
		return addrLess(a.Addr(), b.Addr())
	}
	return a.Seq().Order < b.Seq().Order
}

// blockContainsAddr reports whether ad falls within the address span of bb's
// ops. This is a proxy for Ghidra's BlockBasic::contains, which tests the
// block's cover range; the span of op addresses is sufficient for warning
// comments, which always attach to an exact op address inside the block.
func blockContainsAddr(bb *BlockBasic, ad address.Address) bool {
	if bb == nil {
		return false
	}
	ops := bb.Ops()
	if len(ops) == 0 {
		return false
	}
	lo, hi := ops[0].Addr(), ops[0].Addr()
	for _, op := range ops[1:] {
		a := op.Addr()
		if addrLess(a, lo) {
			lo = a
		}
		if addrLess(hi, a) {
			hi = a
		}
	}
	return !addrLess(ad, lo) && !addrLess(hi, ad)
}

// findCommentPosition maps a comment address to (block index, intra-block order)
// following CommentSorter::findPosition: the comment attaches to the op at the
// lowest address >= ad when that op's block contains ad; otherwise to the end of
// the previous op's block when that block contains ad.
//
// Simplification vs C++: the header/warningheader and displayUnplaced paths are
// not modelled (Gosleigh does not yet route header warnings through the comment
// database), and "block contains" uses the op-address span rather than the block
// cover range. Both are exact for the warnings the decompiler currently emits,
// which attach to a live op's own address.
// C++ parity: comment.cc CommentSorter::findPosition (comment.cc:270).
func findCommentPosition(alive []*PcodeOp, ad address.Address) (int32, int, bool) {
	var at *PcodeOp   // lowest-seqnum op with address >= ad
	var prev *PcodeOp // highest-seqnum op with address < ad
	for _, op := range alive {
		if !addrLess(op.Addr(), ad) { // op.Addr() >= ad
			if at == nil || seqLess(op, at) {
				at = op
			}
		} else {
			if prev == nil || seqLess(prev, op) {
				prev = op
			}
		}
	}
	if at != nil && at.Parent() != nil {
		if at.Addr() == ad || blockContainsAddr(at.Parent(), ad) {
			return at.Parent().Index(), opIndexInBlock(at), true
		}
	}
	if prev != nil && prev.Parent() != nil && blockContainsAddr(prev.Parent(), ad) {
		// Treat the comment as being at the very end of this block.
		return prev.Parent().Index(), len(prev.Parent().Ops()), true
	}
	return 0, 0, false
}

// opIndexInBlock returns the position of op within its parent block's op list,
// or the block length if it is not found (which sorts the comment to the end).
func opIndexInBlock(op *PcodeOp) int {
	bb := op.Parent()
	if bb == nil {
		return 0
	}
	ops := bb.Ops()
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return len(ops)
}

// buildCommentPositions computes, for every instr-type comment in fd's comment
// database, the basic block and order where PrintC should emit it. Comments are
// wrapped in the C-style delimiters here so the emitter only prints tokens.
// Returns nil when there are no comments (the common case), keeping output
// byte-identical for functions the decompiler issued no warning for.
// C++ parity: comment.cc CommentSorter::setupFunctionList + PrintC comment
// delimiters (printc.hh setCStyleComments -> "/* " ... " */").
func buildCommentPositions(fd *Funcdata) map[int32][]positionedComment {
	if fd == nil || fd.commentDB == nil || len(fd.commentDB.comments) == 0 {
		return nil
	}
	var comms []*Comment
	for _, c := range fd.commentDB.comments {
		if c.Type&instrCommentType != 0 {
			comms = append(comms, c)
		}
	}
	if len(comms) == 0 {
		return nil
	}
	// Order comments by (address, uniq) so same-address comments keep their
	// insertion order (matching CommentOrder and the setupFunctionList walk).
	sort.SliceStable(comms, func(i, j int) bool {
		a, b := comms[i], comms[j]
		if a.Addr != b.Addr {
			return addrLess(a.Addr, b.Addr)
		}
		return a.Uniq < b.Uniq
	})

	var alive []*PcodeOp
	for _, op := range fd.GetPcodeOpBank().AliveOps() {
		if op != nil && op.Parent() != nil {
			alive = append(alive, op)
		}
	}

	result := make(map[int32][]positionedComment)
	for _, c := range comms {
		idx, order, ok := findCommentPosition(alive, c.Addr)
		if !ok {
			continue
		}
		result[idx] = append(result[idx], positionedComment{
			order: order,
			uniq:  c.Uniq,
			text:  "/* " + c.Text + " */",
		})
	}
	// Within each block, order by (order, uniq): comments precede the first
	// printed op whose order is >= theirs, ties broken by insertion order.
	for k := range result {
		cs := result[k]
		sort.SliceStable(cs, func(i, j int) bool {
			if cs[i].order != cs[j].order {
				return cs[i].order < cs[j].order
			}
			return cs[i].uniq < cs[j].uniq
		})
		result[k] = cs
	}
	return result
}
