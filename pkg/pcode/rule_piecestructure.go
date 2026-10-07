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

import "gosleigh/pkg/address"

// pieceNode is one Varnode of a CONCAT tree: the PIECE op reading it, its
// input slot, its byte offset within the root's data-type, and whether it is
// a leaf. C++ parity: PieceNode.
type pieceNode struct {
	op         *PcodeOp
	slot       int
	typeOffset int64
	leaf       bool
}

func (n pieceNode) varnode() *Varnode { return n.op.Input(n.slot) }

// pieceIsLeaf reports whether vn ends the CONCAT tree under rootVn.
// C++ parity: PieceNode::isLeaf.
func pieceIsLeaf(rootVn, vn *Varnode, relOffset int64) bool {
	if vn.IsMapped() && rootVn.GetSymbolEntry() != vn.GetSymbolEntry() {
		return true
	}
	if !vn.IsWritten() || vn.Def().Code() != CPUI_PIECE {
		return true
	}
	if vn.LoneDescend() == nil {
		return true
	}
	if vn.IsAddrTied() {
		addr := rootVn.Addr()
		addr.Offset += uint64(relOffset)
		if vn.Addr() != addr {
			return true
		}
	}
	return false
}

// gatherPieces walks the CONCAT tree below op, recording every node.
// C++ parity: PieceNode::gatherPieces.
func gatherPieces(stack *[]pieceNode, rootVn *Varnode, op *PcodeOp, baseOffset, rootOffset int64) {
	be := rootVn.Space() != nil && rootVn.Space().BigEndian
	for i := 0; i < 2; i++ {
		vn := op.Input(i)
		offset := baseOffset
		if be == (i == 1) {
			offset += int64(op.Input(1 - i).Size())
		}
		res := pieceIsLeaf(rootVn, vn, offset-rootOffset)
		*stack = append(*stack, pieceNode{op: op, slot: i, typeOffset: offset, leaf: res})
		if !res {
			gatherPieces(stack, rootVn, vn.Def(), offset, rootOffset)
		}
	}
}

// isPieceStructured: is a value of this type better built by separate
// assignments than by a concatenation? C++ parity: Datatype::isPieceStructured.
func isPieceStructured(dt Datatype) bool {
	return dt != nil && dt.Metatype() <= TYPE_ARRAY
}

// varnodeStructuredType is the structured data-type of vn's symbol or vn.
// C++ parity: Varnode::getStructuredType.
func varnodeStructuredType(vn *Varnode) Datatype {
	var ct Datatype
	if e := vn.GetSymbolEntry(); e != nil && e.Symbol() != nil {
		ct = e.Symbol().Type()
	} else {
		ct = vn.Type()
	}
	if isPieceStructured(ct) {
		return ct
	}
	return nil
}

// RulePieceStructure renders the concatenation of structure pieces as
// separate field writes: the leaves of the CONCAT tree get the storage of
// their field (COPYs where needed) and are marked proto-partial, and the root
// is registered so Merge::groupPartials makes them pieces of one variable.
// C++ parity: RulePieceStructure.
type RulePieceStructure struct{ batchRule }

func NewRulePieceStructure(group string) *RulePieceStructure {
	r := &RulePieceStructure{}
	r.batchRule = newBatchRule(group, "piecestructure", []OpCode{CPUI_PIECE, CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRulePieceStructure(g) })
	return r
}

// determineDatatype finds the structured type the output of a CONCAT tree
// fills and the output's offset within it. C++ parity:
// RulePieceStructure::determineDatatype.
func (r *RulePieceStructure) determineDatatype(vn *Varnode) (Datatype, int64) {
	ct := varnodeStructuredType(vn)
	if ct == nil {
		return nil, 0
	}
	if ct.Size() == vn.Size() {
		return ct, 0
	}
	// vn is a partial
	entry := vn.GetSymbolEntry()
	if entry == nil {
		return nil, 0
	}
	baseOffset := addressOverlap(vn.Addr(), entry.Addr(), ct.Size())
	if baseOffset < 0 {
		return nil, 0
	}
	baseOffset += int64(entry.Offset())
	subType := ct
	subOffset := baseOffset
	for subType != nil && subType.Size() > vn.Size() {
		subType, subOffset = datatypeSubType(subType, subOffset)
	}
	if subType != nil && subType.Size() == vn.Size() && subOffset == 0 && !isPieceStructured(subType) {
		return nil, 0 // don't split out CONCAT forming a concrete sub-type
	}
	return ct, baseOffset
}

// addressOverlap is the offset of a within [b, b+size), or -1.
// C++ parity: Address::overlap(0, b, size).
func addressOverlap(a, b address.Address, size int32) int64 {
	if a.Space != b.Space || a.Offset < b.Offset || a.Offset-b.Offset >= uint64(size) {
		return -1
	}
	return int64(a.Offset - b.Offset)
}

// spanningRange reports whether [offset, offset+size) of ct crosses more than
// one non-structured element. C++ parity: RulePieceStructure::spanningRange.
func spanningRange(ct Datatype, offset int64, size int32) bool {
	if offset+int64(size) > int64(ct.Size()) {
		return false
	}
	newOff := offset
	for {
		ct, newOff = datatypeSubType(ct, newOff)
		if ct == nil {
			return true // unknown span, assume multiple
		}
		if newOff+int64(size) > int64(ct.Size()) {
			return true
		}
		if !isPieceStructured(ct) {
			return false
		}
	}
}

// convertZextToPiece turns zext into PIECE(0, x), typing the zero by the
// field it fills. C++ parity: RulePieceStructure::convertZextToPiece.
func convertZextToPiece(zext *PcodeOp, ct Datatype, offset int64, data *Funcdata) bool {
	outvn, invn := zext.Output(), zext.Input(0)
	if invn.IsConstant() {
		return false
	}
	sz := outvn.Size() - invn.Size()
	if sz > 8 {
		return false
	}
	if outvn.Space() == nil || !outvn.Space().BigEndian {
		offset += int64(invn.Size())
	}
	newOff := offset
	for ct != nil && ct.Size() > sz {
		ct, newOff = datatypeSubType(ct, newOff)
	}
	zerovn := data.NewConstant(sz, 0)
	if ct != nil && ct.Size() == sz {
		SetVarnodeType(zerovn, ct)
	}
	data.OpSetOpcode(zext, CPUI_PIECE)
	data.OpInsertInput(zext, zerovn, 0)
	return true
}

// findReplaceZext converts INT_ZEXT leaves spanning several fields into
// PIECEs. C++ parity: RulePieceStructure::findReplaceZext.
func findReplaceZext(stack []pieceNode, structuredType Datatype, data *Funcdata) bool {
	change := false
	for _, node := range stack {
		if !node.leaf {
			continue
		}
		vn := node.varnode()
		if !vn.IsWritten() || vn.Def().Code() != CPUI_INT_ZEXT {
			continue
		}
		if !spanningRange(structuredType, node.typeOffset, vn.Size()) {
			continue
		}
		if convertZextToPiece(vn.Def(), structuredType, node.typeOffset, data) {
			change = true
		}
	}
	return change
}

// separateSymbol: should root and leaf belong to different symbols?
// C++ parity: RulePieceStructure::separateSymbol.
func separateSymbol(root, leaf *Varnode) bool {
	if root.GetSymbolEntry() != leaf.GetSymbolEntry() {
		return true
	}
	if root.IsAddrTied() {
		return false
	}
	if !leaf.IsWritten() || leaf.IsProtoPartial() {
		return true
	}
	op := leaf.Def()
	if op.IsMarker() {
		return true
	}
	if op.Code() != CPUI_PIECE {
		return false
	}
	return isPieceStructured(leaf.Type())
}

func (r *RulePieceStructure) apply(op *PcodeOp, data *Funcdata) int {
	if op.addlFlags&PcodeOpConcatRoot != 0 {
		return 0 // CONCAT tree already visited
	}
	outvn := op.Output()
	ct, baseOffset := r.determineDatatype(outvn)
	if ct == nil {
		return 0
	}
	if op.Code() == CPUI_INT_ZEXT {
		if convertZextToPiece(op, outvn.Type(), 0, data) {
			return 1
		}
		return 0
	}
	// Check that outvn really is the root of the tree.
	if zext := outvn.LoneDescend(); zext != nil {
		switch zext.Code() {
		case CPUI_PIECE:
			return 0 // more PIECEs below us
		case CPUI_INT_ZEXT:
			if convertZextToPiece(zext, zext.Output().Type(), 0, data) {
				return 1
			}
			return 0
		}
	}
	var stack []pieceNode
	for {
		gatherPieces(&stack, outvn, op, baseOffset, baseOffset)
		if !findReplaceZext(stack, ct, data) {
			break
		}
		stack = stack[:0]
	}
	op.SetAdditionalFlag(PcodeOpConcatRoot)
	anyAddrTied := outvn.IsAddrTied()
	baseAddr := outvn.Addr()
	baseAddr.Offset -= uint64(baseOffset)
	tf := sharedTypeFactory
	for _, node := range stack {
		vn := node.varnode()
		addr := baseAddr
		addr.Offset += uint64(node.typeOffset)
		addr.Renormalize(vn.Size()) // Allow for possible join address
		if vn.Addr() == addr {
			if !node.leaf || !separateSymbol(outvn, vn) {
				// Already at its storage and part of the root's symbol.
				if !vn.IsAddrTied() && !vn.IsProtoPartial() {
					vn.SetFlags(VarnodeProtoPartial)
				}
				anyAddrTied = anyAddrTied || vn.IsAddrTied()
				continue
			}
		}
		if node.leaf {
			copyOp := data.NewOp(1, node.op.Addr())
			newVn := data.NewVarnodeOut(vn.Size(), addr, copyOp)
			anyAddrTied = anyAddrTied || newVn.IsAddrTied()
			newType := tf.exactPiece(ct, node.typeOffset, vn.Size())
			if newType == nil {
				newType = vn.Type()
			}
			SetVarnodeType(newVn, newType)
			data.OpSetOpcode(copyOp, CPUI_COPY)
			data.OpSetInput(copyOp, vn, 0)
			data.OpSetInput(node.op, newVn, node.slot)
			data.OpInsertBefore(copyOp, node.op)
			if !newVn.IsAddrTied() {
				newVn.SetFlags(VarnodeProtoPartial)
			}
			continue
		}
		// An inner node that is not addrtied with a lone descendant: give it
		// the correct storage.
		defOp := vn.Def()
		loneOp := vn.LoneDescend()
		slot := loneOp.GetSlot(vn)
		data.OpUnsetOutput(defOp)
		newVn := data.NewVarnodeOut(vn.Size(), addr, defOp)
		SetVarnodeType(newVn, vn.Type())
		data.OpSetInput(loneOp, newVn, slot)
		data.DeleteVarnode(vn)
		if !newVn.IsAddrTied() {
			newVn.SetFlags(VarnodeProtoPartial)
		}
	}
	if !anyAddrTied {
		data.protoPartial = append(data.protoPartial, op)
	}
	return 1
}

// groupPartials groups the CONCAT trees RulePieceStructure registered.
// C++ parity: Merge::groupPartials.
func (m *Merge) groupPartials() {
	for _, op := range m.fd.protoPartial {
		if op.IsDead() || op.addlFlags&PcodeOpConcatRoot == 0 {
			continue
		}
		m.groupPartialRoot(op.Output())
	}
}

// groupPartialRoot makes the nodes of a CONCAT tree pieces of the root's
// variable, unless a node merged with something else meanwhile.
// C++ parity: Merge::groupPartialRoot.
func (m *Merge) groupPartialRoot(vn *Varnode) {
	high := vn.High()
	if high == nil || len(high.Instances()) != 1 {
		return
	}
	var baseOffset int64
	if e := vn.GetSymbolEntry(); e != nil {
		baseOffset = int64(e.Offset())
	}
	var pieces []pieceNode
	gatherPieces(&pieces, vn, vn.Def(), baseOffset, baseOffset)
	for _, p := range pieces {
		nv := p.varnode()
		if !nv.IsProtoPartial() || nv.High() == nil || len(nv.High().Instances()) != 1 {
			for _, q := range pieces {
				q.varnode().ClearFlags(VarnodeProtoPartial)
			}
			return
		}
	}
	for _, p := range pieces {
		p.varnode().High().groupWith(p.typeOffset-baseOffset, high)
	}
}
