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

import "github.com/knewstimek/gosleigh/pkg/address"

// processJoins splits every join-space Varnode into its real pieces, so
// join addresses take no part in heritage: a read becomes a PIECE of the
// pieces, a write is SUBPIECEd into them (once, when the pieces' space is
// heritaged). C++ parity: Heritage::processJoins.
func (h *Heritage) processJoins() {
	js := h.fd.joinSpace
	if js == nil {
		return
	}
	for _, vn := range h.fd.VarnodesBySpace(js) {
		joinrec := address.FindJoin(vn.Offset())
		if joinrec == nil || joinrec.Unified.Size != vn.Size() {
			continue // C++ throws: joined varnode does not match its record
		}
		if vn.IsFree() {
			if joinrec.IsFloatExtension() {
				h.floatExtensionRead(vn, joinrec)
			} else {
				h.splitJoinRead(vn, joinrec)
			}
		}
		info := h.infoForSpace(joinrec.Piece(0).Space)
		if info == nil || h.pass != info.Delay {
			continue // It is too soon to heritage this space
		}
		if joinrec.IsFloatExtension() {
			h.floatExtensionWrite(vn, joinrec)
		} else {
			h.splitJoinWrite(vn, joinrec)
		}
	}
}

// entryBlock is the function's first basic block.
func (fd *Funcdata) entryBlock() *BlockBasic {
	bg := fd.GetBasicBlocks()
	if bg == nil || bg.GetSize() == 0 {
		return nil
	}
	bb, _ := bg.GetBlock(0).Concrete().(*BlockBasic)
	return bb
}

func (h *Heritage) infoForSpace(spc *address.Space) *HeritageInfo {
	for i := range h.infoList {
		if h.infoList[i].Space == spc {
			return &h.infoList[i]
		}
	}
	return nil
}

// splitJoinLevel splits each Varnode of lastcombo into a most and least
// significant half along the join pieces; an unsplit Varnode is followed by
// nil. C++ parity: Heritage::splitJoinLevel.
func (h *Heritage) splitJoinLevel(lastcombo []*Varnode, joinrec *address.JoinRecord) []*Varnode {
	var nextlev []*Varnode
	numpieces := joinrec.NumPieces()
	recnum := 0
	for _, curvn := range lastcombo {
		if curvn.Size() == joinrec.Piece(recnum).Size {
			nextlev = append(nextlev, curvn, nil)
			recnum++
			continue
		}
		sizeaccum := int32(0)
		j := recnum
		for ; j < numpieces; j++ {
			sizeaccum += joinrec.Piece(j).Size
			if sizeaccum == curvn.Size() {
				j++
				break
			}
		}
		numinhalf := (j - recnum) / 2 // Will be at least 1
		sizeaccum = 0
		for k := 0; k < numinhalf; k++ {
			sizeaccum += joinrec.Piece(recnum + k).Size
		}
		var mosthalf, leasthalf *Varnode
		if numinhalf == 1 {
			mosthalf = h.fd.NewVarnode(sizeaccum, joinrec.Piece(recnum).Addr())
		} else {
			mosthalf = h.fd.NewUnique(sizeaccum)
		}
		if j-recnum == 2 {
			vdata := joinrec.Piece(recnum + 1)
			leasthalf = h.fd.NewVarnode(vdata.Size, vdata.Addr())
		} else {
			leasthalf = h.fd.NewUnique(curvn.Size() - sizeaccum)
		}
		nextlev = append(nextlev, mosthalf, leasthalf)
		recnum = j
	}
	return nextlev
}

// splitJoinRead rebuilds a free join Varnode from its pieces with PIECE ops.
// C++ parity: Heritage::splitJoinRead.
func (h *Heritage) splitJoinRead(vn *Varnode, joinrec *address.JoinRecord) {
	op := vn.LoneDescend() // vn isFree, so loneDescend must be non-null
	if op == nil {
		return
	}
	isPrimitive := true
	if vn.IsTypeLock() {
		isPrimitive = isPrimitiveWhole(vn.Type())
	}
	lastcombo := []*Varnode{vn}
	for len(lastcombo) < joinrec.NumPieces() {
		nextlev := h.splitJoinLevel(lastcombo, joinrec)
		for i, curvn := range lastcombo {
			mosthalf, leasthalf := nextlev[2*i], nextlev[2*i+1]
			if leasthalf == nil {
				continue // Varnode didn't get split this level
			}
			concat := h.fd.NewOp(2, op.Addr())
			h.fd.OpSetOpcode(concat, CPUI_PIECE)
			h.fd.OpSetOutput(concat, curvn)
			h.fd.OpSetInput(concat, mosthalf, 0)
			h.fd.OpSetInput(concat, leasthalf, 1)
			h.fd.OpInsertBefore(concat, op)
			if isPrimitive {
				mosthalf.SetPrecisHi() // Trigger the double precision rules
				leasthalf.SetPrecisLo()
			} else {
				concat.SetFlag(PcodeOpNoCollapse)
			}
			op = concat // Keep op as the earliest op of the construction
		}
		lastcombo = lastcombo[:0]
		for _, curvn := range nextlev {
			if curvn != nil {
				lastcombo = append(lastcombo, curvn)
			}
		}
	}
}

// splitJoinWrite splits a written or input join Varnode into its pieces
// with SUBPIECE ops. C++ parity: Heritage::splitJoinWrite.
func (h *Heritage) splitJoinWrite(vn *Varnode, joinrec *address.JoinRecord) {
	op := vn.Def() // vn cannot be free: it has a def or is an input
	bb := h.fd.entryBlock()
	isPrimitive := true
	if vn.IsTypeLock() {
		isPrimitive = isPrimitiveWhole(vn.Type())
	}
	lastcombo := []*Varnode{vn}
	for len(lastcombo) < joinrec.NumPieces() {
		nextlev := h.splitJoinLevel(lastcombo, joinrec)
		for i, curvn := range lastcombo {
			mosthalf, leasthalf := nextlev[2*i], nextlev[2*i+1]
			if leasthalf == nil {
				continue // Varnode didn't get split this level
			}
			var split *PcodeOp
			if vn.IsInput() {
				split = h.fd.NewOp(2, bb.startAddr())
			} else {
				split = h.fd.NewOp(2, op.Addr())
			}
			h.fd.OpSetOpcode(split, CPUI_SUBPIECE)
			h.fd.OpSetOutput(split, mosthalf)
			h.fd.OpSetInput(split, curvn, 0)
			h.fd.OpSetInput(split, h.fd.NewConstant(4, uint64(leasthalf.Size())), 1)
			if op == nil {
				h.fd.OpInsertBegin(split, bb)
			} else {
				h.fd.OpInsertAfter(split, op)
			}
			op = split // Keep op as the latest op of the construction

			split = h.fd.NewOp(2, op.Addr())
			h.fd.OpSetOpcode(split, CPUI_SUBPIECE)
			h.fd.OpSetOutput(split, leasthalf)
			h.fd.OpSetInput(split, curvn, 0)
			h.fd.OpSetInput(split, h.fd.NewConstant(4, 0), 1)
			h.fd.OpInsertAfter(split, op)
			if isPrimitive {
				mosthalf.SetPrecisHi()
				leasthalf.SetPrecisLo()
			}
			op = split
		}
		lastcombo = lastcombo[:0]
		for _, curvn := range nextlev {
			if curvn != nil {
				lastcombo = append(lastcombo, curvn)
			}
		}
	}
}

// floatExtensionRead reads a float through its wider register.
// C++ parity: Heritage::floatExtensionRead.
func (h *Heritage) floatExtensionRead(vn *Varnode, joinrec *address.JoinRecord) {
	op := vn.LoneDescend()
	if op == nil {
		return
	}
	trunc := h.fd.NewOp(1, op.Addr())
	vdata := joinrec.Piece(0) // Float extensions have exactly 1 piece
	bigvn := h.fd.NewVarnode(vdata.Size, vdata.Addr())
	h.fd.OpSetOpcode(trunc, CPUI_FLOAT_FLOAT2FLOAT)
	h.fd.OpSetOutput(trunc, vn)
	h.fd.OpSetInput(trunc, bigvn, 0)
	h.fd.OpInsertBefore(trunc, op)
}

// floatExtensionWrite extends a float into its wider register.
// C++ parity: Heritage::floatExtensionWrite.
func (h *Heritage) floatExtensionWrite(vn *Varnode, joinrec *address.JoinRecord) {
	op := vn.Def()
	bb := h.fd.entryBlock()
	var ext *PcodeOp
	if vn.IsInput() {
		ext = h.fd.NewOp(1, bb.startAddr())
	} else {
		ext = h.fd.NewOp(1, op.Addr())
	}
	vdata := joinrec.Piece(0)
	h.fd.OpSetOpcode(ext, CPUI_FLOAT_FLOAT2FLOAT)
	h.fd.NewVarnodeOut(vdata.Size, vdata.Addr(), ext)
	h.fd.OpSetInput(ext, vn, 0)
	if op == nil {
		h.fd.OpInsertBegin(ext, bb)
	} else {
		h.fd.OpInsertAfter(ext, op)
	}
}

// numHeritagePasses is how many times the space has been heritaged
// (negative while its delay has not passed).
// C++ parity: Funcdata::numHeritagePasses / Heritage::numHeritagePasses.
func (fd *Funcdata) numHeritagePasses(spc *address.Space) int32 {
	h := fd.heritage
	if h == nil {
		return 0
	}
	h.BuildInfoList()
	if info := h.infoForSpace(spc); info != nil {
		return h.pass - info.Delay
	}
	return 0
}
