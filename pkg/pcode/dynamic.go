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

// DynamicHash is a robust identifier for Varnodes whose storage is ephemeral
// (temporaries, constants). The hash is computed by walking a bounded portion
// of the data-flow graph surrounding a root Varnode and CRC-folding the edges.
//
// This file ports the hash-decoding static helpers along with a minimal
// container and lookup entry points; the full calcHash / uniqueHash walk
// (including crc_update and the ToOpEdge sort) is left as a follow-up once
// PcodeOp sequence numbers and varnode walks expose the full C++ surface.
//
// C++ parity: dynamic.hh DynamicHash
type DynamicHash struct {
	addr address.Address // Address most closely associated with variable
	hash uint64          // Calculated hash value
}

// Hash returns the current computed hash.
// C++ parity: DynamicHash::getHash
func (d *DynamicHash) Hash() uint64 {
	if d == nil {
		return 0
	}
	return d.hash
}

// Address returns the code address most closely associated with the variable.
// C++ parity: DynamicHash::getAddress
func (d *DynamicHash) Address() address.Address {
	if d == nil {
		return address.Address{}
	}
	return d.addr
}

// Clear resets the in-progress hash state so the container can be reused.
// C++ parity: DynamicHash::clear
func (d *DynamicHash) Clear() {
	if d == nil {
		return
	}
	d.addr = address.Address{}
	d.hash = 0
}

// CalcHash computes the hash for the given root Varnode using the requested
// method variant (0..3). The full C++ implementation performs a bounded BFS of
// the data-flow graph, recording ToOpEdge entries and folding them through
// crc_update; porting that walk requires the PcodeOp sequence-number
// infrastructure which is still only partial.
// TODO: port DynamicHash::calcHash(const Varnode*, uint4)
// C++ parity: dynamic.cc DynamicHash::calcHash
func (d *DynamicHash) CalcHash(root *Varnode, method uint32) {
	if d == nil || root == nil {
		return
	}
	d.addr = root.Addr()
	d.hash = 0
}

// UniqueHash selects the lowest method variant producing a hash unique among
// Varnodes sharing the same address within fd. Full implementation pending;
// for now we simply call CalcHash(method=0) so the entry point exists for
// dependent Actions to link against.
// TODO: port DynamicHash::uniqueHash(const Varnode*, Funcdata*)
// C++ parity: dynamic.cc DynamicHash::uniqueHash
func (d *DynamicHash) UniqueHash(root *Varnode, fd *Funcdata) {
	d.CalcHash(root, 0)
}

// FindVarnode is the inverse of CalcHash: given an address and a previously
// captured hash, return the matching Varnode. Pending the calcHash port, this
// linear-scans the VarnodeBank and returns the first candidate whose address
// matches; this is enough for the current action stubs to exercise the lookup
// path even though full uniqueness across collisions is not yet guaranteed.
// TODO: reinstate the C++ collision-walk once ToOpEdge/opedge hashing lands.
// C++ parity: dynamic.cc DynamicHash::findVarnode
func (d *DynamicHash) FindVarnode(fd *Funcdata, addr address.Address, hash uint64) *Varnode {
	if fd == nil {
		return nil
	}
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil {
			continue
		}
		if vn.Addr() == addr {
			return vn
		}
	}
	return nil
}

// FindOp returns the PcodeOp matching the given address/hash pair. Pending the
// calcHash port this performs a linear scan of ops at the given address.
// TODO: reinstate the collision walk once ToOpEdge hashing lands.
// C++ parity: dynamic.cc DynamicHash::findOp
func (d *DynamicHash) FindOp(fd *Funcdata, addr address.Address, hash uint64) *PcodeOp {
	if fd == nil {
		return nil
	}
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil {
			continue
		}
		if op.Addr() == addr {
			return op
		}
	}
	return nil
}

// GetSlotFromHash pulls the slot field out of a dynamic hash. A slot of 31
// encodes "output Varnode" and is returned as -1.
// C++ parity: DynamicHash::getSlotFromHash
func GetSlotFromHash(h uint64) int32 {
	res := int32((h >> 32) & 0x1f)
	if res == 31 {
		res = -1
	}
	return res
}

// GetMethodFromHash pulls the method index out of a dynamic hash.
// C++ parity: DynamicHash::getMethodFromHash
func GetMethodFromHash(h uint64) uint32 { return uint32((h >> 44) & 0xf) }

// GetOpCodeFromHash pulls the encoded op-code out of a dynamic hash.
// C++ parity: DynamicHash::getOpCodeFromHash
func GetOpCodeFromHash(h uint64) uint32 { return uint32((h >> 37) & 0x7f) }

// GetPositionFromHash pulls the collision-position field out of a dynamic hash.
// C++ parity: DynamicHash::getPositionFromHash
func GetPositionFromHash(h uint64) uint32 { return uint32((h >> 49) & 0x7) }

// GetTotalFromHash pulls the collision-total field out of a dynamic hash.
// C++ parity: DynamicHash::getTotalFromHash
func GetTotalFromHash(h uint64) uint32 { return uint32((h>>52)&0x7) + 1 }

// GetIsNotAttached reports whether the attached-bit is clear in the hash.
// C++ parity: DynamicHash::getIsNotAttached
func GetIsNotAttached(h uint64) bool { return ((h >> 48) & 1) != 0 }

// ClearTotalPosition wipes the collision/total/position bits out of a hash so
// two hashes can be compared for value-equivalence without the collision data.
// C++ parity: DynamicHash::clearTotalPosition
func ClearTotalPosition(h uint64) uint64 {
	const mask = uint64(0x3f) << 49
	return h &^ mask
}

// GetComparable returns the low 32 bits, which is the formal hash value used
// for equality comparisons across methods.
// C++ parity: DynamicHash::getComparable
func GetComparable(h uint64) uint32 { return uint32(h) }
