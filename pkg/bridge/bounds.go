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

package bridge

import (
	"fmt"
	"sort"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// AddrRange is a half-open range [Lo, Hi) of offsets in the entry's space.
type AddrRange struct{ Lo, Hi uint64 }

// flowBounds is the range flow may follow. Ghidra's FlowInfo has one range,
// [baddr, eaddr], always the whole space for a decompile
// (Funcdata::startProcessing); Gosleigh lets the host give the function's
// extent as several ranges (a split function), with no ranges meaning the
// whole space as in Ghidra.
type flowBounds []AddrRange

func (b flowBounds) contains(off uint64) bool {
	if len(b) == 0 {
		return true
	}
	for _, r := range b {
		if off >= r.Lo && off < r.Hi {
			return true
		}
	}
	return false
}

// last is the final address of the range holding off (Ghidra reports a
// fall-through past the range as flowing from eaddr).
func (b flowBounds) last(off uint64) uint64 {
	for _, r := range b {
		if off >= r.Lo && off < r.Hi {
			return r.Hi - 1
		}
	}
	return off
}

// outOfBounds collects the targets flow did not follow because they lie
// outside the bounds, each with the first address that flowed to it.
type outOfBounds struct {
	from  map[address.Address]address.Address
	order []address.Address
}

func (o *outOfBounds) add(from, to address.Address) {
	if o.from == nil {
		o.from = map[address.Address]address.Address{}
	}
	if _, ok := o.from[to]; !ok {
		o.from[to] = from
		o.order = append(o.order, to)
	}
}

// stubs returns a halt_missing record for every target not decoded anyway,
// in address order.
// C++ parity: FlowInfo::handleOutOfBounds (flow.cc:519) for the warning,
// FlowInfo::fillinBranchStubs (flow.cc:888) for the halts.
func (o *outOfBounds) stubs(known map[address.Address]int) []instructionRecord {
	sort.Slice(o.order, func(i, j int) bool { return o.order[i].Less(o.order[j]) })
	var out []instructionRecord
	for _, to := range o.order {
		if _, ok := known[to]; ok {
			continue
		}
		msg := fmt.Sprintf("Function flow out of bounds: %s flows to %s", rawWithShortcut(o.from[to]), rawWithShortcut(to))
		out = append(out, instructionRecord{translation: haltTranslation(to), halt: pcode.PcodeOpMissing, note: msg})
	}
	return out
}

// rawWithShortcut renders an address as Ghidra's getShortcut + printRaw;
// the shortcut is the space name's first letter (ram -> r).
func rawWithShortcut(a address.Address) string {
	s := ""
	if a.Space != nil && a.Space.Name != "" {
		c := a.Space.Name[0]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		s = string(c)
	}
	return s + pcode.PrintRawAddr(a)
}
