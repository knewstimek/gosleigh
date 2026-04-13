/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pcode

import "gosleigh/pkg/address"

// StringSequence is the Go scaffold for StringSequence in constseq.cc.
type StringSequence struct {
	valid bool
}

// NewStringSequence is the Go scaffold for StringSequence::StringSequence in constseq.cc.
func NewStringSequence(_ *Funcdata, _ Datatype, _ any, root *PcodeOp, _ address.Address) *StringSequence {
	seq := &StringSequence{}
	if root != nil && root.Code() == CPUI_COPY {
		seq.valid = true
	}
	return seq
}

// IsValid is the Go scaffold for StringSequence::isValid in constseq.cc.
func (s *StringSequence) IsValid() bool {
	return s != nil && s.valid
}

// Transform is the Go scaffold for StringSequence::transform in constseq.cc.
func (s *StringSequence) Transform() bool {
	// TODO: Port ArraySequence/StringSequence collection, interference checks,
	// and CALLOTHER replacement logic from constseq.cc.
	_ = s
	return false
}

// HeapSequence is the Go scaffold for HeapSequence in constseq.cc.
type HeapSequence struct {
	valid bool
}

// NewHeapSequence is the Go scaffold for HeapSequence::HeapSequence in constseq.cc.
func NewHeapSequence(_ *Funcdata, _ Datatype, root *PcodeOp) *HeapSequence {
	seq := &HeapSequence{}
	if root != nil && root.Code() == CPUI_STORE {
		seq.valid = true
	}
	return seq
}

// IsValid is the Go scaffold for HeapSequence::isValid in constseq.cc.
func (h *HeapSequence) IsValid() bool {
	return h != nil && h.valid
}

// Transform is the Go scaffold for HeapSequence::transform in constseq.cc.
func (h *HeapSequence) Transform() bool {
	// TODO: Port ArraySequence/HeapSequence store collection and INDIRECT
	// reconstruction logic from constseq.cc.
	_ = h
	return false
}
