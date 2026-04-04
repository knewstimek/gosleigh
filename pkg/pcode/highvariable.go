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

// HighVariable is a high-level variable that may be backed by one or more
// low-level Varnodes (SSA values). It carries a human-readable name for
// output in the decompiler.
//
// C++ parity: varnode.hh HighVariable (partial)
type HighVariable struct {
	name      string
	instances []*Varnode
}

// NewHighVariable creates a HighVariable with the given name and zero instances.
// C++ parity: HighVariable::HighVariable
func NewHighVariable(name string) *HighVariable {
	return &HighVariable{name: name}
}

// Name returns the display name of this variable.
func (hv *HighVariable) Name() string {
	if hv == nil {
		return ""
	}
	return hv.name
}

// SetName sets the display name.
func (hv *HighVariable) SetName(name string) {
	if hv == nil {
		return
	}
	hv.name = name
}

// AddInstance associates a Varnode with this high variable and sets the
// back-pointer on the varnode.
// C++ parity: HighVariable::merge / Varnode::setHigh
func (hv *HighVariable) AddInstance(vn *Varnode) {
	if hv == nil || vn == nil {
		return
	}
	hv.instances = append(hv.instances, vn)
	vn.SetHigh(hv)
}

// NumInstances returns the number of associated low-level varnodes.
func (hv *HighVariable) NumInstances() int {
	if hv == nil {
		return 0
	}
	return len(hv.instances)
}

// GetInstance returns the i-th associated varnode, or nil if out of range.
func (hv *HighVariable) GetInstance(i int) *Varnode {
	if hv == nil || i < 0 || i >= len(hv.instances) {
		return nil
	}
	return hv.instances[i]
}
