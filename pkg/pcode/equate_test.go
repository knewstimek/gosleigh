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

import "testing"

// TestEquateIsValueClose follows EquateSymbol::isValueClose: a value matches
// itself, its complement, negation, +/-1 and its sign-extended form.
func TestEquateIsValueClose(t *testing.T) {
	sym := &Symbol{category: SymbolEquate, equateValue: 0x10}
	for _, v := range []uint64{0x10, 0xffffffef, 0xfffffff0, 0x11, 0xf} {
		if !sym.isValueClose(v, 4) {
			t.Errorf("0x%x should be close to 0x10", v)
		}
	}
	if sym.isValueClose(0x20, 4) {
		t.Error("0x20 is not close to 0x10")
	}
	neg := &Symbol{category: SymbolEquate, equateValue: ^uint64(0)} // -1
	if !neg.isValueClose(0xffff, 2) {
		t.Error("-1 sign-extended should match 0xffff at size 2")
	}
}
