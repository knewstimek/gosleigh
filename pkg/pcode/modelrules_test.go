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

// TestModelRulesWin64 checks the x86-64 Windows <input>/<output> rules:
// a struct of size 3/5/6/7 goes by pointer, anything over pointermax (8)
// goes by pointer, and a returned struct of size 3 is returned through a
// hidden pointer that takes the first input register.
func TestModelRulesWin64(t *testing.T) {
	in, reg, _ := win64Model()
	in.SetModelRules([]CspecRuleSpec{{TypeName: "struct", Sizes: "3,5,6,7", ConvertToPtr: true}}, 8, 8)
	out, _, _ := win64Model()
	out.SetModelRules([]CspecRuleSpec{{TypeName: "struct", Sizes: "3,5,6,7", HiddenReturn: true}}, 0, 8)
	pm := &ProtoModel{InputParams: in, OutputParams: out}

	tf := sharedTypeFactory
	s6 := tf.GetStructSized("S6", 6, nil)
	s16 := tf.GetStructSized("S16", 16, nil)
	i4 := tf.GetBase(4, TYPE_INT, "int")
	res, ok := pm.assignParameterStorage(s6, []Datatype{s6, s16, i4})
	if !ok {
		t.Fatal("assignment failed")
	}
	if len(res) != 5 {
		t.Fatalf("pieces = %d, want output + hidden + 3 inputs", len(res))
	}
	if res[1].flags&pieceHiddenRetParm == 0 || res[1].addr.Space != reg || res[1].addr.Offset != 0x08 {
		t.Errorf("hidden return pointer = %+v, want first register", res[1])
	}
	for i, want := range []uint64{0x10, 0x50} {
		p := res[2+i]
		if p.typ.Metatype() != TYPE_PTR || p.flags&pieceIndirectStorage == 0 || p.addr.Offset != want {
			t.Errorf("input %d = %+v, want pointer in register %#x", i, p, want)
		}
	}
	if p := res[4]; p.typ != i4 || p.addr.Offset != 0x58 {
		t.Errorf("int input = %+v, want int in register 0x58", p)
	}
}
