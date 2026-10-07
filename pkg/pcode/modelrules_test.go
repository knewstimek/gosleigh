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
	"encoding/xml"
	"testing"

	"gosleigh/pkg/address"
)

// parseRules decodes the <rule> elements of a parameter list snippet.
func parseRules(t *testing.T, src string) []CspecRule {
	t.Helper()
	var list struct {
		Rules []CspecRule `xml:"rule"`
	}
	if err := xml.Unmarshal([]byte("<input>"+src+"</input>"), &list); err != nil {
		t.Fatal(err)
	}
	return list.Rules
}

// TestModelRulesWin64 checks the x86-64 Windows <input>/<output> rules:
// a struct of size 3/5/6/7 goes by pointer, anything over pointermax (8)
// goes by pointer, and a returned struct of size 3 is returned through a
// hidden pointer that takes the first input register.
func TestModelRulesWin64(t *testing.T) {
	in, reg, _ := win64Model()
	in.SetModelRules(parseRules(t, `<rule><datatype name="struct" sizes="3,5,6,7"/><convert_to_ptr/></rule>`), 8, 8, false)
	out, _, _ := win64Model()
	out.SetModelRules(parseRules(t, `<rule><datatype name="struct" sizes="3,5,6,7"/><hidden_return/></rule>`), 0, 8, true)
	if !out.AutoKilledByCallLegacy() {
		t.Error("a hidden_return rule does not decide the return storage: legacy autoKilledByCall")
	}
	pm := &ProtoModel{InputParams: in, OutputParams: out}

	tf := sharedTypeFactory
	s6 := tf.GetStructSized("S6", 6, nil)
	s16 := tf.GetStructSized("S16", 16, nil)
	i4 := tf.GetBase(4, TYPE_INT, "int")
	res, ok := pm.assignParameterStorage(&prototypePieces{outtype: s6, intypes: []Datatype{s6, s16, i4}, firstVarArgSlot: -1})
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

// sysvModel is the x86-64 gcc input list: XMM0_Qa..XMM1_Qa (float), RDI,
// RSI (general), then the stack from offset 8.
func sysvModel(output bool) (*ParamListStandard, *address.Space, *address.Space, *address.Space) {
	reg := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8}
	stack := &address.Space{Name: "stack", Kind: address.SpaceKindStack, Index: 2, AddrSize: 8}
	join := address.JoinSpaceAt(9)
	specs := []ParamEntrySpec{
		{Space: reg, AddressBase: 0x1200, MinSize: 4, MaxSize: 8, IsFloat: true, GroupID: 0},
		{Space: reg, AddressBase: 0x1240, MinSize: 4, MaxSize: 8, IsFloat: true, GroupID: 1},
		{Space: reg, AddressBase: 0x38, MinSize: 1, MaxSize: 8, GroupID: 2},
		{Space: reg, AddressBase: 0x30, MinSize: 1, MaxSize: 8, GroupID: 3},
	}
	if !output {
		specs = append(specs, ParamEntrySpec{Space: stack, AddressBase: 8, MinSize: 1, MaxSize: 500, Align: 8, GroupID: 4})
	}
	pl := NewParamListStandard(specs)
	pl.SetJoinContext(join, func(*address.Space, uint64, int32) string { return "" })
	return pl, reg, stack, join
}

// TestModelRulesSysV checks join_dual_class and goto_stack: a {double,long}
// structure takes XMM0_Qa and RDI as one join, a 24-byte structure goes to
// the stack, and a double after it still takes the next float register.
func TestModelRulesSysV(t *testing.T) {
	in, reg, stack, join := sysvModel(false)
	in.SetModelRules(parseRules(t, `<rule><datatype name="any" maxsize="16"/><join_dual_class/></rule>
		<rule><datatype name="any"/><goto_stack/></rule>`), 0, 8, false)
	if len(in.modelRules) != 2 {
		t.Fatalf("rules = %d, want 2", len(in.modelRules))
	}
	tf := sharedTypeFactory
	f8 := tf.GetBase(8, TYPE_FLOAT, "double")
	i8 := tf.GetBase(8, TYPE_INT, "long")
	mixed := tf.GetStructSized("Mixed", 16, []TypeField{{Ident: 0, Offset: 0, Name: "d", Type: f8}, {Ident: 1, Offset: 8, Name: "l", Type: i8}})
	big := tf.GetStructSized("Big", 24, []TypeField{{Ident: 0, Offset: 0, Name: "a", Type: i8}, {Ident: 1, Offset: 8, Name: "b", Type: i8}, {Ident: 2, Offset: 16, Name: "c", Type: i8}})
	proto := &prototypePieces{outtype: tf.GetVoid(), intypes: []Datatype{mixed, big, f8}, firstVarArgSlot: -1}
	res, ok := in.assignInputs(proto, []parameterPieces{{typ: tf.GetVoid()}})
	if !ok || len(res) != 4 {
		t.Fatalf("assignment failed: %v %d", ok, len(res))
	}
	if res[1].addr.Space != join {
		t.Fatalf("Mixed = %+v, want join storage", res[1].addr)
	}
	rec := address.FindAddJoin(join, []address.VarnodeData{{Space: reg, Offset: 0x38, Size: 8}, {Space: reg, Offset: 0x1200, Size: 8}}, 0)
	if res[1].addr != rec.Unified.Addr() {
		t.Errorf("Mixed join = %+v, want RDI:XMM0_Qa (most significant first)", res[1].addr)
	}
	if res[2].addr.Space != stack || res[2].addr.Offset != 8 {
		t.Errorf("Big = %+v, want stack+8", res[2].addr)
	}
	if res[3].addr.Space != reg || res[3].addr.Offset != 0x1240 {
		t.Errorf("double = %+v, want XMM1_Qa", res[3].addr)
	}
}

// TestFillinOutputJoin checks the join_dual_class output rule: RAX and RDX
// trials (consecutive general entries from the first) are both used.
func TestFillinOutputJoin(t *testing.T) {
	reg := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8}
	specs := []ParamEntrySpec{
		{Space: reg, AddressBase: 0x1200, MinSize: 4, MaxSize: 8, IsFloat: true, GroupID: 0},
		{Space: reg, AddressBase: 0x1240, MinSize: 4, MaxSize: 8, IsFloat: true, GroupID: 1},
		{Space: reg, AddressBase: 0x00, MinSize: 1, MaxSize: 8, GroupID: 2},
		{Space: reg, AddressBase: 0x10, MinSize: 1, MaxSize: 8, GroupID: 3},
	}
	out := NewParamListStandard(specs)
	out.SetModelRules(parseRules(t, `<rule><datatype name="any" maxsize="16"/><join_dual_class/></rule>
		<rule><datatype name="any"/><hidden_return/></rule>`), 0, 8, true)
	if out.AutoKilledByCallLegacy() {
		t.Error("join_dual_class decides the return storage: not legacy")
	}
	active := NewParamActive(false)
	for _, off := range []uint64{0x00, 0x10} {
		active.RegisterTrial(address.Address{Space: reg, Offset: off}, 8)
		active.Trial(active.NumTrials() - 1).MarkActive()
	}
	out.FillinMapOut(active)
	for i := 0; i < active.NumTrials(); i++ {
		if !active.Trial(i).IsUsed() {
			t.Errorf("trial %d not used", i)
		}
	}
}
