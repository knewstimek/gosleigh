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

// TestCastStandardC checks CastStrategyC.CastStandard against the generic C
// casting rules ported from cast.cc CastStrategyC::castStandard.
func TestCastStandardC(t *testing.T) {
	tf := NewTypeFactory()
	cs := NewCastStrategyC(tf)

	i4 := tf.GetBase(4, TYPE_INT, "int")
	u4 := tf.GetBase(4, TYPE_UINT, "uint")
	i2 := tf.GetBase(2, TYPE_INT, "short")
	vd := tf.GetVoid()
	pi := tf.GetPointer(4, i4, 1)
	pu := tf.GetPointer(4, u4, 1)
	pv := tf.GetPointer(4, vd, 1)

	cases := []struct {
		name           string
		req, cur       Datatype
		careUI, carePU bool
		wantCast       bool // true: CastStandard returns req (cast); false: returns nil
	}{
		{"equal int -> no cast", i4, i4, true, true, false},
		{"int from uint, careUI -> cast", i4, u4, true, true, true},
		{"int from uint, !careUI -> no cast", i4, u4, false, true, false},
		{"ptr(int) from ptr(uint) -> cast", pi, pu, true, true, true},
		{"ptr(int) from ptr(void) -> no cast", pi, pv, true, true, false},
		{"size mismatch int4<-int2 -> cast", i4, i2, true, true, true},
		{"from void -> cast", i4, vd, true, true, true},
		{"uint from ptr, !carePU -> no cast", u4, pi, true, false, false},
		{"uint from ptr, carePU -> cast", u4, pi, true, true, true},
	}

	for _, c := range cases {
		got := cs.CastStandard(c.req, c.cur, c.careUI, c.carePU)
		gotCast := got != nil
		if gotCast != c.wantCast {
			t.Errorf("%s: CastStandard cast=%v, want %v (got type %v)", c.name, gotCast, c.wantCast, got)
			continue
		}
		if gotCast && got != c.req {
			t.Errorf("%s: CastStandard returned %v, want req %v", c.name, got, c.req)
		}
	}
}
