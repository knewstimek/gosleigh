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

package specs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The embedded copies must stay identical to the specs every golden test
// loads, or the library would decompile with a different spec than the one
// measured.
func TestEmbeddedMatchesTestdata(t *testing.T) {
	entries, err := os.ReadDir("data")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		got, err := os.ReadFile(filepath.Join("data", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sla", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from testdata/sla", e.Name())
		}
	}
}

func TestX86(t *testing.T) {
	for _, bits := range []int{32, 64} {
		for _, cc := range []string{CompilerWindows, CompilerGCC, CompilerGolang} {
			s, err := X86(bits, cc)
			if err != nil || len(s.SLA) == 0 || len(s.Pspec) == 0 || len(s.Cspec) == 0 {
				t.Errorf("X86(%d, %q) = %q, %v", bits, cc, s.ID, err)
			}
		}
	}
	if _, err := X86(16, CompilerWindows); err == nil {
		t.Error("X86(16) should fail")
	}
	if _, err := X86(64, "borland"); err == nil {
		t.Error("X86(64, borland) should fail")
	}
}
