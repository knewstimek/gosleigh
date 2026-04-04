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

package sla

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestParsePspec verifies that ParsePspec correctly extracts context_set entries
// from x86.pspec and excludes tracked_set entries.
func TestParsePspec(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// pspec_test.go lives at pkg/sla/; x86.pspec is at ../../testdata/sla/x86.pspec
	pspecPath := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "x86.pspec")

	data, err := ParsePspec(pspecPath)
	if err != nil {
		t.Fatalf("ParsePspec: %v", err)
	}

	// context_set must contain addrsize=1 and opsize=1
	got := make(map[string]uint64)
	for _, e := range data.ContextSet {
		got[e.Name] = e.Value
	}

	if v, ok := got["addrsize"]; !ok {
		t.Error("missing addrsize in ContextSet")
	} else if v != 1 {
		t.Errorf("addrsize: want 1, got %d", v)
	}

	if v, ok := got["opsize"]; !ok {
		t.Error("missing opsize in ContextSet")
	} else if v != 1 {
		t.Errorf("opsize: want 1, got %d", v)
	}

	// tracked_set entries (DF) must NOT appear in ContextSet
	if _, ok := got["DF"]; ok {
		t.Error("tracked_set entry DF must not appear in ContextSet")
	}

	t.Logf("parsed %d context_set entries: %v", len(data.ContextSet), data.ContextSet)
}
