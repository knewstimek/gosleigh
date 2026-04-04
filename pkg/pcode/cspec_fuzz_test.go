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

// FuzzParseCspec guards ParseCspecBytes against arbitrary byte sequences.
// It asserts that no panic occurs -- a returned error is acceptable because
// malformed XML is expected to fail gracefully.
//
// Run with: go test -fuzz=FuzzParseCspec ./pkg/pcode/
func FuzzParseCspec(f *testing.F) {
	// Seed corpus: known valid inputs and edge cases.
	f.Add([]byte(minimalCdeclXML))
	f.Add([]byte(`<compiler_spec></compiler_spec>`))
	f.Add([]byte(``))
	f.Add([]byte(`<compiler_spec><stackpointer register="ESP" space="ram"/></compiler_spec>`))
	f.Add([]byte(`<?xml version="1.0"?><compiler_spec/>`))
	f.Add([]byte(`not xml`))
	f.Add([]byte(`<`))
	f.Add([]byte(`<compiler_spec><prototype name="__cdecl"><input><pentry/></input></prototype></compiler_spec>`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic -- error return is fine.
		_, _ = ParseCspecBytes(data)
	})
}
