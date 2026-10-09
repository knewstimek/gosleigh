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

// Package specs embeds the Ghidra language specs a host needs to decompile
// without shipping spec files next to its binary. Only x86 (32/64-bit) is
// embedded; importing this package adds about 1 MB.
//
// The files under data/ are copies of testdata/sla (Ghidra 12 packed .sla and
// the matching x86.ldefs pspec/cspec pairs); TestEmbeddedMatchesTestdata keeps
// them identical.
package specs

import (
	_ "embed"
	"fmt"

	"github.com/knewstimek/gosleigh/pkg/decomp"
)

var (
	//go:embed data/x86.sla
	x86SLA []byte
	//go:embed data/x86.pspec
	x86Pspec []byte
	//go:embed data/x86win.cspec
	x86Win []byte
	//go:embed data/x86gcc.cspec
	x86Gcc []byte
	//go:embed data/x86-64.sla
	x64SLA []byte
	//go:embed data/x86-64.pspec
	x64Pspec []byte
	//go:embed data/x86-64-win.cspec
	x64Win []byte
	//go:embed data/x86-64-gcc.cspec
	x64Gcc []byte
)

// Compiler ids follow x86.ldefs <compiler id=...>.
const (
	CompilerWindows = "windows" // Visual Studio (and clang targeting Windows)
	CompilerGCC     = "gcc"
)

// X86 returns the embedded spec for x86 with the given address size (32 or
// 64) and compiler id, as x86.ldefs pairs them: x86:LE:32:default and
// x86:LE:64:default with x86win/x86gcc and x86-64-win/x86-64-gcc.
func X86(bits int, compiler string) (decomp.Spec, error) {
	var s decomp.Spec
	switch bits {
	case 32:
		s = decomp.Spec{SLA: x86SLA, Pspec: x86Pspec}
		switch compiler {
		case CompilerWindows:
			s.Cspec = x86Win
		case CompilerGCC:
			s.Cspec = x86Gcc
		}
	case 64:
		s = decomp.Spec{SLA: x64SLA, Pspec: x64Pspec}
		switch compiler {
		case CompilerWindows:
			s.Cspec = x64Win
		case CompilerGCC:
			s.Cspec = x64Gcc
		}
	default:
		return decomp.Spec{}, fmt.Errorf("specs: x86 address size %d not embedded (32 or 64)", bits)
	}
	if s.Cspec == nil {
		return decomp.Spec{}, fmt.Errorf("specs: x86 compiler %q not embedded (%q or %q)", compiler, CompilerWindows, CompilerGCC)
	}
	s.ID = fmt.Sprintf("x86:LE:%d:default:%s", bits, compiler)
	return s, nil
}
