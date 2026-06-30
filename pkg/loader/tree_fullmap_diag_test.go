package loader_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// treeMapCase configures one golden run through the universal-action tree.
type treeMapCase struct {
	name      string // friendly label
	goldenKey string // key in ghidra_golden.json
	slaRel    string // .sla path relative to this dir
	pspecRel  string // .pspec path relative to this dir
	cspecRel  string // .cspec path relative to this dir ("" = no cspec)
	prog      []byte
	procEntry string // SetProcessEntry name; "" disables processEntry mode
	ghosts    int    // ghost param count (processEntry mode)
	maxInstr  int
}

// runTreeCase builds the function and runs the faithful universal-action tree,
// returning the Ghidra-format C output for the given case config.
func runTreeCase(t *testing.T, dir string, c treeMapCase) (string, bool) {
	t.Helper()
	slaPath := filepath.Join(dir, c.slaRel)
	pspecPath := filepath.Join(dir, c.pspecRel)
	if _, err := os.Stat(slaPath); err != nil {
		t.Logf("[%s] SKIP: sla not found (%v)", c.name, err)
		return "", false
	}
	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: c.prog}).Build()
	if err != nil {
		t.Logf("[%s] BUILD-ERR: %v", c.name, err)
		return "", false
	}
	mi := c.maxInstr
	if mi == 0 {
		mi = 60
	}
	cfg := bridge.BuildConfig{Name: "entry", Entry: base, MaxInstructions: mi}
	// Pass the cspec so the universal-action tree builds an arch-aware default
	// ProtoModel (register params + integer return register). Without it,
	// register-based ABIs (x86-64, AArch64) lose their parameters/return value.
	if c.cspecRel != "" {
		cfg.CspecPath = filepath.Join(dir, c.cspecRel)
	}
	result, err := bridge.Build(engine, cfg)
	if err != nil {
		t.Logf("[%s] BRIDGE-ERR: %v", c.name, err)
		return "", false
	}
	fd := result.Funcdata
	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	db.SetCurrent("decompile").Perform(fd)
	p := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation()).SetGhidraFormat()
	if c.procEntry != "" {
		p = p.SetProcessEntry(c.procEntry, c.ghosts)
	}
	out, err := p.Emit(fd)
	if err != nil {
		t.Logf("[%s] EMIT-ERR: %v", c.name, err)
		return "", false
	}
	return out, true
}

// TestTreeFullGoldenMap (TREE_MAP=1) runs the universal-action tree against every
// golden that has reconstructable bytes, across architectures, and reports a
// match/mismatch map + diff. Diagnostic only; never fails. Builds the full gap map
// for promoting the tree to the production decompile path.
func TestTreeFullGoldenMap(t *testing.T) {
	if os.Getenv("TREE_MAP") == "" {
		t.Skip("set TREE_MAP=1 to run")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)

	const x86sla = "../sla/testdata/x86-packed.sla"
	const x86pspec = "../../testdata/sla/x86.pspec"
	const x86cspec = "../../testdata/sla/x86gcc.cspec"

	cases := []treeMapCase{
		// x86-32 corpus (processEntry, 2 ghost params). cdecl cspec: no register
		// params, EAX return -- arch-aware model resolves to the same x86 EAX(0,4).
		{"gcd", "gcd_x86_32", x86sla, x86pspec, x86cspec, []byte{0x8b, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x04, 0x85, 0xc9, 0x74, 0x0b, 0x99, 0xf7, 0xf9, 0x8b, 0xc1, 0x8b, 0xca, 0x85, 0xd2, 0x75, 0xf5, 0xc3}, "processEntry", 2, 60},
		{"abs_val", "abs_ifelse_x86_32", x86sla, x86pspec, x86cspec, []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7D, 0x07, 0x8B, 0x45, 0x08, 0xF7, 0xD8, 0xEB, 0x03, 0x8B, 0x45, 0x08, 0x5D, 0xC3}, "processEntry", 2, 60},
		{"classify2", "nested_if_x86_32", x86sla, x86pspec, x86cspec, []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7E, 0x18, 0x8B, 0x45, 0x0C, 0x3B, 0x45, 0x08, 0x7E, 0x09, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x0B, 0xEB, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x02, 0x33, 0xC0, 0x5D, 0xC3}, "processEntry", 2, 60},
		{"classify_sign", "classify_sign_x86_32", x86sla, x86pspec, x86cspec, []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x83, 0xF8, 0x00, 0x74, 0x0C, 0x83, 0xF8, 0x00, 0x7F, 0x0B, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xEB, 0x09, 0x31, 0xC0, 0xEB, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3}, "processEntry", 2, 60},
		{"multiply", "multiply_x86_32", x86sla, x86pspec, x86cspec, []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x0F, 0xAF, 0x45, 0x0C, 0x5D, 0xC3}, "processEntry", 2, 60},
		{"add3", "add3_x86_32", x86sla, x86pspec, x86cspec, []byte{0x55, 0x89, 0xE5, 0x53, 0x8B, 0x5D, 0x08, 0x03, 0x5D, 0x0C, 0x03, 0x5D, 0x10, 0x89, 0xD8, 0x5B, 0x5D, 0xC3}, "processEntry", 2, 60},
		{"counted_loop", "counted_loop_x86_32", x86sla, x86pspec, x86cspec, []byte{0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x05, 0x7D, 0x0B, 0x8B, 0x4D, 0xF8, 0x03, 0x4D, 0xFC, 0x89, 0x4D, 0xF8, 0xEB, 0xE6, 0x8B, 0x45, 0xF8, 0x8B, 0xE5, 0x5D, 0xC3}, "processEntry", 2, 60},
		{"sum_list", "sum_list_x86_32", x86sla, x86pspec, x86cspec, []byte{0x55, 0x8B, 0xEC, 0x51, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x83, 0x7D, 0x08, 0x00, 0x74, 0x16, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0xFC, 0x03, 0x08, 0x89, 0x4D, 0xFC, 0x8B, 0x55, 0x08, 0x8B, 0x42, 0x04, 0x89, 0x45, 0x08, 0xEB, 0xE4, 0x8B, 0x45, 0xFC, 0x8B, 0xE5, 0x5D, 0xC3}, "processEntry", 2, 60},
		// x86-64: SysV add, processEntry void form. gcc cspec: RDI/RSI... params, RAX return.
		{"x64_add_ret", "x64_add_ret", "../sla/testdata/x86-64-packed.sla", "../../testdata/sla/x86-64.pspec", "../../testdata/sla/x86-64-gcc.cspec", []byte{0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3}, "processEntry", 2, 10},
		// AArch64: plain entry name (no processEntry), params recovered. cspec: x0/x1... params, x0 return.
		{"aarch64_add_ret", "aarch64_add_ret", "../../testdata/sla/AARCH64.sla", "../../testdata/sla/AARCH64.pspec", "../../testdata/sla/AARCH64.cspec", []byte{0x00, 0x00, 0x01, 0x8B, 0xC0, 0x03, 0x5F, 0xD6}, "", 0, 10},
		// complex_max_x86_32: bytes not reconstructable (instruction-overlap golden); tracked separately.
	}

	pass := 0
	total := 0
	for _, c := range cases {
		got, ok := runTreeCase(t, dir, c)
		if !ok {
			continue
		}
		total++
		want := strings.TrimSpace(loadGhidraGolden(t, c.goldenKey))
		gotT := strings.TrimSpace(got)
		if gotT == want {
			pass++
			t.Logf("[MAP %s] MATCH", c.name)
		} else {
			t.Logf("[MAP %s] MISMATCH\n--- WANT ---\n%s\n--- GOT ---\n%s", c.name, want, gotT)
		}
	}
	t.Logf("TREE FULL MAP: %d/%d byte-identical (complex_max excluded: no bytes)", pass, total)
}
