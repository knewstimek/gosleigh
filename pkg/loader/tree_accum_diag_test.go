package loader_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// TestTreeAccumDiag (ACCUM_DIAG=1) runs the universal-action tree on counted_loop
// and dumps the SSA op stream + the HighVariable grouping (which varnodes share a
// High pointer), to confirm whether the two loop registers (register:0x0 counter and
// register:0x4 accumulator) are over-merged into one High. Diagnostic only.
func TestTreeAccumDiag(t *testing.T) {
	if os.Getenv("ACCUM_DIAG") == "" {
		t.Skip("set ACCUM_DIAG=1 to run")
	}
	// counted_loop bytes (same as tree_goldens_diag_test.go:64).
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x05, 0x7D, 0x0B, 0x8B, 0x4D, 0xF8, 0x03, 0x4D, 0xFC, 0x89, 0x4D, 0xF8, 0xEB, 0xE6, 0x8B, 0x45, 0xF8, 0x8B, 0xE5, 0x5D, 0xC3}
	if os.Getenv("ACCUM_CASE") == "sum_list" {
		// sum_list bytes (same as tree_goldens_diag_test.go:65).
		prog = []byte{0x55, 0x8B, 0xEC, 0x51, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x83, 0x7D, 0x08, 0x00, 0x74, 0x16, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0xFC, 0x03, 0x08, 0x89, 0x4D, 0xFC, 0x8B, 0x55, 0x08, 0x8B, 0x42, 0x04, 0x89, 0x45, 0x08, 0xEB, 0xE4, 0x8B, 0x45, 0xFC, 0x8B, 0xE5, 0x5D, 0xC3}
	}
	if os.Getenv("ACCUM_CASE") == "classify_sign" {
		prog = []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x83, 0xF8, 0x00, 0x74, 0x0C, 0x83, 0xF8, 0x00, 0x7F, 0x0B, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xEB, 0x09, 0x31, 0xC0, 0xEB, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3}
	}

	dir := "."
	slaPath := dir + "/../sla/testdata/x86-packed.sla"
	pspecPath := dir + "/../../testdata/sla/x86.pspec"
	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "entry", Entry: base, MaxInstructions: 60})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}
	fd := result.Funcdata

	// RAW_DUMP: dump SSA right after heritage (before any analysis rules) to see
	// the raw instruction lowering (e.g. the jg flag expression). Returns early.
	if os.Getenv("RAW_DUMP") != "" {
		pcode.NewHeritage(fd, result.HeritageSpaces).Heritage(result.Graph)
		pcode.NewActionStackPtrFlow("analysis").Apply(fd)
		var rb strings.Builder
		rb.WriteString("=== RAW SSA (post-heritage) ===\n")
		for _, op := range fd.GetPcodeOpBank().AliveOps() {
			par := "detached"
			if op.Parent() != nil {
				par = fmt.Sprintf("blk%d", op.Parent().Index())
			}
			rb.WriteString("  [" + par + "] ")
			if out := op.Output(); out != nil {
				rb.WriteString(vnHi(out) + " = ")
			}
			rb.WriteString(op.Code().String())
			for s := 0; s < op.NumInput(); s++ {
				rb.WriteString(" " + vnHi(op.Input(s)))
			}
			rb.WriteString("\n")
		}
		t.Logf("%s", rb.String())
		return
	}

	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	act := db.SetCurrent("decompile")
	act.Perform(fd)

	// Dump SSA op stream.
	var sb strings.Builder
	sb.WriteString("=== SSA DUMP: counted_loop tree ===\n")
	bg := fd.GetBasicBlocks()
	for i := 0; i < bg.GetSize(); i++ {
		bb, ok := bg.GetBlock(i).Concrete().(*pcode.BlockBasic)
		if !ok || bb == nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("-- block %d --\n", i))
		for _, op := range bb.Ops() {
			sb.WriteString("  ")
			if out := op.Output(); out != nil {
				sb.WriteString(vnHi(out) + " = ")
			}
			sb.WriteString(op.Code().String())
			for s := 0; s < op.NumInput(); s++ {
				sb.WriteString(" " + vnHi(op.Input(s)))
			}
			sb.WriteString("\n")
		}
	}
	t.Logf("%s", sb.String())

	// Dump HighVariable grouping: distinct High pointer -> instances.
	groups := map[string][]*pcode.Varnode{}
	order := []string{}
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		hv := vn.High()
		key := "<nil>"
		if hv != nil {
			key = fmt.Sprintf("%p#%s", hv, hv.Name())
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], vn)
	}
	// Dump all alive ops (including any detached from basic blocks) to locate
	// definitions of varnodes referenced but not shown in the block walk.
	var ab strings.Builder
	ab.WriteString("=== ALIVE OPS ===\n")
	for _, op := range fd.GetPcodeOpBank().AliveOps() {
		par := "detached"
		if op.Parent() != nil {
			par = fmt.Sprintf("blk%d", op.Parent().Index())
		}
		ab.WriteString("  [" + par + "] ")
		if out := op.Output(); out != nil {
			ab.WriteString(vnHi(out) + " = ")
		}
		ab.WriteString(op.Code().String())
		for s := 0; s < op.NumInput(); s++ {
			ab.WriteString(" " + vnHi(op.Input(s)))
		}
		flags := ""
		if op.HasFlag(pcode.PcodeOpNonPrinting) {
			flags += " NONPRINT"
		}
		ab.WriteString(flags + "\n")
	}
	t.Logf("%s", ab.String())

	// Production dump for comparison: fresh build + bridge.Decompile (mutates fd
	// in place), then dump alive ops.
	if os.Getenv("PROD_DUMP") != "" {
		engine2, base2, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
		if err != nil {
			t.Fatalf("Build prod: %v", err)
		}
		result2, err := bridge.Build(engine2, bridge.BuildConfig{Name: "entry", Entry: base2, MaxInstructions: 60})
		if err != nil {
			t.Fatalf("bridge.Build prod: %v", err)
		}
		_, err = bridge.Decompile(engine2, result2, bridge.DecompileConfig{GhidraFormat: true, ProcessEntryName: "processEntry", GhostParams: 2})
		if err != nil {
			t.Fatalf("Decompile prod: %v", err)
		}
		var pb strings.Builder
		pb.WriteString("=== PRODUCTION ALIVE OPS ===\n")
		for _, op := range result2.Funcdata.GetPcodeOpBank().AliveOps() {
			par := "detached"
			if op.Parent() != nil {
				par = fmt.Sprintf("blk%d", op.Parent().Index())
			}
			pb.WriteString("  [" + par + "] ")
			if out := op.Output(); out != nil {
				pb.WriteString(vnHi(out) + " = ")
			}
			pb.WriteString(op.Code().String())
			for s := 0; s < op.NumInput(); s++ {
				pb.WriteString(" " + vnHi(op.Input(s)))
			}
			if op.HasFlag(pcode.PcodeOpNonPrinting) {
				pb.WriteString(" NONPRINT")
			}
			pb.WriteString("\n")
		}
		t.Logf("%s", pb.String())
	}

	sort.Strings(order)
	var hb strings.Builder
	hb.WriteString("=== HIGH GROUPS: counted_loop tree ===\n")
	for _, key := range order {
		hb.WriteString(key + ":\n")
		for _, vn := range groups[key] {
			hb.WriteString("    " + vnHi(vn) + "\n")
		}
	}
	t.Logf("%s", hb.String())
}

// vnHi formats a varnode as space:0xoff[size]#hvname<flags> for high-group diagnosis.
func vnHi(vn *pcode.Varnode) string {
	if vn == nil {
		return "<nil>"
	}
	name := ""
	if hv := vn.High(); hv != nil {
		name = hv.Name()
	}
	flags := ""
	if vn.IsInput() {
		flags += "I"
	}
	if vn.IsAddrTied() {
		flags += "T"
	}
	if vn.IsWritten() {
		flags += "W"
	}
	sp := "?"
	if vn.Space() != nil {
		sp = vn.Space().Name
	}
	return fmt.Sprintf("%s:0x%x[%d]#%s<%s>", sp, vn.Offset(), vn.Size(), name, flags)
}
