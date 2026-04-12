package loader_test

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

func TestMSVC_AbsVal_Debug(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7D, 0x07, 0x8B, 0x45, 0x08, 0xF7, 0xD8, 0xEB, 0x03, 0x8B, 0x45, 0x08, 0x5D, 0xC3}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Dump per-instruction pcode before bridge.Build to see raw translation.
	t.Log("=== PER-INSTRUCTION RAW PCODE ===")
	for i := 0; i < len(prog); {
		addr := address.Address{Space: base.Space, Offset: base.Offset + uint64(i)}
		tr, err2 := engine.TranslateInstructionAt(addr)
		if err2 != nil {
			t.Logf("  [0x%x] translate error: %v", i, err2)
			break
		}
		t.Logf("  instr @0x%x len=%d next=0x%x ops=%d", i, tr.Length, tr.Next.Offset, len(tr.Ops))
		for _, op := range tr.Ops {
			t.Logf("    %v", op.OpCode)
			for si, vn := range op.Inputs {
				t.Logf("      in[%d] space=%s off=0x%x size=%d", si, vn.Space.Name, vn.Offset, vn.Size)
			}
			if op.Output != nil {
				t.Logf("      out  space=%s off=0x%x size=%d", op.Output.Space.Name, op.Output.Offset, op.Output.Size)
			}
		}
		if tr.Length <= 0 {
			break
		}
		i += tr.Length
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "entry", Entry: base, MaxInstructions: 60})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	t.Log("=== BLOCKS BEFORE HERITAGE ===")
	graph := result.Graph
	t.Logf("num blocks: %d", graph.GetSize())
	for i := 0; i < graph.GetSize(); i++ {
		blk := graph.GetBlock(i)
		if blk == nil {
			continue
		}
		t.Logf("block[%d] index=%d in=%d out=%d", i, blk.Index(), blk.SizeIn(), blk.SizeOut())
		for oi := 0; oi < blk.SizeOut(); oi++ {
			edge := blk.OutEdge(oi)
			t.Logf("  -> block[%d]", edge.Point.Index())
		}
	}

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)

	t.Log("=== PCODE AFTER HERITAGE ===")
	for _, op := range result.Funcdata.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		out := "<nil>"
		if op.Output() != nil {
			vn := op.Output()
			out = fmt.Sprintf("[%s:%d:%d]", spaceName(vn.Space()), vn.Offset(), vn.Size())
		}
		inputs := ""
		for si := 0; si < op.NumInput(); si++ {
			vn := op.Input(si)
			if vn == nil {
				inputs += " <nil>"
			} else {
				inputs += fmt.Sprintf(" [%s:%x:%d]", spaceName(vn.Space()), vn.Offset(), vn.Size())
				if vn.IsInput() {
					inputs += "(in)"
				}
				if vn.IsConstant() {
					inputs += fmt.Sprintf("(c=%x)", vn.Offset())
				}
			}
		}
		t.Logf("  %v %s =%s", op.Code(), inputs, out)
	}

	spf := pcode.NewActionStackPtrFlow("analysis")
	changed := spf.Apply(result.Funcdata)
	t.Logf("=== ActionStackPtrFlow: changed=%d stackSpace=%v ===", changed, spf.StackSpace())

	pcode.NewActionFoldFlagConditions("analysis").Apply(result.Funcdata)
	pcode.NewActionConstantFold("analysis").Apply(result.Funcdata)

	t.Log("=== CBRANCH OPS AFTER FOLD ===")
	for _, op := range result.Funcdata.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		if op.Code() != pcode.CPUI_CBRANCH {
			continue
		}
		t.Logf("CBRANCH: target=%v cond=%v", formatVn(op.Input(0)), formatVnChain(result.Funcdata, op.Input(1), 3))
	}
}

func spaceName(sp *address.Space) string {
	if sp == nil {
		return "nil"
	}
	return sp.Name
}

func formatVn(vn *pcode.Varnode) string {
	if vn == nil {
		return "<nil>"
	}
	sp := vn.Space()
	nm := spaceName(sp)
	if vn.IsConstant() {
		return fmt.Sprintf("const:0x%x", vn.Offset())
	}
	if vn.IsInput() {
		return fmt.Sprintf("%s:%x:%d(IN)", nm, vn.Offset(), vn.Size())
	}
	return fmt.Sprintf("%s:%x:%d", nm, vn.Offset(), vn.Size())
}

func formatVnChain(fd *pcode.Funcdata, vn *pcode.Varnode, depth int) string {
	if vn == nil || depth == 0 {
		return formatVn(vn)
	}
	def := vn.Def()
	if def == nil {
		return formatVn(vn)
	}
	inputs := ""
	for i := 0; i < def.NumInput(); i++ {
		if i > 0 {
			inputs += ","
		}
		inputs += formatVnChain(fd, def.Input(i), depth-1)
	}
	return fmt.Sprintf("%v(%s)", def.Code(), inputs)
}

func TestMSVC_Classify2_Debug(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7E, 0x18, 0x8B, 0x45, 0x0C, 0x3B, 0x45, 0x08, 0x7E, 0x09, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x0B, 0xEB, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x02, 0x33, 0xC0, 0x5D, 0xC3}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "entry", Entry: base, MaxInstructions: 60})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)

	t.Log("=== EAX RIGHT AFTER Heritage ===")
	for _, vn2 := range result.Funcdata.GetVarnodeBank().AllVarnodes() {
		if vn2 == nil || vn2.Space() == nil { continue }
		if vn2.Space().Name != "register" || vn2.Offset() != 0 || vn2.Size() != 4 { continue }
		dc := "no-def"
		if vn2.Def() != nil { dc = fmt.Sprintf("%v", vn2.Def().Code()) }
		t.Logf("  EAX vn: isInput=%v isWritten=%v ndesc=%d def=%s", vn2.IsInput(), vn2.IsWritten(), vn2.NumDescend(), dc)
	}

	spf := pcode.NewActionStackPtrFlow("analysis")
	spf.Apply(result.Funcdata)

	var regSpaceIdx int = -1
	stackSpace := spf.StackSpace()
	for _, vn := range result.Funcdata.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		sp := vn.Space()
		if (sp.Kind == address.SpaceKindStack || sp.Name == "stack") && stackSpace == nil {
			stackSpace = sp
		}
		if sp.Kind == address.SpaceKindProcessor && sp.Name == "register" && regSpaceIdx < 0 {
			regSpaceIdx = int(sp.Index)
		}
	}
	cdecl := pcode.NewProtoModelFromCspec(result.CspecData, stackSpace, nil)
	if regSpaceIdx >= 0 {
		cdecl.WithReturnReg(regSpaceIdx, 0, 4)
	}
	t.Logf("ReturnReg: spaceIdx=%d offset=0 size=4", regSpaceIdx)

	pcode.ApplyCallingConvention(result.Funcdata, cdecl)

	t.Log("=== AFTER ApplyCallingConvention: RETURN ops ===")
	for _, op := range result.Funcdata.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != pcode.CPUI_RETURN {
			continue
		}
		t.Logf("RETURN ninput=%d", op.NumInput())
		for i := 0; i < op.NumInput(); i++ {
			vn := op.Input(i)
			if vn == nil {
				t.Logf("  in[%d] = nil", i)
			} else {
				defCode := "no-def"
				if vn.Def() != nil {
					defCode = fmt.Sprintf("%v", vn.Def().Code())
				}
				t.Logf("  in[%d] space=%s off=0x%x size=%d isInput=%v isConst=%v isWritten=%v def=%s",
					i, spaceName(vn.Space()), vn.Offset(), vn.Size(),
					vn.IsInput(), vn.IsConstant(), vn.IsWritten(), defCode)
			}
		}
	}

	t.Log("=== EAX-range varnodes (register:0:4) ===")
	for _, vn := range result.Funcdata.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		if vn.Space().Name != "register" || vn.Offset() != 0 || vn.Size() != 4 {
			continue
		}
		defCode := "no-def"
		if vn.Def() != nil {
			defCode = fmt.Sprintf("%v", vn.Def().Code())
		}
		t.Logf("  EAX vn: isInput=%v isWritten=%v ndesc=%d def=%s",
			vn.IsInput(), vn.IsWritten(), vn.NumDescend(), defCode)
	}
}
