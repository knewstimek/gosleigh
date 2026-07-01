//go:build ignore

package main

import (
	"fmt"
	"path/filepath"
	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

func main() {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7E, 0x18, 0x8B, 0x45, 0x0C, 0x3B, 0x45, 0x08, 0x7E, 0x09, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x0B, 0xEB, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x02, 0x33, 0xC0, 0x5D, 0xC3}
	engine, base, err := (&loader.EngineBuilder{
		SLAPath: filepath.Join("pkg/sla/testdata/x86-packed.sla"),
		PspecPath: filepath.Join("testdata/sla/x86.pspec"),
		Bytes: prog}).Build()
	if err != nil { panic(err) }
	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "entry", Entry: base, MaxInstructions: 60})
	if err != nil { panic(err) }
	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
	spf := pcode.NewActionStackPtrFlow("analysis")
	spf.Apply(result.Funcdata)
	var regSpaceIdx int = -1
	stackSpace := spf.StackSpace()
	for _, vn := range result.Funcdata.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil { continue }
		sp := vn.Space()
		if (sp.Kind == address.SpaceKindStack || sp.Name == "stack") && stackSpace == nil { stackSpace = sp }
		if sp.Kind == address.SpaceKindProcessor && sp.Name == "register" && regSpaceIdx < 0 { regSpaceIdx = int(sp.Index) }
	}
	cdecl := pcode.NewProtoModelFromCspec(result.CspecData, stackSpace, nil)
	if regSpaceIdx >= 0 { cdecl.WithReturnReg(regSpaceIdx, 0, 4) }
	pcode.ApplyCallingConvention(result.Funcdata, cdecl)
	pcode.NewMerge(result.Funcdata).MergeMarker()
	pcode.NewActionFoldFlagConditions("analysis").Apply(result.Funcdata)
	pcode.NewActionConstantFold("analysis").Apply(result.Funcdata)
	pcode.NewActionDeadCode("analysis").Apply(result.Funcdata)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
	pcode.NewBatchAActionPool("batch-a2", "analysis").Perform(result.Funcdata)
	pcode.NewActionSeedSignedOps("analysis").Apply(result.Funcdata)
	pcode.NewActionInferTypesLegacy("analysis").Apply(result.Funcdata)
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionPreferComplement("analysis").Apply(result.Funcdata)

	// Find all consumers of the INT_SLESS@553737 varnode
	fmt.Println("=== CONSUMERS of unique:553737 ===")
	for _, op := range result.Funcdata.GetPcodeOpBank().AllOps() {
		if op == nil { continue }
		for i := 0; i < op.NumInput(); i++ {
			inp := op.Input(i)
			if inp == nil { continue }
			if inp.Space() == nil || !inp.Space().IsUnique() { continue }
			if inp.Offset() != 553737 { continue }
			fmt.Printf("  consumer: %v @%v dead=%v (input[%d])\n", op.Code(), op.Seq(), op.IsDead(), i)
		}
		if op.Output() != nil && op.Output().Space() != nil && op.Output().Space().IsUnique() && op.Output().Offset() == 553737 {
			fmt.Printf("  DEFINER: %v @%v dead=%v\n", op.Code(), op.Seq(), op.IsDead())
		}
	}
	fmt.Println()

	// Check what happens before batch-a
	fmt.Println("=== ALSO dump BOOL_OR ops ===")
	for _, op := range result.Funcdata.GetPcodeOpBank().AllOps() {
		if op == nil || (op.Code() != pcode.CPUI_BOOL_OR && op.Code() != pcode.CPUI_INT_OR) { continue }
		out := op.Output()
		outStr := "nil"
		if out != nil { outStr = fmt.Sprintf("%s:%d ndesc=%d", out.Space().Name, out.Offset(), out.NumDescend()) }
		fmt.Printf("%v @%v dead=%v out=%s\n", op.Code(), op.Seq(), op.IsDead(), outStr)
		for i := 0; i < op.NumInput(); i++ {
			inp := op.Input(i)
			if inp == nil { continue }
			def2 := "nil"
			if d2 := inp.Def(); d2 != nil { def2 = d2.Code().String() }
			fmt.Printf("  in[%d]: %s:%d ndesc=%d def=%s\n", i, inp.Space().Name, inp.Offset(), inp.NumDescend(), def2)
		}
	}
}
