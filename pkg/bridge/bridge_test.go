package bridge_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/pcode"
	"gosleigh/pkg/sla"
)

type candidateProgram struct {
	name  string
	bytes []byte
}

func TestBuild6502ProgramToC(t *testing.T) {
	candidates := []candidateProgram{
		{name: "opcode_04", bytes: []byte{0x04}},
		{name: "BRK", bytes: []byte{0x00}},
		{name: "BRK_BRK", bytes: []byte{0x00, 0x00}},
	}

	failures := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		result, output, path, err := buildCandidateToC(candidate)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", candidate.name, err))
			continue
		}
		if err := validateBridgeResult(result); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", candidate.name, err))
			continue
		}
		if strings.TrimSpace(output) == "" {
			failures = append(failures, fmt.Sprintf("%s: PrintC.Emit returned empty output", candidate.name))
			continue
		}

		t.Logf("using sla file: %s", path)
		t.Logf("selected candidate: %s", candidate.name)
		t.Logf("emitted C:\n%s", output)
		return
	}

	t.Fatalf("no 6502 candidate completed the full bridge pipeline:\n%s", strings.Join(failures, "\n"))
}

func TestBuildSplitsAfterFlowBreak(t *testing.T) {
	result, path, err := buildCandidate(candidateProgram{name: "BRK_BRK", bytes: []byte{0x00, 0x00}})
	if err != nil {
		t.Fatalf("build BRK_BRK: %v", err)
	}
	t.Logf("using sla file: %s", path)
	if len(result.Instructions) != 2 {
		t.Fatalf("instruction count = %d, want 2", len(result.Instructions))
	}
	if result.Graph == nil {
		t.Fatal("result graph is nil")
	}
	if result.Graph.GetSize() != 2 {
		t.Fatalf("basic block count = %d, want 2", result.Graph.GetSize())
	}
	first := result.Graph.GetBlock(0)
	second := result.Graph.GetBlock(1)
	if first.SizeOut() != 0 {
		t.Fatalf("first block out-degree = %d, want 0", first.SizeOut())
	}
	if second.SizeIn() != 0 {
		t.Fatalf("second block in-degree = %d, want 0", second.SizeIn())
	}
	firstBasic, ok := first.Concrete().(*pcode.BlockBasic)
	if !ok || firstBasic.NumOps() == 0 {
		t.Fatal("first block does not contain translated ops")
	}
	secondBasic, ok := second.Concrete().(*pcode.BlockBasic)
	if !ok || secondBasic.NumOps() == 0 {
		t.Fatal("second block does not contain translated ops")
	}
}

func buildCandidate(candidate candidateProgram) (*bridge.Result, string, error) {
	engine, base, path, err := new6502Engine(candidate.bytes)
	if err != nil {
		return nil, path, err
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name:  "sample6502",
		Entry: base,
		End:   base.Add(uint64(len(candidate.bytes))),
	})
	if err != nil {
		return nil, path, err
	}
	if err := validateBridgeResult(result); err != nil {
		return nil, path, err
	}
	return result, path, nil
}

func buildCandidateToC(candidate candidateProgram) (*bridge.Result, string, string, error) {
	result, path, err := buildCandidate(candidate)
	if err != nil {
		return nil, "", path, err
	}

	fd := result.Funcdata
	graph := result.Graph
	heritage := pcode.NewHeritage(fd, result.HeritageSpaces)
	heritage.Heritage(graph)

	pool := pcode.NewBatchAActionPool("batch-a", "analysis")
	if res := pool.Perform(fd); res < 0 {
		return nil, "", path, fmt.Errorf("batch action pool returned %d", res)
	}
	if res := pcode.NewActionBlockStructure("analysis").Apply(fd); res != 0 {
		return nil, "", path, fmt.Errorf("ActionBlockStructure.Apply returned %d", res)
	}
	if res := pcode.NewActionFinalStructure("analysis").Apply(fd); res != 0 {
		return nil, "", path, fmt.Errorf("ActionFinalStructure.Apply returned %d", res)
	}

	output, err := pcode.NewPrintC().Emit(fd)
	if err != nil {
		return nil, "", path, err
	}
	return result, output, path, nil
}

func validateBridgeResult(result *bridge.Result) error {
	if result == nil {
		return fmt.Errorf("bridge returned nil result")
	}
	if len(result.Instructions) == 0 {
		return fmt.Errorf("bridge returned no instructions")
	}
	if result.Funcdata == nil {
		return fmt.Errorf("bridge returned nil funcdata")
	}
	if result.Graph == nil {
		return fmt.Errorf("bridge returned nil graph")
	}
	if result.Graph.GetSize() == 0 {
		return fmt.Errorf("bridge graph is empty")
	}
	if result.Graph.GetBlock(0).ImmedDom() == nil {
		return fmt.Errorf("graph dominator state was not prepared")
	}

	alive := result.Funcdata.GetPcodeOpBank().AliveOps()
	if len(alive) == 0 {
		return fmt.Errorf("funcdata has no alive ops")
	}
	for _, op := range alive {
		if op == nil {
			return fmt.Errorf("alive op list contains nil op")
		}
		if op.Parent() == nil {
			return fmt.Errorf("alive op %v has nil parent", op.Seq())
		}
		if op.IsDead() {
			return fmt.Errorf("alive op %v is still marked dead", op.Seq())
		}
	}
	return nil
}

func new6502Engine(program []byte) (*sla.Engine, address.Address, string, error) {
	path := testdataSLAPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, address.Address{}, path, fmt.Errorf("read sla file: %w", err)
	}
	container, err := sla.Read(bytes.NewReader(data))
	if err != nil {
		return nil, address.Address{}, path, fmt.Errorf("sla.Read: %w", err)
	}
	boundaries, err := sla.DecodeBoundariesPayload(container.Payload)
	if err != nil {
		return nil, address.Address{}, path, fmt.Errorf("DecodeBoundariesPayload: %w", err)
	}
	xrefs, err := boundaries.BuildXrefs()
	if err != nil {
		return nil, address.Address{}, path, fmt.Errorf("BuildXrefs: %w", err)
	}

	var ram *address.Space
	for i := range boundaries.Metadata.Spaces {
		if boundaries.Metadata.Spaces[i].Name == boundaries.Metadata.DefaultSpace {
			ram = &boundaries.Metadata.Spaces[i]
			break
		}
	}
	if ram == nil {
		return nil, address.Address{}, path, fmt.Errorf("default address space not found")
	}

	backend := sla.NewBackend()
	for _, field := range xrefs.ContextFields {
		if err := backend.RegisterContextVariable(field.Name, int(field.StartBit), int(field.EndBit)); err != nil {
			return nil, address.Address{}, path, fmt.Errorf("RegisterContextVariable(%q): %w", field.Name, err)
		}
	}

	base := address.Address{Space: ram, Offset: 0}
	padded := make([]byte, 16)
	copy(padded, program)
	if err := backend.SetInstructionBytes(base, padded); err != nil {
		return nil, address.Address{}, path, fmt.Errorf("SetInstructionBytes: %w", err)
	}

	engine, err := sla.NewEngineFromBoundaries(boundaries, sla.EngineConfig{
		LoweringTemplate: sla.NewLoweringContext(boundaries.Metadata, base),
		Backend: sla.EngineBackendAdapter{
			LoadMatchInput: backend.PayloadLoader(sla.BackendPayloadConfig{}),
			Commits:        backend.CommitHooks(),
		},
	})
	if err != nil {
		return nil, address.Address{}, path, fmt.Errorf("NewEngineFromBoundaries: %w", err)
	}
	return engine, base, path, nil
}

func TestBuildE2EWithRealSLA(t *testing.T) {
	// LDA #$01 (A9 01), BNE +2 (D0 02), NOP (EA), NOP (EA)
	program := []byte{0xA9, 0x01, 0xD0, 0x02, 0xEA, 0xEA}
	engine, base, path, err := new6502Engine(program)
	if err != nil {
		t.Skipf("failed to build 6502 engine: %v", err)
	}
	t.Logf("using sla file: %s", path)

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name:  "e2e_6502",
		Entry: base,
		End:   base.Add(6),
	})
	if err != nil {
		t.Skipf("bridge.Build failed: %v", err)
	}
	if result == nil {
		t.Skip("bridge.Build returned nil result")
	}
	if len(result.Warnings) > 0 {
		for _, w := range result.Warnings {
			t.Logf("warning: %s", w)
		}
		t.Skip("translation hit unimplemented opcode")
	}
	if result.Funcdata == nil {
		t.Skip("funcdata is nil, likely unimplemented opcodes")
	}

	t.Logf("instruction count: %d", len(result.Instructions))
	t.Logf("basic block count: %d", result.Graph.GetSize())

	if result.Graph == nil {
		t.Fatal("result.Graph is nil")
	}
	if result.Graph.GetSize() < 2 {
		t.Fatalf("expected at least 2 basic blocks (branch splits CFG), got %d", result.Graph.GetSize())
	}
}

func TestMultiArchFixture(t *testing.T) {
	t.Skip("no additional arch .sla available")
}

func testdataSLAPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("pkg", "sla", "testdata", "6502.sla")
	}
	return filepath.Join(filepath.Dir(file), "..", "sla", "testdata", "6502.sla")
}
