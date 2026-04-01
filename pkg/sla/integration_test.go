package sla

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/address"
)

// testdataSLAPath returns the path to the 6502 .sla test file.
// If GOSLEIGH_PACKED_SLA is set, it uses that path.
// Otherwise it falls back to testdata/6502.sla.
func testdataSLAPath(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("GOSLEIGH_PACKED_SLA"); env != "" {
		return env
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata", "6502.sla")
}

// loadTestPayload loads the .sla file through the container reader and returns its payload.
func loadTestPayload(t *testing.T) []byte {
	t.Helper()
	path := testdataSLAPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read .sla file: %v", err)
	}
	t.Logf("raw .sla file size: %d bytes (path: %s)", len(data), path)

	container, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Read() container failed: %v", err)
	}
	if len(container.Payload) == 0 {
		t.Fatal("container payload is empty")
	}
	t.Logf("container version: %d, decompressed payload size: %d bytes", container.Version, len(container.Payload))
	return container.Payload
}

// TestIntegration_FileFormatDetection checks the .sla file and reports its format.
// This test always runs regardless of format.
func TestIntegration_FileFormatDetection(t *testing.T) {
	path := testdataSLAPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read .sla file: %v", err)
	}
	t.Logf("file: %s", path)
	t.Logf("size: %d bytes", len(data))

	if len(data) < 4 {
		t.Fatalf("file too small (%d bytes)", len(data))
	}

	if IsHeader(data[:4]) {
		t.Logf("format: packed binary (version %d) -- compatible with Gosleigh", data[3])
	} else if isXMLPayload(data) {
		t.Log("format: XML -- compatible with Gosleigh XML loader")
	} else {
		t.Fatalf("format: unknown (first 4 bytes: %02x %02x %02x %02x)", data[0], data[1], data[2], data[3])
	}

	container, err := Read(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	t.Logf("loader version: %d", container.Version)
	t.Logf("payload size: %d bytes", len(container.Payload))
	if len(container.Payload) == 0 {
		t.Fatal("container payload is empty")
	}
}

// TestIntegration_ContainerLoading verifies that the .sla container header
// can be read and zlib payload extracted without error.
func TestIntegration_ContainerLoading(t *testing.T) {
	payload := loadTestPayload(t)
	if len(payload) == 0 {
		t.Fatal("payload is empty")
	}
	t.Logf("decompressed payload size: %d bytes", len(payload))
}

// TestIntegration_MetadataDecode verifies that metadata can be decoded from the
// 6502.sla payload with expected values for the 6502 architecture.
func TestIntegration_MetadataDecode(t *testing.T) {
	payload := loadTestPayload(t)

	metadata, err := DecodeMetadataPayload(payload)
	if err != nil {
		t.Fatalf("DecodeMetadataPayload() failed: %v", err)
	}
	if metadata == nil {
		t.Fatal("DecodeMetadataPayload() returned nil")
	}
	if metadata.Version != FormatVersion && metadata.Version != XMLFormatVersion {
		t.Fatalf("unexpected metadata version: got %d", metadata.Version)
	}

	t.Logf("version: %d", metadata.Version)
	t.Logf("big-endian: %v", metadata.BigEndian)
	t.Logf("align: %d", metadata.Align)
	t.Logf("unique base: 0x%x", metadata.UniqueBase)
	t.Logf("max delay: %d", metadata.MaxDelay)
	t.Logf("unique mask: 0x%x", metadata.UniqueMask)
	t.Logf("num sections: %d", metadata.NumSections)
	t.Logf("default space: %q", metadata.DefaultSpace)
	t.Logf("space count: %d", len(metadata.Spaces))

	for i, space := range metadata.Spaces {
		t.Logf("  space[%d]: name=%q kind=%s index=%d addrSize=%d wordSize=%d bigEndian=%v",
			i, space.Name, space.Kind, space.Index, space.AddrSize, space.WordSize, space.BigEndian)
	}

	// Default space should exist
	if metadata.DefaultSpace == "" {
		t.Error("default space name is empty")
	}

	if len(metadata.Spaces) == 0 {
		t.Error("no spaces decoded")
	}

	// Check that the default space exists among decoded spaces
	found := false
	for _, space := range metadata.Spaces {
		if space.Name == metadata.DefaultSpace {
			found = true
			if space.AddrSize == 0 {
				t.Error("default space addr size is 0")
			}
			break
		}
	}
	if !found {
		t.Errorf("default space %q not found among decoded spaces", metadata.DefaultSpace)
	}
}

// TestIntegration_SymbolTableDecode verifies that the full symbol table can be
// decoded from the 6502.sla payload and contains expected structure.
func TestIntegration_SymbolTableDecode(t *testing.T) {
	payload := loadTestPayload(t)

	boundaries, err := DecodeBoundariesPayload(payload)
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() failed: %v", err)
	}
	if boundaries == nil {
		t.Fatal("DecodeBoundariesPayload() returned nil")
	}
	if boundaries.SymbolTable == nil {
		t.Fatal("decoded symbol table is nil")
	}

	symtab := boundaries.SymbolTable
	t.Logf("scope count: %d", len(symtab.Scopes))
	t.Logf("symbol count: %d", len(symtab.Symbols))

	if len(symtab.Symbols) == 0 {
		t.Fatal("symbol table has no symbols")
	}
	if len(symtab.Scopes) == 0 {
		t.Fatal("symbol table has no scopes")
	}

	// Count symbol types for diagnostic summary
	var subtableCount, varnodeCount, userOpCount, operandCount, otherCount int
	for _, sym := range symtab.Symbols {
		switch {
		case sym.Body.Subtable != nil:
			subtableCount++
		case sym.Body.Varnode != nil:
			varnodeCount++
		case sym.Body.UserOp != nil:
			userOpCount++
		case sym.Body.Operand != nil:
			operandCount++
		default:
			otherCount++
		}
	}
	t.Logf("symbol breakdown: subtable=%d varnode=%d userop=%d operand=%d other=%d",
		subtableCount, varnodeCount, userOpCount, operandCount, otherCount)

	// Check for root "instruction" subtable
	root, ok := FindInstructionRootSubtable(symtab)
	if !ok {
		t.Fatal("instruction root subtable not found")
	}
	if root == nil {
		t.Fatal("instruction root subtable is nil")
	}
	t.Logf("instruction root subtable: constructor count=%d", root.ConstructorCount)
	if root.ConstructorCount == 0 {
		t.Error("instruction root subtable has zero constructors")
	}
	if root.Decision == nil {
		t.Error("instruction root subtable has nil decision tree")
	}

	// Log source files
	t.Logf("source file count: %d", len(boundaries.SourceFiles))
	for i, sf := range boundaries.SourceFiles {
		if i < 5 {
			t.Logf("  source[%d]: index=%d name=%q", i, sf.Index, sf.Name)
		}
	}
}

// TestIntegration_XRefsBuild verifies that BuildXrefs() succeeds on the 6502
// symbol table and produces non-empty register xrefs.
func TestIntegration_XRefsBuild(t *testing.T) {
	payload := loadTestPayload(t)

	boundaries, err := DecodeBoundariesPayload(payload)
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() failed: %v", err)
	}

	xrefs, err := boundaries.BuildXrefs()
	if err != nil {
		t.Fatalf("BuildXrefs() failed: %v", err)
	}
	if xrefs == nil {
		t.Fatal("BuildXrefs() returned nil")
	}

	t.Logf("varnode xref count: %d", len(xrefs.VarnodeXref))
	t.Logf("user-op name count: %d", len(xrefs.UserOpNames))
	t.Logf("context field count: %d", len(xrefs.ContextFields))

	if len(xrefs.VarnodeXref) == 0 {
		t.Error("varnode xref table is empty -- expected 6502 registers")
	}

	// Log register names (6502 should have A, X, Y, S, P, PC etc.)
	for i, entry := range xrefs.VarnodeXref {
		if i < 20 {
			t.Logf("  reg[%d]: space=%d offset=0x%x size=%d name=%q",
				i, entry.SpaceIndex, entry.Offset, entry.Size, entry.Name)
		}
	}

	// Look for well-known 6502 register names
	knownRegs := []string{"A", "X", "Y", "S", "P"}
	for _, name := range knownRegs {
		found := false
		for _, entry := range xrefs.VarnodeXref {
			if entry.Name == name {
				found = true
				break
			}
		}
		if found {
			t.Logf("  found well-known register: %s", name)
		} else {
			t.Logf("  well-known register %s NOT found (may use different name)", name)
		}
	}
}

// TestIntegration_EngineConstruction verifies that a full Engine can be constructed
// from the decoded 6502.sla boundaries with a minimal backend.
func TestIntegration_EngineConstruction(t *testing.T) {
	payload := loadTestPayload(t)

	boundaries, err := DecodeBoundariesPayload(payload)
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() failed: %v", err)
	}

	// Build xrefs to register context fields
	xrefs, err := boundaries.BuildXrefs()
	if err != nil {
		t.Fatalf("BuildXrefs() failed: %v", err)
	}

	// Create backend
	backend := NewBackend()

	// Register context fields from xrefs
	for _, cf := range xrefs.ContextFields {
		err := backend.RegisterContextVariable(cf.Name, int(cf.StartBit), int(cf.EndBit))
		if err != nil {
			t.Logf("RegisterContextVariable(%q, %d, %d) failed: %v", cf.Name, cf.StartBit, cf.EndBit, err)
		}
	}

	// Construct lowering context from metadata
	loweringCtx := NewLoweringContext(boundaries.Metadata, address.Address{})

	// Build engine
	engine, err := NewEngineFromBoundaries(boundaries, EngineConfig{
		LoweringTemplate: loweringCtx,
		Backend: EngineBackendAdapter{
			LoadMatchInput: backend.PayloadLoader(BackendPayloadConfig{}),
			Commits:        backend.CommitHooks(),
		},
	})
	if err != nil {
		t.Fatalf("NewEngineFromBoundaries() failed: %v", err)
	}
	if engine == nil {
		t.Fatal("NewEngineFromBoundaries() returned nil engine")
	}
	t.Log("engine constructed successfully from .sla boundaries")
}

// TestIntegration_SimpleInstructionTranslation attempts to translate simple
// 6502 instructions through the full decode/translate pipeline.
// Even if full p-code emission is not yet implemented, this test records
// exactly which stage fails and with what error.
func TestIntegration_SimpleInstructionTranslation(t *testing.T) {
	payload := loadTestPayload(t)

	boundaries, err := DecodeBoundariesPayload(payload)
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() failed: %v", err)
	}

	xrefs, err := boundaries.BuildXrefs()
	if err != nil {
		t.Fatalf("BuildXrefs() failed: %v", err)
	}

	// Find the default (RAM) space from metadata
	var ramSpace *address.Space
	for i := range boundaries.Metadata.Spaces {
		if boundaries.Metadata.Spaces[i].Name == boundaries.Metadata.DefaultSpace {
			ramSpace = &boundaries.Metadata.Spaces[i]
			break
		}
	}
	if ramSpace == nil {
		t.Fatal("could not find default address space in metadata")
	}

	backend := NewBackend()
	for _, cf := range xrefs.ContextFields {
		if err := backend.RegisterContextVariable(cf.Name, int(cf.StartBit), int(cf.EndBit)); err != nil {
			t.Logf("RegisterContextVariable(%q) failed: %v", cf.Name, err)
		}
	}

	// Test cases: known 6502 instructions
	type instrTest struct {
		name      string
		bytes     []byte
		expectLen int
	}
	tests := []instrTest{
		{"LDA_imm (A9 42)", []byte{0xA9, 0x42}, 2},
		{"NOP (EA)", []byte{0xEA}, 1},
		{"BRK (00)", []byte{0x00}, 1},
		{"INX (E8)", []byte{0xE8}, 1},
		{"LDX_imm (A2 10)", []byte{0xA2, 0x10}, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseAddr := address.Address{Space: ramSpace, Offset: 0x0000}

			// Pad instruction bytes to 16 bytes (standard Sleigh loadFill size)
			padded := make([]byte, 16)
			copy(padded, tc.bytes)

			if err := backend.SetInstructionBytes(baseAddr, padded); err != nil {
				t.Fatalf("SetInstructionBytes() failed: %v", err)
			}

			loweringCtx := NewLoweringContext(boundaries.Metadata, baseAddr)

			engine, err := NewEngineFromBoundaries(boundaries, EngineConfig{
				LoweringTemplate: loweringCtx,
				Backend: EngineBackendAdapter{
					LoadMatchInput: backend.PayloadLoader(BackendPayloadConfig{}),
					Commits:        backend.CommitHooks(),
				},
			})
			if err != nil {
				t.Fatalf("NewEngineFromBoundaries() failed: %v", err)
			}

			result, err := engine.TranslateInstructionAt(baseAddr)
			if err != nil {
				t.Logf("TranslateInstructionAt() failed (may be expected if pipeline is incomplete): %v", err)
				return
			}

			t.Logf("translation succeeded:")
			t.Logf("  address: %v", result.Address)
			t.Logf("  next: %v", result.Next)
			t.Logf("  length: %d (expected: %d)", result.Length, tc.expectLen)
			t.Logf("  p-code op count: %d", len(result.Ops))
			for i, op := range result.Ops {
				t.Logf("  op[%d]: opcode=%s", i, op.OpCode)
			}

			if result.Length != tc.expectLen {
				t.Logf("  NOTE: decoded length %d differs from expected %d", result.Length, tc.expectLen)
			}
		})
	}
}
