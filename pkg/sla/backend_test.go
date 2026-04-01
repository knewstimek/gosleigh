package sla

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gosleigh/pkg/address"
)

func TestBackendPayloadLoaderLoadsInstructionAndContextByAddress(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	base := address.Address{Space: ram, Offset: 0x401000}

	backend := NewBackend()
	backend.SetDefaultContextWords([]uint64{0x1122334455667788})
	if err := backend.SetInstructionBytes(base, []byte{0xaa, 0xbb, 0xcc}); err != nil {
		t.Fatalf("SetInstructionBytes() returned error: %v", err)
	}

	loader := backend.PayloadLoader(BackendPayloadConfig{InstructionSize: 4})
	match, ok, err := loader(base)
	if err != nil {
		t.Fatalf("payload loader returned error: %v", err)
	}
	if !ok {
		t.Fatal("payload loader unexpectedly reported miss for mapped instruction bytes")
	}
	if !bytes.Equal(match.Instruction, []byte{0xaa, 0xbb, 0xcc, 0x00}) {
		t.Fatalf("instruction bytes mismatch: got %v", match.Instruction)
	}
	if !bytes.Equal(match.Context, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}) {
		t.Fatalf("context bytes mismatch: got %v", match.Context)
	}
	roundtrip := contextWordsFromBytes(match.Context)
	if len(roundtrip) != 1 || roundtrip[0] != 0x1122334455667788 {
		t.Fatalf("context roundtrip mismatch: got %v", roundtrip)
	}
}

func TestBackendPayloadLoaderMissWhenInstructionUnavailable(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	base := address.Address{Space: ram, Offset: 0x401100}

	backend := NewBackend()
	backend.SetDefaultContextWords([]uint64{0x77})

	loader := backend.PayloadLoader(BackendPayloadConfig{})
	match, ok, err := loader(base)
	if err != nil {
		t.Fatalf("payload loader returned error on miss: %v", err)
	}
	if ok {
		t.Fatal("payload loader unexpectedly reported hit without instruction bytes")
	}
	if len(match.Instruction) != 0 || len(match.Context) != 0 {
		t.Fatalf("payload loader miss should return empty match, got %+v", match)
	}
}

func TestBackendPayloadLoaderFallsBackToRawInstructionReader(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	base := address.Address{Space: ram, Offset: 0x402000}

	backend := NewBackend()
	backend.SetDefaultContextWords([]uint64{0x99})
	if err := backend.SetRawInstructionReader(ram, bytes.NewReader([]byte{0xde, 0xad, 0xbe}), 3, base.Offset); err != nil {
		t.Fatalf("SetRawInstructionReader() returned error: %v", err)
	}

	loader := backend.PayloadLoader(BackendPayloadConfig{InstructionSize: 4})
	match, ok, err := loader(base)
	if err != nil {
		t.Fatalf("payload loader returned error: %v", err)
	}
	if !ok {
		t.Fatal("payload loader unexpectedly reported miss for raw instruction reader")
	}
	if !bytes.Equal(match.Instruction, []byte{0xde, 0xad, 0xbe, 0x00}) {
		t.Fatalf("raw-reader instruction bytes mismatch: got %v", match.Instruction)
	}
	if !bytes.Equal(match.Context, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99}) {
		t.Fatalf("raw-reader context bytes mismatch: got %v", match.Context)
	}
}

func TestBackendRawInstructionReaderMissWhenInitialByteUnavailable(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	backend := NewBackend()
	if err := backend.SetRawInstructionReader(ram, bytes.NewReader([]byte{0x10, 0x20, 0x30}), 3, 0x5000); err != nil {
		t.Fatalf("SetRawInstructionReader() returned error: %v", err)
	}

	if _, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x4fff}, 2); err != nil {
		t.Fatalf("LoadInstructionBytes(before vma) returned error: %v", err)
	} else if ok {
		t.Fatal("LoadInstructionBytes(before vma) unexpectedly reported hit")
	}

	if _, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x5003}, 1); err != nil {
		t.Fatalf("LoadInstructionBytes(after file) returned error: %v", err)
	} else if ok {
		t.Fatal("LoadInstructionBytes(after file) unexpectedly reported hit")
	}
}

func TestBackendRawInstructionReaderAttachLifecycleMatchesRawLoadImage(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 4)
	backend := NewBackend()
	if err := backend.SetRawInstructionReader(nil, bytes.NewReader([]byte{0xde, 0xad, 0xbe}), 3, 0x9000); err != nil {
		t.Fatalf("SetRawInstructionReader(nil space) returned error: %v", err)
	}

	if err := backend.AdjustRawInstructionVMA(1); err == nil {
		t.Fatal("AdjustRawInstructionVMA() should fail before AttachRawInstructionSpace()")
	}
	if _, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x9000}, 1); err != nil {
		t.Fatalf("LoadInstructionBytes() before attach returned error: %v", err)
	} else if ok {
		t.Fatal("LoadInstructionBytes() should miss before AttachRawInstructionSpace()")
	}

	if err := backend.AttachRawInstructionSpace(ram); err != nil {
		t.Fatalf("AttachRawInstructionSpace() returned error: %v", err)
	}

	got, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x9000}, 4)
	if err != nil {
		t.Fatalf("LoadInstructionBytes() after attach returned error: %v", err)
	}
	if !ok {
		t.Fatal("LoadInstructionBytes() should hit after AttachRawInstructionSpace()")
	}
	if !bytes.Equal(got, []byte{0xde, 0xad, 0xbe, 0x00}) {
		t.Fatalf("attached raw-reader instruction bytes mismatch: got %v", got)
	}

	if err := backend.AdjustRawInstructionVMA(1); err != nil {
		t.Fatalf("AdjustRawInstructionVMA() after attach returned error: %v", err)
	}
	if _, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x9000}, 1); err != nil {
		t.Fatalf("LoadInstructionBytes() after rebase returned error: %v", err)
	} else if ok {
		t.Fatal("LoadInstructionBytes() should miss at the old base after rebasing")
	}
}

func TestBackendOpenRawInstructionFileLoadsAndClosesSource(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	path := filepath.Join(t.TempDir(), "raw-image.bin")
	if err := os.WriteFile(path, []byte{0x11, 0x22, 0x33}, 0o600); err != nil {
		t.Fatalf("WriteFile() returned error: %v", err)
	}

	backend := NewBackend()
	if err := backend.OpenRawInstructionFile(path, nil, 0x7000); err != nil {
		t.Fatalf("OpenRawInstructionFile() returned error: %v", err)
	}
	if err := backend.AttachRawInstructionSpace(ram); err != nil {
		t.Fatalf("AttachRawInstructionSpace() returned error: %v", err)
	}

	got, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x7001}, 4)
	if err != nil {
		t.Fatalf("LoadInstructionBytes() returned error: %v", err)
	}
	if !ok {
		t.Fatal("LoadInstructionBytes() unexpectedly reported miss for open raw file")
	}
	if !bytes.Equal(got, []byte{0x22, 0x33, 0x00, 0x00}) {
		t.Fatalf("file-backed instruction bytes mismatch: got %v", got)
	}

	if err := backend.CloseRawInstructionSource(); err != nil {
		t.Fatalf("CloseRawInstructionSource() returned error: %v", err)
	}
	if _, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x7001}, 1); err != nil {
		t.Fatalf("LoadInstructionBytes() after close returned error: %v", err)
	} else if ok {
		t.Fatal("LoadInstructionBytes() should miss after CloseRawInstructionSource()")
	}
}

func TestBackendRawInstructionSourceRequiresCloseBeforeReplacement(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	path := filepath.Join(t.TempDir(), "raw-image.bin")
	if err := os.WriteFile(path, []byte{0xaa}, 0o600); err != nil {
		t.Fatalf("WriteFile() returned error: %v", err)
	}

	backend := NewBackend()
	if err := backend.SetRawInstructionReader(ram, bytes.NewReader([]byte{0x10}), 1, 0x8000); err != nil {
		t.Fatalf("SetRawInstructionReader() returned error: %v", err)
	}
	if err := backend.SetRawInstructionReader(ram, bytes.NewReader([]byte{0x20}), 1, 0x9000); err == nil {
		t.Fatal("SetRawInstructionReader() should require CloseRawInstructionSource() before replacement")
	}
	if err := backend.OpenRawInstructionFile(path, ram, 0x8000); err == nil {
		t.Fatal("OpenRawInstructionFile() should require CloseRawInstructionSource() before replacement")
	}
	if err := backend.CloseRawInstructionSource(); err != nil {
		t.Fatalf("CloseRawInstructionSource() returned error: %v", err)
	}
	if err := backend.OpenRawInstructionFile(path, nil, 0x8000); err != nil {
		t.Fatalf("OpenRawInstructionFile() after close returned error: %v", err)
	}
	if err := backend.CloseRawInstructionSource(); err != nil {
		t.Fatalf("final CloseRawInstructionSource() returned error: %v", err)
	}
}

func TestBackendAdjustRawInstructionVMAScalesAndRebasesRawImage(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 4)
	backend := NewBackend()
	if err := backend.SetRawInstructionReader(ram, bytes.NewReader([]byte{0xde, 0xad, 0xbe}), 3, 0x9000); err != nil {
		t.Fatalf("SetRawInstructionReader() returned error: %v", err)
	}

	if _, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x9004}, 1); err != nil {
		t.Fatalf("LoadInstructionBytes(0x9004) before rebase returned error: %v", err)
	} else if ok {
		t.Fatal("LoadInstructionBytes(0x9004) should miss before rebasing the raw image")
	}

	if err := backend.AdjustRawInstructionVMA(1); err != nil {
		t.Fatalf("AdjustRawInstructionVMA(1) returned error: %v", err)
	}

	got, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x9004}, 4)
	if err != nil {
		t.Fatalf("LoadInstructionBytes(0x9004) after first rebase returned error: %v", err)
	}
	if !ok {
		t.Fatal("LoadInstructionBytes(0x9004) should hit after word-size-scaled rebasing")
	}
	if !bytes.Equal(got, []byte{0xde, 0xad, 0xbe, 0x00}) {
		t.Fatalf("rebased instruction bytes mismatch after first adjust: got %v", got)
	}

	if err := backend.AdjustRawInstructionVMA(2); err != nil {
		t.Fatalf("AdjustRawInstructionVMA(2) returned error: %v", err)
	}

	if _, ok, err := backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x9004}, 1); err != nil {
		t.Fatalf("LoadInstructionBytes(0x9004) after second rebase returned error: %v", err)
	} else if ok {
		t.Fatal("LoadInstructionBytes(0x9004) should miss after cumulative rebasing moves the base again")
	}

	got, ok, err = backend.LoadInstructionBytes(address.Address{Space: ram, Offset: 0x900c}, 4)
	if err != nil {
		t.Fatalf("LoadInstructionBytes(0x900c) after second rebase returned error: %v", err)
	}
	if !ok {
		t.Fatal("LoadInstructionBytes(0x900c) should hit after cumulative rebasing")
	}
	if !bytes.Equal(got, []byte{0xde, 0xad, 0xbe, 0x00}) {
		t.Fatalf("rebased instruction bytes mismatch after second adjust: got %v", got)
	}
}

func TestBackendTranslateBindingsWirePayloadAndCommitHooks(t *testing.T) {
	backend := NewBackend()
	bindings := backend.TranslateBindings(BackendPayloadConfig{})
	if bindings.Payloads.Loader == nil {
		t.Fatal("TranslateBindings() did not wire payload loader")
	}
	if bindings.Commits.ApplyCommit == nil {
		t.Fatal("TranslateBindings() did not wire commit hook")
	}
}

func TestBackendCommitHooksMirrorFlowAndRegionContextWrites(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	backend := NewBackend()
	backend.SetDefaultContextWords([]uint64{0x5500})

	hooks := backend.CommitHooks()
	if hooks.ApplyCommit == nil {
		t.Fatal("CommitHooks() did not install ApplyCommit hook")
	}

	if err := hooks.ApplyCommit(ApplyCommitRequest{
		Commit: ContextSet{
			Number: 0,
			Mask:   0x00ff,
			Value:  0x0012,
			Flow:   true,
		},
		CommitAddr: address.Address{Space: ram, Offset: 0x1000},
		HasNext:    false,
	}); err != nil {
		t.Fatalf("flow ApplyCommit returned error: %v", err)
	}

	if err := hooks.ApplyCommit(ApplyCommitRequest{
		Commit: ContextSet{
			Number: 0,
			Mask:   0x00ff,
			Value:  0x0034,
			Flow:   false,
		},
		CommitAddr: address.Address{Space: ram, Offset: 0x1002},
		NextAddr:   address.Address{Space: ram, Offset: 0x1003},
		HasNext:    true,
	}); err != nil {
		t.Fatalf("region ApplyCommit returned error: %v", err)
	}

	readWord := func(offset uint64) uint64 {
		words, err := backend.LoadContextWords(address.Address{Space: ram, Offset: offset}, nil)
		if err != nil {
			t.Fatalf("LoadContextWords(0x%x) returned error: %v", offset, err)
		}
		if len(words) == 0 {
			t.Fatalf("LoadContextWords(0x%x) returned no words", offset)
		}
		return words[0]
	}

	if got := readWord(0x0fff); got != 0x5500 {
		t.Fatalf("pre-flow context mismatch: got 0x%x want 0x5500", got)
	}
	if got := readWord(0x1001); got != 0x5512 {
		t.Fatalf("flow context mismatch: got 0x%x want 0x5512", got)
	}
	if got := readWord(0x1002); got != 0x5534 {
		t.Fatalf("non-flow point context mismatch: got 0x%x want 0x5534", got)
	}
	if got := readWord(0x1003); got != 0x5512 {
		t.Fatalf("post-region context mismatch: got 0x%x want 0x5512", got)
	}
}

func TestBackendAllowContextSetDropsContextWrites(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	addr := address.Address{Space: ram, Offset: 0x2000}

	backend := NewBackend()
	backend.SetDefaultContextWords([]uint64{0x6600})
	backend.AllowContextSet(false)

	hooks := backend.CommitHooks()
	if err := hooks.ApplyCommit(ApplyCommitRequest{
		Commit: ContextSet{
			Number: 0,
			Mask:   0x00ff,
			Value:  0x00aa,
			Flow:   true,
		},
		CommitAddr: addr,
	}); err != nil {
		t.Fatalf("ApplyCommit returned error with allowSet=false: %v", err)
	}

	words, err := backend.LoadContextWords(addr, nil)
	if err != nil {
		t.Fatalf("LoadContextWords() returned error: %v", err)
	}
	if len(words) == 0 || words[0] != 0x6600 {
		t.Fatalf("allowSet=false should preserve defaults, got %v", words)
	}
}

func TestBackendLoadContextHooksIntegrateWithParserContextLoad(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	addr := address.Address{Space: ram, Offset: 0x3000}

	backend := NewBackend()
	backend.SetDefaultContextWords([]uint64{0xab00})
	if err := backend.SetContextChangePoint(addr, 0, 0x00ff, 0x0034); err != nil {
		t.Fatalf("SetContextChangePoint() returned error: %v", err)
	}

	ctx := NewParserContext(addr, nil)
	ctx.SetContextWords([]uint64{0xffff})
	if err := ctx.LoadContext(backend.LoadContextHooks()); err != nil {
		t.Fatalf("LoadContext() returned error: %v", err)
	}
	if len(ctx.ContextWords) == 0 || ctx.ContextWords[0] != 0xab34 {
		t.Fatalf("parser context words mismatch: got %v want [0xab34]", ctx.ContextWords)
	}
}

func TestBackendContextVariableDefaultsByName(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	addr := address.Address{Space: ram, Offset: 0x4100}

	backend := NewBackend()
	if err := backend.RegisterContextVariable("mode", 0, 7); err != nil {
		t.Fatalf("RegisterContextVariable(mode) returned error: %v", err)
	}
	if err := backend.RegisterContextVariable("flags", 60, 63); err != nil {
		t.Fatalf("RegisterContextVariable(flags) returned error: %v", err)
	}
	if err := backend.SetVariableDefault("mode", 0xab); err != nil {
		t.Fatalf("SetVariableDefault(mode) returned error: %v", err)
	}
	if err := backend.SetVariableDefault("flags", 0x5); err != nil {
		t.Fatalf("SetVariableDefault(flags) returned error: %v", err)
	}

	gotMode, err := backend.GetVariableDefault("mode")
	if err != nil {
		t.Fatalf("GetVariableDefault(mode) returned error: %v", err)
	}
	if gotMode != 0xab {
		t.Fatalf("GetVariableDefault(mode) mismatch: got 0x%x want 0xab", gotMode)
	}
	gotFlags, err := backend.GetVariableDefault("flags")
	if err != nil {
		t.Fatalf("GetVariableDefault(flags) returned error: %v", err)
	}
	if gotFlags != 0x5 {
		t.Fatalf("GetVariableDefault(flags) mismatch: got 0x%x want 0x5", gotFlags)
	}

	words, err := backend.LoadContextWords(addr, nil)
	if err != nil {
		t.Fatalf("LoadContextWords() returned error: %v", err)
	}
	if len(words) != 1 {
		t.Fatalf("LoadContextWords() size mismatch: got %d want 1", len(words))
	}
	wantWord := (uint64(0xab) << 56) | 0x5
	if words[0] != wantWord {
		t.Fatalf("default context word mismatch: got 0x%x want 0x%x", words[0], wantWord)
	}

	gotAtAddr, err := backend.GetVariable("mode", addr)
	if err != nil {
		t.Fatalf("GetVariable(mode, addr) returned error: %v", err)
	}
	if gotAtAddr != 0xab {
		t.Fatalf("GetVariable(mode, addr) mismatch: got 0x%x want 0xab", gotAtAddr)
	}
}

func TestBackendContextVariableSetAndGetByAddress(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)

	backend := NewBackend()
	if err := backend.RegisterContextVariable("mode", 0, 7); err != nil {
		t.Fatalf("RegisterContextVariable(mode) returned error: %v", err)
	}
	if err := backend.RegisterContextVariable("submode", 8, 15); err != nil {
		t.Fatalf("RegisterContextVariable(submode) returned error: %v", err)
	}
	if err := backend.SetVariableDefault("mode", 0x11); err != nil {
		t.Fatalf("SetVariableDefault(mode) returned error: %v", err)
	}
	if err := backend.SetVariableDefault("submode", 0x22); err != nil {
		t.Fatalf("SetVariableDefault(submode) returned error: %v", err)
	}

	if err := backend.SetVariable("mode", address.Address{Space: ram, Offset: 0x5010}, 0x44); err != nil {
		t.Fatalf("SetVariable(mode @0x5010) returned error: %v", err)
	}
	if err := backend.SetVariable("mode", address.Address{Space: ram, Offset: 0x5020}, 0x66); err != nil {
		t.Fatalf("SetVariable(mode @0x5020) returned error: %v", err)
	}

	modeCases := []struct {
		offset uint64
		want   uint64
	}{
		{offset: 0x500f, want: 0x11},
		{offset: 0x5010, want: 0x44},
		{offset: 0x501f, want: 0x44},
		{offset: 0x5020, want: 0x66},
		{offset: 0x5040, want: 0x66},
	}
	for _, tc := range modeCases {
		got, err := backend.GetVariable("mode", address.Address{Space: ram, Offset: tc.offset})
		if err != nil {
			t.Fatalf("GetVariable(mode, 0x%x) returned error: %v", tc.offset, err)
		}
		if got != tc.want {
			t.Fatalf("GetVariable(mode, 0x%x) mismatch: got 0x%x want 0x%x", tc.offset, got, tc.want)
		}
	}

	gotSubmode, err := backend.GetVariable("submode", address.Address{Space: ram, Offset: 0x5040})
	if err != nil {
		t.Fatalf("GetVariable(submode) returned error: %v", err)
	}
	if gotSubmode != 0x22 {
		t.Fatalf("GetVariable(submode) mismatch: got 0x%x want 0x22", gotSubmode)
	}

	words, err := backend.LoadContextWords(address.Address{Space: ram, Offset: 0x5040}, nil)
	if err != nil {
		t.Fatalf("LoadContextWords(0x5040) returned error: %v", err)
	}
	if len(words) == 0 {
		t.Fatal("LoadContextWords(0x5040) returned no words")
	}
	wantWord := uint64(0x6622000000000000)
	if words[0] != wantWord {
		t.Fatalf("context word mismatch at 0x5040: got 0x%x want 0x%x", words[0], wantWord)
	}
}

func TestBackendSetVariableStopsAtNextExplicitChangePoint(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)

	backend := NewBackend()
	if err := backend.RegisterContextVariable("mode", 0, 7); err != nil {
		t.Fatalf("RegisterContextVariable(mode) returned error: %v", err)
	}
	if err := backend.SetVariableDefault("mode", 0x10); err != nil {
		t.Fatalf("SetVariableDefault(mode) returned error: %v", err)
	}
	if err := backend.SetVariable("mode", address.Address{Space: ram, Offset: 0x7000}, 0x20); err != nil {
		t.Fatalf("SetVariable(mode @0x7000) returned error: %v", err)
	}
	if err := backend.SetVariable("mode", address.Address{Space: ram, Offset: 0x7040}, 0x30); err != nil {
		t.Fatalf("SetVariable(mode @0x7040) returned error: %v", err)
	}
	if err := backend.SetVariable("mode", address.Address{Space: ram, Offset: 0x7020}, 0x40); err != nil {
		t.Fatalf("SetVariable(mode @0x7020) returned error: %v", err)
	}

	cases := []struct {
		offset uint64
		want   uint64
	}{
		{offset: 0x701f, want: 0x20},
		{offset: 0x7020, want: 0x40},
		{offset: 0x703f, want: 0x40},
		{offset: 0x7040, want: 0x30},
		{offset: 0x7080, want: 0x30},
	}
	for _, tc := range cases {
		got, err := backend.GetVariable("mode", address.Address{Space: ram, Offset: tc.offset})
		if err != nil {
			t.Fatalf("GetVariable(mode, 0x%x) returned error: %v", tc.offset, err)
		}
		if got != tc.want {
			t.Fatalf("GetVariable(mode, 0x%x) mismatch: got 0x%x want 0x%x", tc.offset, got, tc.want)
		}
	}

	words, first, last, err := backend.LoadContextWordsWithRange(address.Address{Space: ram, Offset: 0x7030}, nil)
	if err != nil {
		t.Fatalf("LoadContextWordsWithRange(0x7030) returned error: %v", err)
	}
	if first != 0x7020 || last != 0x703f {
		t.Fatalf("range mismatch at 0x7030: got [0x%x,0x%x] want [0x7020,0x703f]", first, last)
	}
	if len(words) == 0 || words[0] != 0x4000000000000000 {
		t.Fatalf("context blob mismatch at 0x7030: got %v want first word 0x4000000000000000", words)
	}

	_, first, last, err = backend.LoadContextWordsWithRange(address.Address{Space: ram, Offset: 0x7050}, nil)
	if err != nil {
		t.Fatalf("LoadContextWordsWithRange(0x7050) returned error: %v", err)
	}
	if first != 0x7040 || last != backendSpaceHighest(ram) {
		t.Fatalf(
			"range mismatch at 0x7050: got [0x%x,0x%x] want [0x7040,0x%x]",
			first,
			last,
			backendSpaceHighest(ram),
		)
	}
}

func TestBackendContextVariableRegistrationParityChecks(t *testing.T) {
	backend := NewBackend()
	if err := backend.RegisterContextVariable("cross", 63, 64); err == nil {
		t.Fatal("RegisterContextVariable() should reject variables spanning multiple words")
	}
	if err := backend.RegisterContextVariable("reverse", 12, 11); err == nil {
		t.Fatal("RegisterContextVariable() should reject reverse bit ranges")
	}
	if err := backend.RegisterContextVariable("ok", 0, 7); err != nil {
		t.Fatalf("RegisterContextVariable(ok) returned error: %v", err)
	}

	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	if err := backend.SetContextChangePoint(address.Address{Space: ram, Offset: 0x6100}, 0, 0xff, 0x12); err != nil {
		t.Fatalf("SetContextChangePoint() returned error: %v", err)
	}
	if err := backend.RegisterContextVariable("late", 8, 15); err == nil {
		t.Fatal("RegisterContextVariable() should reject registration after context writes are initialized")
	}

	addr := address.Address{Space: ram, Offset: 0x6100}
	if _, err := backend.GetVariableDefault("missing"); err == nil {
		t.Fatal("GetVariableDefault() should fail for non-existent variables")
	}
	if err := backend.SetVariableDefault("missing", 1); err == nil {
		t.Fatal("SetVariableDefault() should fail for non-existent variables")
	}
	if _, err := backend.GetVariable("missing", addr); err == nil {
		t.Fatal("GetVariable() should fail for non-existent variables")
	}
	if err := backend.SetVariable("missing", addr, 1); err == nil {
		t.Fatal("SetVariable() should fail for non-existent variables")
	}
}

func TestBackendLoadContextWordsWithRangeMatchesContextBoundaries(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	reg := testBackendSpace("register", address.SpaceKindProcessor, 2, 1)

	backend := NewBackend()
	backend.SetDefaultContextWords([]uint64{0x5500})
	if err := backend.SetContextChangePoint(address.Address{Space: ram, Offset: 0x100}, 0, 0x00ff, 0x0012); err != nil {
		t.Fatalf("SetContextChangePoint() returned error: %v", err)
	}
	if err := backend.SetContextRegion(
		address.Address{Space: ram, Offset: 0x120},
		address.Address{Space: ram, Offset: 0x130},
		0,
		0x00ff,
		0x0034,
	); err != nil {
		t.Fatalf("SetContextRegion() returned error: %v", err)
	}

	cases := []struct {
		addr      address.Address
		wantFirst uint64
		wantLast  uint64
		wantWord  uint64
	}{
		{
			addr:      address.Address{Space: ram, Offset: 0x0ff},
			wantFirst: 0x0,
			wantLast:  0x0ff,
			wantWord:  0x5500,
		},
		{
			addr:      address.Address{Space: ram, Offset: 0x110},
			wantFirst: 0x100,
			wantLast:  0x11f,
			wantWord:  0x5512,
		},
		{
			addr:      address.Address{Space: ram, Offset: 0x125},
			wantFirst: 0x120,
			wantLast:  0x12f,
			wantWord:  0x5534,
		},
		{
			addr:      address.Address{Space: ram, Offset: 0x130},
			wantFirst: 0x130,
			wantLast:  backendSpaceHighest(ram),
			wantWord:  0x5512,
		},
		{
			addr:      address.Address{Space: reg, Offset: 0x125},
			wantFirst: 0x0,
			wantLast:  backendSpaceHighest(reg),
			wantWord:  0x5500,
		},
	}
	for _, tc := range cases {
		words, first, last, err := backend.LoadContextWordsWithRange(tc.addr, nil)
		if err != nil {
			t.Fatalf("LoadContextWordsWithRange(%v) returned error: %v", tc.addr, err)
		}
		if first != tc.wantFirst || last != tc.wantLast {
			t.Fatalf(
				"range mismatch at %v: got [0x%x,0x%x] want [0x%x,0x%x]",
				tc.addr,
				first,
				last,
				tc.wantFirst,
				tc.wantLast,
			)
		}
		if len(words) == 0 || words[0] != tc.wantWord {
			t.Fatalf("context word mismatch at %v: got %v want first word 0x%x", tc.addr, words, tc.wantWord)
		}
	}
}

func TestBackendGetSetFileNameMirrorsLoadImageFileName(t *testing.T) {
	backend := NewBackend()
	if got := backend.GetFileName(); got != "" {
		t.Fatalf("initial GetFileName() should be empty, got %q", got)
	}
	backend.SetFileName("test-binary.bin")
	if got := backend.GetFileName(); got != "test-binary.bin" {
		t.Fatalf("GetFileName() mismatch: got %q want %q", got, "test-binary.bin")
	}
}

func TestBackendGetSetArchTypeMirrorsLoadImageArchType(t *testing.T) {
	backend := NewBackend()
	if got := backend.GetArchType(); got != "" {
		t.Fatalf("initial GetArchType() should be empty, got %q", got)
	}
	backend.SetArchType("x86:LE:64:default")
	if got := backend.GetArchType(); got != "x86:LE:64:default" {
		t.Fatalf("GetArchType() mismatch: got %q want %q", got, "x86:LE:64:default")
	}
}

func TestBackendContextSizeMirrorsRegisteredVariableCount(t *testing.T) {
	backend := NewBackend()
	if got := backend.ContextSize(); got != 0 {
		t.Fatalf("initial ContextSize() should be 0, got %d", got)
	}
	if err := backend.RegisterContextVariable("mode", 0, 7); err != nil {
		t.Fatalf("RegisterContextVariable(mode) returned error: %v", err)
	}
	if got := backend.ContextSize(); got != 1 {
		t.Fatalf("ContextSize() after single-word variable: got %d want 1", got)
	}
	if err := backend.RegisterContextVariable("wide", 64, 71); err != nil {
		t.Fatalf("RegisterContextVariable(wide) returned error: %v", err)
	}
	if got := backend.ContextSize(); got != 2 {
		t.Fatalf("ContextSize() after two-word variable: got %d want 2", got)
	}
}

func TestBackendSetVariableRegionPaintsContextAcrossRange(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	backend := NewBackend()
	if err := backend.RegisterContextVariable("mode", 0, 7); err != nil {
		t.Fatalf("RegisterContextVariable(mode) returned error: %v", err)
	}
	if err := backend.SetVariableDefault("mode", 0x10); err != nil {
		t.Fatalf("SetVariableDefault(mode) returned error: %v", err)
	}

	begad := address.Address{Space: ram, Offset: 0x8000}
	endad := address.Address{Space: ram, Offset: 0x8010}
	if err := backend.SetVariableRegion("mode", begad, endad, 0xab); err != nil {
		t.Fatalf("SetVariableRegion() returned error: %v", err)
	}

	cases := []struct {
		offset uint64
		want   uint64
	}{
		{offset: 0x7fff, want: 0x10},
		{offset: 0x8000, want: 0xab},
		{offset: 0x800f, want: 0xab},
		{offset: 0x8010, want: 0x10},
	}
	for _, tc := range cases {
		got, err := backend.GetVariable("mode", address.Address{Space: ram, Offset: tc.offset})
		if err != nil {
			t.Fatalf("GetVariable(mode, 0x%x) returned error: %v", tc.offset, err)
		}
		if got != tc.want {
			t.Fatalf("GetVariable(mode, 0x%x) mismatch: got 0x%x want 0x%x", tc.offset, got, tc.want)
		}
	}
}

func TestBackendSetVariableRegionRejectsNonExistentVariable(t *testing.T) {
	ram := testBackendSpace("ram", address.SpaceKindProcessor, 1, 1)
	backend := NewBackend()
	err := backend.SetVariableRegion(
		"missing",
		address.Address{Space: ram, Offset: 0x1000},
		address.Address{Space: ram, Offset: 0x2000},
		0x42,
	)
	if err == nil {
		t.Fatal("SetVariableRegion() should fail for non-existent variable")
	}
}

func testBackendSpace(name string, kind address.SpaceKind, index uint16, wordSize uint8) *address.Space {
	return &address.Space{
		Name:      name,
		Kind:      kind,
		Index:     index,
		AddrSize:  8,
		WordSize:  wordSize,
		BigEndian: false,
		Physical:  true,
	}
}
