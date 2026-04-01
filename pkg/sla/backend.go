package sla

import (
	"fmt"
	"io"
	"os"
	"sync"

	"gosleigh/pkg/address"
)

const (
	defaultBackendInstructionSize = 16
	backendContextWordBits        = 64
)

// BackendPayloadConfig controls how address-based payloads are read for translation.
// The default instruction size mirrors Sleigh::resolve() calling LoadImage::loadFill(...,16,...).
type BackendPayloadConfig struct {
	InstructionSize int
}

// BackendTranslateBindings is a minimal TranslateSubtable-ready projection.
// It wires the backend into TranslateInput.Payloads.Loader and TranslateInput.Commits.
type BackendTranslateBindings struct {
	Payloads TranslatePayloadSource
	Commits  ApplyCommitsHooks
}

type backendContextWrite struct {
	start  address.Address
	end    address.Address
	hasEnd bool
	word   int
	mask   uint64
	value  uint64
}

type backendContextVariable struct {
	word  int
	shift uint
	mask  uint64
}

// backendRawInstructionImage mirrors the contiguous file/stream state carried by ghidra::RawLoadImage.
type backendRawInstructionImage struct {
	reader io.ReaderAt
	closer io.Closer
	space  *address.Space
	size   uint64
	vma    uint64
}

// Backend is a concrete minimal runtime backend for the current shell.
// It mirrors the needed boundaries of ghidra::LoadImage and ContextDatabase/ContextCache:
// instruction bytes by address, context words by address, and context writes from applyCommits().
type Backend struct {
	mu sync.RWMutex

	// image stores byte-addressable instruction data, keyed by absolute address.
	image map[address.Address]byte

	// rawImage mirrors RawLoadImage file-backed bytes for standalone instruction fetch.
	rawImage *backendRawInstructionImage

	// defaultContext mirrors ContextDatabase default blob values.
	defaultContext []uint64

	// contextVariables mirrors ContextInternal::variables in globalcontext.hh/.cc.
	contextVariables map[string]backendContextVariable

	// registeredContextWords tracks ContextInternal::size semantics from registerVariable().
	registeredContextWords int

	// contextWrites are applied in insertion order, where later writes override earlier writes
	// on overlapping masked bits, matching ContextDatabase "paint" style updates.
	contextWrites []backendContextWrite

	// allowSet mirrors ContextCache::allowSet() in globalcontext.hh.
	allowSet bool
}

// NewBackend creates an empty in-memory backend.
func NewBackend() *Backend {
	return &Backend{
		image:            make(map[address.Address]byte),
		contextVariables: make(map[string]backendContextVariable),
		allowSet:         true,
	}
}

// SetRawInstructionReader installs a contiguous reader-backed instruction image.
// This mirrors RawLoadImage carrying a stream, filesize, optional attached space, and VMA.
func (b *Backend) SetRawInstructionReader(space *address.Space, reader io.ReaderAt, size uint64, vma uint64) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	if reader == nil {
		return fmt.Errorf("set raw instruction reader: reader is nil")
	}
	if space != nil {
		if err := space.Validate(); err != nil {
			return fmt.Errorf("set raw instruction reader: %w", err)
		}
	}
	if size > backendMaxReaderAtSize {
		return fmt.Errorf("set raw instruction reader: size %d exceeds ReaderAt limit", size)
	}

	b.mu.Lock()
	if b.rawImage != nil {
		b.mu.Unlock()
		return fmt.Errorf("set raw instruction reader: raw instruction source is already configured")
	}
	err := b.replaceRawInstructionImageLocked(&backendRawInstructionImage{
		reader: reader,
		space:  space,
		size:   size,
		vma:    vma,
	})
	b.mu.Unlock()
	return err
}

// OpenRawInstructionFile mirrors RawLoadImage::open() recovering filesize from a file-backed image.
// The address space attachment remains a separate lifecycle step, like RawLoadImage::attachToSpace().
func (b *Backend) OpenRawInstructionFile(path string, space *address.Space, vma uint64) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	if path == "" {
		return fmt.Errorf("open raw instruction file: path is empty")
	}
	if space != nil {
		if err := space.Validate(); err != nil {
			return fmt.Errorf("open raw instruction file: %w", err)
		}
	}

	b.mu.Lock()
	if b.rawImage != nil {
		b.mu.Unlock()
		return fmt.Errorf("open raw instruction file: raw instruction source is already configured")
	}
	file, err := os.Open(path)
	if err != nil {
		b.mu.Unlock()
		return fmt.Errorf("open raw instruction file: unable to open raw image file %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		b.mu.Unlock()
		file.Close()
		return fmt.Errorf("open raw instruction file: stat %q: %w", path, err)
	}
	if info.Size() < 0 {
		b.mu.Unlock()
		file.Close()
		return fmt.Errorf("open raw instruction file: negative file size for %q", path)
	}

	raw := &backendRawInstructionImage{
		reader: file,
		closer: file,
		space:  space,
		size:   uint64(info.Size()),
		vma:    vma,
	}
	err = b.replaceRawInstructionImageLocked(raw)
	b.mu.Unlock()
	if err != nil {
		file.Close()
		return err
	}
	return nil
}

// AttachRawInstructionSpace mirrors ghidra::RawLoadImage::attachToSpace().
func (b *Backend) AttachRawInstructionSpace(space *address.Space) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	if space == nil {
		return fmt.Errorf("attach raw instruction space: address space is nil")
	}
	if err := space.Validate(); err != nil {
		return fmt.Errorf("attach raw instruction space: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rawImage == nil {
		return fmt.Errorf("attach raw instruction space: raw instruction source is not configured")
	}
	b.rawImage.space = space
	return nil
}

// CloseRawInstructionSource releases the current raw instruction image, if any.
func (b *Backend) CloseRawInstructionSource() error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	b.mu.Lock()
	err := b.replaceRawInstructionImageLocked(nil)
	b.mu.Unlock()
	return err
}

// AdjustRawInstructionVMA mirrors ghidra::RawLoadImage::adjustVma().
// The adjustment is expressed in addressable units, then scaled to bytes using
// the attached space word size before rebasing the first byte of the raw image.
func (b *Backend) AdjustRawInstructionVMA(adjust uint64) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rawImage == nil {
		return fmt.Errorf("adjust raw instruction vma: raw instruction source is not configured")
	}
	if b.rawImage.space == nil {
		return fmt.Errorf("adjust raw instruction vma: raw instruction space is not attached")
	}

	// Mirror RawLoadImage::adjustVma() calling AddrSpace::addressToByte().
	b.rawImage.vma += adjust * uint64(b.rawImage.space.WordSize)
	return nil
}

// SetInstructionBytes stores contiguous instruction bytes beginning at addr.
func (b *Backend) SetInstructionBytes(addr address.Address, data []byte) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	if err := addr.Validate(); err != nil {
		return fmt.Errorf("set instruction bytes: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	last := addr.Offset + uint64(len(data)-1)
	if last < addr.Offset {
		return fmt.Errorf("set instruction bytes: address overflow for %d bytes at %v", len(data), addr)
	}

	b.mu.Lock()
	for i := range data {
		b.image[address.Address{Space: addr.Space, Offset: addr.Offset + uint64(i)}] = data[i]
	}
	b.mu.Unlock()
	return nil
}

// SetDefaultContextWords defines the default context blob for addresses without overlays.
func (b *Backend) SetDefaultContextWords(words []uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defaultWords := cloneContextWords(words)
	if len(defaultWords) < b.registeredContextWords {
		grown := make([]uint64, b.registeredContextWords)
		copy(grown, defaultWords)
		defaultWords = grown
	}
	b.defaultContext = defaultWords
	b.mu.Unlock()
}

// RegisterContextVariable mirrors ContextInternal::registerVariable() bit-range registration.
func (b *Backend) RegisterContextVariable(name string, sbit int, ebit int) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	if sbit < 0 || ebit < 0 {
		return fmt.Errorf("register context variable: negative bit range (%d,%d)", sbit, ebit)
	}
	if ebit < sbit {
		return fmt.Errorf("register context variable: end bit %d before start bit %d", ebit, sbit)
	}
	word := sbit / backendContextWordBits
	if (ebit / backendContextWordBits) != word {
		return fmt.Errorf("register context variable: context variable does not fit in one word")
	}

	startBit := sbit - word*backendContextWordBits
	endBit := ebit - word*backendContextWordBits
	shift := backendContextWordBits - endBit - 1
	mask := ^uint64(0) >> uint(startBit+shift)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Mirrors ContextInternal::registerVariable() rejecting registrations after split initialization.
	if len(b.contextWrites) != 0 {
		return fmt.Errorf("register context variable: cannot register new context variables after context writes are initialized")
	}
	if b.contextVariables == nil {
		b.contextVariables = make(map[string]backendContextVariable)
	}
	b.contextVariables[name] = backendContextVariable{
		word:  word,
		shift: uint(shift),
		mask:  mask,
	}
	if word+1 > b.registeredContextWords {
		b.registeredContextWords = word + 1
	}
	if len(b.defaultContext) < b.registeredContextWords {
		grown := make([]uint64, b.registeredContextWords)
		copy(grown, b.defaultContext)
		b.defaultContext = grown
	}
	return nil
}

// SetVariableDefault mirrors ContextDatabase::setVariableDefault().
func (b *Backend) SetVariableDefault(name string, value uint64) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	variable, err := b.contextVariableLocked(name)
	if err != nil {
		return fmt.Errorf("set variable default: %w", err)
	}
	if len(b.defaultContext) <= variable.word {
		grown := make([]uint64, variable.word+1)
		copy(grown, b.defaultContext)
		b.defaultContext = grown
	}
	wordMask := variable.mask << variable.shift
	wordValue := b.defaultContext[variable.word]
	wordValue &= ^wordMask
	wordValue |= (value & variable.mask) << variable.shift
	b.defaultContext[variable.word] = wordValue
	return nil
}

// GetVariableDefault mirrors ContextDatabase::getDefaultValue().
func (b *Backend) GetVariableDefault(name string) (uint64, error) {
	if b == nil {
		return 0, fmt.Errorf("backend is nil")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	variable, err := b.contextVariableLocked(name)
	if err != nil {
		return 0, fmt.Errorf("get variable default: %w", err)
	}
	if variable.word >= len(b.defaultContext) {
		return 0, nil
	}
	return (b.defaultContext[variable.word] >> variable.shift) & variable.mask, nil
}

// SetVariable mirrors ContextDatabase::setVariable() for named context variables.
func (b *Backend) SetVariable(name string, addr address.Address, value uint64) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	variable, err := b.contextVariable(name)
	if err != nil {
		return fmt.Errorf("set variable: %w", err)
	}
	mask := variable.mask << variable.shift
	shiftedValue := (value & variable.mask) << variable.shift
	return b.SetContextChangePoint(addr, variable.word, mask, shiftedValue)
}

// GetVariable mirrors ContextDatabase::getVariable().
func (b *Backend) GetVariable(name string, addr address.Address) (uint64, error) {
	if b == nil {
		return 0, fmt.Errorf("backend is nil")
	}
	variable, err := b.contextVariable(name)
	if err != nil {
		return 0, fmt.Errorf("get variable: %w", err)
	}
	words, err := b.LoadContextWords(addr, nil)
	if err != nil {
		return 0, err
	}
	if variable.word >= len(words) {
		return 0, nil
	}
	return (words[variable.word] >> variable.shift) & variable.mask, nil
}

// AllowContextSet toggles whether context writes are accepted.
// When false, setContext-like operations are ignored, matching ContextCache::allowSet().
func (b *Backend) AllowContextSet(val bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.allowSet = val
	b.mu.Unlock()
}

// LoadInstructionBytes mirrors the LoadImage::loadFill boundary in pull form.
// It returns ok=false if the first byte at addr is unavailable.
func (b *Backend) LoadInstructionBytes(addr address.Address, size int) ([]byte, bool, error) {
	if b == nil {
		return nil, false, fmt.Errorf("backend is nil")
	}
	if err := addr.Validate(); err != nil {
		return nil, false, fmt.Errorf("load instruction bytes: %w", err)
	}
	if size < 0 {
		return nil, false, fmt.Errorf("load instruction bytes: negative size %d", size)
	}
	if size == 0 {
		return []byte{}, true, nil
	}

	out := make([]byte, size)

	b.mu.RLock()
	first, ok := b.image[addr]
	if ok {
		out[0] = first

		for i := 1; i < size; i++ {
			off := addr.Offset + uint64(i)
			if off < addr.Offset {
				b.mu.RUnlock()
				return nil, false, fmt.Errorf("load instruction bytes: address overflow at index %d", i)
			}
			key := address.Address{Space: addr.Space, Offset: off}
			val, found := b.image[key]
			if !found {
				// RawLoadImage::loadFill() behavior: once the read starts, trailing unavailable
				// bytes are zero-filled instead of treated as a hard miss.
				break
			}
			out[i] = val
		}
		b.mu.RUnlock()
		return out, true, nil
	}
	raw := b.rawImage
	if raw == nil || !backendSameSpace(addr, address.Address{Space: raw.space}) {
		b.mu.RUnlock()
		return nil, false, nil
	}
	readSize, ok := backendRawInstructionReadableSize(raw, addr, size)
	if !ok {
		b.mu.RUnlock()
		return nil, false, nil
	}
	section := io.NewSectionReader(raw.reader, int64(addr.Offset-raw.vma), int64(readSize))
	if _, err := io.ReadFull(section, out[:readSize]); err != nil {
		b.mu.RUnlock()
		return nil, false, fmt.Errorf("load instruction bytes: raw image read failed at %v: %w", addr, err)
	}
	b.mu.RUnlock()
	return out, true, nil
}

// LoadContextWords mirrors ContextCache::getContext() by retrieving a context blob for addr.
func (b *Backend) LoadContextWords(addr address.Address, current []uint64) ([]uint64, error) {
	words, _, _, err := b.LoadContextWordsWithRange(addr, current)
	return words, err
}

// LoadContextWordsWithRange mirrors ContextDatabase::getContext(addr, first, last) cache bounds.
func (b *Backend) LoadContextWordsWithRange(addr address.Address, current []uint64) ([]uint64, uint64, uint64, error) {
	if b == nil {
		return nil, 0, 0, fmt.Errorf("backend is nil")
	}
	if err := addr.Validate(); err != nil {
		return nil, 0, 0, fmt.Errorf("load context words: %w", err)
	}

	b.mu.RLock()
	words := b.loadContextWordsLocked(addr, current)
	first, last := b.contextRangeLocked(addr)
	b.mu.RUnlock()
	return words, first, last, nil
}

// SetContextChangePoint mirrors ContextDatabase::setContextChangePoint().
func (b *Backend) SetContextChangePoint(addr address.Address, num int, mask uint64, value uint64) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	if err := addr.Validate(); err != nil {
		return fmt.Errorf("set context change point: %w", err)
	}
	if num < 0 {
		return fmt.Errorf("context word index %d is negative", num)
	}

	b.mu.Lock()
	if !b.allowSet {
		b.mu.Unlock()
		return nil
	}

	write := backendContextWrite{
		start: addr,
		word:  num,
		mask:  mask,
		value: value & mask,
	}
	// Mirror ContextDatabase::getRegionToChangePoint(): stop at the next explicit
	// overlapping write so earlier change-points do not override later fixed points.
	if end, ok := b.nextContextChangeBoundaryLocked(addr, num, mask); ok {
		write.end = end
		write.hasEnd = true
	}
	b.contextWrites = append(b.contextWrites, write)
	b.mu.Unlock()
	return nil
}

// SetContextRegion mirrors ContextDatabase::setContextRegion() with an exclusive addr2 bound.
func (b *Backend) SetContextRegion(addr1 address.Address, addr2 address.Address, num int, mask uint64, value uint64) error {
	if err := addr1.Validate(); err != nil {
		return fmt.Errorf("set context region: start address: %w", err)
	}
	if !addr2.IsInvalid() {
		if err := addr2.Validate(); err != nil {
			return fmt.Errorf("set context region: end address: %w", err)
		}
		if !backendSameSpace(addr1, addr2) {
			return fmt.Errorf("set context region: address space mismatch (%v -> %v)", addr1, addr2)
		}
		if addr2.Less(addr1) {
			return fmt.Errorf("set context region: end before start (%v -> %v)", addr1, addr2)
		}
		if addr1 == addr2 {
			return nil
		}
	}
	return b.appendContextWrite(backendContextWrite{
		start:  addr1,
		end:    addr2,
		hasEnd: !addr2.IsInvalid(),
		word:   num,
		mask:   mask,
		value:  value & mask,
	})
}

func (b *Backend) appendContextWrite(write backendContextWrite) error {
	if b == nil {
		return fmt.Errorf("backend is nil")
	}
	if write.word < 0 {
		return fmt.Errorf("context word index %d is negative", write.word)
	}
	b.mu.Lock()
	if !b.allowSet {
		b.mu.Unlock()
		return nil
	}
	b.contextWrites = append(b.contextWrites, write)
	b.mu.Unlock()
	return nil
}

// PayloadLoader returns a TranslatePayloadSource.Loader-compatible callback.
// This is the concrete LoadImage/ContextDatabase adapter used by TranslateSubtable address lookup.
func (b *Backend) PayloadLoader(config BackendPayloadConfig) func(addr address.Address) (MatchInput, bool, error) {
	instructionSize := config.InstructionSize
	if instructionSize <= 0 {
		instructionSize = defaultBackendInstructionSize
	}
	return func(addr address.Address) (MatchInput, bool, error) {
		instruction, ok, err := b.LoadInstructionBytes(addr, instructionSize)
		if err != nil {
			return MatchInput{}, false, err
		}
		if !ok {
			return MatchInput{}, false, nil
		}
		words, err := b.LoadContextWords(addr, nil)
		if err != nil {
			return MatchInput{}, false, err
		}
		return MatchInput{
			Instruction: instruction,
			Context:     contextBytesFromWords(words),
		}, true, nil
	}
}

// TranslateBindings returns minimal backend adapters for address-based translation.
func (b *Backend) TranslateBindings(config BackendPayloadConfig) BackendTranslateBindings {
	return BackendTranslateBindings{
		Payloads: TranslatePayloadSource{
			Loader: b.PayloadLoader(config),
		},
		Commits: b.CommitHooks(),
	}
}

// LoadContextHooks returns ParserContext::loadContext()-style hooks backed by this backend.
func (b *Backend) LoadContextHooks() LoadContextHooks {
	return LoadContextHooks{
		LoadContextWords: func(addr address.Address, current []uint64) ([]uint64, error) {
			return b.LoadContextWords(addr, current)
		},
	}
}

// CommitHooks returns ParserContext::applyCommits()-style cache write hooks backed by this backend.
func (b *Backend) CommitHooks() ApplyCommitsHooks {
	return ApplyCommitsHooks{
		// Mirrors context.cc fallback behavior: unresolved symbols can still commit to current instruction addr.
		ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
			if req.Context == nil {
				return address.Address{}, fmt.Errorf("resolve commit address: parser context is nil")
			}
			return req.Context.GetAddr(), nil
		},
		ApplyCommit: func(req ApplyCommitRequest) error {
			if req.Commit.Flow || !req.HasNext {
				return b.SetContextChangePoint(req.CommitAddr, req.Commit.Number, req.Commit.Mask, req.Commit.Value)
			}
			return b.SetContextRegion(req.CommitAddr, req.NextAddr, req.Commit.Number, req.Commit.Mask, req.Commit.Value)
		},
	}
}

func (b *Backend) contextVariable(name string) (backendContextVariable, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.contextVariableLocked(name)
}

func (b *Backend) contextVariableLocked(name string) (backendContextVariable, error) {
	variable, ok := b.contextVariables[name]
	if !ok {
		return backendContextVariable{}, fmt.Errorf("non-existent context variable: %s", name)
	}
	return variable, nil
}

func (b *Backend) replaceRawInstructionImageLocked(next *backendRawInstructionImage) error {
	if b.rawImage != nil && b.rawImage.closer != nil {
		if err := b.rawImage.closer.Close(); err != nil {
			return fmt.Errorf("replace raw instruction source: %w", err)
		}
	}
	b.rawImage = next
	return nil
}

func (b *Backend) loadContextWordsLocked(addr address.Address, current []uint64) []uint64 {
	size := b.contextSizeLocked(len(current))
	words := make([]uint64, size)
	if len(b.defaultContext) > 0 {
		copy(words, b.defaultContext)
	} else if len(current) > 0 {
		copy(words, current)
	}
	for i := range b.contextWrites {
		write := b.contextWrites[i]
		if !backendAddressInWriteRange(addr, write) {
			continue
		}
		if write.word < 0 || write.word >= len(words) {
			continue
		}
		words[write.word] = (words[write.word] & ^write.mask) | (write.value & write.mask)
	}
	return words
}

func (b *Backend) contextSizeLocked(currentLen int) int {
	size := len(b.defaultContext)
	if size == 0 {
		size = currentLen
	}
	if b.registeredContextWords > size {
		size = b.registeredContextWords
	}
	for i := range b.contextWrites {
		if b.contextWrites[i].word+1 > size {
			size = b.contextWrites[i].word + 1
		}
	}
	return size
}

func (b *Backend) contextRangeLocked(addr address.Address) (uint64, uint64) {
	first := uint64(0)
	last := backendSpaceHighest(addr.Space)
	for i := range b.contextWrites {
		write := b.contextWrites[i]
		if !backendSameSpace(addr, write.start) {
			continue
		}
		if write.start.Offset <= addr.Offset {
			if write.start.Offset > first {
				first = write.start.Offset
			}
		} else {
			bound := write.start.Offset - 1
			if bound < last {
				last = bound
			}
		}
		if !write.hasEnd {
			continue
		}
		if write.end.Offset <= addr.Offset {
			if write.end.Offset > first {
				first = write.end.Offset
			}
		} else {
			bound := write.end.Offset - 1
			if bound < last {
				last = bound
			}
		}
	}
	if last < first {
		last = first
	}
	return first, last
}

func (b *Backend) nextContextChangeBoundaryLocked(addr address.Address, num int, mask uint64) (address.Address, bool) {
	var boundary address.Address
	found := false
	for i := range b.contextWrites {
		write := b.contextWrites[i]
		if write.word != num {
			continue
		}
		if (write.mask & mask) == 0 {
			continue
		}
		if !backendSameSpace(addr, write.start) {
			continue
		}
		if write.start.Offset <= addr.Offset {
			continue
		}
		if !found || write.start.Offset < boundary.Offset {
			boundary = write.start
			found = true
		}
	}
	return boundary, found
}

func backendAddressInWriteRange(addr address.Address, write backendContextWrite) bool {
	if !backendSameSpace(addr, write.start) {
		return false
	}
	if addr.Less(write.start) {
		return false
	}
	if !write.hasEnd {
		return true
	}
	if !backendSameSpace(addr, write.end) {
		return false
	}
	return addr.Less(write.end)
}

func backendSameSpace(a address.Address, b address.Address) bool {
	if a.Space == nil || b.Space == nil {
		return false
	}
	if a.Space == b.Space {
		return true
	}
	return a.Space.Index == b.Space.Index
}

func backendSpaceHighest(space *address.Space) uint64 {
	if space == nil {
		return 0
	}
	if space.AddrSize >= 8 {
		return ^uint64(0)
	}
	bits := uint(space.AddrSize) * 8
	return (uint64(1) << bits) - 1
}

func backendRawInstructionReadableSize(raw *backendRawInstructionImage, addr address.Address, size int) (uint64, bool) {
	if raw == nil || size <= 0 {
		return 0, false
	}
	if addr.Offset < raw.vma {
		return 0, false
	}
	fileOffset := addr.Offset - raw.vma
	if fileOffset >= raw.size {
		return 0, false
	}
	readSize := uint64(size)
	remaining := raw.size - fileOffset
	if readSize > remaining {
		readSize = remaining
	}
	return readSize, readSize != 0
}

func contextBytesFromWords(words []uint64) []byte {
	if len(words) == 0 {
		return nil
	}
	out := make([]byte, len(words)*8)
	for i := range words {
		base := i * 8
		word := words[i]
		out[base] = byte(word >> 56)
		out[base+1] = byte(word >> 48)
		out[base+2] = byte(word >> 40)
		out[base+3] = byte(word >> 32)
		out[base+4] = byte(word >> 24)
		out[base+5] = byte(word >> 16)
		out[base+6] = byte(word >> 8)
		out[base+7] = byte(word)
	}
	return out
}

const backendMaxReaderAtSize = ^uint64(0) >> 1
