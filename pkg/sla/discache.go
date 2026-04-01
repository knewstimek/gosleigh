package sla

import (
	"errors"
	"fmt"
	"sync"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

var ErrRawBuildUnresolved = errors.New("raw build must be resolved before emit")

// DisassemblyCache stores parser contexts by address for re-entry paths.
type DisassemblyCache struct {
	mu       sync.RWMutex
	contexts map[address.Address]*ParserContext
	rawOps   map[address.Address][]pcode.RawOp
	// Mirrors sleigh.hh PcodeCacher lifetime: one reusable staging object is
	// active for at most one instruction address at a time.
	rawBuild       *rawBuildState
	rawBuildAddr   address.Address
	rawBuildActive bool

	// parserList/parserHash mirror DisassemblyCache::list/hashtable reuse in sleigh.cc.
	// Misses allocate from a circular parser context pool and reset parse state.
	parserList []*ParserContext
	parserHash []*ParserContext
	parserNext int
	parserMask uint64
}

// rawBuildState mirrors PcodeCacher (sleigh.hh / sleigh.cc) pool ownership.
//
// C++ PcodeCacher owns a contiguous VarnodeData pool (poolstart/curpool/endpool)
// plus a deque<PcodeData> of issued instructions. allocateVarnodes() bump-allocates
// from the pool; allocateInstruction() appends to the deque. When the pool grows
// via expandPool(), all issued PcodeData pointers (outvar/invar) and label_refs
// are rebound to the new allocation.
//
// Go adaptation: varnodes slice = the pool, issued slice = the deque.
// refs tracks per-op pool indices so rebindIssuedAfterExpand() can fix slice
// headers after a grow, achieving the same pointer-stability guarantee as C++
// expandPool(). The pool starts at defaultVarnodePoolSize (600) matching C++.
//
// A single DisassemblyCache-owned instance is reused instruction-by-instruction
// via reset(), mirroring PcodeCacher::clear() which resets curpool to poolstart
// but never frees the pool until the destructor.
type rawBuildState struct {
	// issued mirrors deque<PcodeData> -- each RawOp's Inputs/Output slice into
	// varnodes via the corresponding refs entry.
	issued []pcode.RawOp
	// refs tracks pool positions for each issued op, enabling rebind after grow.
	// Mirrors the implicit pointer relationship in C++ PcodeData.outvar/invar.
	refs []rawBuildIssuedRef
	// varnodes is the VarnodeData pool (C++ poolstart..endpool).
	// len(varnodes) corresponds to curpool - poolstart.
	varnodes []pcode.VarnodeData
	// labelRefs mirrors PcodeCacher::label_refs (list<RelativeRecord>).
	// Each entry stores a pool index + the issued-op index at the time of
	// addLabelRef, matching RelativeRecord.calling_index = issued.size().
	labelRefs []rawBuildRelativeRef
	// labels mirrors PcodeCacher::labels (vector<uintb>).
	// Undefined entries use rawBuildLabelUnset (C++ uses 0xbadbeef).
	labels []uint64
	// resolveDone mirrors the one-instruction tail discipline in sleigh.cc:
	// resolveRelatives() is a distinct phase from emit(), and repeating
	// resolve without new staged ops is a no-op.
	resolveDone bool
}

// rawBuildIssuedRef tracks varnode-pool ownership for one issued op.
// It lets pool relocation rebind input/output views without pointer scans.
type rawBuildIssuedRef struct {
	inputStart int
	inputCount int
	hasOutput  bool
	outputSlot int
}

// rawBuildRelativeRef mirrors sleigh.cc RelativeRecord with direct varnode-pool
// ownership rather than external pointer scans.
type rawBuildRelativeRef struct {
	varnodeSlot  int
	callingIndex uint64
}

const rawBuildLabelUnset = ^uint64(0)

// defaultVarnodePoolSize mirrors the initial pool allocation in
// PcodeCacher::PcodeCacher() (sleigh.cc): "uint4 maxsize = 600".
// Starting with the same capacity avoids early reallocations for
// typical instruction builds.
const defaultVarnodePoolSize = 600

// NewDisassemblyCache creates an empty parser-context cache.
func NewDisassemblyCache() *DisassemblyCache {
	cache := &DisassemblyCache{
		contexts: make(map[address.Address]*ParserContext),
		rawOps:   make(map[address.Address][]pcode.RawOp),
	}
	cache.initializeParserReuse(defaultParserContextReuse, defaultParserContextWindow)
	return cache
}

const (
	defaultParserContextReuse  = 8
	defaultParserContextWindow = 256
)

func (c *DisassemblyCache) initializeParserReuse(reuse int, window int) {
	c.mu.Lock()
	c.initializeParserReuseLocked(reuse, window)
	c.mu.Unlock()
}

func (c *DisassemblyCache) initializeParserReuseLocked(reuse int, window int) {
	if reuse < 1 {
		reuse = 1
	}
	if window < 1 {
		window = 1
	}
	// C++ cache uses power-of-two windows and masks offsets by (window-1).
	window = roundUpPow2(window)
	c.parserList = make([]*ParserContext, reuse)
	c.parserHash = make([]*ParserContext, window)
	c.parserMask = uint64(window - 1)
	c.parserNext = 0
}

func roundUpPow2(v int) int {
	if v <= 1 {
		return 1
	}
	n := 1
	for n < v {
		n <<= 1
	}
	return n
}

// SetParserContext stores a parser context for an address.
func (c *DisassemblyCache) SetParserContext(addr address.Address, ctx *ParserContext) error {
	if c == nil {
		return fmt.Errorf("disassembly cache is nil")
	}
	if ctx == nil {
		return fmt.Errorf("parser context is nil")
	}
	c.mu.Lock()
	c.contexts[addr] = ctx
	c.mu.Unlock()
	return nil
}

// GetParserContext returns the cached parser context for an address.
func (c *DisassemblyCache) GetParserContext(addr address.Address) (*ParserContext, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	ctx, ok := c.contexts[addr]
	if !ok {
		ctx, ok = c.parserContextFromHashLocked(addr)
	}
	c.mu.RUnlock()
	return ctx, ok
}

// DeleteParserContext removes a parser context from the cache.
func (c *DisassemblyCache) DeleteParserContext(addr address.Address) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	_, okMap := c.contexts[addr]
	if okMap {
		delete(c.contexts, addr)
	}
	okHash := c.deleteParserContextFromHashLocked(addr)
	c.mu.Unlock()
	return okMap || okHash
}

// HasParserContext reports whether an address has a cached parser context.
func (c *DisassemblyCache) HasParserContext(addr address.Address) bool {
	_, ok := c.GetParserContext(addr)
	return ok
}

// ObtainParserContext mirrors DisassemblyCache::getParserContext in sleigh.cc.
// Same-address hash hits reuse the existing context. Misses recycle one slot from
// the circular parser list, set address, and reset parser state to uninitialized.
func (c *DisassemblyCache) ObtainParserContext(addr address.Address, constSpace *address.Space) (*ParserContext, error) {
	if c == nil {
		return nil, fmt.Errorf("disassembly cache is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if ctx, ok := c.contexts[addr]; ok && ctx != nil {
		if ctx.GetConstSpace() == nil && constSpace != nil {
			ctx.Initialize(constSpace)
		}
		return ctx, nil
	}

	if len(c.parserList) == 0 || len(c.parserHash) == 0 {
		c.initializeParserReuseLocked(defaultParserContextReuse, defaultParserContextWindow)
	}
	if hit, ok := c.parserContextFromHashLocked(addr); ok && hit != nil {
		if hit.GetConstSpace() == nil && constSpace != nil {
			hit.Initialize(constSpace)
		}
		return hit, nil
	}

	slot := c.parserNext
	c.parserNext++
	if c.parserNext >= len(c.parserList) {
		c.parserNext = 0
	}
	ctx := c.parserList[slot]
	if ctx == nil {
		ctx = NewParserContext(addr, constSpace)
		c.parserList[slot] = ctx
	} else {
		ctx.SetAddr(addr)
		// Mirrors ParserContext::setAddr() in context.hh clearing cached n2addr.
		ctx.SetN2addr(address.Address{})
		ctx.SetParserState(ParseStateUninitialized)
		if ctx.GetConstSpace() == nil && constSpace != nil {
			ctx.Initialize(constSpace)
		}
	}
	c.parserHash[c.hashIndexLocked(addr)] = ctx
	return ctx, nil
}

func (c *DisassemblyCache) hashIndexLocked(addr address.Address) uint64 {
	if len(c.parserHash) == 0 {
		return 0
	}
	return addr.Offset & c.parserMask
}

func (c *DisassemblyCache) parserContextFromHashLocked(addr address.Address) (*ParserContext, bool) {
	if len(c.parserHash) == 0 {
		return nil, false
	}
	index := c.hashIndexLocked(addr)
	candidate := c.parserHash[index]
	if candidate == nil {
		return nil, false
	}
	if candidate.GetAddr() != addr {
		return nil, false
	}
	return candidate, true
}

func (c *DisassemblyCache) deleteParserContextFromHashLocked(addr address.Address) bool {
	if len(c.parserHash) == 0 {
		return false
	}
	index := c.hashIndexLocked(addr)
	candidate := c.parserHash[index]
	if candidate == nil || candidate.GetAddr() != addr {
		return false
	}
	c.parserHash[index] = nil
	return true
}

// SetParserState updates the parse state of a cached parser context.
func (c *DisassemblyCache) SetParserState(addr address.Address, state ParseState) error {
	ctx, ok := c.GetParserContext(addr)
	if !ok {
		return fmt.Errorf("parser context for %v not found", addr)
	}
	ctx.SetParserState(state)
	return nil
}

// GetPcodeParserContext returns the cached parser context only when it is in pcode state.
func (c *DisassemblyCache) GetPcodeParserContext(addr address.Address) (*ParserContext, bool) {
	ctx, ok := c.GetParserContext(addr)
	if !ok || ctx == nil || ctx.GetParserState() != ParseStatePcode {
		return nil, false
	}
	return ctx, true
}

// HasPcodeParserContext reports whether an address has a cached parser context in pcode state.
func (c *DisassemblyCache) HasPcodeParserContext(addr address.Address) bool {
	_, ok := c.GetPcodeParserContext(addr)
	return ok
}

// RequirePcodeParserContext returns a cached pcode parser context or an error.
func (c *DisassemblyCache) RequirePcodeParserContext(addr address.Address) (*ParserContext, error) {
	ctx, ok := c.GetPcodeParserContext(addr)
	if !ok {
		return nil, fmt.Errorf("pcode parser context for %v not found", addr)
	}
	return ctx, nil
}

// SetRawOps stores emitted raw p-code ops for an instruction address.
func (c *DisassemblyCache) SetRawOps(addr address.Address, ops []pcode.RawOp) error {
	if c == nil {
		return fmt.Errorf("disassembly cache is nil")
	}
	copied := cloneRawOps(ops)
	c.mu.Lock()
	c.rawOps[addr] = copied
	c.mu.Unlock()
	return nil
}

// GetRawOps returns emitted raw p-code ops for an instruction address.
func (c *DisassemblyCache) GetRawOps(addr address.Address) ([]pcode.RawOp, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	ops, ok := c.rawOps[addr]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return cloneRawOps(ops), true
}

// DeleteRawOps removes raw p-code ops for an instruction address.
func (c *DisassemblyCache) DeleteRawOps(addr address.Address) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	_, ok := c.rawOps[addr]
	if ok {
		delete(c.rawOps, addr)
	}
	c.mu.Unlock()
	return ok
}

// BeginRawBuild resets cache-backed raw-op ownership for one instruction address.
func (c *DisassemblyCache) BeginRawBuild(addr address.Address, capacity int) error {
	if c == nil {
		return fmt.Errorf("disassembly cache is nil")
	}
	if err := addr.Validate(); err != nil {
		return fmt.Errorf("raw build address: %w", err)
	}
	if capacity < 0 {
		capacity = 0
	}
	c.mu.Lock()
	if c.rawBuild == nil {
		c.rawBuild = newRawBuildState(capacity)
	} else {
		c.rawBuild.reset(capacity)
	}
	c.activateRawBuildLocked(addr, c.rawBuild)
	delete(c.rawOps, addr)
	c.mu.Unlock()
	return nil
}

// RawBuildLength reports the current issued-op count for a staged raw build.
func (c *DisassemblyCache) RawBuildLength(addr address.Address) (uint64, error) {
	if c == nil {
		return 0, fmt.Errorf("disassembly cache is nil")
	}
	c.mu.RLock()
	state, err := c.rawBuildStateLocked(addr)
	c.mu.RUnlock()
	if err != nil {
		return 0, err
	}
	return uint64(len(state.issued)), nil
}

// AppendRawBuild appends lowered ops and tracks relative label references.
func (c *DisassemblyCache) AppendRawBuild(addr address.Address, source OpTplBoundary, lowered []pcode.RawOp, labelBase uint64) error {
	if c == nil {
		return fmt.Errorf("disassembly cache is nil")
	}
	labelRefID := uint64(0)
	hasRelative := len(source.Inputs) > 0 && source.Inputs[0].Offset.Kind == ConstKindRelative
	if hasRelative {
		if len(lowered) == 0 {
			return fmt.Errorf("relative branch opcode %q lowered to no raw ops", source.Opcode)
		}
		if len(lowered[0].Inputs) == 0 {
			return fmt.Errorf("relative branch opcode %q lowered without first input", source.Opcode)
		}
		var err error
		labelRefID, err = addLabelBase(source.Inputs[0].Offset.Value, labelBase)
		if err != nil {
			return err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.rawBuildStateLocked(addr)
	if err != nil {
		return err
	}
	firstOpIndex := len(state.issued)
	for i := range lowered {
		if err := state.appendIssued(lowered[i]); err != nil {
			return err
		}
	}
	state.markUnresolved()
	if hasRelative {
		if firstOpIndex < 0 || firstOpIndex >= len(state.refs) {
			return fmt.Errorf("relative branch first op index %d out of range", firstOpIndex)
		}
		firstRef := state.refs[firstOpIndex]
		if firstRef.inputCount <= 0 {
			return fmt.Errorf("relative branch first op %d has no input varnodes", firstOpIndex)
		}
		slot := firstRef.inputStart
		if slot < 0 || slot >= len(state.varnodes) {
			return fmt.Errorf("relative branch first input slot %d out of range", slot)
		}
		if err := state.addLabelRef(slot, uint64(firstOpIndex)); err != nil {
			return err
		}
		state.varnodes[slot].Offset = labelRefID
	}
	return nil
}

// AddRawBuildLabel records an absolute label at the next issued-op slot.
func (c *DisassemblyCache) AddRawBuildLabel(addr address.Address, labelID uint64) error {
	if c == nil {
		return fmt.Errorf("disassembly cache is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.rawBuildStateLocked(addr)
	if err != nil {
		return err
	}
	if err := state.addLabel(labelID, uint64(len(state.issued))); err != nil {
		return err
	}
	state.markUnresolved()
	return nil
}

// ResolveRawBuild resolves staged relative branches in place.
// Mirrors PcodeCacher::resolveRelatives().
func (c *DisassemblyCache) ResolveRawBuild(addr address.Address) error {
	if c == nil {
		return fmt.Errorf("disassembly cache is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.rawBuildStateLocked(addr)
	if err != nil {
		return err
	}
	return c.resolveRawBuildLocked(addr, state)
}

// EmitRawBuildTo emits staged raw ops to a sink in issued order, then commits
// immutable cache-owned copies and closes staging.
// Mirrors PcodeCacher::emit(addr, PcodeEmit*).
func (c *DisassemblyCache) EmitRawBuildTo(addr address.Address, emitter pcode.RawEmitter) error {
	if c == nil {
		return fmt.Errorf("disassembly cache is nil")
	}
	if emitter == nil {
		return fmt.Errorf("raw emitter is nil")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.rawBuildStateLocked(addr)
	if err != nil {
		return err
	}
	return c.emitRawBuildToLocked(addr, state, emitter)
}

// CancelRawBuild drops staged state without committing raw ops.
func (c *DisassemblyCache) CancelRawBuild(addr address.Address) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	state, err := c.rawBuildStateLocked(addr)
	ok := err == nil
	if ok {
		c.deactivateRawBuildLocked(state)
	}
	c.mu.Unlock()
	return ok
}

func addLabelBase(labelID uint64, labelBase uint64) (uint64, error) {
	if ^uint64(0)-labelBase < labelID {
		return 0, fmt.Errorf("relative label id %d with base %d overflows uint64", labelID, labelBase)
	}
	return labelBase + labelID, nil
}

func (c *DisassemblyCache) rawBuildStateLocked(addr address.Address) (*rawBuildState, error) {
	if !c.rawBuildActive || c.rawBuild == nil || c.rawBuildAddr != addr {
		return nil, fmt.Errorf("raw build for %v not found", addr)
	}
	return c.rawBuild, nil
}

func (c *DisassemblyCache) committedRawOpsLocked(addr address.Address) ([]pcode.RawOp, error) {
	ops, ok := c.rawOps[addr]
	if !ok {
		return nil, fmt.Errorf("raw ops for %v not found", addr)
	}
	return cloneRawOps(ops), nil
}

func (c *DisassemblyCache) resolveRawBuildLocked(addr address.Address, state *rawBuildState) error {
	if state.resolveDone {
		return nil
	}
	if err := state.resolveRelatives(); err != nil {
		return fmt.Errorf("resolve raw build for %v: %w", addr, err)
	}
	state.resolveDone = true
	return nil
}

func (c *DisassemblyCache) emitRawBuildToLocked(addr address.Address, state *rawBuildState, emitter pcode.RawEmitter) error {
	if emitter == nil {
		return fmt.Errorf("raw emitter is nil")
	}
	// Mirrors oneInstruction() tail discipline in sleigh.cc:
	// resolveRelatives() must run before emit().
	if !state.resolveDone {
		return fmt.Errorf("%w: %v", ErrRawBuildUnresolved, addr)
	}
	// Mirror PcodeCacher::emit() sink routing while isolating staged ownership.
	//
	// C++ PcodeCacher::emit() passes raw pointers from the issued deque directly
	// to PcodeEmit::dump() without cloning -- the emitter borrows the data and
	// the cache clear()s afterwards. Go emits cloned copies so the sink cannot
	// mutate retryable staging state; this is a deliberate Go adaptation.
	//
	// C++ PcodeEmit::dump() is infallible (void return). Go sink may fail
	// explicitly; staged ownership is preserved on failure so callers can
	// retry or cancel -- another deliberate deviation from the C++ model.
	for i := range state.issued {
		if err := emitter.EmitRaw(cloneRawOp(state.issued[i])); err != nil {
			return fmt.Errorf("raw emitter failed at op %d for %v: %w", i, addr, err)
		}
	}
	// Commit an independent cache-owned snapshot after successful sink emission.
	committed := cloneRawOps(state.issued)
	c.rawOps[addr] = committed
	c.deactivateRawBuildLocked(state)
	return nil
}

func (c *DisassemblyCache) deactivateRawBuildLocked(state *rawBuildState) {
	if state != nil {
		// Mirrors PcodeCacher::clear() semantics after a staging lifecycle closes.
		state.reset(0)
	}
	c.rawBuildActive = false
	c.rawBuildAddr = address.Address{}
}

func (c *DisassemblyCache) activateRawBuildLocked(addr address.Address, state *rawBuildState) {
	c.rawBuild = state
	c.rawBuildAddr = addr
	c.rawBuildActive = true
}

func newRawBuildState(capacity int) *rawBuildState {
	state := &rawBuildState{}
	state.reset(capacity)
	return state
}

// reset mirrors PcodeCacher::clear() -- resets issued/labels/labelRefs cursors
// while keeping pool allocation so the backing arrays are reused across
// instruction lifecycles (C++ resets curpool to poolstart but never frees).
func (s *rawBuildState) reset(capacity int) {
	if s == nil {
		return
	}
	if capacity < 0 {
		capacity = 0
	}
	if cap(s.issued) < capacity {
		s.issued = make([]pcode.RawOp, 0, capacity)
	} else {
		s.issued = s.issued[:0]
	}
	if cap(s.refs) < capacity {
		s.refs = make([]rawBuildIssuedRef, 0, capacity)
	} else {
		s.refs = s.refs[:0]
	}
	if cap(s.labelRefs) < capacity {
		s.labelRefs = make([]rawBuildRelativeRef, 0, capacity)
	} else {
		s.labelRefs = s.labelRefs[:0]
	}
	if cap(s.labels) < capacity {
		s.labels = make([]uint64, 0, capacity)
	} else {
		s.labels = s.labels[:0]
	}
	// Mirror PcodeCacher pool: initial capacity is defaultVarnodePoolSize (600)
	// matching the C++ constructor. On subsequent resets the existing (possibly
	// grown) capacity is retained, just like C++ clear() keeps the pool.
	varnodeCapacity := capacity * 3
	if varnodeCapacity < defaultVarnodePoolSize {
		varnodeCapacity = defaultVarnodePoolSize
	}
	if cap(s.varnodes) < varnodeCapacity {
		s.varnodes = make([]pcode.VarnodeData, 0, varnodeCapacity)
	} else {
		s.varnodes = s.varnodes[:0]
	}
	s.resolveDone = false
}

func (s *rawBuildState) markUnresolved() {
	if s == nil {
		return
	}
	s.resolveDone = false
}

// allocateInstruction mirrors PcodeCacher::allocateInstruction() -- appends
// an empty PcodeData to the issued deque and returns its index.
// The caller is responsible for filling in OpCode, Inputs, Output via
// pool-allocated varnodes. This method exists for future dump() parity;
// the current AppendRawBuild path uses appendIssued which combines
// allocation and data copy in a single step.
func (s *rawBuildState) allocateInstruction() int {
	idx := len(s.issued)
	s.issued = append(s.issued, pcode.RawOp{})
	s.refs = append(s.refs, rawBuildIssuedRef{})
	return idx
}

// appendIssued is the combined allocate-and-copy path used by AppendRawBuild.
// It allocates pool varnodes for all inputs + optional output, copies the data,
// and wires the issued RawOp's slices into the pool.
// Mirrors the sequence: allocateVarnodes() -> fill data -> allocateInstruction()
// -> set outvar/invar from the C++ SleighBuilder::dump() flow.
func (s *rawBuildState) appendIssued(op pcode.RawOp) error {
	inputCount := len(op.Inputs)
	total := inputCount
	if op.Output != nil {
		total++
	}

	start, err := s.allocateVarnodes(total)
	if err != nil {
		return err
	}
	if inputCount > 0 {
		copy(s.varnodes[start:start+inputCount], op.Inputs)
	}
	ref := rawBuildIssuedRef{
		inputStart: start,
		inputCount: inputCount,
	}
	issued := pcode.RawOp{
		SeqNum: op.SeqNum,
		OpCode: op.OpCode,
	}
	if inputCount > 0 {
		issued.Inputs = s.varnodes[start : start+inputCount]
	}
	if op.Output != nil {
		outputSlot := start + inputCount
		s.varnodes[outputSlot] = *op.Output
		issued.Output = &s.varnodes[outputSlot]
		ref.hasOutput = true
		ref.outputSlot = outputSlot
	}
	s.issued = append(s.issued, issued)
	s.refs = append(s.refs, ref)
	return nil
}

// allocateVarnodes mirrors PcodeCacher::allocateVarnodes(uint4 size).
// It bump-allocates count entries from the pool and returns the start index.
// If the pool is too small, ensureVarnodeCapacity grows it (like expandPool).
func (s *rawBuildState) allocateVarnodes(count int) (int, error) {
	if count < 0 {
		return 0, fmt.Errorf("raw build varnode allocation count %d is negative", count)
	}
	start := len(s.varnodes)
	if count == 0 {
		return start, nil
	}
	if err := s.ensureVarnodeCapacity(count); err != nil {
		return 0, err
	}
	s.varnodes = s.varnodes[:start+count]
	return start, nil
}

// ensureVarnodeCapacity mirrors PcodeCacher::expandPool(uint4 size).
// Grows the pool if needed, copies old data, and rebinds all issued op
// slice headers to the new backing array (same as C++ expandPool rebinding
// outvar/invar pointers and label_refs.dataptr).
func (s *rawBuildState) ensureVarnodeCapacity(extra int) error {
	if extra <= 0 {
		return nil
	}
	need := len(s.varnodes) + extra
	if need <= cap(s.varnodes) {
		return nil
	}
	curCap := cap(s.varnodes)
	increase := need - curCap
	// Mirrors sleigh.cc PcodeCacher::expandPool(): grow by request, with a floor.
	if increase < 100 {
		increase = 100
	}
	newCap := curCap + increase
	if newCap < need {
		newCap = need
	}
	oldPool := s.varnodes
	newPool := make([]pcode.VarnodeData, len(oldPool), newCap)
	copy(newPool, oldPool)
	s.varnodes = newPool
	return s.rebindIssuedAfterExpand(oldPool)
}

func (s *rawBuildState) rebindIssuedAfterExpand(oldPool []pcode.VarnodeData) error {
	if len(oldPool) == 0 || len(s.issued) == 0 {
		return nil
	}
	if len(s.refs) != len(s.issued) {
		return fmt.Errorf("raw build issued/reference shape mismatch: issued=%d refs=%d", len(s.issued), len(s.refs))
	}
	for i := range s.issued {
		ref := s.refs[i]
		if ref.inputCount > 0 {
			end := ref.inputStart + ref.inputCount
			if ref.inputStart < 0 || end < ref.inputStart || end > len(s.varnodes) {
				return fmt.Errorf("raw build input range for op %d escaped varnode pool", i)
			}
			s.issued[i].Inputs = s.varnodes[ref.inputStart:end]
		}
		if ref.hasOutput {
			if ref.outputSlot < 0 || ref.outputSlot >= len(s.varnodes) {
				return fmt.Errorf("raw build output slot for op %d escaped varnode pool", i)
			}
			s.issued[i].Output = &s.varnodes[ref.outputSlot]
		} else {
			s.issued[i].Output = nil
		}
	}
	return nil
}

func (s *rawBuildState) addLabel(labelID uint64, opIndex uint64) error {
	maxInt := int(^uint(0) >> 1)
	if labelID > uint64(maxInt) {
		return fmt.Errorf("relative label id %d does not fit host index range", labelID)
	}
	for len(s.labels) <= int(labelID) {
		s.labels = append(s.labels, rawBuildLabelUnset)
	}
	s.labels[int(labelID)] = opIndex
	return nil
}

func (s *rawBuildState) addLabelRef(varnodeSlot int, callingIndex uint64) error {
	if varnodeSlot < 0 || varnodeSlot >= len(s.varnodes) {
		return fmt.Errorf("relative label varnode slot %d out of range", varnodeSlot)
	}
	s.labelRefs = append(s.labelRefs, rawBuildRelativeRef{
		varnodeSlot:  varnodeSlot,
		callingIndex: callingIndex,
	})
	return nil
}

// resolveRelatives mirrors PcodeCacher::resolveRelatives() (sleigh.cc).
// For each label reference, computes (labels[id] - calling_index) & mask
// and patches the varnode offset in place. The mask comes from labelMask
// which matches C++ calc_mask(ptr->size).
func (s *rawBuildState) resolveRelatives() error {
	for _, ref := range s.labelRefs {
		if ref.varnodeSlot < 0 || ref.varnodeSlot >= len(s.varnodes) {
			return fmt.Errorf("relative label varnode slot %d out of range", ref.varnodeSlot)
		}
		ptr := &s.varnodes[ref.varnodeSlot]
		id := ptr.Offset
		if id > uint64(int(^uint(0)>>1)) {
			return fmt.Errorf("relative label id %d out of host index range", id)
		}
		if int(id) >= len(s.labels) || s.labels[int(id)] == rawBuildLabelUnset {
			// Mirrors sleigh.cc PcodeCacher::resolveRelatives():
			// "Reference to non-existant sleigh label"
			return fmt.Errorf("relative label id %d: reference to non-existant sleigh label", id)
		}
		mask, err := labelMask(ptr.Size)
		if err != nil {
			return err
		}
		target := s.labels[int(id)]
		ptr.Offset = (target - ref.callingIndex) & mask
	}
	return nil
}

func cloneRawOp(op pcode.RawOp) pcode.RawOp {
	out := op
	if len(op.Inputs) != 0 {
		out.Inputs = make([]pcode.VarnodeData, len(op.Inputs))
		copy(out.Inputs, op.Inputs)
	}
	if op.Output != nil {
		vn := *op.Output
		out.Output = &vn
	}
	return out
}

func cloneRawOps(ops []pcode.RawOp) []pcode.RawOp {
	if len(ops) == 0 {
		return nil
	}
	out := make([]pcode.RawOp, len(ops))
	for i := range ops {
		out[i] = cloneRawOp(ops[i])
	}
	return out
}
