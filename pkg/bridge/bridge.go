package bridge

import (
	"errors"
	"fmt"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
	"gosleigh/pkg/sla"
)

type BuildConfig struct {
	Name            string
	Entry           address.Address
	End             address.Address
	MaxInstructions int
	// CspecPath is the optional path to a .cspec calling convention file.
	// When non-empty, the cspec is parsed and stored in Result.CspecData.
	CspecPath string
	// SymbolName overrides the display name on the resulting Funcdata when
	// non-empty. This allows callers to wire in a recovered symbol name
	// (e.g. from DWARF or a PE import table) without changing the internal
	// name used for address resolution.
	SymbolName string
}

type Result struct {
	Funcdata       *pcode.Funcdata
	Graph          *pcode.BlockGraph
	Instructions   []sla.InstructionTranslation
	HeritageSpaces []*address.Space
	Warnings       []string
	// CspecData is set when BuildConfig.CspecPath is non-empty.
	CspecData *pcode.CspecData
}

type instructionRecord struct {
	translation sla.InstructionTranslation
	flow        instructionFlow
}

type instructionFlow struct {
	directTarget    address.Address
	fallthroughAddr address.Address
	hasDirect       bool
	hasFallthrough  bool
	terminates      bool
	conditional     bool
}

type varKey struct {
	space  *address.Space
	offset uint64
	size   uint32
}

type edgeKey struct {
	from *pcode.BlockBasic
	to   *pcode.BlockBasic
}

type spaceSummary struct {
	constSpace     *address.Space
	uniqueSpace    *address.Space
	uniqueBase     uint64
	heritageSpaces []*address.Space
}

func Build(engine *sla.Engine, cfg BuildConfig) (*Result, error) {
	if engine == nil {
		return nil, fmt.Errorf("build bridge: engine is nil")
	}
	if err := cfg.Entry.Validate(); err != nil {
		return nil, fmt.Errorf("build bridge: entry address: %w", err)
	}
	if cfg.End.IsInvalid() && cfg.MaxInstructions <= 0 {
		return nil, fmt.Errorf("build bridge: end address or max instructions is required")
	}

	records, warnings, err := collectInstructions(engine, cfg)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		if len(warnings) > 0 {
			return &Result{Warnings: warnings}, nil
		}
		return nil, fmt.Errorf("build bridge: no instructions translated")
	}

	summary := summarizeSpaces(records, cfg.Entry.Space)
	fd := pcode.NewFuncdata(resolveName(cfg.Name), cfg.Entry, summary.uniqueSpace, summary.uniqueBase, summary.constSpace)
	graph := pcode.NewBlockGraph()

	starts := discoverBlockStarts(records)
	blockByAddr := make(map[address.Address]*pcode.BlockBasic, len(starts))
	instToBlock := make(map[address.Address]*pcode.BlockBasic, len(records))
	lastInBlock := make(map[*pcode.BlockBasic]instructionRecord, len(starts))
	currentDefs := make(map[varKey]*pcode.Varnode)

	var current *pcode.BlockBasic
	for idx, record := range records {
		addr := record.translation.Address
		if starts[addr] {
			current = graph.NewBlockBasicInGraph()
			blockByAddr[addr] = current
			if idx == 0 {
				current.SetFlag(pcode.BlockFlagEntryPoint)
			}
		}
		if current == nil {
			return nil, fmt.Errorf("build bridge: missing basic block for instruction %v", addr)
		}
		instToBlock[addr] = current
		lastInBlock[current] = record

		if err := addInstructionOps(fd, current, record.translation, currentDefs); err != nil {
			return nil, err
		}
	}

	addCFGEdges(graph, blockByAddr, instToBlock, lastInBlock)
	graph.FindSpanningTree()
	assignUnreachableIndices(graph)
	graph.CalcForwardDominator()
	fd.SetBasicBlocks(graph)
	fd.SetFlag(pcode.FuncBlocksGenerated)

	translations := make([]sla.InstructionTranslation, len(records))
	for i := range records {
		translations[i] = records[i].translation
	}

	result := &Result{
		Funcdata:       fd,
		Graph:          graph,
		Instructions:   translations,
		HeritageSpaces: summary.heritageSpaces,
		Warnings:       warnings,
	}

	// Wire recovered symbol name onto Funcdata when provided.
	// This sets the display name used by PrintC for the function declaration.
	if cfg.SymbolName != "" {
		fd.SetDisplayName(cfg.SymbolName)
	}

	// Parse cspec if provided. Store in result but do not apply -- callers
	// may apply after Heritage via pcode.ApplyCallingConvention.
	if cfg.CspecPath != "" {
		cs, csErr := pcode.ParseCspec(cfg.CspecPath)
		if csErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("cspec parse %q: %v", cfg.CspecPath, csErr))
		} else {
			result.CspecData = cs
		}
	}

	return result, nil
}

func BuildFuncdata(engine *sla.Engine, cfg BuildConfig) (*pcode.Funcdata, error) {
	result, err := Build(engine, cfg)
	if err != nil {
		return nil, err
	}
	return result.Funcdata, nil
}

func collectInstructions(engine *sla.Engine, cfg BuildConfig) ([]instructionRecord, []string, error) {
	limit := cfg.MaxInstructions
	if limit <= 0 {
		limit = int(^uint(0) >> 1)
	}

	known := make(map[address.Address]int)
	records := make([]instructionRecord, 0, min(limit, 16))

	// pending holds addresses yet to be scanned. We use a worklist so that
	// branch targets reachable only via a forward/unconditional branch are also
	// collected. The entry point is always the first item.
	//
	// C++ ref: FlowInfo::generate / FlowInfo::setRange in FlowInfo.cc collects
	// all reachable addresses by following branch targets recursively.
	pending := []address.Address{cfg.Entry}
	pendingSeen := map[address.Address]struct{}{cfg.Entry: {}}

	for len(pending) > 0 && len(records) < limit {
		cur := pending[0]
		pending = pending[1:]

		// Linear scan from cur until a hard terminator, range boundary, or limit.
		for len(records) < limit {
			if !cfg.End.IsInvalid() {
				if !sameSpace(cur, cfg.End) {
					return nil, nil, fmt.Errorf("build bridge: end address %v is not in entry space %v", cfg.End, cfg.Entry.Space)
				}
				if !cur.Less(cfg.End) {
					break
				}
			}
			if _, exists := known[cur]; exists {
				// Already collected via another path; stop this linear scan.
				break
			}

			translation, err := engine.TranslateInstructionAt(cur)
			if err != nil {
				var unimplErr *sla.UnimplError
				if errors.As(err, &unimplErr) {
					warn := fmt.Sprintf("unimplemented at %v: %v", cur, err)
					return records, []string{warn}, nil
				}
				return nil, nil, fmt.Errorf("build bridge: translate instruction at %v: %w", cur, err)
			}
			if len(translation.Ops) == 0 {
				return nil, nil, fmt.Errorf("build bridge: instruction %v has no raw ops", cur)
			}
			if translation.Length <= 0 && translation.Next == cur {
				return nil, nil, fmt.Errorf("build bridge: instruction %v did not advance", cur)
			}

			records = append(records, instructionRecord{translation: translation})
			known[cur] = len(records) - 1

			if translation.Next == cur {
				break
			}

			// Enqueue any direct branch target for later worklist processing.
			// We enqueue now (before building knownAddrs) so that the target is
			// added even when this linear scan terminates early.
			if cfg.End.IsInvalid() {
				if target, ok := extractBranchTarget(translation, cfg.Entry.Space); ok {
					if _, seen := pendingSeen[target]; !seen {
						pendingSeen[target] = struct{}{}
						pending = append(pending, target)
					}
				}
			}

			// When no explicit End address is given, stop linear scan on an unconditional terminator
			// (RETURN, BRANCHIND, or BRANCH). Without this guard the scanner follows translation.Next
			// past the end of the function into uninitialised bytes, collecting garbage instructions
			// and corrupting the knownAddrs set used by resolveTarget.
			//
			// When End is set the caller defines the exact byte range to collect (e.g. bridge_test.go
			// BRK_BRK), so we honour the range boundary instead and let the loop continue.
			//
			// CBRANCH is excluded: its fall-through edge always points to the next sequential address,
			// so we must continue collecting that instruction.
			//
			// C++ ref: FlowInfo::setRange / FlowInfo::hasTerminator in FlowInfo.cc.
			if cfg.End.IsInvalid() && hasHardTerminator(translation) {
				break
			}
			cur = translation.Next
		}
	}

	if len(records) == 0 {
		return nil, nil, nil
	}

	knownAddrs := make(map[address.Address]struct{}, len(records))
	for _, record := range records {
		knownAddrs[record.translation.Address] = struct{}{}
	}
	for idx := range records {
		records[idx].flow = analyzeInstructionFlow(records[idx].translation, cfg.Entry.Space, knownAddrs)
	}

	return records, nil, nil
}

// extractBranchTarget returns the branch target address embedded in a BRANCH or
// CBRANCH op, if one exists. Used by the worklist to enqueue unreachable-by-
// linear-scan targets before knownAddrs is built.
func extractBranchTarget(translation sla.InstructionTranslation, entrySpace *address.Space) (address.Address, bool) {
	for _, raw := range translation.Ops {
		switch raw.OpCode {
		case pcode.CPUI_BRANCH, pcode.CPUI_CBRANCH:
			if len(raw.Inputs) == 0 {
				continue
			}
			input := raw.Inputs[0]
			if input.Space == nil {
				continue
			}
			if input.Space.Kind != address.SpaceKindConstant {
				return input.Address(), true
			}
			// Constant-space operand: interpret as relative offset from Next.
			if target, ok := addSignedOffset(translation.Next, int64(int8(input.Offset))); ok {
				return target, true
			}
			if entrySpace != nil {
				return address.Address{Space: entrySpace, Offset: input.Offset}, true
			}
		}
	}
	return address.Address{}, false
}

func summarizeSpaces(records []instructionRecord, entrySpace *address.Space) spaceSummary {
	summary := spaceSummary{
		constSpace:  defaultConstSpace(),
		uniqueSpace: defaultUniqueSpace(entrySpace),
	}
	heritageSet := make(map[*address.Space]struct{})

	for _, record := range records {
		for _, op := range record.translation.Ops {
			for _, input := range op.Inputs {
				summary.observe(&input)
				summary.collectHeritageSpace(input.Space, entrySpace, heritageSet)
			}
			if op.Output != nil {
				summary.observe(op.Output)
				summary.collectHeritageSpace(op.Output.Space, entrySpace, heritageSet)
			}
		}
	}
	return summary
}

func (s *spaceSummary) observe(vn *pcode.VarnodeData) {
	if vn == nil || vn.Space == nil {
		return
	}
	switch vn.Space.Kind {
	case address.SpaceKindConstant:
		s.constSpace = vn.Space
	case address.SpaceKindUnique:
		s.uniqueSpace = vn.Space
		end := vn.Offset + uint64(vn.Size)
		if end > s.uniqueBase {
			s.uniqueBase = end
		}
	}
}

func (s *spaceSummary) collectHeritageSpace(space *address.Space, entrySpace *address.Space, seen map[*address.Space]struct{}) {
	if space == nil || space == entrySpace {
		return
	}
	switch space.Kind {
	case address.SpaceKindConstant, address.SpaceKindUnique:
		return
	}
	if _, exists := seen[space]; exists {
		return
	}
	seen[space] = struct{}{}
	s.heritageSpaces = append(s.heritageSpaces, space)
}

func discoverBlockStarts(records []instructionRecord) map[address.Address]bool {
	starts := make(map[address.Address]bool, len(records))
	if len(records) == 0 {
		return starts
	}
	starts[records[0].translation.Address] = true

	known := make(map[address.Address]struct{}, len(records))
	for _, record := range records {
		known[record.translation.Address] = struct{}{}
	}

	for _, record := range records {
		if record.flow.hasDirect {
			if _, exists := known[record.flow.directTarget]; exists {
				starts[record.flow.directTarget] = true
			}
		}
		if record.flow.terminates {
			if _, exists := known[record.translation.Next]; exists {
				starts[record.translation.Next] = true
			}
		}
	}

	return starts
}

func addInstructionOps(fd *pcode.Funcdata, block *pcode.BlockBasic, translation sla.InstructionTranslation, defs map[varKey]*pcode.Varnode) error {
	if fd == nil || block == nil {
		return fmt.Errorf("build bridge: funcdata or block is nil")
	}
	for _, raw := range translation.Ops {
		op := fd.GetPcodeOpBank().CreateWithSeq(len(raw.Inputs), raw.SeqNum)
		fd.OpSetOpcode(op, raw.OpCode)
		appendAliveOp(fd, block, op)

		for slot, input := range raw.Inputs {
			vn := resolveInput(fd, input, defs)
			if shouldMaterializeConstant(raw.OpCode, slot, vn) {
				vn = materializeConstantInput(fd, block, raw.SeqNum.Address, vn)
			}
			fd.OpSetInput(op, vn, slot)
		}
		if raw.Output != nil {
			out := fd.NewVarnodeOut(int32(raw.Output.Size), raw.Output.Address(), op)
			defs[makeVarKey(*raw.Output)] = out
		}
	}
	return nil
}

func appendAliveOp(fd *pcode.Funcdata, block *pcode.BlockBasic, op *pcode.PcodeOp) {
	if fd == nil || block == nil || op == nil {
		return
	}
	if block.NumOps() == 0 {
		op.SetFlag(pcode.PcodeOpStartBasic)
	}
	op.SetParent(block)
	block.AddOp(op)
	fd.OpMarkAlive(op)
}

func resolveInput(fd *pcode.Funcdata, input pcode.VarnodeData, defs map[varKey]*pcode.Varnode) *pcode.Varnode {
	if input.Space != nil && input.Space.IsConstant() {
		return fd.NewConstant(int32(input.Size), input.Offset)
	}

	key := makeVarKey(input)
	if vn, exists := defs[key]; exists {
		return vn
	}

	vn := fd.NewVarnode(int32(input.Size), input.Address())
	// Do NOT store read varnodes in defs. If this location has not been written
	// yet (no output defined it), it is a function live-in that Heritage will
	// rename to an SSA input varnode. Storing the read would cause subsequent
	// reads of the same register to reuse the same varnode object, which breaks
	// Heritage's per-use renaming: Heritage marks the varnode active, renames
	// the first user, then clears active -- leaving other users with the old
	// pre-Heritage raw varnode.
	// C++ parity: Ghidra's SLEIGH builder creates a fresh varnode per read.
	return vn
}

func shouldMaterializeConstant(opcode pcode.OpCode, slot int, vn *pcode.Varnode) bool {
	if vn == nil || !vn.IsConstant() {
		return false
	}
	value := truncateConstantForSize(vn.Offset(), vn.Size())
	switch opcode {
	case pcode.CPUI_INT_SUB:
		return slot == 1 && value != 0 && value != 1
	case pcode.CPUI_INT_ADD:
		return value != allOnesForSize(vn.Size()) && value&signBitForSize(vn.Size()) != 0
	default:
		return false
	}
}

func materializeConstantInput(fd *pcode.Funcdata, block *pcode.BlockBasic, addr address.Address, constant *pcode.Varnode) *pcode.Varnode {
	copyOp := fd.NewOp(1, addr)
	fd.OpSetOpcode(copyOp, pcode.CPUI_COPY)
	appendAliveOp(fd, block, copyOp)
	fd.OpSetInput(copyOp, constant, 0)
	return fd.NewUniqueOut(constant.Size(), copyOp)
}

func addCFGEdges(graph *pcode.BlockGraph, blockByAddr map[address.Address]*pcode.BlockBasic, instToBlock map[address.Address]*pcode.BlockBasic, lastInBlock map[*pcode.BlockBasic]instructionRecord) {
	seen := make(map[edgeKey]struct{})
	for _, block := range blockByAddr {
		record, exists := lastInBlock[block]
		if !exists {
			continue
		}
		if record.flow.conditional {
			addEdge(graph, seen, block, instToBlock[record.flow.fallthroughAddr])
			addEdge(graph, seen, block, blockByAddr[record.flow.directTarget])
			continue
		}
		if record.flow.hasDirect {
			addEdge(graph, seen, block, blockByAddr[record.flow.directTarget])
			continue
		}
		if record.flow.hasFallthrough {
			addEdge(graph, seen, block, instToBlock[record.flow.fallthroughAddr])
		}
	}
}

func addEdge(graph *pcode.BlockGraph, seen map[edgeKey]struct{}, from *pcode.BlockBasic, to *pcode.BlockBasic) {
	if graph == nil || from == nil || to == nil {
		return
	}
	key := edgeKey{from: from, to: to}
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	graph.AddEdge(&from.FlowBlock, &to.FlowBlock, 0)
}

func assignUnreachableIndices(graph *pcode.BlockGraph) {
	if graph == nil {
		return
	}
	maxIndex := int32(-1)
	for idx := 0; idx < graph.GetSize(); idx++ {
		block := graph.GetBlock(idx)
		if block.Index() > maxIndex {
			maxIndex = block.Index()
		}
	}
	for idx := 0; idx < graph.GetSize(); idx++ {
		block := graph.GetBlock(idx)
		if block.Index() >= 0 {
			continue
		}
		maxIndex++
		block.SetIndex(maxIndex)
	}
}

func analyzeInstructionFlow(translation sla.InstructionTranslation, entrySpace *address.Space, known map[address.Address]struct{}) instructionFlow {
	flow := instructionFlow{}
	for _, raw := range translation.Ops {
		switch raw.OpCode {
		case pcode.CPUI_BRANCH:
			flow.terminates = true
			flow.hasFallthrough = false
			if target, ok := resolveTarget(translation, raw, entrySpace, known); ok {
				flow.directTarget = target
				flow.hasDirect = true
			}
		case pcode.CPUI_CBRANCH:
			flow.terminates = true
			flow.conditional = true
			flow.hasFallthrough = true
			flow.fallthroughAddr = translation.Next
			if target, ok := resolveTarget(translation, raw, entrySpace, known); ok {
				flow.directTarget = target
				flow.hasDirect = true
			}
		case pcode.CPUI_BRANCHIND, pcode.CPUI_RETURN:
			flow.terminates = true
			flow.hasFallthrough = false
		case pcode.CPUI_CALL, pcode.CPUI_CALLIND, pcode.CPUI_CALLOTHER:
			if !flow.terminates {
				flow.hasFallthrough = true
				flow.fallthroughAddr = translation.Next
			}
		}
	}

	if !flow.terminates && !flow.hasFallthrough && !translation.Next.IsInvalid() {
		flow.hasFallthrough = true
		flow.fallthroughAddr = translation.Next
	}
	return flow
}

func resolveTarget(translation sla.InstructionTranslation, raw pcode.RawOp, entrySpace *address.Space, known map[address.Address]struct{}) (address.Address, bool) {
	if len(raw.Inputs) == 0 {
		return address.Address{}, false
	}
	input := raw.Inputs[0]
	if input.Space == nil {
		return address.Address{}, false
	}
	if input.Space.Kind != address.SpaceKindConstant {
		target := input.Address()
		_, exists := known[target]
		return target, exists
	}

	candidates := make([]address.Address, 0, 5)
	if entrySpace != nil {
		candidates = append(candidates, address.Address{Space: entrySpace, Offset: input.Offset})
	}
	if translation.Address.Space != nil {
		candidates = append(candidates, address.Address{Space: translation.Address.Space, Offset: input.Offset})
	}
	if translation.Next.Space != nil {
		candidates = append(candidates, address.Address{Space: translation.Next.Space, Offset: input.Offset})
	}
	if target, ok := addSignedOffset(translation.Next, int64(int8(input.Offset))); ok {
		candidates = append(candidates, target)
	}
	if target, ok := addSignedOffset(translation.Address, int64(int8(input.Offset))); ok {
		candidates = append(candidates, target)
	}

	for _, candidate := range candidates {
		if _, exists := known[candidate]; exists {
			return candidate, true
		}
	}
	return address.Address{}, false
}

func truncateConstantForSize(value uint64, size int32) uint64 {
	if size <= 0 {
		return value
	}
	bits := uint(size) * 8
	if bits >= 64 {
		return value
	}
	return value & ((uint64(1) << bits) - 1)
}

func signBitForSize(size int32) uint64 {
	if size <= 0 {
		return 0
	}
	bits := uint(size) * 8
	if bits >= 64 {
		return uint64(1) << 63
	}
	return uint64(1) << (bits - 1)
}

func allOnesForSize(size int32) uint64 {
	if size <= 0 {
		return 0
	}
	bits := uint(size) * 8
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}

func addSignedOffset(base address.Address, delta int64) (address.Address, bool) {
	if base.Space == nil {
		return address.Address{}, false
	}
	if delta >= 0 {
		return address.Address{Space: base.Space, Offset: base.Offset + uint64(delta)}, true
	}
	magnitude := uint64(-delta)
	if magnitude > base.Offset {
		return address.Address{}, false
	}
	return address.Address{Space: base.Space, Offset: base.Offset - magnitude}, true
}

func sameSpace(left address.Address, right address.Address) bool {
	if left.Space == right.Space {
		return true
	}
	if left.Space == nil || right.Space == nil {
		return false
	}
	return left.Space.Index == right.Space.Index
}

func makeVarKey(vn pcode.VarnodeData) varKey {
	return varKey{space: vn.Space, offset: vn.Offset, size: vn.Size}
}

func defaultConstSpace() *address.Space {
	return &address.Space{
		Name:      "const",
		Kind:      address.SpaceKindConstant,
		Index:     ^uint16(0),
		AddrSize:  8,
		WordSize:  1,
		BigEndian: false,
		Physical:  false,
	}
}

func defaultUniqueSpace(entrySpace *address.Space) *address.Space {
	addrSize := uint8(8)
	if entrySpace != nil && entrySpace.AddrSize != 0 {
		addrSize = entrySpace.AddrSize
	}
	return &address.Space{
		Name:      "unique",
		Kind:      address.SpaceKindUnique,
		Index:     ^uint16(0) - 1,
		AddrSize:  addrSize,
		WordSize:  1,
		BigEndian: false,
		Physical:  false,
	}
}

func resolveName(name string) string {
	if name == "" {
		return "bridge_func"
	}
	return name
}

func min(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

// hasHardTerminator reports whether translation contains an unconditional terminating op
// (RETURN, BRANCHIND, or BRANCH). CBRANCH is excluded because its fall-through edge
// continues to the next sequential instruction, which must still be collected.
// C++ ref: FlowInfo::hasTerminator / BasicBlock successor discovery in FlowInfo.cc.
func hasHardTerminator(translation sla.InstructionTranslation) bool {
	for _, op := range translation.Ops {
		switch op.OpCode {
		case pcode.CPUI_RETURN, pcode.CPUI_BRANCHIND:
			return true
		case pcode.CPUI_BRANCH:
			// Unconditional branch: no fall-through.
			return true
		}
	}
	return false
}
