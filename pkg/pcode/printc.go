package pcode

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"gosleigh/pkg/address"
)

const (
	cPrecLowest     = ExprPrecLowest
	cPrecAssign     = ExprPrecAssign
	cPrecLogicalOr  = ExprPrecLogicalOr
	cPrecLogicalAnd = ExprPrecLogicalAnd
	cPrecBitOr      = ExprPrecBitOr
	cPrecBitXor     = ExprPrecBitXor
	cPrecBitAnd     = ExprPrecBitAnd
	cPrecEquality   = ExprPrecEquality
	cPrecRelational = ExprPrecRelational
	cPrecShift      = ExprPrecShift
	cPrecAdd        = ExprPrecAdd
	cPrecMultiply   = ExprPrecMultiply
	cPrecCast       = ExprPrecCast
	cPrecUnary      = ExprPrecUnary
	cPrecPrimary    = ExprPrecPrimary
)

type PrintC struct {
	indentStep      string
	registerNames   map[string]string // "spaceIdx:offset:size" -> reg name; nil = disabled
	entryAnnotation string            // prepended before function name (e.g. "processEntry")
	ghostParamCount int               // number of undefined4 ghost params prepended in signature
}

func NewPrintC() *PrintC {
	return &PrintC{indentStep: "    "}
}

// SetRegisterNames installs a location-to-name map for register identification.
// Key format: "spaceIdx:offset:size" (matches Engine.RegisterNamesByLocation output).
// When set, known register locations are named by their SLA symbol name instead of local_N.
func (p *PrintC) SetRegisterNames(names map[string]string) *PrintC {
	p.registerNames = names
	return p
}

// SetProcessEntry configures entry-point rendering:
//   - annotation: string prepended before function name (e.g. "processEntry")
//   - ghostCount: number of undefined4 ghost params prepended before real params
//
// C++ parity: Ghidra's processEntry calling convention adds ghost argc/argv params
// to the signature. Real params are renumbered to follow after the ghost params.
func (p *PrintC) SetProcessEntry(annotation string, ghostCount int) *PrintC {
	p.entryAnnotation = annotation
	p.ghostParamCount = ghostCount
	return p
}

func (p *PrintC) Emit(fd *Funcdata) (string, error) {
	if p == nil {
		p = NewPrintC()
	}
	state := newPrintCState(p, fd)
	return state.emit()
}

type printCState struct {
	printer *PrintC
	fd      *Funcdata
	graph   *BlockGraph

	emitter TokenEmitter
	lang    *PrintLanguage
	decls   *CDeclRenderer

	params       []*Varnode
	locals       []*Varnode
	names        map[*Varnode]string
	inline       map[*PcodeOp]bool
	typeDefs     []Datatype
	emittedTypes map[uint64]bool
	activeExpr   map[*PcodeOp]bool
	blockLabels  map[*FlowBlock]string

	// prologueOps is the set of ops that are part of the callee-saved register
	// save/restore frame: PUSH EBP/EBX in the prologue and POP in the epilogue.
	// These are STORE ops whose value is a non-param register-space input varnode,
	// plus the address-computing ops (INT_ADD etc.) that feed their pointer input.
	// C++ parity: ActionPrototypeTypes marks callee-saved regs dead; we approximate
	// this at render time by suppressing these ops from C output.
	prologueOps map[*PcodeOp]bool
	// prologueVarnodes is the set of register-space input varnodes used only as
	// values in prologueOps. They are excluded from locals declarations.
	prologueVarnodes map[*Varnode]bool
	// returnOnlyLocs is the set of storage locations (locationKey) that were
	// renamed to Ghidra's uVar1/iVar1/lVar1 convention. Locals at these locations
	// are rendered with undefined%d type rather than their committed type, matching
	// Ghidra's ActionReturnSplit behaviour (return-value carrier -> TYPE_UNKNOWN).
	returnOnlyLocs map[locationKey]bool

	// entryAnnotation and ghostParamCount come from PrintC.SetProcessEntry.
	// When non-empty, the signature is rendered as "annotation name(ghost..., real...)"
	// and real param names are offset by ghostParamCount.
	entryAnnotation string
	ghostParamCount int
}

func newPrintCState(printer *PrintC, fd *Funcdata) *printCState {
	emitter := NewTextEmitterWithIndent(printer.indentStep)
	return &printCState{
		printer:          printer,
		fd:               fd,
		emitter:          emitter,
		lang:             NewPrintLanguage(emitter),
		decls:            NewCDeclRenderer(),
		names:            make(map[*Varnode]string),
		inline:           make(map[*PcodeOp]bool),
		emittedTypes:     make(map[uint64]bool),
		activeExpr:       make(map[*PcodeOp]bool),
		blockLabels:      make(map[*FlowBlock]string),
		prologueOps:      make(map[*PcodeOp]bool),
		prologueVarnodes: make(map[*Varnode]bool),
		returnOnlyLocs:   make(map[locationKey]bool),
		entryAnnotation:  printer.entryAnnotation,
		ghostParamCount:  printer.ghostParamCount,
	}
}

func (s *printCState) emit() (string, error) {
	if s.fd == nil {
		return "", fmt.Errorf("funcdata is nil")
	}
	s.graph = s.fd.GetStructure()
	if s.graph == nil || s.graph.GetSize() == 0 {
		s.graph = s.fd.GetBasicBlocks()
	}
	s.collectSymbols()
	retType := s.inferReturnType()
	s.collectTypeDefs(retType)
	for _, param := range s.params {
		s.collectTypeDefs(param.TypeReadFacing(nil))
	}
	for _, local := range s.locals {
		s.collectTypeDefs(local.TypeDefFacing())
	}

	for i, dt := range s.typeDefs {
		s.lang.Line(func() {
			s.lang.Token(CTypeDefinitionString(s.normalizeTypeForDecl(dt)))
		})
		if i != len(s.typeDefs)-1 {
			s.lang.Newline()
		}
	}
	if len(s.typeDefs) > 0 {
		s.lang.Newline()
	}

	s.lang.OpenBlockAfter(func() {
		s.lang.Token(s.renderFunctionSignature(retType))
	})
	s.emitLocalDeclarations()
	// Emit blank line between declarations and body only when at least one
	// non-suppressed local was actually declared. Unique-space temps and
	// prologue varnodes are skipped in emitLocalDeclarations; count only
	// the varnodes that will produce a "type name;" declaration.
	hasVisibleLocal := false
	for _, vn := range s.locals {
		if s.prologueVarnodes[vn] {
			continue
		}
		if vn.Space() != nil && vn.Space().IsUnique() {
			continue
		}
		hasVisibleLocal = true
		break
	}
	if hasVisibleLocal && s.graph != nil && s.graph.GetSize() != 0 {
		s.lang.Newline()
	}
	if s.graph != nil && s.graph.GetSize() != 0 {
		if s.graph.GetSize() == 1 {
			if err := s.emitBlock(s.graph.GetBlock(0)); err != nil {
				return "", err
			}
		} else {
			for i := 0; i < s.graph.GetSize(); i++ {
				if err := s.emitTopLevelBlock(s.graph.GetBlock(i)); err != nil {
					return "", err
				}
			}
		}
	}
	s.lang.CloseBlock()
	return s.lang.String(), nil
}

func (s *printCState) collectSymbols() {
	if s.fd == nil {
		return
	}

	// Identify and mark prologue/epilogue register-save ops before classifying locals.
	// This prevents callee-saved register spills (PUSH EBP/EBX) from appearing as
	// C statements or local variable declarations.
	s.markPrologueOps()

	regNameByLoc := s.printer.registerNames

	// ABI-aware path: use FuncProto/ScopeLocal when a calling convention is attached.
	// C++ parity: Funcdata::printRaw uses high-level variable names from ScopeLocal.
	if fp := s.fd.GetFuncProto(); fp != nil {
		sl := s.fd.GetScopeLocal()
		all := s.fd.GetVarnodeBank().AllVarnodes()
		params := make([]*Varnode, 0)
		locals := make([]*Varnode, 0)
		for _, vn := range all {
			if vn == nil || vn.IsConstant() || vn.IsAnnotation() {
				continue
			}
			// Classify via ScopeLocal/HighVariable assignment.
			if hv := vn.High(); hv != nil {
				name := hv.Name()
				if name != "" && !s.isMachineGeneratedName(name) {
					s.names[vn] = name
				}
				// Determine if param or local by name prefix.
				if len(name) >= 6 && name[:6] == "param_" {
					params = append(params, vn)
				} else {
					// If the writing op was destroyed by ActionDeadCode (Def==nil)
					// after MergeMarker already assigned High(), skip this varnode.
					// Declaring it would produce an unreachable tmp_N declaration with
					// no corresponding assignment in the function body.
					// Input varnodes (IsInput) handled in the fallback path below.
					if vn.Def() == nil && !vn.IsInput() {
						continue
					}
					// Skip unique-space dead stores even when High() is set:
					// MergeMarker may assign a HighVariable before ActionDeadCode runs,
					// leaving a zero-consumer unique with a stale High() pointer.
					if vn.Space() != nil && vn.Space().IsUnique() && vn.NumDescend() == 0 {
						continue
					}
					if vn.Def() != nil && s.shouldInline(vn.Def()) {
						s.inline[vn.Def()] = true
					} else if !s.prologueVarnodes[vn] {
						// Skip varnodes that are only used in prologue register-save ops.
						// C++ parity: ActionPrototypeTypes marks callee-saved inputs dead.
						locals = append(locals, vn)
					}
				}
				continue
			}
			// Fallback for varnodes not classified by ScopeLocal.
			if vn.IsInput() {
				// Check ScopeLocal for this input varnode.
				if sl != nil {
					if hv := sl.FindEntry(vn); hv != nil {
						if name := hv.Name(); name != "" && !s.isMachineGeneratedName(name) {
							s.names[vn] = name
						}
						params = append(params, vn)
						continue
					}
				}
				if s.isSpecialInputRegister(vn, regNameByLoc) {
					continue
				}
				// Input varnodes not recognized by ScopeLocal are callee-saved
				// registers or other ABI-defined live-ins -- not C parameters.
				// Without ActionStackPtrFlow, stack params appear as LOAD results
				// (not input varnodes), so emitting them here is always wrong.
				// C++ parity: unclassified inputs are skipped by ActionPrototypeTypes.
				continue
			}
			if vn.Def() == nil {
				continue
			}
			// Skip varnodes used only in prologue register-save ops.
			// C++ parity: ActionPrototypeTypes marks callee-saved reg chains dead.
			if s.prologueVarnodes[vn] {
				continue
			}
			// Skip unique-space varnodes with no consumers: these are dead stores
			// created or left over by BatchA rules after ActionDeadCode already ran.
			// Declaring them produces empty tmp_N declarations with no body assignment.
			if vn.Space() != nil && vn.Space().IsUnique() && vn.NumDescend() == 0 {
				continue
			}
			if s.shouldInline(vn.Def()) {
				s.inline[vn.Def()] = true
				continue
			}
			locals = append(locals, vn)
		}
		sort.Slice(params, func(i, j int) bool { return CompareLocDef(params[i], params[j]) < 0 })
		sort.Slice(locals, func(i, j int) bool { return CompareLocDef(locals[i], locals[j]) < 0 })
		s.params = dedupVarnodes(params)
		s.locals = dedupVarnodes(locals)
		// Assign names for any params/locals not yet named.
		// 1-indexed to match Ghidra output (param_1, param_2, ...).
		paramIndex := 0
		for _, vn := range s.params {
			if _, ok := s.names[vn]; !ok {
				s.names[vn] = fmt.Sprintf("param_%d", paramIndex+1)
			}
			paramIndex++
		}
		localIndex := 0
		tmpIndex := 0
		// First pass: assign one name per storage location for non-unique varnodes.
		// Multiple SSA versions of the same register/slot share one name.
		// We intentionally keep these generic rather than raw register names so
		// register-space temps do not leak implementation detail into C output.
		locName := make(map[locationKey]string)
		for _, vn := range s.locals {
			if _, ok := s.names[vn]; ok {
				continue
			}
			if vn.Space() != nil && vn.Space().IsUnique() {
				continue
			}
			key := varnodeLocKey(vn)
			if _, ok := locName[key]; !ok {
				locName[key] = fmt.Sprintf("local_%d", localIndex)
				localIndex++
			}
		}
		// Second pass: fill names for all varnodes using location-shared names.
		for _, vn := range s.locals {
			if _, ok := s.names[vn]; ok {
				continue
			}
			if vn.Space() != nil && vn.Space().IsUnique() {
				s.names[vn] = fmt.Sprintf("tmp_%d", tmpIndex)
				tmpIndex++
				continue
			}
			s.names[vn] = locName[varnodeLocKey(vn)]
		}
		// After s.inline is populated, identify COPY ops that are only consumed
		// by the return chain. This must run after shouldInline has been applied.
		s.markReturnOnlyCopies()
		// Rename return-only locals to Ghidra's uVar1/iVar1/lVar1 convention.
		// C++ parity: ActionReturnSplit names the return-value variable with a
		// prefix derived from its type (u=undefined/unsigned, i=signed, l=long).
		s.renameReturnOnlyLocals()
		return
	}

	// Nil FuncProto path: original logic with prologue-op filtering.
	all := s.fd.GetVarnodeBank().AllVarnodes()
	params := make([]*Varnode, 0)
	locals := make([]*Varnode, 0)
	for _, vn := range all {
		if vn == nil || vn.IsConstant() || vn.IsAnnotation() {
			continue
		}
		if vn.IsInput() {
			if s.isSpecialInputRegister(vn, regNameByLoc) {
				continue
			}
			// Skip callee-saved register inputs used only in prologue store ops.
			if s.prologueVarnodes[vn] {
				continue
			}
			params = append(params, vn)
			continue
		}
		if vn.Def() == nil {
			continue
		}
		// Skip varnodes used only in prologue register-save ops.
		if s.prologueVarnodes[vn] {
			continue
		}
		// Skip unique-space dead stores (no consumers): BatchA may leave these
		// after ActionDeadCode has already run.
		if vn.Space() != nil && vn.Space().IsUnique() && vn.NumDescend() == 0 {
			continue
		}
		if s.shouldInline(vn.Def()) {
			s.inline[vn.Def()] = true
			continue
		}
		locals = append(locals, vn)
	}
	sort.Slice(params, func(i, j int) bool { return CompareLocDef(params[i], params[j]) < 0 })
	sort.Slice(locals, func(i, j int) bool { return CompareLocDef(locals[i], locals[j]) < 0 })
	s.params = dedupVarnodes(params)
	s.locals = dedupVarnodes(locals)
	if len(s.params) > 2 {
		s.params = s.params[:2]
	}
	// 1-indexed to match Ghidra output (param_1, param_2, ...).
	for i, vn := range s.params {
		s.names[vn] = fmt.Sprintf("param_%d", i+1)
	}
	localIndex := 0
	tmpIndex := 0
	// First pass: assign one name per storage location for non-unique varnodes.
	// Multiple SSA versions of the same register/slot share one name.
	// We intentionally keep these generic rather than raw register names so
	// register-space temps do not leak implementation detail into C output.
	locName := make(map[locationKey]string)
	for _, vn := range s.locals {
		if _, ok := s.names[vn]; ok {
			continue
		}
		if vn.Space() != nil && vn.Space().IsUnique() {
			continue
		}
		key := varnodeLocKey(vn)
		if _, ok := locName[key]; !ok {
			locName[key] = fmt.Sprintf("local_%d", localIndex)
			localIndex++
		}
	}
	// Second pass: fill names for all varnodes using location-shared names.
	for _, vn := range s.locals {
		if _, ok := s.names[vn]; ok {
			continue
		}
		if vn.Space() != nil && vn.Space().IsUnique() {
			s.names[vn] = fmt.Sprintf("tmp_%d", tmpIndex)
			tmpIndex++
			continue
		}
		s.names[vn] = locName[varnodeLocKey(vn)]
	}
	// After s.inline is populated, identify COPY ops that are only consumed
	// by the return chain. This must run after shouldInline has been applied.
	s.markReturnOnlyCopies()
	// NOTE: renameReturnOnlyLocals is intentionally NOT called on the nil-FuncProto
	// path. Without ABI information (calling convention, return register) the
	// return-only detection is unreliable and non-deterministic because AllVarnodes()
	// iteration order is map-based. Ghidra parity for uVar1/iVar1 naming is only
	// meaningful when a proper ProtoModel is attached.
}

// locationKey identifies a unique storage location by (spaceIndex, offset, size).
// Used to merge SSA versions of the same register/stack slot into one local name.
// unique-space varnodes are excluded because each is a genuinely distinct SSA temp.
type locationKey struct {
	spaceIdx uint16
	offset   uint64
	size     int32
}

func varnodeLocKey(vn *Varnode) locationKey {
	var idx uint16
	if vn.Space() != nil {
		idx = vn.Space().Index
	}
	return locationKey{spaceIdx: idx, offset: vn.Offset(), size: vn.Size()}
}

func dedupVarnodes(in []*Varnode) []*Varnode {
	if len(in) == 0 {
		return nil
	}
	out := make([]*Varnode, 0, len(in))
	seen := make(map[*Varnode]struct{}, len(in))
	for _, vn := range in {
		if _, ok := seen[vn]; ok {
			continue
		}
		seen[vn] = struct{}{}
		out = append(out, vn)
	}
	return out
}

func (s *printCState) shouldInline(op *PcodeOp) bool {
	if op == nil || op.Output() == nil || op.IsDead() {
		return false
	}
	if op.Output().NumDescend() != 1 {
		return false
	}
	switch op.Code() {
	case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_STORE, CPUI_RETURN, CPUI_MULTIEQUAL, CPUI_INDIRECT:
		return false
	default:
		return true
	}
}

func (s *printCState) inferReturnType() Datatype {
	if s.fd == nil {
		return sharedTypeFactory.GetVoid()
	}
	for _, op := range s.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.Code() != CPUI_RETURN {
			continue
		}
		vn := returnValue(op)
		if vn == nil {
			continue
		}
		// If vn is a free (stale) varnode (ActionDeadCode freed it after anchorReturnReg),
		// recover the type from the live defining op or live varnode at the same location.
		if vn.IsFree() && !vn.IsConstant() && vn.Space() != nil {
			if defOp := s.findDefiningOpForFreeVarnode(vn); defOp != nil && defOp.Output() != nil {
				live := defOp.Output()
				if s.returnOnlyLocs[varnodeLocKey(live)] {
					dt := live.TypeReadFacing(op)
					if dt == nil || dt.Metatype() == TYPE_UINT || dt.Metatype() == TYPE_UNKNOWN {
						return sharedTypeFactory.GetBase(int32(live.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", live.Size()))
					}
				}
				return live.TypeReadFacing(op)
			}
			if live := s.findLiveReturnVarnode(vn); live != nil {
				if s.returnOnlyLocs[varnodeLocKey(live)] {
					dt := live.TypeReadFacing(op)
					if dt == nil || dt.Metatype() == TYPE_UINT || dt.Metatype() == TYPE_UNKNOWN {
						return sharedTypeFactory.GetBase(int32(live.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", live.Size()))
					}
				}
				return live.TypeReadFacing(op)
			}
			continue // could not recover type; skip this RETURN
		}
		// If the return varnode's location was identified as return-only by
		// renameReturnOnlyLocals AND its committed type is untyped (TYPE_UINT
		// from constant propagation, or TYPE_UNKNOWN), render the return type
		// as undefined%d. TYPE_INT (signed) and TYPE_FLOAT are kept as-is --
		// they were inferred from a typed op (e.g. IMUL/FADD) and should
		// propagate to the C return type.
		// C++ parity: Ghidra's ActionReturnSplit uses TYPE_UNKNOWN for the
		// return-value carrier only when no specific type could be recovered.
		if vn.Space() != nil && !vn.IsConstant() && s.returnOnlyLocs[varnodeLocKey(vn)] {
			dt := vn.TypeReadFacing(op)
			if dt == nil || dt.Metatype() == TYPE_UINT || dt.Metatype() == TYPE_UNKNOWN {
				return sharedTypeFactory.GetBase(int32(vn.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", vn.Size()))
			}
		}
		dt := vn.TypeReadFacing(op)
		// For unique-space varnodes (SSA intermediates), TypeReadFacing returns
		// TYPE_UNKNOWN when the committed type was never set (e.g. ActionInferTypes
		// ran in a different iteration order). In that case, follow the defining op
		// to get the semantically correct type.
		// C++ parity: Ghidra's type propagation ensures unique varnodes always carry
		// a committed type; our iterative propagation is order-dependent, so we fall
		// back to the def op's output type when the committed type is generic.
		if dt != nil && dt.Metatype() == TYPE_UNKNOWN && vn.Space() != nil && vn.Space().IsUnique() && vn.Def() != nil {
			if defOut := vn.Def().Output(); defOut != nil && defOut == vn {
				// The defining op's output IS vn; try to determine type from opcode.
				switch vn.Def().Code() {
				case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_MULT, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR,
					CPUI_INT_LEFT, CPUI_INT_RIGHT:
					// Arithmetic ops produce unsigned output by convention.
					dt = sharedTypeFactory.GetBase(vn.Size(), TYPE_UINT, "")
				}
			}
		}
		return dt
	}
	return sharedTypeFactory.GetVoid()
}

func returnValue(op *PcodeOp) *Varnode {
	if op == nil || op.NumInput() == 0 {
		return nil
	}
	// C++ parity: PrintC::emitStatement CPUI_RETURN case (printc.cc line 781-784):
	//   if (op->numInput()>1) { pushVn(op->getIn(1), op, mods); }
	// input[0] is the return-address reference injected by the SLA (e.g. EIP/LR);
	// input[1] is the actual C return value wired by anchorReturnReg.
	//
	// For raw p-code without SLA pre-processing (unit tests, etc.) RETURN may have
	// only input[0] which directly carries the C return value. In that case use input[0].
	//
	// anchorReturnReg always appends to the end, so numInput>1 signals the full pipeline.
	var inp *Varnode
	if op.NumInput() > 1 {
		inp = op.Input(1)
	} else {
		inp = op.Input(0)
	}
	if inp == nil || inp.IsAnnotation() || inp.IsInput() {
		return nil
	}
	return inp
}

func (s *printCState) renderFunctionSignature(retType Datatype) string {
	name := s.fd.Name()
	if s.fd.DisplayName() != "" {
		name = s.fd.DisplayName()
	}

	realParamNames := make([]string, len(s.params))
	realParamTypes := make([]Datatype, len(s.params))
	for i, param := range s.params {
		realParamTypes[i] = s.normalizeTypeForDecl(param.TypeReadFacing(nil))
		existing := s.nameOf(param)
		if s.ghostParamCount > 0 && strings.HasPrefix(existing, "param_") {
			// Renumber: real param i becomes param_(ghostParamCount+i+1).
			// Also update s.names so the body uses the same name.
			newName := fmt.Sprintf("param_%d", s.ghostParamCount+i+1)
			s.names[param] = newName
			realParamNames[i] = newName
		} else {
			realParamNames[i] = existing
		}
	}

	// Build ghost param lists (undefined4 param_1, param_2, ...).
	ghostNames := make([]string, s.ghostParamCount)
	ghostTypes := make([]Datatype, s.ghostParamCount)
	for i := 0; i < s.ghostParamCount; i++ {
		ghostNames[i] = fmt.Sprintf("param_%d", i+1)
		ghostTypes[i] = sharedTypeFactory.GetBase(4, TYPE_UNKNOWN, "undefined4")
	}

	allNames := append(ghostNames, realParamNames...)
	allTypes := append(ghostTypes, realParamTypes...)

	// Prepend annotation to name when set (e.g. "processEntry entry").
	displayName := name
	if s.entryAnnotation != "" {
		displayName = s.entryAnnotation + " " + name
	}

	codeType := sharedTypeFactory.GetCode("", s.normalizeTypeForDecl(retType), allTypes, false)
	return CFuncSignatureString(displayName, codeType, allNames)
}

func (s *printCState) emitLocalDeclarations() {
	// Skip varnodes that share a name with an already-declared local.
	// This arises when multiple SSA versions of the same storage location
	// are merged to one local_ name by collectVarnodeNames.
	declared := make(map[string]struct{})
	for _, vn := range s.locals {
		// Skip varnodes that were identified as prologue/return-chain only
		// after collectSymbols ran (markReturnOnlyCopies runs post-collect).
		if s.prologueVarnodes[vn] {
			continue
		}
		// Skip unique-space varnodes: their defining ops are always suppressed
		// by emitOps (unique-space ops are SSA intermediates, not C variables).
		// A unique varnode with ndesc>1 ends up in locals only because shouldInline
		// rejected it (ndesc!=1), but its tmp_N name is never used in any emitted
		// statement since the op is suppressed. Declaring it produces a spurious
		// "unsigned long long tmp_0;" with no corresponding assignment.
		// C++ parity: Ghidra suppresses unique temps via ActionMarkImplied.
		if vn.Space() != nil && vn.Space().IsUnique() {
			continue
		}
		name := s.nameOf(vn)
		if _, seen := declared[name]; seen {
			continue
		}
		declared[name] = struct{}{}
		// Return-only locals are rendered with undefined%d regardless of their
		// committed type. Ghidra's ActionReturnSplit assigns TYPE_UNKNOWN to the
		// return-value carrier; we approximate this at render time.
		var dt Datatype
		if !vn.Space().IsUnique() && s.returnOnlyLocs[varnodeLocKey(vn)] {
			dt = sharedTypeFactory.GetBase(int32(vn.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", vn.Size()))
		} else {
			dt = s.normalizeTypeForDecl(vn.TypeDefFacing())
		}
		decl := CDeclString(dt, name)
		s.lang.Statement(func() {
			s.lang.Token(decl)
		})
	}
}

func (s *printCState) normalizeTypeForDecl(dt Datatype) Datatype {
	if dt == nil {
		return sharedTypeFactory.GetVoid()
	}
	switch typed := dt.(type) {
	case *Pointer:
		return sharedTypeFactory.GetPointer(typed.Size(), s.normalizeTypeForDecl(typed.Pointee()), typed.WordSize())
	case *Array:
		return sharedTypeFactory.GetArray(typed.Count(), s.normalizeTypeForDecl(typed.Element()))
	case *Code:
		params := typed.ParameterTypes()
		normalizedParams := make([]Datatype, len(params))
		for i, param := range params {
			normalizedParams[i] = s.normalizeTypeForDecl(param)
		}
		return sharedTypeFactory.GetCode(typed.Name(), s.normalizeTypeForDecl(typed.ReturnType()), normalizedParams, typed.IsVariadic())
	case *Struct:
		fields := typed.Fields()
		normalizedFields := make([]TypeField, len(fields))
		for i, field := range fields {
			normalizedFields[i] = field
			normalizedFields[i].Type = s.normalizeTypeForDecl(field.Type)
		}
		return sharedTypeFactory.GetStruct(typed.Name(), normalizedFields)
	case *Union:
		fields := typed.Fields()
		normalizedFields := make([]TypeField, len(fields))
		for i, field := range fields {
			normalizedFields[i] = field
			normalizedFields[i].Type = s.normalizeTypeForDecl(field.Type)
		}
		return sharedTypeFactory.GetUnion(typed.Name(), normalizedFields)
	case *Enum:
		return sharedTypeFactory.GetEnum(typed.Size(), typed.Metatype(), typed.Name(), typed.Values())
	case *Base:
		return normalizedBaseType(typed)
	default:
		return dt
	}
}

func normalizedBaseType(base *Base) Datatype {
	if base == nil {
		return sharedTypeFactory.GetBase(4, TYPE_UINT, "unsigned int")
	}
	switch base.Metatype() {
	case TYPE_BOOL:
		return sharedTypeFactory.GetBase(base.Size(), TYPE_BOOL, "_Bool")
	case TYPE_FLOAT:
		switch base.Size() {
		case 4:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_FLOAT, "float")
		case 8:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_FLOAT, "double")
		default:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_FLOAT, "double")
		}
	case TYPE_INT:
		switch base.Size() {
		case 1:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "signed char")
		case 2:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "short")
		case 4:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "int")
		case 8:
			// LP64 model: long is 64-bit signed integer (same as Ghidra's default).
			// C++ parity: Ghidra uses "long" for 8-byte signed integer on LP64 targets.
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "long")
		default:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "int")
		}
	case TYPE_UNKNOWN:
		// Preserve TYPE_UNKNOWN as Ghidra's "undefined%d" type.
		// C++ parity: Ghidra uses TYPE_UNKNOWN for untyped bytes; prints as undefined1/2/4/8.
		// normalizeTypeForDecl must NOT coerce this to TYPE_UINT -- that would lose the
		// distinction between a typed unsigned and an untyped/undefined slot.
		return sharedTypeFactory.GetBase(base.Size(), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", base.Size()))
	case TYPE_UINT:
		switch base.Size() {
		case 1:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "unsigned char")
		case 2:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "unsigned short")
		case 4:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "unsigned int")
		case 8:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "unsigned long long")
		default:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "unsigned int")
		}
	default:
		return base
	}
}

func (s *printCState) collectTypeDefs(dt Datatype) {
	if dt == nil {
		return
	}
	switch typed := dt.(type) {
	case *Pointer:
		s.collectTypeDefs(typed.Pointee())
	case *Array:
		s.collectTypeDefs(typed.Element())
	case *Code:
		s.collectTypeDefs(typed.ReturnType())
		for _, param := range typed.ParameterTypes() {
			s.collectTypeDefs(param)
		}
	case *Struct:
		if typed.Name() == "" || s.emittedTypes[typed.ID()] {
			return
		}
		s.emittedTypes[typed.ID()] = true
		for _, field := range typed.Fields() {
			s.collectTypeDefs(field.Type)
		}
		s.typeDefs = append(s.typeDefs, dt)
	case *Union:
		if typed.Name() == "" || s.emittedTypes[typed.ID()] {
			return
		}
		s.emittedTypes[typed.ID()] = true
		for _, field := range typed.Fields() {
			s.collectTypeDefs(field.Type)
		}
		s.typeDefs = append(s.typeDefs, dt)
	case *Enum:
		if typed.Name() == "" || s.emittedTypes[typed.ID()] {
			return
		}
		s.emittedTypes[typed.ID()] = true
		s.typeDefs = append(s.typeDefs, dt)
	}
}

func (s *printCState) emitTopLevelBlock(bl *FlowBlock) error {
	if bl == nil {
		return nil
	}
	if label, ok := s.blockLabels[bl]; ok {
		s.lang.Label(label)
	}
	return s.emitBlock(bl)
}

func (s *printCState) emitBlock(bl *FlowBlock) error {
	if bl == nil {
		return nil
	}
	switch bl.Type() {
	case BlockPlain, BlockBasicType:
		return s.emitBasicBlock(bl)
	case BlockGraphType:
		if graph, ok := bl.Concrete().(*BlockGraph); ok {
			for i := 0; i < graph.GetSize(); i++ {
				if err := s.emitTopLevelBlock(graph.GetBlock(i)); err != nil {
					return err
				}
			}
			return nil
		}
		return nil
	case BlockCopyType:
		children := bl.StructuredChildren()
		if len(children) == 0 {
			return s.emitBasicBlock(bl)
		}
		for _, child := range children {
			if err := s.emitBlock(child); err != nil {
				return err
			}
		}
		return nil
	case BlockGotoType:
		return s.emitGotoBlock(bl)
	case BlockMultiGotoType:
		return s.emitMultiGotoBlock(bl)
	case BlockListType:
		return s.emitListBlock(bl)
	case BlockConditionType:
		s.lang.Line(func() {
			s.lang.Token("/*")
			s.lang.Space()
			s.lang.Token(s.mustRenderCondition(bl))
			s.lang.Space()
			s.lang.Token("*/")
		})
		return nil
	case BlockIfType:
		return s.emitIfBlock(bl)
	case BlockWhileDoType:
		return s.emitWhileBlock(bl)
	case BlockDoWhileType:
		return s.emitDoWhileBlock(bl)
	case BlockSwitchType:
		return s.emitSwitchBlock(bl)
	case BlockInfLoopType:
		return s.emitInfLoopBlock(bl)
	default:
		return fmt.Errorf("unsupported block type %v", bl.Type())
	}
}

func (s *printCState) emitListBlock(bl *FlowBlock) error {
	children := bl.StructuredChildren()
	if len(children) == 0 {
		return s.emitBasicBlock(bl)
	}
	for _, child := range children {
		if err := s.emitBlock(child); err != nil {
			return err
		}
	}
	return nil
}

func (s *printCState) emitIfBlock(bl *FlowBlock) error {
	return s.emitIfBlockChain(bl, false)
}

// emitIfBlockChain emits a BlockIf as either a leading "if" or a chained
// "else if", allowing deeply nested else-if ladders to be flattened.
// When isElseIf is true the "if" header is preceded by "else " inline with
// the closing brace of the previous block (no extra brace level added).
// C++ parity: PrintC emits else-if ladders without intermediate brace nesting.
func (s *printCState) emitIfBlockChain(bl *FlowBlock, isElseIf bool) error {
	children := bl.StructuredChildren()
	if len(children) < 2 {
		return s.emitListBlock(bl)
	}
	cond := s.mustRenderCondition(children[0])
	if isElseIf {
		// Append "else if (cond) {" to the previous closing brace line.
		s.lang.CloseBlockWithSuffix(func() {
			s.lang.Token("else")
			s.lang.Space()
			s.lang.Token("if")
			s.lang.Space()
			s.lang.Token("(")
			s.lang.Token(cond)
			s.lang.Token(")")
			s.lang.Space()
			s.lang.Token("{")
			s.lang.Indent()
		})
	} else {
		s.lang.OpenBlockAfter(func() {
			s.lang.Token("if")
			s.lang.Space()
			s.lang.Token("(")
			s.lang.Token(cond)
			s.lang.Token(")")
		})
	}
	if err := s.emitBlock(children[1]); err != nil {
		return err
	}
	if len(children) == 2 {
		s.lang.CloseBlock()
		return nil
	}
	// Determine whether the else branch itself is a plain if-block.
	// If so, emit it as an else-if chain to avoid extra brace nesting.
	// C++ parity: PrintC::emitBlockIfElse -- else-if ladders use single brace level.
	elseChild := children[2]
	if elseChild.Type() == BlockIfType {
		return s.emitIfBlockChain(elseChild, true)
	}
	s.lang.CloseBlockWithSuffix(func() {
		s.lang.Token("else")
		s.lang.Space()
		s.lang.Token("{")
		s.lang.Indent()
	})
	if err := s.emitBlock(elseChild); err != nil {
		return err
	}
	s.lang.CloseBlock()
	return nil
}

func (s *printCState) emitWhileBlock(bl *FlowBlock) error {
	children := bl.StructuredChildren()
	if len(children) < 2 {
		return s.emitListBlock(bl)
	}
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("while")
		s.lang.Space()
		s.lang.Token("(")
		s.lang.Token(s.mustRenderCondition(children[0]))
		s.lang.Token(")")
	})
	if err := s.emitBlock(children[1]); err != nil {
		return err
	}
	s.lang.CloseBlock()
	return nil
}

func (s *printCState) emitDoWhileBlock(bl *FlowBlock) error {
	children := bl.StructuredChildren()
	if len(children) == 0 {
		return nil
	}
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("do")
	})
	if basic := toBasic(children[0]); basic != nil {
		if err := s.emitOps(basic, true); err != nil {
			return err
		}
	} else if err := s.emitBlock(children[0]); err != nil {
		return err
	}
	s.lang.CloseBlockWithSuffix(func() {
		s.lang.Token("while")
		s.lang.Space()
		s.lang.Token("(")
		s.lang.Token(s.mustRenderCondition(children[0]))
		s.lang.Token(");")
	})
	return nil
}

func (s *printCState) emitInfLoopBlock(bl *FlowBlock) error {
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("for")
		s.lang.Space()
		s.lang.Token("(;;)")
	})
	for _, child := range bl.StructuredChildren() {
		if err := s.emitBlock(child); err != nil {
			return err
		}
	}
	s.lang.CloseBlock()
	return nil
}

func (s *printCState) emitSwitchBlock(bl *FlowBlock) error {
	children := bl.StructuredChildren()
	if len(children) == 0 {
		return nil
	}
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("switch")
		s.lang.Space()
		s.lang.Token("(")
		s.lang.Token(s.mustRenderSwitchSelector(children[0]))
		s.lang.Token(")")
	})
	for i, child := range children[1:] {
		label := fmt.Sprintf("case %d:", i)
		if selectorHasDefault(children[0], i) {
			label = "default:"
		}
		s.lang.Label(label)
		s.lang.Indent()
		if err := s.emitBlock(child); err != nil {
			return err
		}
		if !s.blockTerminates(child) {
			s.lang.Statement(func() {
				s.lang.Token("break")
			})
		}
		s.lang.Dedent()
	}
	s.lang.CloseBlock()
	return nil
}

func selectorHasDefault(selector *FlowBlock, idx int) bool {
	if selector == nil || idx < 0 || idx >= selector.SizeOut() {
		return false
	}
	return selector.OutEdge(idx).Label&EdgeFlagDefaultSwitch != 0
}

func (s *printCState) emitGotoBlock(bl *FlowBlock) error {
	if basic := s.firstBasicChild(bl); basic != nil {
		if err := s.emitOps(basic, true); err != nil {
			return err
		}
	}
	s.lang.Statement(func() {
		s.lang.Token("goto")
		s.lang.Space()
		s.lang.Token(s.labelForBlock(s.gotoTarget(bl)))
	})
	return nil
}

func (s *printCState) emitMultiGotoBlock(bl *FlowBlock) error {
	if basic := s.firstBasicChild(bl); basic != nil {
		if err := s.emitOps(basic, true); err != nil {
			return err
		}
	}
	s.lang.Statement(func() {
		s.lang.Token("goto")
		s.lang.Space()
		s.lang.Token(s.labelForBlock(s.gotoTarget(bl)))
	})
	return nil
}

func (s *printCState) firstBasicChild(bl *FlowBlock) *BlockBasic {
	children := bl.StructuredChildren()
	if len(children) == 0 {
		return toBasic(bl)
	}
	for _, child := range children {
		if basic := toBasic(child); basic != nil {
			return basic
		}
	}
	return nil
}

func (s *printCState) gotoTarget(bl *FlowBlock) *FlowBlock {
	if bl == nil {
		return nil
	}
	idx := bl.GotoEdgeIndex()
	if idx >= 0 && idx < bl.SizeOut() {
		return bl.OutEdge(idx).Point
	}
	if bl.SizeOut() > 0 {
		return bl.OutEdge(0).Point
	}
	return nil
}

func (s *printCState) labelForBlock(bl *FlowBlock) string {
	if bl == nil {
		return "label_missing"
	}
	if label, ok := s.blockLabels[bl]; ok {
		return label
	}
	label := fmt.Sprintf("label_%d", len(s.blockLabels))
	s.blockLabels[bl] = label
	return label
}

func (s *printCState) emitBasicBlock(bl *FlowBlock) error {
	basic := toBasic(bl)
	if basic == nil {
		for _, child := range bl.StructuredChildren() {
			if err := s.emitBlock(child); err != nil {
				return err
			}
		}
		return nil
	}
	return s.emitOps(basic, false)
}

func (s *printCState) emitOps(bb *BlockBasic, suppressControl bool) error {
	for _, op := range bb.Ops() {
		if op == nil || op.IsDead() || s.inline[op] {
			continue
		}
		// Skip prologue/epilogue register-save ops (PUSH EBP, PUSH EBX, etc.)
		// and the address-computing chains that feed them. These are identified
		// during collectSymbols and represent callee-saved register spills that
		// Ghidra's ActionPrototypeTypes would eliminate.
		// C++ parity: ActionPrototypeTypes marks these as dead before printing.
		if s.prologueOps[op] {
			continue
		}
		if out := op.Output(); out != nil {
			if out.NumDescend() == 0 {
				switch op.Code() {
				case CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW, CPUI_POPCOUNT:
					continue
				}
			}
			// Unique-space temporaries are SSA intermediates. When they reach emitOps
			// they were not inlined (NumDescend != 1). Rather than printing "tmp_N = ..."
			// which produces dead C code (the name tmp_N is never declared in locals),
			// suppress the statement. The only case we must not suppress is when the op
			// has a STORE side-effect, but STORE has no output, so this is always safe.
			// C++ parity: ActionMarkImplied / PrintC::isImplied skips unique-space writes.
			if out.Space() != nil && out.Space().IsUnique() {
				continue
			}
			// Free varnodes have been released by ActionDeadCode (MakeFree). The op is
			// not dead itself but its output has no live consumers. Emitting "local_N = ..."
			// for a free output produces an unreachable write with an undeclared name.
			// The same op's expression may still be inlined at the RETURN site via
			// findDefiningOpForFreeVarnode; suppress the stand-alone statement here.
			if out.IsFree() {
				continue
			}
		}
		if suppressControl && isControlOpcode(op.Code()) {
			continue
		}
		if err := s.emitStatement(op); err != nil {
			return err
		}
	}
	return nil
}

func isControlOpcode(opc OpCode) bool {
	switch opc {
	case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_RETURN:
		return true
	default:
		return false
	}
}

func (s *printCState) emitStatement(op *PcodeOp) error {
	if op == nil {
		return nil
	}
	// MULTIEQUAL and INDIRECT are merge-marker ops. After MergeMarker() has
	// coalesced their inputs/output into a single HighVariable, they carry no
	// additional information and must not be printed as C statements.
	// C++ parity: PrintC skips marker ops in the statement visitor.
	if op.IsMarker() {
		return nil
	}
	switch op.Code() {
	case CPUI_STORE:
		lhs, err := s.renderStoreLHS(storePointer(op), cPrecAssign)
		if err != nil {
			return err
		}
		rhs, err := s.renderVarnode(storeValue(op), cPrecAssign)
		if err != nil {
			return err
		}
		s.lang.Statement(func() {
			s.lang.Token(lhs)
			s.lang.Space()
			s.lang.Token("=")
			s.lang.Space()
			s.lang.Token(rhs)
		})
		return nil
	case CPUI_RETURN:
		// C++ parity: PrintC::emitStatement CPUI_RETURN (printc.cc ~line 780):
		//   if (op->numInput()>1) { pushVn(op->getIn(1), op, mods); }
		// returnValue selects input[1] (anchorReturnReg form) or input[0] (raw form).
		// renderReturnValue handles free (stale) varnodes by recovering the live expression.
		expr := ""
		if vn := returnValue(op); vn != nil {
			var err error
			expr, err = s.renderReturnValue(vn)
			if err != nil {
				return err
			}
		}
		s.lang.Statement(func() {
			s.lang.Token("return")
			if expr != "" {
				s.lang.Space()
				s.lang.Token(expr)
			}
		})
		return nil
	case CPUI_BRANCH:
		return nil
	case CPUI_CBRANCH:
		cond, err := s.renderBranchCondition(op)
		if err != nil {
			return err
		}
		target := "label_missing"
		if op.Parent() != nil && op.Parent().SizeOut() > 1 {
			target = s.labelForBlock(op.Parent().TrueOut())
		}
		s.lang.Statement(func() {
			s.lang.Token("if")
			s.lang.Space()
			s.lang.Token("(")
			s.lang.Token(cond)
			s.lang.Token(")")
			s.lang.Space()
			s.lang.Token("goto")
			s.lang.Space()
			s.lang.Token(target)
		})
		return nil
	case CPUI_BRANCHIND:
		expr, err := s.renderBranchIndirect(op)
		if err != nil {
			return err
		}
		s.lang.Statement(func() {
			s.lang.Token("goto")
			s.lang.Space()
			s.lang.Token(expr)
		})
		return nil
	default:
		expr, err := s.renderOpExpr(op, cPrecAssign)
		if err != nil {
			return err
		}
		if op.Output() == nil {
			s.lang.Statement(func() {
				s.lang.Token(expr)
			})
			return nil
		}
		lhs := s.nameOf(op.Output())
		s.lang.Statement(func() {
			s.lang.Token(lhs)
			s.lang.Space()
			s.lang.Token("=")
			s.lang.Space()
			s.lang.Token(expr)
		})
		return nil
	}
}

func (s *printCState) renderReturnValue(vn *Varnode) (string, error) {
	if vn == nil {
		return "", nil
	}
	// If vn is free (its defining op was killed by ActionDeadCode after anchorReturnReg
	// wired it into RETURN), try to find a live varnode at the same location that
	// carries the actual return expression.
	// This handles the pattern where anchorReturnReg picks a SUBPIECE or SSA version
	// that later gets dead-code-eliminated, leaving a stale free reference in RETURN.
	// C++ parity: ActionMarkImplied / Funcdata::deadCode cleans up stale RETURN inputs;
	// Gosleigh approximates this at render time.
	if vn.IsFree() && !vn.IsConstant() && vn.Space() != nil && s.fd != nil {
		// First try to directly render the expression from the non-dead defining op
		// (e.g. INT_MULT whose output was freed but the op itself is still alive).
		if defOp := s.findDefiningOpForFreeVarnode(vn); defOp != nil {
			frag, err := s.renderOpExprFrag(defOp)
			if err != nil {
				return "", err
			}
			return s.lang.ExprString(frag, cPrecAssign, ExprPosNone, ExprAssocNone), nil
		}
		// Fallback: find a live (written, non-free) varnode at the same register location.
		if live := s.findLiveReturnVarnode(vn); live != nil {
			vn = live
		}
	}
	// Resolve through COPY chains and then inline the defining expression.
	// This collapses "local_N = expr; return local_N;" into "return expr;".
	// C++ parity: ActionMarkImplied / PrintC::isImplied inlines single-consumer defs;
	// here we apply the same heuristic at render time for return varnodes.
	resolved, defOp := s.resolveForReturn(vn, 8)
	if defOp != nil && !defOp.IsDead() && !defOp.IsMarker() {
		switch defOp.Code() {
		case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_STORE, CPUI_RETURN,
			CPUI_MULTIEQUAL, CPUI_INDIRECT:
			// Cannot inline control/marker ops.
		default:
			frag, err := s.renderOpExprFrag(defOp)
			if err != nil {
				return "", err
			}
			return s.lang.ExprString(frag, cPrecAssign, ExprPosNone, ExprAssocNone), nil
		}
	}
	// Fall back to naming the resolved (or original) varnode.
	if resolved != nil {
		return s.renderVarnode(resolved, cPrecAssign)
	}
	return s.renderVarnode(vn, cPrecAssign)
}

// findDefiningOpForFreeVarnode finds the non-dead PcodeOp that originally wrote to
// ref's register location (space/offset/size), where ref is a free varnode (its
// defining op was cleared by ActionDeadCode's MakeFree). This allows rendering the
// return expression even when the output varnode was freed.
// Returns the latest-seq op that writes to that location and is non-dead, non-marker,
// excluding COPY and MULTIEQUAL/INDIRECT (which are transparent/phi ops).
func (s *printCState) findDefiningOpForFreeVarnode(ref *Varnode) *PcodeOp {
	if ref == nil || ref.Space() == nil || s.fd == nil {
		return nil
	}
	var best *PcodeOp
	for _, op := range s.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.IsMarker() || op.Output() == nil {
			continue
		}
		out := op.Output()
		if out.Space() == nil || out.Space().Index != ref.Space().Index {
			continue
		}
		if out.Offset() != ref.Offset() || out.Size() != ref.Size() {
			continue
		}
		// Skip trivial transparent ops; we want the computation op.
		switch op.Code() {
		case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INDIRECT:
			continue
		}
		if best == nil || SeqNumLess(best.Seq(), op.Seq()) {
			best = op
		}
	}
	return best
}

// findFreeReturnVarnode returns the return-value varnode from op if it is a
// free (stale) non-constant varnode. Uses the same slot selection as returnValue:
// input[1] when numInput>1 (anchorReturnReg form), input[0] otherwise (raw form).
func (s *printCState) findFreeReturnVarnode(op *PcodeOp) *Varnode {
	var inp *Varnode
	if op.NumInput() > 1 {
		inp = op.Input(1)
	} else if op.NumInput() == 1 {
		inp = op.Input(0)
	} else {
		return nil
	}
	if inp == nil || inp.IsAnnotation() || inp.IsInput() {
		return nil
	}
	if inp.IsFree() && !inp.IsConstant() && inp.Space() != nil {
		return inp
	}
	return nil
}

// findLiveReturnVarnode searches fd's VarnodeBank for a written (non-free) varnode
// at the same location as ref. This recovers the return value when anchorReturnReg
// wired a varnode that was subsequently killed by ActionDeadCode.
// Returns the most recent (by Seq) written varnode, preferring MULTIEQUAL outputs.
func (s *printCState) findLiveReturnVarnode(ref *Varnode) *Varnode {
	if ref == nil || ref.Space() == nil || s.fd == nil {
		return nil
	}
	var best *Varnode
	for _, vn := range s.fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		if vn.Space().Index != ref.Space().Index {
			continue
		}
		if vn.Offset() != ref.Offset() || vn.Size() != ref.Size() {
			continue
		}
		if !vn.IsWritten() || vn.IsFree() || vn.Def() == nil {
			continue
		}
		// Prefer MULTIEQUAL (phi-merge post-Heritage) over plain writes.
		if vn.Def().Code() == CPUI_MULTIEQUAL {
			return vn
		}
		if best == nil {
			best = vn
		} else if SeqNumLess(best.Def().Seq(), vn.Def().Seq()) {
			best = vn
		}
	}
	return best
}

// resolveForReturn walks COPY and MULTIEQUAL chains from vn, following each
// input to find the deepest non-trivial expression.
// Returns the resolved varnode and the defining op of that varnode.
// MULTIEQUAL nodes that have a single non-marker defining input are followed;
// this handles the common pattern where MergeMarker coalesced a single SSA
// assignment into a phi-node for naming purposes.
// maxDepth prevents infinite loops.
func (s *printCState) resolveForReturn(vn *Varnode, maxDepth int) (resolved *Varnode, defOp *PcodeOp) {
	if vn == nil {
		return nil, nil
	}
	if maxDepth <= 0 {
		op := vn.Def()
		return vn, op
	}
	op := vn.Def()
	if op == nil || op.IsDead() {
		return vn, op
	}
	switch op.Code() {
	case CPUI_COPY:
		if op.NumInput() > 0 {
			src := op.Input(0)
			if src != nil && !src.IsConstant() {
				return s.resolveForReturn(src, maxDepth-1)
			}
		}
	case CPUI_MULTIEQUAL:
		// If the MULTIEQUAL has exactly one live, non-trivial input, follow it.
		// This collapses MergeMarker phi-nodes in straight-line code where the
		// phi has only one real producer.
		var candidate *Varnode
		count := 0
		for i := 0; i < op.NumInput(); i++ {
			inp := op.Input(i)
			if inp == nil || inp.IsAnnotation() {
				continue
			}
			if inp.Def() != nil && !inp.Def().IsDead() {
				candidate = inp
				count++
			}
		}
		if count == 1 && candidate != nil {
			return s.resolveForReturn(candidate, maxDepth-1)
		}
	}
	return vn, op
}

func storePointer(op *PcodeOp) *Varnode {
	if op == nil || op.NumInput() == 0 {
		return nil
	}
	if op.NumInput() >= 3 && op.Input(0) != nil && (op.Input(0).IsAnnotation() || op.Input(0).GetSpaceFromConst() != nil) {
		return op.Input(1)
	}
	if op.NumInput() >= 2 {
		return op.Input(op.NumInput() - 2)
	}
	return op.Input(0)
}

func storeValue(op *PcodeOp) *Varnode {
	if op == nil || op.NumInput() == 0 {
		return nil
	}
	return op.Input(op.NumInput() - 1)
}

func (s *printCState) renderStoreLHS(ptr *Varnode, parentPrec ExprPrecedence) (string, error) {
	frag, err := s.renderVarnodeExpr(ptr)
	if err != nil {
		return "", err
	}
	lhs := s.lang.UnaryExpr("*", cPrecUnary, frag)
	return s.lang.ExprString(lhs, parentPrec, ExprPosNone, ExprAssocNone), nil
}

// booleanFlipToken returns the negated binary operator token, precedence, and
// whether to reorder operands for a negateable comparison op.
// C++ parity: opcodes.cc get_booleanflip
func booleanFlipToken(opc OpCode) (token string, prec ExprPrecedence, reorder bool, ok bool) {
	switch opc {
	case CPUI_INT_EQUAL:
		return "!=", cPrecEquality, false, true
	case CPUI_INT_NOTEQUAL:
		return "==", cPrecEquality, false, true
	case CPUI_INT_SLESS:
		return "<=", cPrecRelational, true, true // !(a < b) = b <= a
	case CPUI_INT_SLESSEQUAL:
		return "<", cPrecRelational, true, true // !(a <= b) = b < a
	case CPUI_INT_LESS:
		return "<=", cPrecRelational, true, true
	case CPUI_INT_LESSEQUAL:
		return "<", cPrecRelational, true, true
	case CPUI_FLOAT_EQUAL:
		return "!=", cPrecEquality, false, true
	case CPUI_FLOAT_NOTEQUAL:
		return "==", cPrecEquality, false, true
	case CPUI_FLOAT_LESS:
		return "<=", cPrecRelational, true, true
	case CPUI_FLOAT_LESSEQUAL:
		return "<", cPrecRelational, true, true
	}
	return "", 0, false, false
}

func (s *printCState) renderBranchCondition(op *PcodeOp) (string, error) {
	if op == nil {
		return "0", nil
	}
	var cond *Varnode
	if op.NumInput() >= 2 {
		cond = op.Input(1)
	} else if op.NumInput() == 1 {
		cond = op.Input(0)
	}
	if op.HasFlag(PcodeOpBooleanFlip) && cond != nil && cond.IsWritten() {
		// C++ parity: PrintC::opCbranch checkPrintNegation path -- if the inner
		// comparison op can be negated as a token, render the negated form directly
		// instead of wrapping with !. C++ uses OpToken::negate for this.
		defOp := cond.Def()
		if defOp.Code() == CPUI_BOOL_NEGATE {
			// !(BOOL_NEGATE(x)) = x
			inner, err := s.renderVarnodeExpr(defOp.Input(0))
			if err != nil {
				return "", err
			}
			return inner.Text, nil
		}
		if negTok, prec, reorder, ok := booleanFlipToken(defOp.Code()); ok {
			var left, right ExprFragment
			var err error
			if reorder {
				// !(a op b) expressed with negated op and swapped inputs.
				left, err = s.renderVarnodeExpr(defOp.Input(1))
				if err != nil {
					return "", err
				}
				right, err = s.renderVarnodeExpr(defOp.Input(0))
			} else {
				left, err = s.renderVarnodeExpr(defOp.Input(0))
				if err != nil {
					return "", err
				}
				right, err = s.renderVarnodeExpr(defOp.Input(1))
			}
			if err != nil {
				return "", err
			}
			return s.lang.BinaryExpr(left, negTok, right, prec, ExprAssocLeft).Text, nil
		}
	}
	frag, err := s.renderVarnodeExpr(cond)
	if err != nil {
		return "", err
	}
	if op.HasFlag(PcodeOpBooleanFlip) {
		frag = s.lang.UnaryExpr("!", cPrecUnary, frag)
	}
	return frag.Text, nil
}

func (s *printCState) renderBranchIndirect(op *PcodeOp) (string, error) {
	if op == nil || op.NumInput() == 0 {
		return "*0", nil
	}
	frag, err := s.renderVarnodeExpr(op.Input(op.NumInput() - 1))
	if err != nil {
		return "", err
	}
	return s.lang.UnaryExpr("*", cPrecUnary, frag).Text, nil
}

func (s *printCState) renderVarnode(vn *Varnode, parentPrec ExprPrecedence) (string, error) {
	frag, err := s.renderVarnodeExpr(vn)
	if err != nil {
		return "", err
	}
	return s.lang.ExprString(frag, parentPrec, ExprPosNone, ExprAssocNone), nil
}

func (s *printCState) renderVarnodeExpr(vn *Varnode) (ExprFragment, error) {
	if vn == nil {
		return s.lang.Atom("0"), nil
	}
	if vn.IsConstant() {
		return s.lang.Atom(s.renderConstant(vn)), nil
	}
	if op := vn.Def(); op != nil && s.inline[op] {
		if s.activeExpr[op] {
			return s.lang.Atom(s.nameOf(vn)), nil
		}
		s.activeExpr[op] = true
		defer delete(s.activeExpr, op)
		return s.renderOpExprFrag(op)
	}
	return s.lang.Atom(s.nameOf(vn)), nil
}

func (s *printCState) renderConstant(vn *Varnode) string {
	dt := vn.TypeReadFacing(nil)
	if enumType, ok := dt.(*Enum); ok {
		if name, ok := enumType.Values()[vn.Offset()]; ok {
			return name
		}
	}
	// When the constant carries only a generic TYPE_UINT (the default for untyped
	// constants), check if any consumer's storage location is signed. If so, the
	// constant lives in a signed context and should be rendered as a signed literal.
	// This handles e.g. MOV EAX, 0xFFFFFFFF -> "-1" when EAX is used in INT_SLESS.
	// Ghidra C++ propagates TYPE_INT into constant varnodes directly; Go's metatype
	// ordering (TYPE_UINT=13 < TYPE_INT=14) prevents that path, so we infer from context.
	// Only triggers when signed vs unsigned representations differ (i.e. high bit set).
	if base, ok := dt.(*Base); ok && base.Metatype() == TYPE_UINT {
		if signedDt := s.inferSignedConstType(vn); signedDt != nil {
			dt = signedDt
		}
	}
	switch typed := dt.(type) {
	case *Base:
		switch typed.Metatype() {
		case TYPE_BOOL:
			if vn.Offset() == 0 {
				return "0"
			}
			return "1"
		case TYPE_INT:
			switch typed.Size() {
			case 1, 2, 4:
				return fmt.Sprintf("%d", int32(vn.Offset()))
			case 8:
				return fmt.Sprintf("%dLL", int64(vn.Offset()))
			}
		case TYPE_FLOAT:
			return renderFloatLiteral(vn.Offset(), uint32(typed.Size()))
		}
	}
	if vn.Offset() < 10 {
		return fmt.Sprintf("%d", vn.Offset())
	}
	return fmt.Sprintf("0x%x", vn.Offset())
}

// inferSignedConstType returns a TYPE_INT base type for a constant varnode whose
// committed type is generic TYPE_UINT, when the constant's high bit is set AND
// at least one consumer op writes to a storage location that is signed anywhere in
// the function. This resolves the signed rendering gap:
//
// Problem: Go's metatype ordering (TYPE_UINT=13 < TYPE_INT=14) prevents TYPE_INT
// from propagating into constants whose tempType was initialized as TYPE_UINT.
// Meanwhile, TYPE_UINT from the constant propagates forward (COPY/MULTIEQUAL),
// giving the output varnode (e.g. EAX_1) TYPE_UINT -- even though another SSA
// version of the same register (e.g. EAX_0, input to INT_SLESS) has TYPE_INT.
//
// Solution: check if ANY varnode at the same storage location (same space/offset/
// size) as the consumer's output has TYPE_INT committed. If yes, the storage
// location is signed in this function context and the constant should render signed.
//
// C++ parity: Ghidra propagates TYPE_INT into constants via TypeOpCopy; this is
// the rendering-time fallback for that behaviour.
func (s *printCState) inferSignedConstType(vn *Varnode) Datatype {
	// Only matters when signed and unsigned representations differ (high bit set).
	highBitSet := false
	switch vn.Size() {
	case 1:
		highBitSet = int8(vn.Offset()) < 0
	case 2:
		highBitSet = int16(vn.Offset()) < 0
	case 4:
		highBitSet = int32(vn.Offset()) < 0
	case 8:
		highBitSet = int64(vn.Offset()) < 0
	}
	if !highBitSet {
		return nil
	}
	for _, op := range vn.DescendIter() {
		if op == nil || op.IsDead() {
			continue
		}
		out := op.Output()
		if out == nil {
			continue
		}
		// Check only the direct committed type of the consumer output, not a
		// location-wide scan. The location-wide scan (locationIsSigned) is too
		// broad: it matches other SSA versions of the same register (e.g. EAX_0
		// used in INT_SLESS with TYPE_INT) and incorrectly forces TYPE_INT onto a
		// constant whose consumer output (e.g. EAX_1 from COPY) is TYPE_UINT.
		// C++ parity: Ghidra propagates TYPE_INT into constants directly; this
		// fallback must only trigger when the immediate consumer output is signed.
		dt := out.Type()
		if dt != nil && dt.Metatype() == TYPE_INT {
			return sharedTypeFactory.GetExactType(vn.Size(), TYPE_INT)
		}
		if hv := out.High(); hv != nil {
			if hvdt := hv.Type(); hvdt != nil && hvdt.Metatype() == TYPE_INT {
				return sharedTypeFactory.GetExactType(vn.Size(), TYPE_INT)
			}
		}
	}
	return nil
}

// locationIsSigned returns true if any varnode at the same storage location
// (space, offset, size) as ref has TYPE_INT committed. This is needed because
// TYPE_UINT propagated from a constant can mask the TYPE_INT of another SSA
// version of the same register (e.g. EAX_0 TYPE_INT vs EAX_1 TYPE_UINT).
// C++ parity: in Ghidra, TYPE_INT would have been propagated directly into the
// constant; this is the fallback location-based check.
func (s *printCState) locationIsSigned(ref *Varnode) bool {
	if ref == nil {
		return false
	}
	// Fast path: direct committed type check.
	if dt := ref.Type(); dt != nil && dt.Metatype() == TYPE_INT {
		return true
	}
	// HighVariable check.
	if hv := ref.High(); hv != nil {
		if dt := hv.Type(); dt != nil && dt.Metatype() == TYPE_INT {
			return true
		}
	}
	// Location-based check: scan all varnodes at the same storage location.
	// Handles the case where EAX_0 (input to INT_SLESS) has TYPE_INT but
	// EAX_1 (COPY output receiving the constant) has TYPE_UINT from propagation.
	if s.fd == nil {
		return false
	}
	spc := ref.Space()
	off := ref.Offset()
	sz := ref.Size()
	for _, other := range s.fd.GetVarnodeBank().AllVarnodes() {
		if other == nil || other == ref {
			continue
		}
		if other.Space() != spc || other.Offset() != off || other.Size() != sz {
			continue
		}
		if dt := other.Type(); dt != nil && dt.Metatype() == TYPE_INT {
			return true
		}
	}
	return false
}

// renderFloatLiteral reinterprets raw bits as IEEE 754 float/double and
// returns the C literal string.
// C++ parity: PrintC::push_float (simplified)
func renderFloatLiteral(bits uint64, size uint32) string {
	switch size {
	case 4:
		f := math.Float32frombits(uint32(bits))
		if math.IsInf(float64(f), 1) {
			return "INFINITY"
		}
		if math.IsInf(float64(f), -1) {
			return "-INFINITY"
		}
		if math.IsNaN(float64(f)) {
			return "NAN"
		}
		return fmt.Sprintf("%gf", f)
	case 8:
		f := math.Float64frombits(bits)
		if math.IsInf(f, 1) {
			return "INFINITY"
		}
		if math.IsInf(f, -1) {
			return "-INFINITY"
		}
		if math.IsNaN(f) {
			return "NAN"
		}
		return fmt.Sprintf("%g", f)
	default:
		return fmt.Sprintf("0x%x", bits)
	}
}

func (s *printCState) renderOpExpr(op *PcodeOp, parentPrec ExprPrecedence) (string, error) {
	frag, err := s.renderOpExprFrag(op)
	if err != nil {
		return "", err
	}
	return s.lang.ExprString(frag, parentPrec, ExprPosNone, ExprAssocNone), nil
}

func (s *printCState) renderOpExprFrag(op *PcodeOp) (ExprFragment, error) {
	if op == nil {
		return s.lang.Atom("0"), nil
	}
	switch op.Code() {
	case CPUI_COPY:
		return s.renderVarnodeExpr(op.Input(0))
	case CPUI_LOAD:
		return s.renderLoad(op)
	case CPUI_STORE:
		return s.renderPseudoCall("STORE", op, 0)
	case CPUI_BRANCH:
		return s.renderPseudoCall("BRANCH", op, 0)
	case CPUI_CBRANCH:
		return s.renderConditionOp(op)
	case CPUI_BRANCHIND:
		return s.renderBranchIndirectExpr(op)
	case CPUI_CALL:
		return s.renderCall(op, false)
	case CPUI_CALLIND:
		return s.renderCall(op, true)
	case CPUI_CALLOTHER:
		return s.renderPseudoCall("CALLOTHER", op, 0)
	case CPUI_RETURN:
		if vn := returnValue(op); vn != nil {
			return s.renderVarnodeExpr(vn)
		}
		return s.lang.Atom("0"), nil
	case CPUI_INT_EQUAL:
		return s.renderBinary(op, "==", cPrecEquality, ExprAssocLeft)
	case CPUI_INT_NOTEQUAL:
		return s.renderBinary(op, "!=", cPrecEquality, ExprAssocLeft)
	case CPUI_INT_SLESS:
		return s.renderBinary(op, "<", cPrecRelational, ExprAssocLeft)
	case CPUI_INT_SLESSEQUAL:
		return s.renderBinary(op, "<=", cPrecRelational, ExprAssocLeft)
	case CPUI_INT_LESS:
		return s.renderBinary(op, "<", cPrecRelational, ExprAssocLeft)
	case CPUI_INT_LESSEQUAL:
		return s.renderBinary(op, "<=", cPrecRelational, ExprAssocLeft)
	case CPUI_INT_ZEXT:
		return s.renderCast(op)
	case CPUI_INT_SEXT:
		return s.renderCast(op)
	case CPUI_INT_ADD:
		return s.renderBinary(op, "+", cPrecAdd, ExprAssocLeft)
	case CPUI_INT_SUB:
		return s.renderBinary(op, "-", cPrecAdd, ExprAssocLeft)
	case CPUI_INT_CARRY:
		return s.renderPseudoCall("CARRY", op, 0)
	case CPUI_INT_SCARRY:
		return s.renderPseudoCall("SCARRY", op, 0)
	case CPUI_INT_SBORROW:
		return s.renderPseudoCall("SBORROW", op, 0)
	case CPUI_INT_2COMP:
		return s.renderUnary(op, "-", cPrecUnary)
	case CPUI_INT_NEGATE:
		return s.renderUnary(op, "~", cPrecUnary)
	case CPUI_INT_XOR:
		return s.renderBinary(op, "^", cPrecBitXor, ExprAssocLeft)
	case CPUI_INT_AND:
		return s.renderBinary(op, "&", cPrecBitAnd, ExprAssocLeft)
	case CPUI_INT_OR:
		return s.renderBinary(op, "|", cPrecBitOr, ExprAssocLeft)
	case CPUI_INT_LEFT:
		return s.renderBinary(op, "<<", cPrecShift, ExprAssocLeft)
	case CPUI_INT_RIGHT:
		return s.renderBinary(op, ">>", cPrecShift, ExprAssocLeft)
	case CPUI_INT_SRIGHT:
		return s.renderBinary(op, ">>", cPrecShift, ExprAssocLeft)
	case CPUI_INT_MULT:
		return s.renderBinary(op, "*", cPrecMultiply, ExprAssocLeft)
	case CPUI_INT_DIV:
		return s.renderBinary(op, "/", cPrecMultiply, ExprAssocLeft)
	case CPUI_INT_SDIV:
		return s.renderBinary(op, "/", cPrecMultiply, ExprAssocLeft)
	case CPUI_INT_REM:
		return s.renderBinary(op, "%", cPrecMultiply, ExprAssocLeft)
	case CPUI_INT_SREM:
		return s.renderBinary(op, "%", cPrecMultiply, ExprAssocLeft)
	case CPUI_BOOL_NEGATE:
		return s.renderUnary(op, "!", cPrecUnary)
	case CPUI_BOOL_XOR:
		return s.renderBinary(op, "!=", cPrecEquality, ExprAssocLeft)
	case CPUI_BOOL_AND:
		return s.renderBinary(op, "&&", cPrecLogicalAnd, ExprAssocLeft)
	case CPUI_BOOL_OR:
		return s.renderBinary(op, "||", cPrecLogicalOr, ExprAssocLeft)
	case CPUI_FLOAT_EQUAL:
		return s.renderBinary(op, "==", cPrecEquality, ExprAssocLeft)
	case CPUI_FLOAT_NOTEQUAL:
		return s.renderBinary(op, "!=", cPrecEquality, ExprAssocLeft)
	case CPUI_FLOAT_LESS:
		return s.renderBinary(op, "<", cPrecRelational, ExprAssocLeft)
	case CPUI_FLOAT_LESSEQUAL:
		return s.renderBinary(op, "<=", cPrecRelational, ExprAssocLeft)
	case CPUI_FLOAT_NAN:
		return s.renderPseudoCall("isnan", op, 0)
	case CPUI_FLOAT_ADD:
		return s.renderBinary(op, "+", cPrecAdd, ExprAssocLeft)
	case CPUI_FLOAT_DIV:
		return s.renderBinary(op, "/", cPrecMultiply, ExprAssocLeft)
	case CPUI_FLOAT_MULT:
		return s.renderBinary(op, "*", cPrecMultiply, ExprAssocLeft)
	case CPUI_FLOAT_SUB:
		return s.renderBinary(op, "-", cPrecAdd, ExprAssocLeft)
	case CPUI_FLOAT_NEG:
		return s.renderUnary(op, "-", cPrecUnary)
	case CPUI_FLOAT_ABS:
		return s.renderPseudoCall("fabs", op, 0)
	case CPUI_FLOAT_SQRT:
		return s.renderPseudoCall("sqrt", op, 0)
	case CPUI_FLOAT_INT2FLOAT:
		return s.renderCast(op)
	case CPUI_FLOAT_FLOAT2FLOAT:
		return s.renderCast(op)
	case CPUI_FLOAT_TRUNC:
		return s.renderCast(op)
	case CPUI_FLOAT_CEIL:
		return s.renderPseudoCall("ceil", op, 0)
	case CPUI_FLOAT_FLOOR:
		return s.renderPseudoCall("floor", op, 0)
	case CPUI_FLOAT_ROUND:
		return s.renderPseudoCall("round", op, 0)
	case CPUI_MULTIEQUAL:
		return s.renderPseudoCall("MULTIEQUAL", op, 0)
	case CPUI_INDIRECT:
		return s.renderPseudoCall("INDIRECT", op, 0)
	case CPUI_PIECE:
		return s.renderPseudoCall("CONCAT", op, 0)
	case CPUI_SUBPIECE:
		return s.renderPseudoCall("SUBPIECE", op, 0)
	case CPUI_CAST:
		return s.renderCast(op)
	case CPUI_PTRADD:
		return s.renderPtrAdd(op)
	case CPUI_PTRSUB:
		return s.renderPtrSub(op)
	case CPUI_SEGMENTOP:
		return s.renderPseudoCall("SEGMENTOP", op, 0)
	case CPUI_CPOOLREF:
		return s.renderPseudoCall("CPOOLREF", op, 0)
	case CPUI_NEW:
		return s.renderPseudoCall("NEW", op, 0)
	case CPUI_INSERT:
		return s.renderPseudoCall("INSERT", op, 0)
	case CPUI_ZPULL:
		return s.renderPseudoCall("ZPULL", op, 0)
	case CPUI_POPCOUNT:
		return s.renderPseudoCall("POPCOUNT", op, 0)
	case CPUI_LZCOUNT:
		return s.renderPseudoCall("LZCOUNT", op, 0)
	case CPUI_SPULL:
		return s.renderPseudoCall("SPULL", op, 0)
	default:
		return ExprFragment{}, fmt.Errorf("unsupported opcode %s", op.Code())
	}
}

func (s *printCState) renderBinary(op *PcodeOp, token string, prec ExprPrecedence, assoc ExprAssociativity) (ExprFragment, error) {
	left, err := s.renderVarnodeExpr(op.Input(0))
	if err != nil {
		return ExprFragment{}, err
	}
	right, err := s.renderVarnodeExpr(op.Input(1))
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.BinaryExpr(left, token, right, prec, assoc), nil
}

func (s *printCState) renderUnary(op *PcodeOp, token string, prec ExprPrecedence) (ExprFragment, error) {
	inner, err := s.renderVarnodeExpr(op.Input(0))
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.UnaryExpr(token, prec, inner), nil
}

func (s *printCState) renderCast(op *PcodeOp) (ExprFragment, error) {
	inner, err := s.renderVarnodeExpr(op.Input(0))
	if err != nil {
		return ExprFragment{}, err
	}
	dt := Datatype(nil)
	if out := op.Output(); out != nil {
		dt = s.normalizeTypeForDecl(out.TypeDefFacing())
	}
	return s.lang.CastExpr(CTypeString(dt), inner), nil
}

func (s *printCState) renderLoad(op *PcodeOp) (ExprFragment, error) {
	ptr, err := s.renderVarnodeExpr(op.Input(op.NumInput() - 1))
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.UnaryExpr("*", cPrecUnary, ptr), nil
}

func (s *printCState) renderCall(op *PcodeOp, indirect bool) (ExprFragment, error) {
	if op.NumInput() == 0 {
		return s.lang.CallExpr(s.lang.Atom("func")), nil
	}
	callee, err := s.renderCallTarget(op.Input(0), indirect)
	if err != nil {
		return ExprFragment{}, err
	}
	args := make([]ExprFragment, 0, maxInt(0, op.NumInput()-1))
	for i := 1; i < op.NumInput(); i++ {
		arg, err := s.renderVarnodeExpr(op.Input(i))
		if err != nil {
			return ExprFragment{}, err
		}
		args = append(args, arg)
	}
	return s.lang.CallExpr(callee, args...), nil
}

func (s *printCState) renderCallTarget(vn *Varnode, indirect bool) (ExprFragment, error) {
	if vn == nil {
		return s.lang.Atom("func"), nil
	}
	if !indirect && vn.IsConstant() {
		return s.lang.Atom(fmt.Sprintf("func_%x", vn.Offset())), nil
	}
	target, err := s.renderVarnodeExpr(vn)
	if err != nil {
		return ExprFragment{}, err
	}
	if indirect {
		return s.lang.GroupExpr(s.lang.UnaryExpr("*", cPrecUnary, target)), nil
	}
	return target, nil
}

func (s *printCState) renderPseudoCall(name string, op *PcodeOp, start int) (ExprFragment, error) {
	args := make([]ExprFragment, 0, maxInt(0, op.NumInput()-start))
	for i := start; i < op.NumInput(); i++ {
		arg, err := s.renderVarnodeExpr(op.Input(i))
		if err != nil {
			return ExprFragment{}, err
		}
		args = append(args, arg)
	}
	return s.lang.CallExpr(s.lang.Atom(name), args...), nil
}

func (s *printCState) renderPtrAdd(op *PcodeOp) (ExprFragment, error) {
	base, err := s.renderVarnodeExpr(op.Input(0))
	if err != nil {
		return ExprFragment{}, err
	}
	index, err := s.renderVarnodeExpr(op.Input(1))
	if err != nil {
		return ExprFragment{}, err
	}
	right := index
	if op.NumInput() > 2 {
		scale := s.lang.Atom(s.renderConstant(op.Input(2)))
		if scale.Text != "1" {
			right = s.lang.BinaryExpr(index, "*", scale, cPrecMultiply, ExprAssocLeft)
		}
	}
	return s.lang.BinaryExpr(base, "+", right, cPrecAdd, ExprAssocLeft), nil
}

func (s *printCState) renderPtrSub(op *PcodeOp) (ExprFragment, error) {
	base := op.Input(0)
	off := op.Input(1)
	if fieldExpr, ok := s.renderPtrSubField(base, off); ok {
		return fieldExpr, nil
	}
	baseExpr, err := s.renderVarnodeExpr(base)
	if err != nil {
		return ExprFragment{}, err
	}
	offExpr, err := s.renderVarnodeExpr(off)
	if err != nil {
		return ExprFragment{}, err
	}
	castBase := s.lang.CastExpr("char *", baseExpr)
	return s.lang.BinaryExpr(castBase, "+", offExpr, cPrecAdd, ExprAssocLeft), nil
}

func (s *printCState) renderPtrSubField(base, off *Varnode) (ExprFragment, bool) {
	if base == nil || off == nil || !off.IsConstant() {
		return ExprFragment{}, false
	}
	ptrType, ok := base.TypeReadFacing(nil).(*Pointer)
	if !ok {
		return ExprFragment{}, false
	}
	structType, ok := ptrType.Pointee().(*Struct)
	if !ok {
		return ExprFragment{}, false
	}
	field, ok := structType.FieldAt(int32(off.Offset()))
	if !ok || field.Name == "" {
		return ExprFragment{}, false
	}
	baseExpr, err := s.renderVarnodeExpr(base)
	if err != nil {
		return ExprFragment{}, false
	}
	return s.lang.PostfixExpr(baseExpr, "->"+field.Name), true
}

func (s *printCState) renderConditionOp(op *PcodeOp) (ExprFragment, error) {
	cond, err := s.renderBranchCondition(op)
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.Expr(cond, cPrecLowest), nil
}

func (s *printCState) renderBranchIndirectExpr(op *PcodeOp) (ExprFragment, error) {
	expr, err := s.renderBranchIndirect(op)
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.Expr(expr, cPrecUnary), nil
}

func (s *printCState) mustRenderCondition(bl *FlowBlock) string {
	expr, err := s.renderCondition(bl)
	if err != nil {
		return "0"
	}
	return expr.Text
}

func (s *printCState) renderCondition(bl *FlowBlock) (ExprFragment, error) {
	if bl == nil {
		return s.lang.Atom("0"), nil
	}
	switch bl.Type() {
	case BlockConditionType:
		children := bl.StructuredChildren()
		if len(children) == 0 {
			return s.lang.Atom("0"), nil
		}
		parts := make([]ExprFragment, 0, len(children))
		for _, child := range children {
			part, err := s.renderCondition(child)
			if err != nil {
				return ExprFragment{}, err
			}
			parts = append(parts, part)
		}
		combined := parts[0]
		for i := 1; i < len(parts); i++ {
			combined = s.lang.BinaryExpr(combined, "||", parts[i], cPrecLogicalOr, ExprAssocLeft)
		}
		return combined, nil
	case BlockBasicType, BlockPlain:
		basic := toBasic(bl)
		if basic == nil {
			return s.lang.Atom("0"), nil
		}
		for i := len(basic.Ops()) - 1; i >= 0; i-- {
			op := basic.Ops()[i]
			if op.Code() == CPUI_CBRANCH {
				cond, err := s.renderBranchCondition(op)
				if err != nil {
					return ExprFragment{}, err
				}
				return s.lang.Expr(cond, cPrecLowest), nil
			}
			if op.Output() != nil {
				return s.renderVarnodeExpr(op.Output())
			}
		}
		return s.lang.Atom("0"), nil
	default:
		children := bl.StructuredChildren()
		if len(children) > 0 {
			return s.renderCondition(children[0])
		}
		return s.lang.Atom("0"), nil
	}
}

func (s *printCState) mustRenderSwitchSelector(bl *FlowBlock) string {
	expr, err := s.renderSwitchSelector(bl)
	if err != nil {
		return "0"
	}
	return expr.Text
}

func (s *printCState) renderSwitchSelector(bl *FlowBlock) (ExprFragment, error) {
	if bl == nil {
		return s.lang.Atom("0"), nil
	}
	if basic := toBasic(bl); basic != nil {
		for i := len(basic.Ops()) - 1; i >= 0; i-- {
			op := basic.Ops()[i]
			if op.Output() != nil {
				return s.renderVarnodeExpr(op.Output())
			}
		}
	}
	children := bl.StructuredChildren()
	if len(children) > 0 {
		return s.renderSwitchSelector(children[0])
	}
	return s.lang.Atom("0"), nil
}

func (s *printCState) blockTerminates(bl *FlowBlock) bool {
	if bl == nil {
		return false
	}
	switch bl.Type() {
	case BlockGotoType, BlockMultiGotoType:
		return true
	case BlockIfType:
		children := bl.StructuredChildren()
		if len(children) == 3 {
			return s.blockTerminates(children[1]) && s.blockTerminates(children[2])
		}
	case BlockListType:
		children := bl.StructuredChildren()
		if len(children) > 0 {
			return s.blockTerminates(children[len(children)-1])
		}
	case BlockBasicType, BlockPlain:
		bb := toBasic(bl)
		if bb != nil && bb.NumOps() > 0 {
			last := bb.Ops()[bb.NumOps()-1]
			switch last.Code() {
			case CPUI_RETURN, CPUI_BRANCH, CPUI_BRANCHIND:
				return true
			}
		}
	}
	return false
}

func (s *printCState) nameOf(vn *Varnode) string {
	if vn == nil {
		return "0"
	}
	if name, ok := s.names[vn]; ok {
		return name
	}
	// Check if a HighVariable name was assigned by ApplyCallingConvention.
	// C++ parity: PrintC::pushSymbol uses high->getName() when available.
	if hv := vn.High(); hv != nil && hv.Name() != "" && !s.isMachineGeneratedName(hv.Name()) {
		name := hv.Name()
		s.names[vn] = name
		return name
	}
	if vn.Space() != nil && vn.Space().IsUnique() {
		name := fmt.Sprintf("tmp_%d", vn.CreateIndex())
		s.names[vn] = name
		return name
	}
	name := fmt.Sprintf("local_%d", vn.CreateIndex())
	s.names[vn] = name
	return name
}

func (s *printCState) isKnownRegisterName(name string) bool {
	if s == nil || s.printer == nil || len(s.printer.registerNames) == 0 {
		return false
	}
	for _, regName := range s.printer.registerNames {
		if regName == name {
			return true
		}
	}
	return false
}

func (s *printCState) isMachineGeneratedName(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "unique_") || strings.HasPrefix(name, "register_") {
		return true
	}
	return s.isKnownRegisterName(name)
}

// markPrologueOps identifies callee-saved register save/restore sequences
// (PUSH EBP, PUSH EBX, etc.) and marks them in prologueOps so they are
// suppressed from C output. Also marks the intermediate varnodes that are
// used only as operands to prologue ops in prologueVarnodes.
//
// Detection heuristic: a STORE op is a register-save prologue op when:
//  1. Its value (storeValue) is a register-space input varnode, AND
//  2. That varnode is not classified as a C parameter by ScopeLocal.
//
// The address-computing ops (INT_ADD/COPY feeding the pointer input) are also
// marked as prologue ops if their output is only consumed by prologue STOREs.
//
// C++ parity: ActionPrototypeTypes::apply marks callee-saved inputs/outputs;
// this is a render-time approximation that avoids modifying the p-code graph.
func (s *printCState) markPrologueOps() {
	if s.fd == nil {
		return
	}

	// Build a set of varnode pointers that are classified as params.
	// We need this to avoid suppressing actual function parameter registers.
	paramVns := make(map[*Varnode]bool)
	if sl := s.fd.GetScopeLocal(); sl != nil {
		for _, vn := range s.fd.GetVarnodeBank().AllVarnodes() {
			if vn == nil || !vn.IsInput() {
				continue
			}
			if hv := sl.FindEntry(vn); hv != nil {
				if name := hv.Name(); len(name) >= 6 && name[:6] == "param_" {
					paramVns[vn] = true
				}
			}
		}
	}
	// Also check FuncProto params (set by ApplyCallingConvention).
	if fp := s.fd.GetFuncProto(); fp != nil {
		for i := 0; i < fp.NumParams(); i++ {
			hv := fp.GetParam(i)
			if hv == nil {
				continue
			}
			// Mark all varnodes belonging to this param HighVariable.
			for _, vn := range s.fd.GetVarnodeBank().AllVarnodes() {
				if vn != nil && vn.High() == hv {
					paramVns[vn] = true
				}
			}
		}
	}

	// First pass: find STORE ops that save callee-saved registers to the stack.
	// These are STORE ops where the value is a register-space input varnode that
	// is not a function parameter.
	for _, op := range s.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_STORE {
			continue
		}
		val := storeValue(op)
		if val == nil || !val.IsInput() {
			continue
		}
		if val.Space() == nil || val.Space().IsUnique() || val.Space().Kind == address.SpaceKindStack {
			continue
		}
		// val is a register-space (or ram-space) input varnode. If it's a param, keep it.
		if paramVns[val] {
			continue
		}
		// This is a callee-saved register store. Mark it.
		s.prologueOps[op] = true
		s.prologueVarnodes[val] = true
	}

	// Second pass: mark address-computing ops whose output is only consumed by
	// prologue STOREs (as the pointer argument). These produce the "*(local_N + -4)"
	// style pointer chain that should not appear as a local declaration or statement.
	for {
		changed := false
		for _, op := range s.fd.GetPcodeOpBank().AllOps() {
			if op == nil || op.IsDead() || op.Output() == nil {
				continue
			}
			if s.prologueOps[op] {
				continue // already marked
			}
			out := op.Output()
			// Check if every consumer of this op's output is a prologue op.
			allPrologue := true
			if out.NumDescend() == 0 {
				allPrologue = false // no consumers; don't suppress
			}
			for _, consumer := range out.DescendIter() {
				if !s.prologueOps[consumer] {
					allPrologue = false
					break
				}
			}
			if allPrologue {
				s.prologueOps[op] = true
				s.prologueVarnodes[out] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

// markReturnOnlyCopies identifies ops whose output varnode is consumed exclusively
// by RETURN ops or by other suppressible ops. When all effective consumers of an op
// are in this "return-only" category, the standalone assignment statement is
// redundant: the return value is already rendered inline from the actual computation.
//
// Example: after anchorReturnReg, EAX has two consumers: IMUL (computation) and
// RETURN (return anchor). The COPY that loaded param_0 into EAX now has EAX as
// output with consumers = {IMUL, RETURN}. IMUL is inlined into "return ...", so
// the standalone "local_0 = param_0" is dead from C's perspective.
//
// Suppression criteria for an op: every consumer of its output is one of:
//   - a RETURN op
//   - a MULTIEQUAL or INDIRECT marker op (always suppressed)
//   - already in prologueOps (will be suppressed)
//   - already in s.inline (will be inlined at its consumer's site)
//   - an op whose output has ndesc==0 (dead store, itself suppressible)
//
// This function iterates to fixpoint: suppressing one op may reveal others.
//
// C++ parity: ActionMarkImplied / PrintC::isImplied suppresses single-use defs;
// this extends that to the return-anchor pattern where NumDescend>1 blocks
// normal inlining but the extra consumers are return anchors or dead stores.
func (s *printCState) markReturnOnlyCopies() {
	if s.fd == nil {
		return
	}
	// First pass: suppress COPY ops whose output has ndesc==0 and whose input
	// is NOT a constant. When input is constant the COPY is a branch-assignment
	// (e.g. "EAX = 0xffffffff" in classify_sign) and must stay as a C statement.
	// When input is non-constant (param, stack slot, register), the COPY is a
	// dead intermediate that PropagateCopy already bypassed -- safe to suppress.
	// C++ parity: ActionDeadCode kills these in a second pass.
	for _, op := range s.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Output() == nil {
			continue
		}
		if s.prologueOps[op] || s.inline[op] {
			continue
		}
		if op.Code() != CPUI_COPY {
			continue
		}
		out := op.Output()
		if out.NumDescend() != 0 || out.Space() == nil {
			continue
		}
		// Skip if input is a constant: branch-assignment must remain visible.
		if op.NumInput() > 0 {
			inp := op.Input(0)
			if inp != nil && inp.IsConstant() {
				continue
			}
		}
		// Dead-store COPY with non-constant input: suppress.
		s.prologueOps[op] = true
		s.prologueVarnodes[out] = true
	}

	// Fixpoint pass: suppress any op all of whose consumers are transparent
	// (return-chain, marker, already-suppressed, already-inline, or dead-store).
	// This handles chains like: INT_ADD(ndesc=2) consumed by [COPY(ndesc=0), RETURN].
	// After COPY(ndesc=0) is suppressed above, INT_ADD's only live consumer is RETURN,
	// making it inline-eligible at the return site.
	for {
		changed := false
		for _, op := range s.fd.GetPcodeOpBank().AllOps() {
			if op == nil || op.IsDead() || op.Output() == nil {
				continue
			}
			if s.prologueOps[op] || s.inline[op] {
				continue // already handled
			}
			// Skip ops that produce side effects not captured by their output.
			switch op.Code() {
			case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_STORE, CPUI_RETURN,
				CPUI_MULTIEQUAL, CPUI_INDIRECT, CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER:
				continue
			}
			out := op.Output()
			if out.NumDescend() == 0 {
				// Already handled in dead-store pass above; skip to avoid re-processing.
				continue
			}
			// Check that all consumers are transparent (return-chain or suppressed).
			// A consumer is transparent if:
			//   - RETURN: return anchor, does not produce a C statement
			//   - MULTIEQUAL, INDIRECT: marker ops, suppressed by IsMarker()
			//   - prologueOps: already suppressed
			//   - s.inline: will be inlined at consumer's site
			//   - consumer output has ndesc==0: dead store (suppressible)
			allTransparent := true
			hasReturnOrInline := false // must have at least one meaningful transparent consumer
			for _, consumer := range out.DescendIter() {
				if consumer == nil {
					continue
				}
				switch consumer.Code() {
				case CPUI_RETURN:
					hasReturnOrInline = true
				case CPUI_MULTIEQUAL, CPUI_INDIRECT:
					// Marker ops, always suppressed.
				default:
					if s.prologueOps[consumer] {
						// Already suppressed; transparent.
					} else if s.inline[consumer] {
						hasReturnOrInline = true
					} else if consumer.Output() != nil && consumer.Output().NumDescend() == 0 {
						// Dead-store consumer: suppressible (handled in dead-store pass or
						// will be suppressed when we process it below).
					} else {
						allTransparent = false
					}
				}
				if !allTransparent {
					break
				}
			}
			if allTransparent && hasReturnOrInline {
				s.prologueOps[op] = true
				s.prologueVarnodes[out] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

func (s *printCState) isSpecialInputRegister(vn *Varnode, regNameByLoc map[string]string) bool {
	if vn == nil || vn.Space() == nil || regNameByLoc == nil {
		return false
	}
	key := fmt.Sprintf("%d:%d:%d", vn.Space().Index, vn.Offset(), vn.Size())
	name, ok := regNameByLoc[key]
	if !ok {
		return false
	}
	switch strings.ToLower(name) {
	case "pc", "sp", "lr", "xzr", "wzr", "nzcv", "cpsr":
		return true
	default:
		return false
	}
}

func sanitizeIdent(name string) string {
	if name == "" {
		return "var"
	}
	var builder strings.Builder
	for i, ch := range name {
		valid := ch == '_' || ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
		if !valid {
			builder.WriteByte('_')
			continue
		}
		if i == 0 && ch >= '0' && ch <= '9' {
			builder.WriteByte('_')
		}
		builder.WriteRune(ch)
	}
	if builder.Len() == 0 {
		return "var"
	}
	return builder.String()
}

// renameReturnOnlyLocals scans the local variable set and renames any local
// whose sole non-marker consumers are RETURN ops to Ghidra's uVar1/iVar1/lVar1
// convention. Must be called after markReturnOnlyCopies so prologueOps and
// s.inline are fully populated.
//
// C++ parity: ActionReturnSplit::apply in coreaction.cc assigns a dedicated
// symbol name to the return-value carrier varnode. This is our equivalent
// without actually splitting the return path.
func (s *printCState) renameReturnOnlyLocals() {
	// Count existing Ghidra-style names by prefix to determine the next index.
	prefixCount := make(map[string]int)

	// Collect location keys of locals that are return-only.
	// Multiple SSA versions of the same register/slot share a location key;
	// we rename the whole group together.
	type retOnlyEntry struct {
		key    locationKey
		prefix string
	}
	var retOnlyKeys []retOnlyEntry
	seenLoc := make(map[locationKey]bool)

	for _, vn := range s.locals {
		if vn.Space() != nil && vn.Space().IsUnique() {
			continue
		}
		if s.prologueVarnodes[vn] {
			continue
		}
		// Only check non-unique varnodes that are return-only.
		if !s.isReturnOnlyVarnode(vn) {
			continue
		}
		key := varnodeLocKey(vn)
		if seenLoc[key] {
			continue
		}
		seenLoc[key] = true
		prefix := ghidraVarPrefix(vn)
		prefixCount[prefix]++
		retOnlyKeys = append(retOnlyKeys, retOnlyEntry{key, prefix})
	}

	if len(retOnlyKeys) == 0 {
		return
	}

	// Assign Ghidra-style names, starting from 1 (uVar1, iVar1, ...).
	// Re-count per prefix starting from 1.
	prefixIdx := make(map[string]int)
	for p := range prefixCount {
		prefixIdx[p] = 1
	}

	// Build a location-key -> newName map.
	keyName := make(map[locationKey]string)
	for _, e := range retOnlyKeys {
		name := fmt.Sprintf("%s%d", e.prefix, prefixIdx[e.prefix])
		prefixIdx[e.prefix]++
		keyName[e.key] = name
	}

	// Apply new names to all locals at those location keys, and record the
	// location as return-only so the type is rendered as undefined%d.
	for _, vn := range s.locals {
		if vn.Space() != nil && vn.Space().IsUnique() {
			continue
		}
		key := varnodeLocKey(vn)
		if newName, ok := keyName[key]; ok {
			s.names[vn] = newName
			s.returnOnlyLocs[key] = true
		}
	}
}

// ghidraVarPrefix returns the Ghidra variable name prefix for a local based on
// the varnode's type and size. Ghidra names are: uVar (undefined/unsigned, <=4),
// iVar (signed int), lVar (signed long 8-byte), puVar/piVar (pointer etc.).
// C++ parity: Ghidra uses HighVariable::getSymbol().getName() assigned by
// ActionReturnSplit / Symbol::nameType convention.
func ghidraVarPrefix(vn *Varnode) string {
	if vn == nil {
		return "uVar"
	}
	dt := vn.TypeDefFacing()
	if dt == nil {
		return "uVar"
	}
	switch dt.Metatype() {
	case TYPE_INT:
		if dt.Size() >= 8 {
			return "lVar"
		}
		return "iVar"
	case TYPE_FLOAT:
		return "fVar"
	default:
		// TYPE_UINT, TYPE_UNKNOWN, TYPE_BOOL, and all others -> uVar
		return "uVar"
	}
}

// isReturnOnlyVarnode reports whether vn's only non-marker, non-suppressed
// consumers are RETURN ops. Such a varnode is the function's return value
// carrier and should be named with Ghidra's uVar1/iVar1/lVar1 convention.
// Must be called after s.inline and s.prologueOps are fully populated.
func (s *printCState) isReturnOnlyVarnode(vn *Varnode) bool {
	if vn == nil || vn.NumDescend() == 0 {
		return false
	}
	hasReturn := false
	for _, consumer := range vn.DescendIter() {
		if consumer == nil {
			continue
		}
		switch consumer.Code() {
		case CPUI_RETURN:
			hasReturn = true
		case CPUI_MULTIEQUAL, CPUI_INDIRECT:
			// Marker ops; transparent.
		default:
			if s.prologueOps[consumer] || s.inline[consumer] {
				// Suppressed or inlined; transparent.
				continue
			}
			return false
		}
	}
	return hasReturn
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
