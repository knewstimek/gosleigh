package pcode

import (
	"fmt"
	"math"
	"sort"
	"strings"
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
	indentStep    string
	registerNames map[string]string // "spaceIdx:offset:size" -> reg name; nil = disabled
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
}

func newPrintCState(printer *PrintC, fd *Funcdata) *printCState {
	emitter := NewTextEmitterWithIndent(printer.indentStep)
	return &printCState{
		printer:      printer,
		fd:           fd,
		emitter:      emitter,
		lang:         NewPrintLanguage(emitter),
		decls:        NewCDeclRenderer(),
		names:        make(map[*Varnode]string),
		inline:       make(map[*PcodeOp]bool),
		emittedTypes: make(map[uint64]bool),
		activeExpr:   make(map[*PcodeOp]bool),
		blockLabels:  make(map[*FlowBlock]string),
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
	if len(s.locals) > 0 && s.graph != nil && s.graph.GetSize() != 0 {
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
				s.names[vn] = name
				// Determine if param or local by name prefix.
				if len(name) >= 6 && name[:6] == "param_" {
					params = append(params, vn)
				} else {
					if vn.Def() != nil && s.shouldInline(vn.Def()) {
						s.inline[vn.Def()] = true
					} else {
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
						s.names[vn] = hv.Name()
						params = append(params, vn)
						continue
					}
				}
				params = append(params, vn)
				continue
			}
			if vn.Def() == nil {
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
		paramIndex := 0
		for _, vn := range s.params {
			if _, ok := s.names[vn]; !ok {
				s.names[vn] = fmt.Sprintf("param_%d", paramIndex)
			}
			paramIndex++
		}
		localIndex := 0
		tmpIndex := 0
		// First pass: assign one name per storage location for non-unique varnodes.
		// Multiple SSA versions of the same register/slot share one name.
		// Register locations are resolved from registerNames first; fallback is local_N.
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
				// Check if this storage location has a known register name.
				if s.printer.registerNames != nil {
					regKey := fmt.Sprintf("%d:%d:%d", key.spaceIdx, key.offset, key.size)
					if regName, ok := s.printer.registerNames[regKey]; ok {
						locName[key] = regName
						continue
					}
				}
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
		return
	}

	// Nil FuncProto path: original logic unchanged.
	all := s.fd.GetVarnodeBank().AllVarnodes()
	params := make([]*Varnode, 0)
	locals := make([]*Varnode, 0)
	for _, vn := range all {
		if vn == nil || vn.IsConstant() || vn.IsAnnotation() {
			continue
		}
		if vn.IsInput() {
			params = append(params, vn)
			continue
		}
		if vn.Def() == nil {
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
	for i, vn := range s.params {
		s.names[vn] = fmt.Sprintf("param_%d", i)
	}
	localIndex := 0
	tmpIndex := 0
	// First pass: assign one name per storage location for non-unique varnodes.
	// Multiple SSA versions of the same register/slot share one name.
	// Register locations are resolved from registerNames first; fallback is local_N.
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
			// Check if this storage location has a known register name.
			if s.printer.registerNames != nil {
				regKey := fmt.Sprintf("%d:%d:%d", key.spaceIdx, key.offset, key.size)
				if regName, ok := s.printer.registerNames[regKey]; ok {
					locName[key] = regName
					continue
				}
			}
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
	out := op.Output()
	if out.Space() == nil || !out.Space().IsUnique() {
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
		if vn := returnValue(op); vn != nil {
			return vn.TypeReadFacing(op)
		}
	}
	return sharedTypeFactory.GetVoid()
}

func returnValue(op *PcodeOp) *Varnode {
	if op == nil || op.NumInput() == 0 {
		return nil
	}
	for i := op.NumInput() - 1; i >= 0; i-- {
		inp := op.Input(i)
		if inp == nil || inp.IsAnnotation() {
			continue
		}
		return inp
	}
	return nil
}

func (s *printCState) renderFunctionSignature(retType Datatype) string {
	name := s.fd.Name()
	if s.fd.DisplayName() != "" {
		name = s.fd.DisplayName()
	}
	paramNames := make([]string, len(s.params))
	paramTypes := make([]Datatype, len(s.params))
	for i, param := range s.params {
		paramNames[i] = s.nameOf(param)
		paramTypes[i] = s.normalizeTypeForDecl(param.TypeReadFacing(nil))
	}
	codeType := sharedTypeFactory.GetCode("", s.normalizeTypeForDecl(retType), paramTypes, false)
	return CFuncSignatureString(name, codeType, paramNames)
}

func (s *printCState) emitLocalDeclarations() {
	// Skip varnodes that share a name with an already-declared local.
	// This arises when multiple SSA versions of the same storage location
	// are merged to one local_ name by collectVarnodeNames.
	declared := make(map[string]struct{})
	for _, vn := range s.locals {
		name := s.nameOf(vn)
		if _, seen := declared[name]; seen {
			continue
		}
		declared[name] = struct{}{}
		decl := CDeclString(s.normalizeTypeForDecl(vn.TypeDefFacing()), name)
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
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "long long")
		default:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "int")
		}
	case TYPE_UINT, TYPE_UNKNOWN:
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
	children := bl.StructuredChildren()
	if len(children) < 2 {
		return s.emitListBlock(bl)
	}
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("if")
		s.lang.Space()
		s.lang.Token("(")
		s.lang.Token(s.mustRenderCondition(children[0]))
		s.lang.Token(")")
	})
	if err := s.emitBlock(children[1]); err != nil {
		return err
	}
	if len(children) == 2 {
		s.lang.CloseBlock()
		return nil
	}
	s.lang.CloseBlockWithSuffix(func() {
		s.lang.Token("else")
		s.lang.Space()
		s.lang.Token("{")
		s.lang.Indent()
	})
	if err := s.emitBlock(children[2]); err != nil {
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
		expr := ""
		if vn := returnValue(op); vn != nil {
			var err error
			expr, err = s.renderVarnode(vn, cPrecAssign)
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
	if hv := vn.High(); hv != nil && hv.Name() != "" {
		name := hv.Name()
		s.names[vn] = name
		return name
	}
	spaceName := "var"
	if vn.Space() != nil && vn.Space().Name != "" {
		spaceName = sanitizeIdent(vn.Space().Name)
	}
	name := fmt.Sprintf("%s_%x_%d", spaceName, vn.Offset(), vn.Size())
	s.names[vn] = name
	return name
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
