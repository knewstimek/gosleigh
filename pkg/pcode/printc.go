package pcode

import (
	"fmt"
	"math"
	"sort"
	"strconv"
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
	ghidraFormat    bool              // emit Ghidra-compatible formatting (no indent, brace on own line, else on new line, no comma-space)
}

func NewPrintC() *PrintC {
	return &PrintC{indentStep: "    "}
}

// SetGhidraFormat enables Ghidra-compatible output formatting:
//   - zero indentation
//   - function opening brace on its own line with blank line between signature and brace
//   - else/else-if on a new line after closing brace
//   - no space after commas in parameter lists
//
// C++ parity: Ghidra PrintC default formatting.
func (p *PrintC) SetGhidraFormat() *PrintC {
	p.ghidraFormat = true
	return p
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
	// localNames caches the local scope's symbol names (isNameUsed).
	localNames map[string]bool
	// opStack holds the ops whose expressions are being rendered, innermost
	// last; the one below an op is its reader (PrintC's readOp).
	opStack []*PcodeOp
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

	// returnCarrierParams maps a return-carrier location key to the param varnode that
	// serves as the direct return carrier (G5: identity-copy phi input detection).
	// Names are resolved post-ghost-rename by finalizeReturnCarrierRenames.
	returnCarrierParams map[locationKey]*Varnode

	// entryAnnotation and ghostParamCount come from PrintC.SetProcessEntry.
	// When non-empty, the signature is rendered as "annotation name(ghost..., real...)"
	// and real param names are offset by ghostParamCount.
	entryAnnotation string
	ghostParamCount int

	// ghidraFormat mirrors PrintC.ghidraFormat for use during emit.
	// Controls function brace placement, else newline style, and comma spacing.
	ghidraFormat bool
	// labelDone records leaves whose label was already printed.
	labelDone map[*FlowBlock]bool
	// sigLayout splits the rendered signature into the pieces
	// emitFunctionDeclaration emits separately; nil when it cannot.
	sigLayout *sigLayout

	// commentPos maps a basic block index to the warning comments PrintC must
	// emit within that block, ordered by the intra-block position they precede.
	// commentCursor tracks how far each block's list has been emitted so a block
	// visited across multiple emit calls resumes correctly. Both are empty unless
	// the decompiler recorded warnings, keeping non-warning output byte-identical.
	// C++ parity: PrintC::commsorter (CommentSorter) driven by emitBlockBasic ->
	// emitCommentGroup (printc.cc:2816/2844).
	commentPos    map[int32][]positionedComment
	commentCursor map[int32]int
}

func newPrintCState(printer *PrintC, fd *Funcdata) *printCState {
	indentStep := printer.indentStep
	if printer.ghidraFormat {
		indentStep = "" // no indentation in Ghidra format
	}
	// EmitPrettyPrint (Oppen) wrapper: inserts Ghidra-faithful line breaks at
	// maxlinesize=100. Non-wrapping output stays byte-identical to the previous
	// TextEmitter path (its sink). C++ parity: EmitPrettyPrint (prettyprint.cc).
	emitter := NewPrettyEmitter(indentStep, ppMaxLineSizeDefault)
	decls := NewCDeclRenderer()
	lang := NewPrintLanguage(emitter)
	if printer.ghidraFormat {
		decls.noCommaSpace = true
		decls.spacedArrays = true // (*param_1) [32], as PrintC::pushTypeEnd
		lang.noCommaSpace = true
	}
	return &printCState{
		printer:             printer,
		fd:                  fd,
		emitter:             emitter,
		lang:                lang,
		decls:               decls,
		names:               make(map[*Varnode]string),
		inline:              make(map[*PcodeOp]bool),
		emittedTypes:        make(map[uint64]bool),
		activeExpr:          make(map[*PcodeOp]bool),
		blockLabels:         make(map[*FlowBlock]string),
		returnCarrierParams: make(map[locationKey]*Varnode),
		entryAnnotation:     printer.entryAnnotation,
		ghostParamCount:     printer.ghostParamCount,
		ghidraFormat:        printer.ghidraFormat,
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

	// Position any auto-generated warning comments into their basic blocks so the
	// statement loop can emit them before the mapped statement. No-op (nil map)
	// when the decompiler recorded no warnings.
	// C++ parity: PrintC::docFunction -> commsorter.setupFunctionList (printc.cc:2782).
	s.commentPos = buildCommentPositions(s.fd)
	s.commentCursor = make(map[int32]int)
	s.collectSymbols()
	retType := s.inferReturnType()
	s.collectTypeDefs(retType)
	for _, param := range s.params {
		s.collectTypeDefs(param.TypeReadFacing(nil))
	}
	for _, local := range s.locals {
		s.collectTypeDefs(local.TypeDefFacing())
	}

	// Ghidra's function output carries no type definitions.
	// C++ parity: PrintC::docFunction (types print only via docTypeDefinitions).
	if s.ghidraFormat {
		s.typeDefs = nil
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

	if s.ghidraFormat {
		// Ghidra format: \n + signature + \n\n + { + \n
		// The leading blank line before the signature is part of Ghidra's output convention.
		// C++ parity: PrintC::emitBlockGraph writes a blank line before the function header.
		s.lang.Newline()
		// Header comments (host plate comments, warning headers), then a
		// blank line. C++ parity: PrintC::docFunction ->
		// emitCommentFuncHeader (emitLineComment(0, ...)).
		if hc := s.fd.headerComments(); len(hc) > 0 {
			for _, c := range hc {
				for _, l := range formatLineComment(c, 0) {
					s.lang.Token(l)
					s.lang.Newline()
				}
			}
			s.lang.Newline()
		}
		s.emitSignature(s.renderFunctionSignature(retType))
		s.lang.Newline()
		s.lang.Newline()
		s.lang.Token("{")
		s.lang.Indent()
		s.lang.Newline()
	} else {
		s.lang.OpenBlockAfter(func() {
			s.lang.Token(s.renderFunctionSignature(retType))
		})
	}
	// Apply post-ghost-rename param names to return-carrier varnodes detected in G5.
	// renderFunctionSignature has now updated param names (param_1 -> param_3 etc.),
	// so we can resolve the correct final name for the return carrier.
	// Emit blank line between declarations and body only when at least one
	// declaration was actually emitted. C++ parity: PrintC::emitLocalVarDecls
	// (printc.cc:2343) emits its separating tagLine on the same `notempty` flag
	// emitScopeVarDecls returns.
	hasVisibleLocal := s.emitLocalDeclarations()
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

	regNameByLoc := s.printer.registerNames

	// ABI-aware path: use FuncProto/ScopeLocal when a calling convention is attached.
	// C++ parity: Funcdata::printRaw uses high-level variable names from ScopeLocal.
	if fp := s.fd.GetFuncProto(); fp != nil {
		sl := s.fd.GetScopeLocal()
		all := s.fd.GetVarnodeBank().AllVarnodes()
		// liveSet is the set of Varnodes currently in the bank (i.e. not destroyed).
		// It is used to restrict the name-representative scan to live instances,
		// mirroring Ghidra's HighVariable::inst invariant (dead members are purged by
		// HighVariable::remove, variable.cc:515, which we do not port).
		liveSet := make(map[*Varnode]struct{}, len(all))
		for _, vn := range all {
			liveSet[vn] = struct{}{}
		}
		params := make([]*Varnode, 0)
		locals := make([]*Varnode, 0)
		// seenParamHV deduplicates HighVariables added to params to avoid duplicate
		// param_N declarations when multiple input SSA versions share one HighVariable.
		// C++ parity: Ghidra uses HighVariable as the unit of declaration (one per HighVar).
		seenParamHV := make(map[*HighVariable]bool)
		// seenHV deduplicates HighVariables added to locals (named HVs only).
		// Kept separate from seenParamHV so that non-input varnodes merged by
		// ActionMergeCopy into a param HighVariable can still appear in locals.
		seenHV := make(map[*HighVariable]bool)
		markerOnly := make(map[*HighVariable]*Varnode)
		// A register the convention preserves, read for its incoming value
		// (an SEH funclet's EBP): unaff_<reg>, declared as a local. The name
		// belongs to the whole variable (the input is its name representative),
		// so an instance merged through an INDIRECT (a stack argument slot
		// holding the incoming ESI) prints as unaff_ESI too. Only real reads
		// count -- the prologue save and INDIRECT guards do not.
		// C++ parity: HighVariable::getNameRepresentative (unaffected first) +
		// ScopeInternal::buildVariableName (Varnode::unaffected branch).
		unaffHigh := make(map[*HighVariable]bool)
		for _, vn := range all {
			if vn == nil || !vn.IsInput() || !vn.IsUnaffected() || vn.IsSpaceBase() {
				continue
			}
			var rn string
			if vn.HasFlags(VarnodeReturnAddress) {
				rn = "retaddr" // C++ parity: buildVariableName (unaff_retaddr)
			} else if isRegisterSpace(vn) {
				rn = regNameByLoc[fmt.Sprintf("%d:%d:%d", vn.Space().Index, vn.Offset(), vn.Size())]
			}
			if rn == "" {
				continue
			}
			insts := []*Varnode{vn}
			if hv := vn.High(); hv != nil {
				insts = insts[:0]
				for i := 0; i < hv.NumInstances(); i++ {
					if inst := hv.GetInstance(i); inst != nil {
						if _, live := liveSet[inst]; live {
							insts = append(insts, inst)
						}
					}
				}
			}
			printed := false
			for _, inst := range insts {
				if s.hasPrintedUse(inst) {
					printed = true
					break
				}
			}
			if !printed {
				continue
			}
			for _, inst := range insts {
				s.names[inst] = "unaff_" + rn
			}
			if hv := vn.High(); hv != nil {
				unaffHigh[hv] = true
			}
			locals = append(locals, vn)
		}
		for _, vn := range all {
			if vn == nil || vn.IsConstant() || vn.IsAnnotation() {
				continue
			}
			if hv := vn.High(); hv != nil && unaffHigh[hv] {
				continue
			}
			// A global variable prints by its global symbol name and is never
			// declared in the function body (only local-scope symbols are,
			// PrintC::emitScopeVarDecls).
			if e := s.fd.globalEntryOf(vn); e != nil {
				s.names[vn], _ = s.globalVarnodeName(vn, e, nil, nil, -1)
				// An implied global piece (ActionMarkExplicit lets an addrtied
				// value through to a containing ZEXT/PIECE) folds into its reader.
				if vn.Def() != nil && s.shouldInline(vn.Def()) {
					s.inline[vn.Def()] = true
				}
				continue
			}
			// Irregular input register: a live-on-entry argument register that was
			// read but not recovered as a parameter (entry-point functions under the
			// stack-based processEntry convention). Ghidra names these in_<regname>
			// and declares them as locals. This is handled before the HighVariable
			// dispatch because such inputs carry a machine-generated HV that would
			// otherwise leave them unnamed (rendered as local_<createindex>). The
			// model's RegParamOffsets gate restricts this to argument registers, so
			// frame and callee-saved registers are still skipped.
			// C++ parity: ScopeInternal::buildVariableName (database.cc:2470) -- an
			// input varnode with no parameter index (index<0) -> "in_" + regname.
			if vn.IsInput() && sl != nil && sl.model != nil && sl.model.EntryPoint &&
				isRegisterSpace(vn) && vn.NumDescend() > 0 {
				if _, isArg := sl.model.IsRegParam(vn.Offset()); isArg {
					key := fmt.Sprintf("%d:%d:%d", vn.Space().Index, vn.Offset(), vn.Size())
					if rn := regNameByLoc[key]; rn != "" {
						s.names[vn] = "in_" + rn
						if vn.Type() == nil {
							sz := vn.Size()
							if sz <= 0 {
								sz = 4
							}
							SetVarnodeType(vn, sharedTypeFactory.GetBase(int32(sz), TYPE_INT, ""))
						}
						locals = append(locals, vn)
						continue
					}
				}
			}
			// An irregular input (named in_<reg> by ActionNameVars) is a local
			// symbol, declared once. C++ parity: ScopeInternal::buildVariableName
			// (input with index < 0) + PrintC::emitScopeVarDecls.
			if hv := vn.High(); vn.IsInput() && hv != nil && (hv.irregularInput || strings.HasPrefix(hv.Name(), "in_")) {
				s.names[vn] = hv.Name()
				if !seenHV[hv] {
					seenHV[hv] = true
					locals = append(locals, vn)
				}
				continue
			}
			// Non-entry argument register that was read but not recovered as a named
			// parameter -- e.g. an accumulator parameter (read AND written) whose full
			// register-width input was created by heritage sub-register normalization and
			// then trimmed back to its sub-register by subvariable flow AFTER parameter
			// recovery ran, so the param HighVariable died with the discarded full-width
			// input. Reclaim it as a parameter by its ABI register slot so it renders as
			// param_N (assigned below by IsRegParam order) instead of a machine temp.
			// Read-only params keep their param HighVariable and take the normal path.
			// C++ parity: ScopeLocal identifies a parameter by its storage address
			// (ParamEntry), not by a pre-assigned HighVariable.
			if vn.IsInput() && sl != nil && sl.model != nil && !sl.model.EntryPoint &&
				isRegisterSpace(vn) && vn.NumDescend() > 0 {
				if _, isArg := sl.model.IsRegParam(vn.Offset()); isArg {
					hv := vn.High()
					hvName := ""
					if hv != nil {
						hvName = hv.Name()
					}
					if !strings.HasPrefix(hvName, "param_") {
						if vn.Type() == nil {
							sz := vn.Size()
							if sz <= 0 {
								sz = 4
							}
							SetVarnodeType(vn, sharedTypeFactory.GetBase(int32(sz), TYPE_INT, ""))
						}
						if hv == nil || !seenParamHV[hv] {
							if hv != nil {
								seenParamHV[hv] = true
							}
							params = append(params, vn)
						}
						continue
					}
				}
			}
			// Classify via ScopeLocal/HighVariable assignment.
			if hv := vn.High(); hv != nil {
				name := hv.Name()
				if name != "" && !s.isMachineGeneratedName(name) {
					s.names[vn] = name
				}
				// Determine if param or local by name prefix.
				// Only input varnodes (IsInput) are real function parameters; non-input
				// varnodes with a "param_" HighVariable name were merged into a param HV
				// by ActionMergeCopy and must stay in locals for G5 identity detection.
				if len(name) >= 6 && name[:6] == "param_" && vn.IsInput() {
					// Only add one representative varnode per HighVariable.
					// All SSA versions of the same logical param share one HighVariable;
					// we only need one varnode in s.params for declaration purposes.
					// Use seenParamHV (not seenHV) so non-input varnodes sharing
					// the same HV (return-carrier COPYs merged by ActionMergeCopy)
					// can still appear in locals for G5 identity detection.
					if !seenParamHV[hv] {
						seenParamHV[hv] = true
						params = append(params, vn)
					}
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
					// MULTIEQUAL/INDIRECT (phi/merge marker) outputs are never rendered as C
					// statements -- they are transparent SSA nodes. Do not register them as
					// the HighVariable representative in seenHV; doing so would block the
					// assignment statements generated by the COPY ops that feed into the phi.
					// Instead, register their name in s.names (so renderVarnodeExpr can look
					// up "local_0" for the phi output when rendering INT_ADD arguments) but
					// skip them for the declaration/statement representative list.
					// C++ parity: Ghidra's implied-varnode mechanism (ActionMarkExplicit)
					// marks phi inputs as explicit so their defining COPY ops become statements;
					// the phi itself is never emitted as a statement.
					// An extra call output (extraout_<reg>) is only ever defined by its
					// INDIRECT creation, which then stands for the declaration.
					if vn.Def() != nil && vn.Def().IsMarker() && hv.isExtraOut() && !seenHV[hv] {
						seenHV[hv] = true
						locals = append(locals, vn)
						continue
					}
					if vn.Def() != nil && vn.Def().IsMarker() {
						if _, ok := markerOnly[hv]; !ok {
							markerOnly[hv] = vn
						}
						// Name is already registered in s.names above (line: s.names[vn] = name).
						// Do NOT mark seenHV so that a non-marker SSA version of the same
						// HighVariable (e.g. the COPY that writes into this phi) can still
						// be added to locals as the declaration/statement representative.
						continue
					}
					if vn.Def() != nil && s.shouldInline(vn.Def()) {
						s.inline[vn.Def()] = true
					} else {
						// Only add one representative varnode per HighVariable for locals too.
						// Input varnodes (isInput=true, no Def) cannot generate assignment
						// statements. When a HighVariable has written SSA versions (e.g. COPY
						// ops feeding a MULTIEQUAL phi node), those written varnodes should be
						// the declaration/statement representative.
						// Therefore, input varnodes do NOT claim seenHV; written varnodes DO.
						// Input varnodes are skipped from locals entirely when the HV is already
						// represented by a written varnode, or will be once one is processed.
						// This prevents stack input SSA-version placeholders from blocking the
						// COPY assignment statements that define the actual values.
						// C++ parity: Ghidra uses isInput() varnodes only for parameters, not
						// for declaring or assigning local variables.
						if !vn.IsInput() {
							// seenHV dedup only applies to NAMED HighVariables (those given names
							// by ScopeLocal.BuildFromVarnodes). Unnamed HVs created by
							// ActionAssignHigh are deduped by location key in the locName pass
							// below, so we must NOT apply seenHV here -- otherwise all but one
							// SSA version of the same register slot would be omitted from s.locals
							// and fall through to the local_N fallback in nameOf.
							hvNamed := name != "" && !s.isMachineGeneratedName(name)
							if !seenHV[hv] || !hvNamed {
								// When a unique-space varnode's sole consumer is a MULTIEQUAL
								// with a named non-unique output, use the MULTIEQUAL output as
								// the declaration representative instead of the unique varnode.
								// The unique is the SSA intermediate after RulePropagateCopy
								// replaced stack inputs; the stack output carries the declared name.
								// C++ parity: Ghidra's mergeMarker coalesces unique inputs into
								// the stack output's HighVariable; the stack varnode is explicit
								// (declared), while the unique is implied (not declared).
								rep := vn
								if vn.Space() != nil && vn.Space().IsUnique() {
									if consumer := vn.LoneDescend(); consumer != nil &&
										consumer.Code() == CPUI_MULTIEQUAL &&
										consumer.Output() != nil &&
										consumer.Output().Space() != nil &&
										!consumer.Output().Space().IsUnique() {
										rep = consumer.Output()
									}
								}
								// Choose the declaration representative via the C++ name
								// representative (HighVariable::getNameRepresentative,
								// variable.cc:492, which keeps the member winning compareName,
								// variable.cc:456) rather than loc_tree first-wins. This makes the
								// rep -- and hence the declaration order and declaration type source
								// -- independent of the stack space index (a varnode's loc_tree
								// position). Ghidra emits declarations in scope symbol-map address
								// order (emitScopeVarDecls, printc.cc:2650), so instance visitation
								// order never drives the declaration.
								// The scan is restricted to live instances (liveSet): C++ inst holds
								// only live members (HighVariable::remove, variable.cc:515, purges dead
								// ones on Varnode destruction); we do not port remove, so an unfiltered
								// scan can pick a dead instance that the bank loop above never visits
								// (leaving it unnamed). A live rep is named by that loop
								// (s.names[vn] = name), so no direct name binding is required here.
								// The symbol (storage and use point) was fixed when
								// ActionNameVars linked it; later casts move defs but
								// not the symbol. C++ parity: Funcdata::linkSymbol.
								if lr := hv.linkedRep; hvNamed && lr != nil && lr.Space() != nil && !lr.Space().IsUnique() {
									if _, ok := liveSet[lr]; ok {
										rep = lr
									}
								} else if hvNamed {
									if nrep := highNameRepresentativeLive(hv, func(vn *Varnode) bool {
										_, ok := liveSet[vn]
										return ok
									}); nrep != nil && nrep.Space() != nil && !nrep.Space().IsUnique() {
										rep = nrep
									}
								}
								if hvNamed {
									seenHV[hv] = true
								}
								locals = append(locals, rep)
							}
						} else if hvNamed := hv.Name() != ""; hvNamed && !seenHV[hv] && !seenParamHV[hv] && !highHasWrittenInstance(hv, liveSet) {
							// An input never written in the function (a frame slot an
							// injected prologue filled) is still a local Symbol; with no
							// written representative it declares itself.
							// C++ parity: PrintC::emitScopeVarDecls declares every local
							// symbol.
							seenHV[hv] = true
							locals = append(locals, vn)
						}
						// Otherwise the written representative declares the variable.
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
			// When a unique-space varnode's sole consumer is a MULTIEQUAL with a
			// named non-unique output, use the MULTIEQUAL output as the declaration
			// representative. This mirrors the HV-path fix above for the fallback
			// path where vn.High() is nil (unique varnode not yet merged by MergeOp).
			// C++ parity: Ghidra's mergeMarker coalesces phi inputs into the stack
			// output HighVariable; the stack varnode is the declared (explicit) variable.
			rep := vn
			if vn.Space() != nil && vn.Space().IsUnique() {
				if consumer := vn.LoneDescend(); consumer != nil &&
					consumer.Code() == CPUI_MULTIEQUAL &&
					consumer.Output() != nil &&
					consumer.Output().Space() != nil &&
					!consumer.Output().Space().IsUnique() {
					rep = consumer.Output()
				}
			}
			locals = append(locals, rep)
		}
		// Parameters are ordered by ABI slot index, not by storage address:
		// register arguments come first in calling-convention order (RDI,RSI,RDX,..
		// / x0,x1,..), then stack arguments by ascending frame offset. For x86-64
		// SysV the register offset order is the INVERSE of the argument order
		// (RDI=0x38 is arg0, RSI=0x30 is arg1), so a raw address sort would emit
		// the signature reversed (param_2, param_1). C++ parity: FuncProto iterates
		// parameters by ParamList slot index (ParamEntry order), not by address.
		// regParamSlotBase keeps stack params after all register params (register
		// ABI indices are small: 0..5 for SysV) while preserving stack offset order.
		const regParamSlotBase = 1 << 20
		paramSortKey := func(vn *Varnode) int {
			if sl != nil && sl.model != nil && isRegisterSpace(vn) {
				if idx, ok := sl.model.IsRegParam(vn.Offset()); ok {
					return idx
				}
			}
			// Stack params sort after register params, in ascending frame offset.
			return regParamSlotBase + int(vn.Offset()&0xffff)
		}
		sort.Slice(params, func(i, j int) bool {
			ki, kj := paramSortKey(params[i]), paramSortKey(params[j])
			if ki != kj {
				return ki < kj
			}
			return CompareLocDef(params[i], params[j]) < 0
		})
		// A variable only ever defined by MULTIEQUAL/INDIRECT (a stack slot a
		// call writes) is still a symbol and is declared through one of them.
		// C++ parity: PrintC::emitScopeVarDecls declares every local symbol.
		for hv, vn := range markerOnly {
			if !seenHV[hv] && !seenParamHV[hv] && !vn.IsInput() {
				seenHV[hv] = true
				locals = append(locals, vn)
			}
		}
		// Mapped symbols declare in storage order, then dynamic symbols.
		// C++ parity: PrintC::emitScopeVarDecls (MapIterator, then the
		// dynamic list).
		sort.Slice(locals, func(i, j int) bool {
			di := locals[i].High() != nil && locals[i].High().dynamicSym
			dj := locals[j].High() != nil && locals[j].High().dynamicSym
			if di != dj {
				return dj
			}
			if c := s.compareMapOrder(locals[i], locals[j]); c != 0 {
				return c < 0
			}
			return CompareLocDef(locals[i], locals[j]) < 0
		})
		s.params = dedupVarnodes(params)
		s.locals = dedupVarnodes(locals)
		s.applySelfLockedParams()
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
			params = append(params, vn)
			continue
		}
		if vn.Def() == nil {
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

// shouldInline decides whether an op's output should be inlined into its sole
// consumer (i.e., the op does not emit a standalone statement).
//
// H8 DIAGNOSTIC NOTE (2026-04-13, A16):
// Previous root-cause hypothesis ("Cover.rebuild misses cross-block liveness")
// was WRONG. The real root cause of TestMSVC_Gcd was that ActionBlockStructure
// CLONED the basic-block graph into a separate structure graph and the clones
// kept a SNAPSHOT of the op list at clone time. Later passes (ActionMergeRequired
// -> Merge::trimOpInput) inserted COPY ops into the ORIGINAL basic blocks; those
// COPYs never appeared in the cloned structure graph that PrintC walks.
//
// FIXED in A16 by making BlockBasic clones delegate their op list to the source
// basic block via a srcDelegate field (block_basic.go). This mirrors C++ Ghidra's
// BlockCopy wrapper that holds a pointer to the original FlowBlock rather than
// copying its ops. After this fix, trim COPYs inserted post-structuring do render.
//
// Remaining mismatch (follow-up work after A16):
//
//	Gosleigh output:
//	  while (param_4 != 0) {
//	    param_4 = param_3 % param_4;
//	    param_3 = param_4;
//	  }
//
//	Ghidra golden:
//	  while (iVar1 = param_4, iVar1 != 0) {
//	    param_4 = param_3 % iVar1;
//	    param_3 = iVar1;
//	  }
//
// The remaining differences are:
//
//	(a) iVar1 variable does not appear as a distinct HighVariable. Gosleigh's
//	    MergeMarker over-merges the register:0x4 (ECX) HV INTO the stack:0x8
//	    (param_4) HV via the MULTIEQUAL phi output that gets named "param_4".
//	    Ghidra keeps them as two separate phi nodes (one for ECX -> iVar1, one
//	    for stack -> param_4). Likely root: Gosleigh's joinblock collapse/NodeJoin
//	    produces fewer phis than Ghidra and then merges too aggressively.
//	    Investigate: RulePushMultiME, NodeJoin, ActionNameVars interactions.
//	(b) No comma expression in the while header. In Ghidra, the entry-slot trim
//	    COPY lands in a block that gets emitted together with the cond block in
//	    setMod(comma_separate) mode. Either Ghidra absorbs the entry block into
//	    cond via BlockList, or it collapses degenerate predecessors. Investigate:
//	    ActionBlockStructure block merging for single-op predecessors.
//
// C++ parity: ActionMarkExplicit::baseExplicit in coreaction.cc:3083.
func (s *printCState) shouldInline(op *PcodeOp) bool {
	if op == nil || op.Output() == nil || op.IsDead() {
		return false
	}
	out := op.Output()
	// Only an IMPLIED varnode is folded into its consumer; an EXPLICIT one is
	// materialized as a named temporary. C++ parity: PrintLanguage::pushVn
	// dispatches on isImplied() alone, independent of the descendant count
	// (printlanguage.cc), and ActionMarkImplied::apply (coreaction.cc) is what
	// sets the flag -- it keeps a cheap expression implied when it is used a small
	// number of times (maxduplicate=2) and its cover is safe, so e.g. "a >> 0x20"
	// used twice term-duplicates inline at both sites (umulhi).
	//
	// Gosleigh used to default-inline every single-descendant op regardless of the
	// flag. That proxy papered over a structural divergence -- AddTreeState ops
	// were created detached from any basic block, so loop-carried PTRADDs ended up
	// in their own HighVariable behind an extra latch COPY -- which is now fixed at
	// the source in Funcdata.NewOpBefore / AddTreeState.buildTree.
	if !out.IsImplied() {
		return false
	}
	if out.NumDescend() != 1 {
		switch op.Code() {
		case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_STORE, CPUI_RETURN,
			CPUI_MULTIEQUAL, CPUI_INDIRECT, CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER, CPUI_NEW:
			return false
		}
		return true
	}
	// Single-descendant path.
	// C++ parity: ActionMarkExplicit::baseExplicit returns -1 (explicit) when any descendant is a marker op (MULTIEQUAL/INDIRECT). coreaction.cc:3083
	// A varnode whose sole consumer is a marker op must be emitted as an explicit statement, not inlined.
	consumer := op.Output().LoneDescend()
	if consumer != nil {
		switch consumer.Code() {
		case CPUI_MULTIEQUAL, CPUI_INDIRECT:
			return false
		}
	}
	// An op whose output lives in a non-unique space (register/stack) and
	// carries a distinct HighVariable must surface as a user-visible statement
	// rather than be inlined into its consumer. C++ parity: printc.cc
	// emitBlockBasic skips markers via notPrinted() but explicit named outputs
	// are always emitted as statements.
	if out := op.Output(); out != nil && out.Space() != nil && !out.Space().IsUnique() {
		if hv := out.High(); hv != nil && hv.Name() != "" {
			// When the consumer is a cross-block COPY that lives in a join/loop-head
			// block, the body assignment must be rendered. A same-HV inline would
			// produce the same text, but the body op carries the actual statement.
			if consumer != nil && consumer.Parent() != op.Parent() {
				return false
			}
		}
	}
	switch op.Code() {
	case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_STORE, CPUI_RETURN, CPUI_MULTIEQUAL, CPUI_INDIRECT:
		return false
	default:
		// A call output is explicit (ActionMarkExplicit::baseExplicit, isCall
		// branch) except the implied unique ActionSetCasts::castOutput moves it
		// to, which folds into its CAST: "puVar1 = (T *)FUN_x(...)".
		return true
	}
}

func (s *printCState) inferReturnType() Datatype {
	// The signature prints the output type ActionOutputPrototype fixed
	// before ActionSetCasts. C++ parity: FuncProto::updateOutputTypes.
	if s.fd != nil {
		if fp := s.fd.GetFuncProto(); fp != nil && fp.GetOutput() != nil {
			if dt := fp.GetOutput().Type(); dt != nil {
				return dt
			}
		}
	}
	return sharedTypeFactory.GetVoid()
}

func returnValue(op *PcodeOp) *Varnode {
	// Input 0 is the return-address placeholder (a constant; 1 on an
	// artificial halt); only input 1 is a return value.
	// C++ parity: PrintC::opReturn (if numInput()>1 push getIn(1)).
	if op == nil || op.NumInput() <= 1 {
		return nil
	}
	inp := op.Input(1)
	if inp == nil || inp.IsAnnotation() {
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
		// The formal type is the merged HighVariable's type.
		// C++ parity: FuncProto::updateInputTypes (vn->getHigh()->getType()).
		realParamTypes[i] = s.normalizeTypeForDecl(param.HighTypeDefFacing())
		existing := s.nameOf(param)
		if s.ghostParamCount > 0 && strings.HasPrefix(existing, "param_") {
			// Renumber: real param i becomes param_(ghostParamCount+i+1).
			// Update s.names for the representative varnode, ALL other instances of the
			// same HighVariable, and the HighVariable name itself.
			// This is necessary because ScopeLocal may assign multiple SSA versions of the
			// same logical param to one HighVariable (all pointing to the same param slot).
			// collectSymbols pre-populates s.names[vn] = hv.Name() for those versions;
			// without updating all of them, body references to non-representative varnodes
			// would still show the old un-shifted name (e.g. "param_2" instead of "param_4").
			// C++ parity: Ghidra uses HighVariable as the unit of naming; all instances
			// share a single name through the HighVariable.
			newName := fmt.Sprintf("param_%d", s.ghostParamCount+i+1)
			s.names[param] = newName
			if hv := param.High(); hv != nil {
				hv.SetName(newName)
				// Update all other SSA versions (instances) of this HighVariable.
				for j := 0; j < hv.NumInstances(); j++ {
					inst := hv.GetInstance(j)
					if inst != nil && inst != param {
						s.names[inst] = newName
					}
				}
			}
			realParamNames[i] = newName
		} else {
			realParamNames[i] = existing
		}
	}

	// Build ghost param lists (undefined4 param_1, param_2, ...).
	// When the function has no real parameters (s.params is empty) and only ghost
	// params exist, Ghidra renders (void) rather than the ghost params.
	// C++ parity: processEntry CC with no real args -> ProtoModel marks no real
	// parameters -> PrintC emits "void" for the parameter list.
	var ghostNames []string
	var ghostTypes []Datatype
	if len(s.params) > 0 {
		ghostNames = make([]string, s.ghostParamCount)
		ghostTypes = make([]Datatype, s.ghostParamCount)
		for i := 0; i < s.ghostParamCount; i++ {
			ghostNames[i] = fmt.Sprintf("param_%d", i+1)
			ghostTypes[i] = sharedTypeFactory.GetBase(4, TYPE_UNKNOWN, "undefined4")
		}
	}

	allNames := append(ghostNames, realParamNames...)
	allTypes := append(ghostTypes, realParamTypes...)

	// Prepend annotation to name when set (e.g. "processEntry entry").
	displayName := name
	if s.entryAnnotation != "" {
		displayName = s.entryAnnotation + " " + name
	} else if fp := s.fd.GetFuncProto(); fp != nil && fp.Model() != nil && fp.Model().PrintInDecl && !fp.Model().IsMerged() {
		// A model other than the architecture default prints its name.
		// C++ parity: printc.cc PrintC::emitFunctionDeclaration (printModelInDecl).
		displayName = fp.Model().Name + " " + name
	}

	codeType := sharedTypeFactory.GetCode("", s.normalizeTypeForDecl(retType), allTypes, false)
	// Use s.decls (which has noCommaSpace set in ghidraFormat mode) instead of the
	// global CFuncSignatureString helper, which always uses a default CDeclRenderer.
	sig := s.decls.FunctionSignature(displayName, codeType, allNames)
	// The return type is printed whole and then a space, so a pointer return
	// reads "undefined4 * FUN_x(...)" rather than the declarator form
	// "undefined4 *FUN_x(...)".
	// C++ parity: printc.cc PrintC::emitPrototypeOutput + emit->spaces(1).
	if s.printer.ghidraFormat {
		sig = strings.Replace(sig, "*"+displayName+"(", "* "+displayName+"(", 1)
		// A pointer to an array or a function returned prints as an abstract
		// type (undefined1 (*) [32]) ahead of the name, not as a declarator
		// wrapped around it. C++ parity: emitPrototypeOutput -> pushType.
		if ptr, ok := codeType.ReturnType().(*Pointer); ok && needsWrappedDeclarator(ptr.Pointee()) {
			params := []string{"void"}
			if len(allTypes) > 0 {
				params = params[:0]
				for i, dt := range allTypes {
					params = append(params, s.decls.Declaration(dt, allNames[i]))
				}
			}
			sig = printedTypeString(ptr) + " " + displayName + "(" + strings.Join(params, ",") + ")"
		}
	}
	s.sigLayout = nil
	if s.printer.ghidraFormat {
		s.sigLayout = newSigLayout(s.decls, sig, name, strings.TrimSuffix(displayName, name), allTypes, allNames)
	}
	return sig
}

// emitLocalDeclarations emits one "type name;" statement per declared local and
// reports whether anything was emitted.
// C++ parity: PrintC::emitLocalVarDecls / emitScopeVarDecls `notempty`.
func (s *printCState) emitLocalDeclarations() bool {
	// Skip varnodes that share a name with an already-declared local.
	// This arises when multiple SSA versions of the same storage location
	// are merged to one local_ name by collectVarnodeNames.
	declared := make(map[string]struct{})
	var sl *ScopeLocal
	if s.fd != nil {
		sl = s.fd.GetScopeLocal()
	}
	decls := make([]localDecl, 0, len(s.locals))
	for _, vn := range s.locals {
		// Skip implied unique-space varnodes: their defining ops are suppressed by
		// emitOps (unique-space ops are SSA intermediates, not C variables), so a
		// tmp_N name is never used in any emitted statement. Declaring them produces
		// a spurious "undefined tmp_0;" with no corresponding assignment.
		// C++ parity: Ghidra suppresses unique temps via ActionMarkImplied.
		// An EXPLICIT unique (e.g. the loop-head snapshot iVar1 = COPY(param)) is a
		// real printed variable and must be declared like any other local.
		if vn.Space() != nil && vn.Space().IsUnique() && !vn.IsExplicit() {
			continue
		}
		// Globals are never declared in the body (a representative swap can
		// carry a global Varnode into s.locals).
		if s.fd.globalEntryOf(vn) != nil {
			continue
		}
		// A piece of a grouped variable is printed through the whole variable,
		// which carries the declaration: the stack Symbol holding it.
		// C++ parity: the group shares one Symbol; emitScopeVarDecls declares it.
		if namedGroupRoot(vn.High(), sl) != nil {
			if sl == nil || vn.Space() != sl.SpaceID() {
				continue
			}
			e := sl.QueryContainer(vn.Addr(), vn.Size(), address.Address{})
			if e == nil || e.Offset() != 0 || e.Symbol() == nil || e.Symbol().Name() == "" || e.Symbol().Type() == nil {
				continue
			}
			name := e.Symbol().Name()
			if _, seen := declared[name]; seen || s.isParamName(name) {
				continue
			}
			declared[name] = struct{}{}
			decls = append(decls, localDecl{
				text:      localDeclString(s.normalizeTypeForDecl(e.Symbol().Type()), name),
				hasOffset: true,
				offset:    e.Addr().Offset,
			})
			continue
		}
		name := s.nameOf(vn)
		if _, seen := declared[name]; seen {
			continue
		}
		// Skip locals whose name was remapped to a parameter name (G5: identity
		// return-carrier). The parameter is already declared in the function
		// signature; re-declaring it as a local would produce duplicate declarations.
		// C++ parity: ActionReturnSplit reuses the param as the return carrier.
		if s.isParamName(name) {
			continue
		}
		declared[name] = struct{}{}
		var dt Datatype
		if st := s.stackSymbolType(vn); st != nil {
			dt = st
		} else {
			// The declaration is the variable's Symbol, typed with the
			// HighVariable's type (not a resolved field of it).
			// C++ parity: Funcdata::linkSymbol (addSymbol with high->getType()).
			ht := vn.HighTypeDefFacing()
			if hv := vn.High(); hv != nil && hv.Type() != nil {
				ht = hv.Type()
			}
			dt = s.normalizeTypeForDecl(ht)
		}
		// A default name's prefix is the printNameBase of the type the
		// variable is declared with; types can still settle after
		// ActionNameVars ran, so re-derive it from the final declared type.
		// C++ parity: buildVariableName names with the symbol's (final) type.
		if renamed := defaultNameWithType(name, dt); renamed != name {
			s.renameLocal(vn, name, renamed)
			delete(declared, name)
			declared[renamed] = struct{}{}
			name = renamed
		}
		decl := localDeclString(dt, name)
		rec := localDecl{text: decl}
		if sp := vn.Space(); sp != nil && sl != nil && sp == sl.SpaceID() {
			rec.hasOffset = true
			rec.offset = vn.Addr().Offset
		} else if e := s.stackEntryOf(vn.High()); e != nil {
			rec.hasOffset = true // A temporary declaring its stack Symbol
			rec.offset = e.Addr().Offset
		}
		decls = append(decls, rec)
	}
	decls = s.mergeScopeOnlyDecls(decls, declared)
	for _, d := range decls {
		text := d.text
		s.lang.Statement(func() {
			s.lang.DeclTokens(text)
		})
	}
	return len(decls) != 0
}

// localDeclString renders a local variable declaration.
// C++ parity: printc.cc PrintC::emitVarDecl -> pushTypeStart/pushTypeEnd.
func localDeclString(dt Datatype, name string) string {
	return printedDeclString(dt, name)
}

// localDecl is one emitted local declaration, tagged with its stack offset when
// the declaration comes from a Symbol/Varnode living in the scope's own space.
// The offset is what orders scope-only declarations against Varnode-backed ones.
type localDecl struct {
	text      string
	hasOffset bool
	offset    uint64
}

// mergeScopeOnlyDecls adds a declaration for every ScopeLocal Symbol that no
// Varnode declared. Gosleigh drives emitLocalDeclarations off the Varnode list,
// but C++ PrintC::emitLocalVarDecls (printc.cc:2326) drives it off the scope's
// Symbol map via emitScopeVarDecls (printc.cc:2650), so a Symbol with no Varnode
// of its own -- exactly the recovered stack arrays ScopeLocal::restructure
// synthesizes from open RangeHints -- was structurally impossible to declare.
//
// The scope-only Symbols are spliced into the Varnode-driven sequence by
// unsigned address, which is the order the C++ MapIterator walks the scope's
// rangemap in (and why "local_res8" at frame offset +8 precedes the negative
// frame slots in Ghidra output). Symbols that a Varnode already declared are
// skipped here rather than in the main loop, so the existing sequence -- and
// therefore every function with no scope-only Symbol -- is byte-identical.
//
// C++ filters reproduced from emitScopeVarDecls: piece entries, unnamed symbols
// and non-first entries of a multi-entry Symbol are not declared. FunctionSymbol
// / LabSymbol have no Gosleigh equivalent in ScopeLocal.
func (s *printCState) mergeScopeOnlyDecls(decls []localDecl, declared map[string]struct{}) []localDecl {
	if s.fd == nil {
		return decls
	}
	sl := s.fd.GetScopeLocal()
	if sl == nil {
		return decls
	}
	space := sl.SpaceID()
	for _, e := range sl.Entries() {
		if e == nil || e.IsDynamic() || e.Offset() != 0 {
			continue // Don't do a partial entry
		}
		sym := e.Symbol()
		if sym == nil || sym.Name() == "" {
			continue
		}
		name := sym.Name()
		if _, seen := declared[name]; seen {
			continue
		}
		if s.isParamName(name) {
			continue
		}
		dt := sym.Type()
		if dt == nil {
			continue
		}
		declared[name] = struct{}{}
		rec := localDecl{
			text:      localDeclString(s.normalizeTypeForDecl(dt), name),
			hasOffset: e.Addr().Space == space,
			offset:    e.Addr().Offset,
		}
		pos := len(decls)
		if rec.hasOffset {
			for i, d := range decls {
				if d.hasOffset && d.offset > rec.offset {
					pos = i
					break
				}
			}
		}
		decls = append(decls, localDecl{})
		copy(decls[pos+1:], decls[pos:])
		decls[pos] = rec
	}
	return decls
}

// stackSymbolType returns the declaration data-type for a stack Varnode taken
// from its ScopeLocal SymbolEntry (built by RestructureVarnode from the committed
// Varnode types via RangeHint), or nil when the Varnode does not map to a stack
// Symbol. A TYPE_UNKNOWN symbol renders as undefined<size>, matching Ghidra's
// undefined stack locals. This is the STEP 4 declaration source: the symbol type
// is snapshotted at restructure time, so it does not leak the later-propagated
// Varnode type. C++ parity: PrintC::emitVarDecl uses sym->getType().
func (s *printCState) stackSymbolType(vn *Varnode) Datatype {
	if vn == nil || vn.Space() == nil || s.fd == nil {
		return nil
	}
	var st Datatype
	if hv := vn.High(); hv != nil && vn.Space().IsUnique() {
		// A temporary standing for a stack variable declares that
		// variable's Symbol. C++ parity: PrintC::emitVarDecl (sym->getType()).
		if e := s.stackEntryOf(hv); e != nil && e.Symbol() != nil {
			st = e.Symbol().Type()
		}
		if st == nil {
			return nil
		}
	} else {
		if vn.Space().IsUnique() {
			return nil
		}
		sl := s.fd.GetScopeLocal()
		if sl == nil {
			return nil
		}
		e := sl.FindEntryAt(vn.Addr(), int32(vn.Size()))
		if e == nil {
			// A piece of a larger stack variable declares the variable.
			e = sl.QueryContainer(vn.Addr(), vn.Size(), address.Address{})
		}
		if e == nil || e.Symbol() == nil {
			return nil
		}
		st = e.Symbol().Type()
	}
	if st == nil {
		return nil
	}
	if st.Metatype() == TYPE_UNKNOWN {
		// The declaration is the symbol's, whatever piece of it vn is.
		// C++ parity: PrintC::emitVarDecl prints sym->getType().
		return sharedTypeFactory.GetBase(st.Size(), TYPE_UNKNOWN, unknownTypeName(st.Size()))
	}
	return s.normalizeTypeForDecl(st)
}

// stackEntryOf is the local stack Symbol entry a variable's stack instances
// map to (the largest, when pieces map separately).
func (s *printCState) stackEntryOf(hv *HighVariable) *SymbolEntry {
	sl := s.fd.GetScopeLocal()
	if sl == nil || hv == nil {
		return nil
	}
	var best *SymbolEntry
	for _, inst := range hv.instances {
		if inst == nil || inst.Space() != sl.SpaceID() {
			continue
		}
		if e := sl.QueryContainer(inst.Addr(), inst.Size(), address.Address{}); e != nil && (best == nil || e.Size() > best.Size()) {
			best = e
		}
	}
	return best
}

func (s *printCState) normalizeTypeForDecl(dt Datatype) Datatype {
	if dt == nil {
		return sharedTypeFactory.GetVoid()
	}
	switch typed := dt.(type) {
	case *Pointer:
		if typed.Flags()&datatypeTypedef != 0 {
			return typed // a typedef prints by its name
		}
		return sharedTypeFactory.GetPointer(typed.Size(), s.normalizeTypeForDecl(typed.Pointee()), typed.WordSize())
	case *Array:
		return sharedTypeFactory.GetArray(typed.Count(), s.normalizeTypeForDecl(typed.Element()))
	case *Code:
		// Preserve a prototype-less code type as-is: normalizing its nil return to
		// void would resurrect a "void (*)(void)" signature and lose the bare
		// "code" spelling Ghidra uses for unknown-signature indirect-call targets.
		if !typed.HasPrototype() {
			return typed
		}
		params := typed.ParameterTypes()
		normalizedParams := make([]Datatype, len(params))
		for i, param := range params {
			normalizedParams[i] = s.normalizeTypeForDecl(param)
		}
		return sharedTypeFactory.GetCode(typed.Name(), s.normalizeTypeForDecl(typed.ReturnType()), normalizedParams, typed.IsVariadic())
	case *Struct:
		if typed.Flags()&datatypeHostNamed != 0 {
			return typed // A host structure is printed as the host defines it
		}
		fields := typed.Fields()
		normalizedFields := make([]TypeField, len(fields))
		for i, field := range fields {
			normalizedFields[i] = field
			normalizedFields[i].Type = s.normalizeTypeForDecl(field.Type)
		}
		return sharedTypeFactory.GetStructSized(typed.Name(), typed.Size(), normalizedFields)
	case *Union:
		fields := typed.Fields()
		normalizedFields := make([]TypeField, len(fields))
		for i, field := range fields {
			normalizedFields[i] = field
			normalizedFields[i].Type = s.normalizeTypeForDecl(field.Type)
		}
		return sharedTypeFactory.GetUnion(typed.Name(), normalizedFields)
	case *Enum:
		return typed // An enumeration prints by its name
	case *Base:
		if typed.Flags()&datatypeTypedef != 0 {
			return typed // a typedef prints by its name
		}
		switch typed.SubMeta() {
		case SUB_INT_UNICODE, SUB_UINT_UNICODE, SUB_UINT_CHAR, SUB_INT_CHAR:
			if typed.Name() != "" {
				return typed // a character type prints by its name (wchar_t, uchar, schar)
			}
		}
		if typed.Flags()&datatypeHostNamed != 0 {
			return typed // C++ prints every data-type by its own name
		}
		return normalizedBaseType(typed, s.longSize())
	default:
		return dt
	}
}

// longSize returns the target's size of C "long" in bytes, taken from the proto
// model's data_organization. Defaults to 8 (LP64) when no model is available.
// This drives whether an 8-byte signed integer is spelled "long" (LP64) or
// "longlong" (LLP64 / Windows x64).
// C++ parity: TypeFactory::sizeOfLong governs which core type fills the size-8 int
// cache slot ("long" when sizeOfLong==8, otherwise "longlong").
func (s *printCState) longSize() int {
	if s != nil && s.fd != nil {
		if fp := s.fd.GetFuncProto(); fp != nil {
			if pm := fp.Model(); pm != nil && pm.LongSize > 0 {
				return pm.LongSize
			}
		}
		if pm := s.fd.DefaultModel(); pm != nil && pm.LongSize > 0 {
			return pm.LongSize
		}
	}
	return 8
}

func normalizedBaseType(base *Base, longSize int) Datatype {
	if base == nil {
		return sharedTypeFactory.GetBase(4, TYPE_UINT, "uint")
	}
	switch base.Metatype() {
	case TYPE_BOOL:
		// Ghidra names the boolean core type "bool" (type.cc:291-292
		// TypeFactory metatype naming), not the C keyword "_Bool".
		return sharedTypeFactory.GetBase(base.Size(), TYPE_BOOL, "bool")
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
			// A size-1 signed integer is spelled "char", not "signed char":
			// Ghidra registers an ASCII "char" core type (TYPE_INT size 1,
			// chartype) that is preferred over any non-char int1 when filling
			// the size-1 TYPE_INT cache slot, so getBase(1,TYPE_INT) resolves
			// to "char" and that is the name every plain 1-byte signed value
			// prints with (golden never emits "signed char").
			// C++ parity: TypeFactory::cacheCoreTypes (type.cc:3645-3646, the
			// "Char is preferred over other int types" branch) plus the
			// setCoreType("char",1,TYPE_INT,true) registration (ghidra_arch.cc:340).
			if base.Name() == "sbyte" {
				return base // the non-character int1 (getBaseNoChar)
			}
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "char")
		case 2:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "short")
		case 4:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "int")
		case 8:
			// 8-byte signed integer. Ghidra names it "long" on LP64 (sizeOfLong==8)
			// and "longlong" on LLP64 / Windows x64 (sizeOfLong==4), matching which
			// core type fills TypeFactory's size-8 int cache slot: on LLP64 "long" is
			// 4 bytes so only "longlong" is size 8; on LP64 both are size 8 and "long"
			// wins the cache slot.
			// C++ parity: TypeFactory::setupSizes / cacheCoreTypes (type.cc).
			if longSize >= 8 {
				return sharedTypeFactory.getSpelling(base.Size(), TYPE_INT, "long")
			}
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "longlong")
		default:
			// Odd sizes are core types named by size: int3, int5, int16.
			// C++ parity: the <coretypes> names (ghidra_arch / Java).
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, fmt.Sprintf("int%d", base.Size()))
		}
	case TYPE_UNKNOWN:
		// The host's DefaultDataType keeps its own name ("undefined").
		if base.Name() == "undefined" {
			return base
		}
		// Preserve TYPE_UNKNOWN as Ghidra's "undefined%d" type.
		// C++ parity: Ghidra uses TYPE_UNKNOWN for untyped bytes; prints as undefined1/2/4/8.
		// normalizeTypeForDecl must NOT coerce this to TYPE_UINT -- that would lose the
		// distinction between a typed unsigned and an untyped/undefined slot.
		return sharedTypeFactory.GetBase(base.Size(), TYPE_UNKNOWN, unknownTypeName(base.Size()))
	case TYPE_UINT:
		// Ghidra prints dt->getName() for its interned core types; the Java-side
		// <coretypes> element names the unsigned bases with short forms, not the
		// C-standard spellings. Mirror the signed TYPE_INT arm above so the
		// signed/unsigned pair stays consistent.
		// C++ parity: type.cc coretype names (byte/ushort/uint/ulong/ulonglong).
		switch base.Size() {
		case 1:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "byte")
		case 2:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "ushort")
		case 4:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "uint")
		case 8:
			// 8-byte unsigned integer. Same longSize() split as the signed size-8
			// name: "ulong" on LP64 (sizeOfLong==8), "ulonglong" on LLP64 /
			// Windows x64 (sizeOfLong==4), matching which unsigned core type fills
			// the size-8 cache slot.
			if longSize >= 8 {
				return sharedTypeFactory.getSpelling(base.Size(), TYPE_UINT, "ulong")
			}
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "ulonglong")
		default:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, fmt.Sprintf("uint%d", base.Size()))
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
	return s.emitBlock(bl)
}

// emitAnyLabel prints the label of the leaf starting bl when that leaf is
// the target of a printed goto, unless an enclosing block prints it.
// C++ parity: PrintC::emitAnyLabelStatement / emitLabelStatement.
func (s *printCState) emitAnyLabel(bl *FlowBlock) {
	leaf := s.pendingLabelLeaf(bl)
	if leaf == nil {
		return
	}
	if s.labelDone == nil {
		s.labelDone = make(map[*FlowBlock]bool)
	}
	s.labelDone[leaf] = true
	s.lang.Label(s.labelForBlock(leaf))
}

// pendingLabelLeaf returns the leaf whose label emitAnyLabel would print.
func (s *printCState) pendingLabelLeaf(bl *FlowBlock) *FlowBlock {
	if bl == nil || bl.HasFlag(BlockFlagLabelBumpUp) {
		return nil
	}
	leaf := bl.getFrontLeaf()
	if leaf == nil || !leaf.HasFlag(BlockFlagUnstructuredTarg) || s.labelDone[leaf] {
		return nil
	}
	return leaf
}

func (s *printCState) emitBlock(bl *FlowBlock) error {
	if bl == nil {
		return nil
	}
	s.emitAnyLabel(bl)
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
		// A condition block reached standalone (not consumed by an if/loop header)
		// has no branch mod set; C++ emitBlockCondition emits nothing in that case
		// (printc.cc:2968 falls through). Emit block(0)'s leading statements (the
		// no_branch behavior) so real assignments are not dropped.
		return s.emitConditionLead(bl)
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
	// A BlockIf produced by newBlockIfGoto stores a goto target and has its true
	// edge removed; it renders as "if (cond) goto label;" with no braced body.
	// C++ parity: PrintC::emitBlockIf getGotoTarget() != 0 branch (printc.cc:3046).
	if bl.GotoTargetBlock() != nil {
		return s.emitIfGotoBlock(bl)
	}
	return s.emitIfBlockChain(bl, false)
}

// emitIfGotoBlock renders a conditional goto: "if (cond) goto label;". The
// enclosing structure emits the fall-through (false) path as the following block.
// C++ parity: PrintC::emitBlockIf with getGotoTarget() set (printc.cc:3046-3049).
func (s *printCState) emitIfGotoBlock(bl *FlowBlock) error {
	condChild := bl
	if children := bl.StructuredChildren(); len(children) > 0 {
		condChild = children[0]
	}
	cond := s.mustRenderConditionFrag(condChild)
	if err := s.emitConditionLead(condChild); err != nil {
		return err
	}
	s.lang.Line(func() {
		s.lang.Token("if")
		s.lang.Space()
		s.emitConditionParen(cond)
		s.lang.Space()
		s.lang.StatementGroup(func() { // emitGotoStatement's beginStatement
			s.emitGotoStatement(bl)
			s.lang.Token(";")
		})
	})
	return nil
}

// isBlockEmpty reports whether a block would produce no visible C output.
// A block is empty when all its ops are dead, inlined, prologue, identity, or
// unique-space temporaries with no named consumers.
//
// Used to suppress empty else branches (e.g., after G5 identity-copy elimination).
// C++ parity: Ghidra's ActionReturnSplit removes the identity branch entirely
// from the block graph; we approximate by skipping empty else at render time.
func (s *printCState) isBlockEmpty(bl *FlowBlock) bool {
	bb, ok := bl.Concrete().(*BlockBasic)
	if !ok {
		return false
	}
	for _, op := range bb.Ops() {
		if op == nil || op.IsDead() || s.inline[op] {
			continue
		}
		if op.HasFlag(PcodeOpNonPrinting) {
			continue
		}
		if out := op.Output(); out != nil {
			if out.Space() != nil && out.Space().IsUnique() && out.NumDescend() == 0 {
				continue
			}
			if out.IsFree() {
				continue
			}
		}
		if isControlOpcode(op.Code()) {
			continue
		}
		return false
	}
	return true
}

// emitConditionLead emits the leading (non-branch) statements of a condition
// block before the enclosing "if"/loop header. For a compound BlockCondition it
// descends into block(0) -- the only sub-block C++ emits under no_branch -- and
// for a basic block it emits the block's ops with the final branch suppressed.
// C++ parity: PrintC::emitBlockIf emits condBlock with no_branch (printc.cc:3026)
// -> emitBlockCondition's no_branch path emits getBlock(0) recursively
// (printc.cc:2972); a BlockList head follows emitBlockLs's no_branch path
// (printc.cc:2925-2965), emitting every leading sub-block in full and only the
// final sub-block's lead.
func (s *printCState) emitConditionLead(bl *FlowBlock) error {
	if bl == nil {
		return nil
	}
	if bl.Type() == BlockConditionType || bl.Type() == BlockMultiGotoType {
		// A multi-goto block emits as its inner block.
		// C++ parity: BlockMultiGoto::emit (getBlock(0)->emit).
		children := bl.StructuredChildren()
		if len(children) > 0 {
			return s.emitConditionLead(children[0])
		}
		return nil
	}
	if bl.Type() == BlockListType {
		// emitBlockLs no_branch (printc.cc:2925-2965): the leading sub-blocks are
		// full statements (e.g. guarded returns); only the final sub-block's branch
		// is withheld for the enclosing "if".
		children := bl.StructuredChildren()
		if len(children) == 0 {
			return nil
		}
		for i := 0; i+1 < len(children); i++ {
			if err := s.emitBlock(children[i]); err != nil {
				return err
			}
		}
		return s.emitConditionLead(children[len(children)-1])
	}
	if basic := toBasic(bl); basic != nil {
		// A condition leaf is still a BlockCopy: its label comes first.
		// C++ parity: PrintC::emitBlockCopy (emitAnyLabelStatement).
		s.emitAnyLabel(bl)
		return s.emitOps(basic, true)
	}
	return nil
}

// conditionLeadEmpty reports whether emitConditionLead would print nothing.
func (s *printCState) conditionLeadEmpty(bl *FlowBlock) bool {
	if bl == nil {
		return true
	}
	children := bl.StructuredChildren()
	switch bl.Type() {
	case BlockConditionType:
		return len(children) == 0 || s.conditionLeadEmpty(children[0])
	case BlockListType:
		for i := 0; i+1 < len(children); i++ {
			if !s.isBlockEmpty(children[i]) {
				return false
			}
		}
		return len(children) == 0 || s.conditionLeadEmpty(children[len(children)-1])
	}
	if basic := toBasic(bl); basic != nil {
		return s.pendingLabelLeaf(bl) == nil && s.isBlockEmpty(&basic.FlowBlock)
	}
	return true
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
	cond := s.mustRenderConditionFrag(children[0])
	if isElseIf {
		if s.ghidraFormat {
			// Ghidra format: close brace on own line, then "else if (cond) {" on next line.
			// C++ parity: Ghidra PrintC emits "}\nelse if (cond) {\n" for else-if chains.
			s.lang.CloseBlock()
			s.lang.Token("else")
			s.lang.Space()
			s.lang.Token("if")
			s.lang.Space()
			s.emitConditionParen(cond)
			s.lang.Space()
			s.lang.Token("{")
			s.lang.Indent()
			s.lang.Newline()
		} else {
			// Standard format: "} else if (cond) {" on same line as closing brace.
			s.lang.CloseBlockWithSuffix(func() {
				s.lang.Token("else")
				s.lang.Space()
				s.lang.Token("if")
				s.lang.Space()
				s.emitConditionParen(cond)
				s.lang.Space()
				s.lang.Token("{")
				s.lang.Indent()
			})
		}
	} else {
		// Emit the condition block's leading (non-branch) statements before the
		// "if" keyword. The condition block can carry real assignments preceding
		// the CBRANCH (e.g. an addrtied local written in the same block as the
		// first comparison: "local = param_1;" then "if (...)"). emitOps with
		// suppressControl skips the branch and the implied condition temp.
		// C++ parity: PrintC::emitBlockIf emits condBlock once with no_branch set
		// (printc.cc:3026-3030) before rendering the "if". For a compound
		// BlockCondition this descends into block(0), the only sub-block C++'s
		// emitBlockCondition emits under no_branch (printc.cc:2972).
		if err := s.emitConditionLead(children[0]); err != nil {
			return err
		}
		s.lang.OpenBlockAfter(func() {
			s.lang.Token("if")
			s.lang.Space()
			s.emitConditionParen(cond)
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
	// Skip empty else branches (e.g., after G5 identity-copy suppression).
	// An else block containing only an identity "param = param" COPY is invisible;
	// suppressing it matches Ghidra's ActionReturnSplit output where the trivial
	// branch is removed entirely.
	// C++ parity: ActionReturnSplit eliminates the identity branch from the graph.
	if s.isBlockEmpty(elseChild) {
		s.lang.CloseBlock()
		return nil
	}
	// C++ merges "else" and "if" through a pending brace: a nested if whose
	// condition block prints statements first emits the brace, giving a plain
	// else block. C++ parity: PrintC::emitBlockIf (pending_brace).
	if elseChild.Type() == BlockIfType {
		if grand := elseChild.StructuredChildren(); len(grand) >= 2 && s.conditionLeadEmpty(grand[0]) {
			return s.emitIfBlockChain(elseChild, true)
		}
	}
	// A conditional goto merges the same way: "else if (cond) goto L;".
	if elseChild.Type() == BlockIfType && elseChild.GotoTargetBlock() != nil {
		condChild := elseChild
		if grand := elseChild.StructuredChildren(); len(grand) > 0 {
			condChild = grand[0]
		}
		if s.conditionLeadEmpty(condChild) {
			cond := s.mustRenderConditionFrag(condChild)
			ifGoto := func() {
				s.lang.Token("else")
				s.lang.Space()
				s.lang.Token("if")
				s.lang.Space()
				s.emitConditionParen(cond)
				s.lang.Space()
				s.lang.StatementGroup(func() {
					s.emitGotoStatement(elseChild)
					s.lang.Token(";")
				})
			}
			if s.ghidraFormat {
				s.lang.CloseBlock()
				s.lang.Line(ifGoto)
			} else {
				s.lang.CloseBlockWithSuffix(ifGoto)
			}
			return nil
		}
	}
	if s.ghidraFormat {
		// Ghidra format: "}\nelse {\n"
		// C++ parity: Ghidra PrintC emits "}\nelse {\n" for terminal else.
		s.lang.CloseBlock()
		s.lang.Token("else")
		s.lang.Space()
		s.lang.Token("{")
		s.lang.Indent()
		s.lang.Newline()
	} else {
		s.lang.CloseBlockWithSuffix(func() {
			s.lang.Token("else")
			s.lang.Space()
			s.lang.Token("{")
			s.lang.Indent()
		})
	}
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
	// Delegate to for-loop rendering when ActionForLoops identified an iterate op.
	// C++ parity: PrintC::emitBlockWhileDo -> emitForLoop when iterateOp != nil
	if wdo, ok := bl.Concrete().(*BlockWhileDo); ok && wdo.IterateOp() != nil {
		return s.emitForBlock(wdo, children)
	}
	// Overflow (while(true)) syntax: the condition head is too complex to be a
	// plain while-condition, so the loop is printed as while(true) with the
	// condition body and its exit test moved inside as "if (cond) break;".
	// C++ parity: PrintC::emitBlockWhileDo hasOverflowSyntax() branch (printc.cc:3149).
	if bl.HasOverflowSyntax() {
		return s.emitWhileBlockOverflow(children)
	}
	// Render the condition block in comma_separate mode if it contains printable
	// ops before the CBRANCH (e.g. iVar1 = param_4 produced by NodeJoin).
	// C++ parity: PrintC::emitBlockWhileDo sets setMod(comma_separate) for condBlock
	// emission (printc.cc ~3186).
	cond := s.renderCondBlockCommaFrag(children[0])
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("while")
		s.lang.Space()
		s.emitConditionParen(cond) // emitted structurally so it can break
	})
	if err := s.emitBlock(children[1]); err != nil {
		return err
	}
	s.lang.CloseBlock()
	return nil
}

// emitWhileBlockOverflow renders a BlockWhileDo whose condition head is too
// complex to be a plain while-condition (hasOverflowSyntax). It emits:
//
//	while( true ) {
//	  <condition-body statements>   // condBlock emitted with no_branch
//	  if (<exit condition>) break;  // condBlock's terminal branch as an if-break
//	  <loop body>                   // getBlock(1)
//	}
//
// C++ parity: PrintC::emitBlockWhileDo hasOverflowSyntax() branch (printc.cc:3149-3176).
// The condition head (children[0]) is a leaf, a BlockCondition, or a BlockList
// whose final sub-block carries the loop-exit branch. Its leading statements are
// emitted via emitConditionLead (the C++ no_branch emission), and the branch
// condition is rendered via mustRenderCondition (the C++ only_branch emission).
func (s *printCState) emitWhileBlockOverflow(children []*FlowBlock) error {
	condBlock := children[0]
	s.lang.OpenBlockAfter(func() {
		// C++ emits "while( true )": no space between keyword and paren.
		s.lang.Token("while")
		s.lang.Token("(")
		s.lang.Space()
		s.lang.Token("true")
		s.lang.Space()
		s.lang.Token(")")
	})
	// The block that carries the terminal (loop-exit) branch. For a BlockList
	// head the earlier sub-blocks are structured statements emitted in full; the
	// final sub-block holds the exit condition.
	branchBl := condBlock
	if condBlock.Type() == BlockListType {
		subs := condBlock.StructuredChildren()
		for i := 0; i+1 < len(subs); i++ {
			if err := s.emitBlock(subs[i]); err != nil {
				return err
			}
		}
		if len(subs) > 0 {
			branchBl = subs[len(subs)-1]
		}
	}
	// Emit the exit-condition block's leading (non-branch) statements, then the
	// "if (cond) break;". C++: condBlock->emit(no_branch) then emitGotoStatement
	// with f_break_goto.
	if err := s.emitConditionLead(branchBl); err != nil {
		return err
	}
	cond := s.mustRenderConditionFrag(branchBl)
	s.lang.Statement(func() {
		s.lang.Token("if")
		s.lang.Space()
		s.emitConditionParen(cond)
		s.lang.Space()
		s.lang.Token("break")
	})
	// Loop body (getBlock(1)); its own back-edge branch is already suppressed.
	if err := s.emitBlock(children[1]); err != nil {
		return err
	}
	s.lang.CloseBlock()
	return nil
}

// renderCondBlockCommaFrag renders a loop condition block in comma_separate
// mode: printable non-CBRANCH ops become assignments joined by ", " ahead of
// the branch condition. C++ parity: PrintC::emitBlockBasic under
// setMod(comma_separate).
func (s *printCState) renderCondBlockCommaFrag(bl *FlowBlock) ExprFragment {
	basic, ok := bl.Concrete().(*BlockBasic)
	if !ok {
		// A compound condition under comma_separate is parenthesized whole
		// and its left leaf drops its own parentheses.
		// C++ parity: PrintC::emitBlockCondition (comma_separate branch).
		if bl.Type() == BlockConditionType {
			if frag, err := s.renderConditionInner(bl, true); err == nil {
				return s.lang.GroupExpr(frag)
			}
		}
		return s.mustRenderConditionFrag(bl)
	}

	var parts []ExprFragment
	var cbranch *PcodeOp

	for _, op := range basic.Ops() {
		if op == nil || op.IsDead() {
			continue
		}
		if s.inline[op] {
			// Exception: a COPY with unique-space output that feeds the while
			// condition (INT_EQUAL/INT_NOTEQUAL/CBRANCH) is the trimOpOutput
			// snapshot, e.g. "iVar1 = param_4" in "while (iVar1 = param_4, ...)".
			// Fall through to the unique-filter / Case 2 code below.
			isTrimCopy := false
			if op.Code() == CPUI_COPY {
				if out := op.Output(); out != nil && out.Space() != nil && out.Space().IsUnique() {
					for _, desc := range out.DescendIter() {
						if desc == nil {
							continue
						}
						switch desc.Code() {
						case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_CBRANCH:
							isTrimCopy = true
						}
					}
				}
			}
			if !isTrimCopy {
				continue
			}
		}
		if op.HasFlag(PcodeOpNonPrinting) {
			continue
		}
		// Skip marker ops (MULTIEQUAL/INDIRECT) -- these are phi merge points.
		if op.IsMarker() {
			continue
		}

		if op.Code() == CPUI_CBRANCH {
			cbranch = op
			continue
		}
		// Skip other control-flow ops.
		if isControlOpcode(op.Code()) {
			continue
		}

		// Skip ops with unique-space outputs that have no named consumer -- these
		// are pure SSA temporaries that would produce "tmp_N = ..." noise.
		if out := op.Output(); out != nil {
			// An explicit unique def is a statement like any other, as in
			// emitOps. C++ parity: emitBlockBasic prints non-implied outputs.
			// A COPY made after ActionMarkImplied (Merge::buildDominantCopy)
			// carries neither flag and prints under its merged variable's name,
			// as in emitOps. C++ parity: emitBlockBasic skips only implied outputs.
			mergedCopy := !out.IsImplied() && !out.IsExplicit() && out.NumDescend() > 0 && out.High() != nil && out.High().NumInstances() > 1
			if out.Space() != nil && out.Space().IsUnique() && !(out.IsExplicit() && out.NumDescend() > 0) && !mergedCopy {
				passedUniqueFilter := false

				// Case 2: TrimOpOutput COPY whose output feeds the while condition,
				// either via INT_EQUAL/INT_NOTEQUAL (1-byte bool result) or directly
				// via CBRANCH Input(1) (4-byte value with implicit "!= 0" rendering).
				// This COPY represents the loop-head phi snapshot, e.g.
				//   "while (iVar1 = param_4, iVar1 != 0)".
				// The output may have multiple consumers (the comparison AND a loop-body
				// COPY-to-named-register), so LoneDescend() returns nil; scan all.
				//
				// C++ parity: Ghidra emits this COPY in comma_separate mode because
				// the unique HV is merged with iVar1 during mergeOp (trimOpOutput names
				// it). Gosleigh keeps it as a separate unnamed unique, so we resolve the
				// name here by following the consumer COPY that writes a named variable.
				if op.Code() == CPUI_COPY {
					for _, desc := range out.DescendIter() {
						if desc != nil && (desc.Code() == CPUI_INT_EQUAL || desc.Code() == CPUI_INT_NOTEQUAL || desc.Code() == CPUI_CBRANCH) {
							passedUniqueFilter = true
							break
						}
					}
					if passedUniqueFilter {
						// Resolve the output name from the loop-body consumer COPY (-> iVar1).
						for _, desc := range out.DescendIter() {
							if desc == nil || desc.Code() != CPUI_COPY {
								continue
							}
							dout := desc.Output()
							if dout == nil || dout.Space() == nil || dout.Space().IsUnique() {
								continue
							}
							nm := s.nameOf(dout)
							if nm != "" && !s.isMachineGeneratedName(nm) {
								s.names[out] = nm
								break
							}
						}
					}
				}

				// Case 1: single consumer is a named non-unique MULTIEQUAL (phi-snapshot COPYs).
				if !passedUniqueFilter {
					consumer := out.LoneDescend()
					if consumer == nil {
						continue
					}
					if consumer.Code() == CPUI_MULTIEQUAL &&
						consumer.Output() != nil &&
						consumer.Output().Space() != nil &&
						!consumer.Output().Space().IsUnique() &&
						s.nameOf(consumer.Output()) != "" {
						// Remap unique output to MULTIEQUAL output's name (same as emitOps).
						s.names[out] = s.nameOf(consumer.Output())
					} else {
						continue
					}
				}
			}
			if out.IsFree() {
				continue
			}
			if out.NumDescend() == 0 {
				switch op.Code() {
				case CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW, CPUI_POPCOUNT:
					continue
				}
			}
		}

		// Render this op as "lhs = rhs" (without semicolon) using renderForPartOp
		// which already handles STORE and assignment ops correctly.
		part, err := s.renderForPartFrag(op)
		if err != nil || part.Text == "" {
			continue
		}
		parts = append(parts, s.lang.StatementExpr(part))
	}

	if cbranch != nil {
		if cond, err := s.renderBranchConditionFrag(cbranch); err == nil && cond.Text != "" {
			parts = append(parts, cond)
		}
	} else {
		// No CBRANCH found: fall back to mustRenderCondition.
		parts = append(parts, s.mustRenderConditionFrag(bl))
	}

	if len(parts) == 0 {
		return s.lang.Atom("")
	}
	res := parts[0]
	for _, p := range parts[1:] {
		res = s.lang.CommaExpr(res, p)
	}
	return res
}

// emitForBlock renders a BlockWhileDo as a C for-loop:
//
//	for (<init>; <cond>; <iter>) { <body> }
//
// The init part is omitted when initializeOp is nil (produces "for (;...").
// The iterate op and initialize op have PcodeOpNonPrinting set so that
// emitOps skips them in their original positions inside body/predecessor.
//
// C++ parity: PrintC::emitForLoop (printc.cc ~3089)
func (s *printCState) emitForBlock(wdo *BlockWhileDo, children []*FlowBlock) error {
	iterOp := wdo.IterateOp()
	initOp := wdo.InitializeOp()

	initFrag, err := s.renderForPartFrag(initOp)
	if err != nil {
		return err
	}
	iterFrag, err := s.renderForPartFrag(iterOp)
	if err != nil {
		return err
	}
	// The condition clause is emitted under comma_separate, exactly like the
	// plain while-do header: C++ emitForLoop sets setMod(comma_separate) at
	// printc.cc:3106 and that mod is still active when condBlock->emit(this)
	// runs at printc.cc:3115. Any printable non-implied op that lives in the
	// condition block is therefore emitted ahead of the branch test, separated
	// by ", " (emitBlockBasic, printc.cc:2839).
	cond := s.renderCondBlockCommaFrag(children[0])

	s.lang.OpenBlockAfter(func() {
		s.lang.Token("for")
		s.lang.Space()
		// Every clause is emitted structurally inside the paren group so long
		// headers break after a ';' like PrintC::emitForLoop.
		ge, grouped := s.lang.Emitter().(GroupEmitter)
		id := 0
		if grouped {
			id = ge.OpenParen("(")
		} else {
			s.lang.Token("(")
		}
		if initOp != nil && !initOp.IsMarker() {
			s.lang.EmitFragment(initFrag)
		}
		s.lang.Token(";")
		s.lang.Space()
		s.lang.EmitFragment(cond)
		s.lang.Token(";")
		s.lang.Space()
		s.lang.EmitFragment(iterFrag)
		if grouped {
			ge.CloseParen(")", id)
		} else {
			s.lang.Token(")")
		}
	})
	if err := s.emitBlock(children[1]); err != nil {
		return err
	}
	s.lang.CloseBlock()
	return nil
}

// renderForPartFrag renders the initializer or iterator op of a for-loop
// header. C++ parity: PrintC::emitForLoop emitExpression(op).
func (s *printCState) renderForPartFrag(op *PcodeOp) (ExprFragment, error) {
	if op == nil || op.IsMarker() {
		return ExprFragment{}, nil
	}
	if op.Code() == CPUI_STORE {
		// The left side stays structured so its tokens can break across
		// lines like any other expression. C++ parity: PrintC::opStore.
		lhs, err := s.renderStoreLHSFrag(storePointer(op))
		if err != nil {
			return ExprFragment{}, err
		}
		rhs, err := s.renderVarnodeExpr(storeValue(op))
		if err != nil {
			return ExprFragment{}, err
		}
		return s.lang.AssignExprFrag(lhs, rhs), nil
	}
	rhs, err := s.renderOpExprFrag(op)
	if err != nil {
		return ExprFragment{}, err
	}
	if op.Output() == nil {
		return rhs, nil
	}
	return s.lang.AssignExprFrag(s.printNameExpr(op.Output()), rhs), nil
}

// emitDoWhileBlock renders a BlockDoWhile as do { body } while (cond);.
//
// C++ parity: PrintC::emitBlockDoWhile (printc.cc:3200). Ghidra emits getBlock(0)
// twice: once under no_branch -- the loop body, with its terminal back-edge branch
// suppressed -- and once under only_branch -- the loop condition. The condition
// therefore comes from the block that actually carries the back-edge branch, which
// is the last leaf of getBlock(0), not its front. getBlock(0) is frequently a
// BlockList (the loop's inner if-blocks concatenated with the incrementing tail),
// so rendering the condition from the front leaf would pick up an inner if's test
// and leaving the tail branch unsuppressed would print it as a dangling if-goto.
func (s *printCState) emitDoWhileBlock(bl *FlowBlock) error {
	children := bl.StructuredChildren()
	if len(children) == 0 {
		return nil
	}
	body := children[0]
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("do")
	})
	// no_branch emission: emit the body with the terminal loop branch suppressed.
	if err := s.emitDoWhileBody(body); err != nil {
		return err
	}
	// only_branch emission: the loop condition is the last-leaf's branch condition.
	cond := s.mustRenderConditionFrag(lastBranchLeaf(body))
	s.lang.CloseBlockWithSuffix(func() {
		s.lang.Token("while")
		s.lang.Space()
		s.emitConditionParen(cond)
		s.lang.Token(";")
	})
	return nil
}

// lastBranchLeaf descends to the block that carries the terminal branch of a
// structured block: for a BlockList/BlockCopy it is the last child (recursively),
// otherwise the block itself. C++ parity: BlockList::emit under only_branch emits
// only its final sub-block, so the branch condition originates from that leaf.
func lastBranchLeaf(bl *FlowBlock) *FlowBlock {
	for bl != nil {
		switch bl.Type() {
		case BlockListType, BlockCopyType:
			children := bl.StructuredChildren()
			if len(children) == 0 {
				return bl
			}
			bl = children[len(children)-1]
		default:
			return bl
		}
	}
	return bl
}

// emitDoWhileBody emits a do-while body (getBlock(0)) with its terminal loop
// branch suppressed. C++ parity: PrintC::emitBlockDoWhile emits getBlock(0) under
// no_branch (printc.cc:3200). For a BlockList the leading sub-blocks are emitted
// in full and only the final sub-block's branch is suppressed.
func (s *printCState) emitDoWhileBody(bl *FlowBlock) error {
	if bl == nil {
		return nil
	}
	// The body is emitted like any block, so the goto target it starts
	// with prints its label. C++ parity: emitBlockLs / emitBlockBasic
	// (emitLabelStatement) under no_branch.
	s.emitAnyLabel(bl)
	switch bl.Type() {
	case BlockListType, BlockCopyType:
		children := bl.StructuredChildren()
		if len(children) == 0 {
			if basic := toBasic(bl); basic != nil {
				return s.emitOps(basic, true)
			}
			return nil
		}
		for i := 0; i+1 < len(children); i++ {
			if err := s.emitBlock(children[i]); err != nil {
				return err
			}
		}
		return s.emitDoWhileBody(children[len(children)-1])
	case BlockBasicType, BlockPlain:
		if basic := toBasic(bl); basic != nil {
			return s.emitOps(basic, true)
		}
		return nil
	default:
		// A structured last leaf (e.g. a compound BlockCondition) carries no body
		// statement past its branch; emit its no_branch lead only.
		return s.emitConditionLead(bl)
	}
}

// emitInfLoopBlock renders a BlockInfLoop as:
//
//	do {
//	  <block 0>
//	} while( true );
//
// C++ parity: PrintC::emitBlockInfLoop (printc.cc:3229). Ghidra prints the loop
// as a do/while(true), not a for(;;); the body (getBlock(0)) emits normally
// because an infinite loop has no terminal loop-condition branch to suppress.
func (s *printCState) emitInfLoopBlock(bl *FlowBlock) error {
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("do")
	})
	for _, child := range bl.StructuredChildren() {
		if err := s.emitBlock(child); err != nil {
			return err
		}
	}
	// "while( true )": no space between keyword and paren, spaces inside, matching
	// PrintC::emitBlockInfLoop and the overflow while(true) rendering above.
	s.lang.CloseBlockWithSuffix(func() {
		s.lang.Token("while")
		s.lang.Token("(")
		s.lang.Space()
		s.lang.Token("true")
		s.lang.Space()
		s.lang.Token(")")
		s.lang.Token(";")
	})
	return nil
}

func (s *printCState) emitSwitchBlock(bl *FlowBlock) error {
	children := bl.StructuredChildren()
	if len(children) == 0 {
		return nil
	}
	// The switch block's own statements come first (no_branch).
	// C++ parity: PrintC::emitBlockSwitch.
	if err := s.emitConditionLead(children[0]); err != nil {
		return err
	}
	// Ghidra emits "switch(...)" with no space before the paren. The brace
	// opens no indent level: case labels sit at the switch's indent and only
	// each case body is indented. C++ parity: Emit::openBrace (not
	// openBraceIndent) plus startIndent per case.
	s.lang.Token("switch")
	s.lang.Token("(")
	s.lang.Token(s.mustRenderSwitchSelector(children[0]))
	s.lang.Token(")")
	s.lang.Space()
	s.lang.Token("{")
	s.lang.Newline()
	cases := getBlockStructInfo(bl).cases
	jt := bl.switchJumpTable(s.fd)
	for i, c := range cases {
		s.emitSwitchCaseLabels(c, jt)
		s.lang.Indent()
		if c.gototype != 0 {
			s.lang.Statement(func() {
				if c.gototype == BlockFlagBreakGoto {
					s.lang.Token("break")
					return
				}
				s.lang.Token("goto")
				s.lang.Space()
				s.lang.Token(s.labelForBlock(c.block))
			})
		} else {
			if err := s.emitBlock(c.block); err != nil {
				return err
			}
			// Blocks that formally exit the switch need an explicit break.
			if c.isexit && i != len(cases)-1 {
				s.lang.Statement(func() {
					s.lang.Token("break")
				})
			}
		}
		s.lang.Dedent()
	}
	s.lang.Token("}")
	s.lang.Newline()
	return nil
}

// emitSwitchCaseLabels prints "default:" or one "case N:" per jump-table
// entry reaching the case. C++ parity: PrintC::emitSwitchCase.
func (s *printCState) emitSwitchCaseLabels(c switchCase, jt *JumpTable) {
	if c.isdefault {
		s.lang.Label("default")
		return
	}
	if jt == nil {
		return
	}
	var ct Datatype
	if op := jt.IndirectOp(); op != nil && op.NumInput() > 0 {
		ct = op.Input(0).HighTypeReadFacing(op) // C++ parity: BlockSwitch::getSwitchType
	}
	for j, n := 0, jt.NumIndicesByBlock(c.basic); j < n; j++ {
		// PrintLanguage.Label appends the ':' itself.
		s.lang.Label("case " + caseLabelText(jt.caseLabel(c.basic, j), ct))
	}
}

// caseLabelText renders a case label constant in the switch variable's type.
// C++ parity: PrintC::pushConstant for the switch type (enum and integer
// paths; jump-table display formats are not modelled).
func caseLabelText(val uint64, ct Datatype) string {
	if ct == nil {
		return formatIntegerLiteral(val, 4, false)
	}
	if e, ok := ct.(*Enum); ok {
		if name, ok := e.Values()[val]; ok {
			return name
		}
	}
	// A char switch variable prints character literals.
	// C++ parity: PrintC::pushConstant -> pushCharConstant.
	if txt, ok := charConstantText(val, ct); ok {
		return txt
	}
	// A pointer-typed switch variable prints its labels as cast hex
	// constants. C++ parity: PrintC::pushConstant TYPE_PTR default path.
	if _, ok := ct.(*Pointer); ok {
		return "(" + printedTypeString(ct) + ")" + fmt.Sprintf("0x%x", val)
	}
	return formatIntegerLiteral(val, ct.Size(), ct.Metatype() == TYPE_INT)
}

// emitGotoStatement renders the unstructured-branch keyword for a BlockGoto or
// BlockIf-goto: break; / continue; / goto label;, selected by the block's
// gotoType (assigned by scopeBreak). Callers wrap this in s.lang.Statement.
// C++ parity: printc.cc PrintC::emitGotoStatement (printc.cc:2369).
func (s *printCState) emitGotoStatement(bl *FlowBlock) {
	switch bl.GotoType() {
	case BlockFlagBreakGoto:
		s.lang.Token("break")
	case BlockFlagContinueGoto:
		s.lang.Token("continue")
	default:
		s.lang.Token("goto")
		s.lang.Space()
		s.lang.Token(s.labelForBlock(s.gotoTarget(bl)))
	}
}

func (s *printCState) emitGotoBlock(bl *FlowBlock) error {
	// The goto's body is a whole structured block, not just a basic block.
	// C++ parity: PrintC::emitBlockGoto (getBlock(0)->emit with no_branch).
	if children := bl.StructuredChildren(); len(children) > 0 && toBasic(children[0]) == nil {
		if err := s.emitBlock(children[0]); err != nil {
			return err
		}
		// No goto when its target is the next block printed.
		if bl.gotoPrints() {
			s.lang.Statement(func() {
				s.emitGotoStatement(bl)
			})
		}
		return nil
	}
	if basic := s.firstBasicChild(bl); basic != nil {
		if err := s.emitOps(basic, true); err != nil {
			return err
		}
	}
	if bl.gotoPrints() {
		s.lang.Statement(func() {
			s.emitGotoStatement(bl)
		})
	}
	return nil
}

// emitMultiGotoBlock prints the wrapped block; its goto edges are printed
// as cases of the enclosing switch. C++ parity: BlockMultiGoto::emit.
func (s *printCState) emitMultiGotoBlock(bl *FlowBlock) error {
	if children := bl.StructuredChildren(); len(children) > 0 {
		return s.emitBlock(children[0])
	}
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
	// A collapsed BlockGoto / BlockIf-goto stores its target directly because the
	// goto edge was removed from the structure graph. Prefer that; fall back to
	// the edge for BlockMultiGoto (whose goto edge is retained).
	if t := bl.GotoTargetBlock(); t != nil {
		return t
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
	if leaf := bl.getFrontLeaf(); leaf != nil {
		bl = leaf
	}
	if label, ok := s.blockLabels[bl]; ok {
		return label
	}
	// Ghidra names a code label after the block's entry address: the host's
	// LAB_ symbol, except that a block made by joining or duplicating others
	// has no symbol and gets a generic joined_/dup_ label.
	// C++ parity: PrintC::emitLabel (queryCodeLabel skipped on hasSpecialLabel).
	label := fmt.Sprintf("label_%d", len(s.blockLabels))
	if bb := toBasic(bl); bb != nil {
		if bb.FirstOp() != nil {
			// Without a code label symbol the label is the block kind, the
			// space shortcut ('r' for the code space) and the raw address.
			raw := "r" + PrintRawAddr(bb.entryAddr()) // C++ parity: BlockBasic::getEntryAddr
			switch {
			case bb.HasFlag(BlockFlagJoinedBlock):
				label = "joined_" + raw
			case bb.HasFlag(BlockFlagDuplicateBlock):
				label = "dup_" + raw
			default:
				label = "code_" + raw
				// A code label the host knows at the entry names it.
				// C++ parity: PrintC::emitLabel -> Scope::queryCodeLabel.
				if hs, ok := s.fd.hostScope.(HostDataScope); ok {
					if hd, ok := hs.QueryData(bb.entryAddr()); ok && hd.Label && hd.Addr == bb.entryAddr() && hd.Name != "" {
						label = hd.Name
					}
				}
			}
		}
	}
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
	// emitCommentGroup emits, in order, the warning comments positioned in this
	// block whose target order is <= limit (all remaining when all==true), and
	// advances the block cursor. Called just before each printed statement (with
	// the statement op's order) and once at block end, mirroring PrintC's
	// emitBlockBasic loop (printc.cc:2844) and the trailing emitCommentGroup(0)
	// (printc.cc:2874).
	blkIdx := bb.Index()
	emitCommentGroup := func(limit int, all bool) {
		cs := s.commentPos[blkIdx]
		cur := s.commentCursor[blkIdx]
		for cur < len(cs) {
			if !all && cs[cur].order > limit {
				break
			}
			text := cs[cur].text
			s.lang.Line(func() { s.lang.Token(text) })
			cur++
		}
		s.commentCursor[blkIdx] = cur
	}
	for opIndex, op := range bb.Ops() {
		if op == nil || op.IsDead() || s.inline[op] {
			continue
		}
		// Skip ops marked as NonPrinting by ActionForLoops (iterate/initialize ops
		// are emitted inside the for-loop header, not as body statements) and the
		// artificial halt after a call that never returns.
		// C++ parity: PcodeOp::notPrinted (marker|nonprinting|noreturn).
		if op.HasFlag(PcodeOpNonPrinting | PcodeOpNoReturn) {
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
			//
			// Faithful exception: Ghidra's PrintC::emitBlockBasic (printc.cc:2836) does
			// NOT suppress by space; it suppresses a statement only when the output is
			// isImplied(). An explicit unique-space def (e.g. a LOAD result named iVar1
			// with several descendants: "iVar1 = *(int *)(param_1 + i*4);") is emitted
			// as a normal "name = expr;" statement. ActionMarkExplicit (coreaction.cc:3244,
			// baseExplicit at coreaction.cc:3009) sets the explicit flag on such varnodes.
			// Our blanket unique suppression is a Gosleigh approximation; keying on
			// IsExplicit is the faithful rule. The NumDescend()>0 clause proxies a Ghidra
			// invariant: ActionMarkExplicit runs after ActionDeadCode has removed
			// no-descendant dead ops (coreaction.cc:3252 beginDef(0) cuts free varnodes),
			// so a real explicit def always has live descendants by print time. Without
			// this clause a residual "sub rsp,0x18" frame COPY (unique = 0x18, explicit,
			// nd==0) that survives our faithful-stack ActionDeadCode would leak
			// "uVarN = 0x18;". KNOWN GAP: that residual COPY should be removed by
			// ActionDeadCode (as Ghidra does); until then NumDescend()>0 proxies Ghidra's
			// no-emit behavior. This mirrors the local nd==0 skip convention above
			// (CARRY/SCARRY/SBORROW/POPCOUNT at line ~2042).
			if out.Space() != nil && out.Space().IsUnique() &&
				!(out.IsExplicit() && out.NumDescend() > 0) {
				// Exception: when the unique varnode's sole consumer is a MULTIEQUAL
				// with a named output, emit this op as an assignment to the MULTIEQUAL
				// output's name. This covers two related patterns:
				//   (1) RulePropagateCopy on phi inputs produces
				//         COPY(reg_result -> unique_tmp) -> MULTIEQUAL(stack_local)
				//       where the MULTIEQUAL output is stack-space.
				//   (2) Merge::trimOpInput inserts
				//         COPY(phi_input -> unique_trim) -> MULTIEQUAL(unique_named)
				//       to break a Cover conflict at phi merge; the MULTIEQUAL output
				//       is unique-space but carries a real HV name (param_N / iVar1).
				// Both cases must emit the trim/propagation COPY as a user-visible
				// statement "name = expr;" because the phi itself is a marker op and
				// is skipped by emitStatement.
				// C++ parity: Ghidra's ActionMarkImplied marks the unique trim output
				// as implied, and the COPY becomes an explicit statement whose output
				// name is the HighVariable's name (param_N, iVar1, etc.).
				consumer := out.LoneDescend()
				if !out.IsImplied() && !out.IsExplicit() && out.NumDescend() > 0 && out.High() != nil && out.High().NumInstances() > 1 {
					// A COPY created after ActionMarkImplied (Merge::buildDominantCopy)
					// carries neither flag; C++ emitBlockBasic prints any non-implied
					// output, here under its merged variable's name.
					goto emit // skip the name-remap fallback below
				}
				if consumer == nil || consumer.Code() != CPUI_MULTIEQUAL ||
					consumer.Output() == nil ||
					s.nameOf(consumer.Output()) == "" ||
					s.isMachineGeneratedName(s.nameOf(consumer.Output())) {
					continue
				}
				// Remap this unique varnode's name to the MULTIEQUAL output's name
				// so that emitStatement writes: name = expr; (not: unique_tmp = expr;)
				s.names[out] = s.nameOf(consumer.Output())
			}
			// Free varnodes have been released by ActionDeadCode (MakeFree). The op is
			// not dead itself but its output has no live consumers. Emitting "local_N = ..."
			// for a free output produces an unreachable write with an undeclared name.
			if out.IsFree() {
				continue
			}
		}
	emit:
		if suppressControl && isControlOpcode(op.Code()) {
			continue
		}
		// Emit any warning comments mapped at or before this statement's position,
		// then the statement. C++ parity: emitCommentGroup(inst) before emitStatement.
		emitCommentGroup(opIndex, false)
		if err := s.emitStatement(op); err != nil {
			return err
		}
	}
	// Emit any remaining comments for this block. C++ parity: emitBlockBasic's
	// trailing emitCommentGroup((PcodeOp *)0) (printc.cc:2874).
	emitCommentGroup(0, true)
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
	// The statement's op is the reader of its inputs (a value that resolves
	// per use reads through it). C++ parity: PrintC::emitStatement -> op->push.
	s.opStack = append(s.opStack, op)
	defer func() { s.opStack = s.opStack[:len(s.opStack)-1] }()
	switch op.Code() {
	case CPUI_STORE:
		lhsFrag, err := s.renderStoreLHSFrag(storePointer(op))
		if err != nil {
			return err
		}
		rhsFrag, err := s.renderVarnodeExpr(storeValue(op))
		if err != nil {
			return err
		}
		rhs := s.lang.ExprString(rhsFrag, cPrecAssign, ExprPosNone, ExprAssocNone)
		s.lang.Statement(func() {
			if rhs != rhsFrag.Text {
				s.emitAssign(s.lang.ExprString(lhsFrag, cPrecAssign, ExprPosNone, ExprAssocNone), rhsFrag, rhs)
				return
			}
			s.lang.EmitAssignFragments(lhsFrag, rhsFrag)
		})
		return nil
	case CPUI_RETURN:
		// C++ parity: PrintC::emitStatement CPUI_RETURN (printc.cc ~line 780):
		//   if (op->numInput()>1) { pushVn(op->getIn(1), op, mods); }
		// returnValue selects input[1] (the return-value wiring form) or input[0] (raw form).
		var frag ExprFragment
		expr := ""
		if vn := returnValue(op); vn != nil {
			var err error
			frag, err = s.renderVarnodeExpr(vn)
			if err != nil {
				return err
			}
			expr = s.lang.ExprString(frag, cPrecAssign, ExprPosNone, ExprAssocNone)
		}
		s.lang.Statement(func() {
			s.lang.Token("return")
			if expr == "" {
				return
			}
			s.lang.Space()
			// C++ parity: PrintC::opReturn pushes the return value through the
			// normal expression path, so its operator break points are live; the
			// flat fallback only applies when the value needed outer parentheses.
			if expr != frag.Text {
				s.lang.Token(expr)
				return
			}
			s.lang.EmitFragment(frag)
		})
		return nil
	case CPUI_BRANCH:
		return nil
	case CPUI_CBRANCH:
		// A raw CBRANCH reaching the statement emitter means structuring left this
		// conditional branch unfolded. This is a Gosleigh fallback: Ghidra's
		// CollapseStructure always resolves a conditional branch into a BlockIf or
		// BlockGoto, and PrintC only ever emits a goto through emitGotoStatement/
		// emitLabel (printc.cc:2369,3299), where the goto and its address-derived
		// label are produced symmetrically so the label is always defined.
		//
		// Emit "if (cond) goto label" only when the true-edge target block is still
		// present, so labelForBlock resolves to a real block. When analysis has
		// removed the branch's out-edges (SizeOut()<2 or a nil true target -- e.g.
		// a return-carrier recovery gap that killed the block's live ops and left an
		// orphan CBRANCH with no successors), the branch target is unrecoverable
		// here; drop the branch rather than emit "goto label_missing", which is an
		// undefined label that does not compile. C++ never reaches this state.
		if op.Parent() == nil || op.Parent().SizeOut() <= 1 || op.Parent().TrueOut() == nil {
			return nil
		}
		cond, err := s.renderBranchConditionFrag(op)
		if err != nil {
			return err
		}
		target := s.labelForBlock(op.Parent().TrueOut())
		s.lang.Statement(func() {
			s.lang.Token("if")
			s.lang.Space()
			s.emitConditionParen(cond)
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
		// Any required cast is already a CPUI_CAST op inserted by ActionSetCasts and
		// rendered by renderOpExpr; no render-time cast synthesis is needed.
		frag, err := s.renderOpExprFrag(op)
		if err != nil {
			return err
		}
		expr := s.lang.ExprString(frag, cPrecAssign, ExprPosNone, ExprAssocNone)
		if op.Output() == nil {
			s.lang.Statement(func() {
				if expr != frag.Text {
					s.lang.Token(expr)
					return
				}
				s.lang.EmitFragment(frag)
			})
			return nil
		}
		lhs := s.printNameExpr(op.Output())
		s.lang.Statement(func() {
			if expr != frag.Text {
				s.emitAssign(lhs.Text, frag, expr)
				return
			}
			s.lang.EmitAssignFragments(lhs, frag)
		})
		return nil
	}
}

// emitAssign emits "lhs = rhs" as a structured token stream when the rendered
// fragment is exactly the fragment tree (no outer parenthesization was needed at
// assignment precedence), so the pretty-printer can break at any operator inside
// the right-hand side. Otherwise it falls back to the flat rendering, which is
// character-identical but offers no interior break point. C++ parity:
// PrintC pushes PrintC::assignment and recurses into the value expression; the
// break points come from emitOp's spaces() calls (printlanguage.cc:333-338).
func (s *printCState) emitAssign(lhs string, frag ExprFragment, rendered string) {
	if rendered != frag.Text {
		s.lang.Token(lhs)
		s.lang.Space()
		s.lang.Token("=")
		s.lang.Space()
		s.lang.Token(rendered)
		return
	}
	s.lang.EmitAssignFragment(lhs, frag)
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
	frag, err := s.renderStoreLHSFrag(ptr)
	if err != nil {
		return "", err
	}
	return s.lang.ExprString(frag, parentPrec, ExprPosNone, ExprAssocNone), nil
}

// renderStoreLHSFrag is renderStoreLHS keeping the expression tree, so the
// statement can break lines inside the stored-to expression.
func (s *printCState) renderStoreLHSFrag(ptr *Varnode) (ExprFragment, error) {
	// C++ parity: PrintC::opStore (printc.cc:519-537) is the mirror of opLoad --
	// when checkArrayDeref accepts the pointer expression the dereference op is
	// NOT pushed and print_store_value is set instead, which makes opPtradd emit
	// a subscript rather than a '+' (printc.cc:900-908). Without this the store
	// side of an array write printed as *(base + index), dropping the element
	// scaling and reading as a byte-sized access in C.
	if checkArrayDeref(ptr) {
		if frag, ok, err := s.renderDerefValue(ptr); err != nil {
			return ExprFragment{}, err
		} else if ok {
			return frag, nil
		}
	}
	frag, err := s.renderVarnodeExpr(ptr)
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.UnaryExpr("*", cPrecUnary, frag), nil
}

// renderDerefValue prints the value a LOAD/STORE pointer expression points at
// without a dereference: a PTRSUB as the field (base->field), a PTRADD as a
// subscript. C++ parity: print_load_value/print_store_value in opPtrsub/opPtradd.
func (s *printCState) renderDerefValue(ptr *Varnode) (ExprFragment, bool, error) {
	if def := ptr.Def(); def != nil && def.Code() == CPUI_PTRSUB && checkArrayDeref(ptr) {
		frag, ok := s.renderPointerValue(ptr)
		return frag, ok, nil
	}
	return s.tryRenderSubscript(ptr)
}

// checkArrayDeref reports whether a LOAD/STORE pointer expression can be printed
// with array (or member) syntax instead of a '*' dereference: the pointer must be
// an implied, written Varnode whose defining op is a PTRSUB or PTRADD. The
// SEGMENTOP hop of the C++ original is omitted because Gosleigh does not emit
// SEGMENTOP.
// C++ parity: printc.cc PrintC::checkArrayDeref (L353-368).
func checkArrayDeref(vn *Varnode) bool {
	if vn == nil || !vn.IsImplied() || !vn.IsWritten() {
		return false
	}
	def := vn.Def()
	if def == nil {
		return false
	}
	return def.Code() == CPUI_PTRSUB || def.Code() == CPUI_PTRADD
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
	frag, err := s.renderBranchConditionFrag(op)
	if err != nil {
		return "", err
	}
	return frag.Text, nil
}

// renderBranchConditionFrag renders a CBRANCH condition as an ExprFragment,
// preserving the outermost operator (and its operand strings) so the emit path
// can wrap at the operator boundary. renderBranchCondition is the flat-string
// wrapper for callers that only need the text.
func (s *printCState) renderBranchConditionFrag(op *PcodeOp) (ExprFragment, error) {
	if op == nil {
		return s.lang.Atom("0"), nil
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
				return ExprFragment{}, err
			}
			return inner, nil
		}
		if negTok, prec, reorder, ok := booleanFlipToken(defOp.Code()); ok {
			var left, right ExprFragment
			var err error
			if reorder {
				// !(a op b) expressed with negated op and swapped inputs.
				left, err = s.renderVarnodeExpr(defOp.Input(1))
				if err != nil {
					return ExprFragment{}, err
				}
				right, err = s.renderVarnodeExpr(defOp.Input(0))
			} else {
				left, err = s.renderVarnodeExpr(defOp.Input(0))
				if err != nil {
					return ExprFragment{}, err
				}
				right, err = s.renderVarnodeExpr(defOp.Input(1))
			}
			if err != nil {
				return ExprFragment{}, err
			}
			// Null pointer comparison: apply null cast even in the BooleanFlip path.
			// C++ parity: PrintC pointer comparison rendering with explicit null cast.
			if negTok == "==" || negTok == "!=" {
				if castStr, constIdx := s.nullPtrCastStr(defOp); castStr != "" {
					nullFrag := s.lang.CastExpr(castStr, s.lang.Atom("0x0"))
					if reorder {
						// Inputs were swapped: constIdx in original -> opposite in swapped.
						if constIdx == 0 {
							right = nullFrag
						} else {
							left = nullFrag
						}
					} else {
						if constIdx == 0 {
							left = nullFrag
						} else {
							right = nullFrag
						}
					}
				}
			}
			return s.lang.BinaryExpr(left, negTok, right, prec, ExprAssocLeft), nil
		}
	}
	frag, err := s.renderVarnodeExpr(cond)
	if err != nil {
		return ExprFragment{}, err
	}
	if op.HasFlag(PcodeOpBooleanFlip) {
		frag = s.lang.UnaryExpr("!", cPrecUnary, frag)
	}
	return frag, nil
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
		if frag, ok := s.renderEnumConstant(vn); ok {
			return frag, nil
		}
		text := s.renderConstant(vn)
		if frag, ok := s.castConstantFrag(vn, text); ok {
			return frag, nil
		}
		return s.lang.Atom(text), nil
	}
	if op := vn.Def(); op != nil && s.inline[op] {
		if s.activeExpr[op] {
			return s.lang.Atom(s.nameOf(vn)), nil
		}
		s.activeExpr[op] = true
		defer delete(s.activeExpr, op)
		return s.renderOpExprFrag(op)
	}
	return s.readExpr(vn), nil
}

// castConstantFrag rebuilds a default-printed constant (typecast + hex) as a
// cast over the integer, so a line can break after the cast.
// C++ parity: PrintC::pushConstant default printing (pushOp(&typecast)).
func (s *printCState) castConstantFrag(vn *Varnode, text string) (ExprFragment, bool) {
	var typeStr string
	switch typed := vn.TypeReadFacing(vn.LoneDescend()).(type) {
	case *Pointer:
		typeStr = printedTypeString(s.normalizeTypeForDecl(typed))
	case *Array, *Struct, *Union:
		typeStr = printedTypeString(typed)
	default:
		return ExprFragment{}, false
	}
	hex := fmt.Sprintf("0x%x", vn.Offset())
	if text != "("+typeStr+")"+hex {
		return ExprFragment{}, false
	}
	return s.lang.CastExpr(typeStr, s.lang.Atom(hex)), true
}

// renderEnumConstant prints an enum constant as its named components joined
// by the enum concatenation token, under a ~ for a complement.
// C++ parity: PrintC::pushEnumConstant (enum_cat: "|" with no spacing, a
// token distinct from the bitwise or).
func (s *printCState) renderEnumConstant(vn *Varnode) (ExprFragment, bool) {
	e, ok := vn.TypeReadFacing(vn.LoneDescend()).(*Enum)
	if !ok {
		return ExprFragment{}, false
	}
	names, complement := e.Matches(vn.Offset())
	if len(names) < 2 && !complement {
		return ExprFragment{}, false // a single name prints as before
	}
	expr := s.lang.Atom(names[0])
	for _, nm := range names[1:] {
		right := s.lang.Atom(nm)
		expr = ExprFragment{Text: expr.Text + "|" + nm, Precedence: cPrecBitOr, op: "enum|", node: &fragNode{
			kind: fragBinary, print1: "|", kids: []ExprFragment{expr, right}, parens: []bool{false, false}}}
	}
	if complement {
		expr = s.lang.UnaryExpr("~", cPrecUnary, expr)
	}
	return expr, true
}

func (s *printCState) renderConstant(vn *Varnode) string {
	dt := vn.TypeReadFacing(vn.LoneDescend()) // C++ parity: getHighTypeReadFacing(op) of the reading op
	if enumType, ok := dt.(*Enum); ok {
		if name, ok := enumType.Values()[vn.Offset()]; ok {
			return name
		}
	}
	// Character constant: a read-facing char type prints as a single-quoted
	// character ('\0', 'A', '\n', ...). C++ parity: PrintC::pushConstant routes an
	// isCharPrint type to pushCharConstant (printc.cc:1813/1821 -> 1669).
	if lit, ok := renderCharConstant(vn, dt); ok {
		return lit
	}
	if lit, ok := s.fd.stringLiteral(vn, dt); ok {
		return lit
	}
	// force_unsigned_token: a constant marked by CastStrategy::markExplicitUnsigned
	// (an operand of a sign-inheriting op that would otherwise read as signed) is
	// printed with a trailing 'U'. C++ parity: PrintC::push_integer (printc.cc:1425).
	// The suffix is not appended to boolean/enum/float/char renderings.
	unsignedSuffix := ""
	if vn.HasAddlFlags(VarnodeUnsignedPrint) {
		unsignedSuffix = "U"
	}
	switch typed := dt.(type) {
	case *Base:
		switch typed.Metatype() {
		case TYPE_BOOL:
			// C++ parity: PrintC::pushBoolConstant.
			if vn.Offset() == 0 {
				return "false"
			}
			return "true"
		case TYPE_INT:
			// C++ parity: PrintC::push_integer with sign=true (printc.cc:1376-1408).
			// Signedness only controls the leading '-'; the radix is still chosen by
			// mostNaturalBase over the magnitude, never forced to decimal. Sizes 1/2/4
			// and 8 share this path (no "LL" suffix: vn->isLongPrint() is unmodeled).
			switch typed.Size() {
			case 1, 2, 4, 8:
				return formatIntegerLiteral(vn.Offset(), typed.Size(), true) + unsignedSuffix
			}
		case TYPE_FLOAT:
			return renderFloatLiteral(vn.Offset(), uint32(typed.Size()))
		}
	case *Pointer:
		// A pointer constant that is not a string literal (handled above) prints
		// as a cast of its hexadecimal value. C++ parity: PrintC::pushConstant
		// TYPE_PTR -> default printing (typecast + force_hex).
		// TODO known mismatch: pushPtrCodeConstant (a function name) is not ported.
		return "(" + printedTypeString(s.normalizeTypeForDecl(typed)) + ")" + fmt.Sprintf("0x%x", vn.Offset())
	case *Array, *Struct, *Union:
		// Composite constants (a zeroed XMM register) take the default
		// printing too: typecast + force_hex. C++ parity: PrintC::pushConstant.
		return "(" + printedTypeString(typed) + ")" + fmt.Sprintf("0x%x", vn.Offset())
	}
	// Untyped constant: choose decimal vs hex following Ghidra's heuristic.
	// C++ parity: PrintC::push_integer (printc.cc:1395-1399) -- values <= 10
	// print decimal; otherwise the radix is mostNaturalBase(val).
	return formatIntegerLiteral(vn.Offset(), vn.Size(), false) + unsignedSuffix
}

// formatIntegerLiteral renders a constant magnitude following the radix and
// sign logic of PrintC::push_integer (printc.cc:1376-1408). When sign is set and
// the value's high bit (per sz) is on, a leading '-' is emitted over the negated
// magnitude. The radix is decimal for magnitudes <= 10, otherwise mostNaturalBase
// decides hex vs decimal. Signedness never forces decimal on its own.
func formatIntegerLiteral(val uint64, sz int32, sign bool) string {
	negsign := false
	if sign {
		mask := bitfieldSizeMask(sz)
		flip := val ^ mask
		if flip < val {
			negsign = true
			val = flip + 1
		}
	}
	var body string
	if val <= 10 {
		body = fmt.Sprintf("%d", val)
	} else if mostNaturalBase(val) == 16 {
		body = fmt.Sprintf("0x%x", val)
	} else {
		body = fmt.Sprintf("%d", val)
	}
	if negsign {
		return "-" + body
	}
	return body
}

// renderCharConstant renders a size-1 character constant as a single-quoted C
// character, mirroring PrintC::pushCharConstant (printc.cc:1669-1718) for the
// common displayFormat==0 path. It returns ok=false when the constant is not a
// (would-be) char, or when the byte value is >= 0x80 -- in which case C++ falls
// back to integer/escape rendering (printc.cc:1693-1703), so the caller lets the
// normal integer path run and the output is unchanged from before this branch.
//
// Ghidra models char as a distinct TypeChar (isCharPrint, isASCII). Gosleigh has
// no char Datatype, but Ghidra's TypeFactory fills the size-1 TYPE_INT core-type
// cache slot with the ASCII "char" type ("Char is preferred over other int
// types", type.cc:3642-3647), so every read-facing size-1 signed integer is
// char. The would-be-char set is therefore isCharPrintLike(dt) (a real char
// subtype, should one ever be modelled) or a plain size-1 TYPE_INT Base. TYPE_UINT
// size-1 ("byte") is not char and is intentionally excluded so byte constants
// keep printing as integers.
func renderCharConstant(vn *Varnode, dt Datatype) (string, bool) {
	return charConstantText(vn.Offset(), dt)
}

// charConstantText is renderCharConstant for a bare value.
func charConstantText(offset uint64, dt Datatype) (string, bool) {
	if dt == nil {
		return "", false
	}
	if dt.Size() > 1 {
		// A wide character carries the L prefix. C++ parity:
		// PrintC::pushCharConstant (doEmitWideCharPrefix).
		if !isCharPrintLike(dt) {
			return "", false
		}
		// The value is taken as a unicode code-point, printed as UTF-8 or
		// as an escape. C++ parity: PrintC::printUnicode.
		val := offset & maskForSize(dt.Size())
		return "L'" + escapeCharForC(int(val)) + "'", true
	}
	charLike := isCharPrintLike(dt)
	if !charLike {
		return "", false
	}
	val := offset & 0xff
	// C++: a size-1 value >= 0x80 is not a valid unicode code-point and (with no
	// forced display format) prints via the integer path (printc.cc:1693-1701).
	if val >= 0x80 {
		return "", false
	}
	return "'" + escapeCharForC(int(val)) + "'", true
}

// escapeCharForC renders one code-point as it appears inside C single quotes,
// following PrintC::printUnicode (printc.cc:1489-1533) and its escape table.
// Only 0x00-0x7f is exercised by renderCharConstant (size-1 char, val < 0x80).
func escapeCharForC(c int) string {
	if unicodeNeedsEscape(c) {
		switch c {
		case 0:
			return "\\0"
		case 7:
			return "\\a"
		case 8:
			return "\\b"
		case 9:
			return "\\t"
		case 10:
			return "\\n"
		case 11:
			return "\\v"
		case 12:
			return "\\f"
		case 13:
			return "\\r"
		case 92:
			return "\\\\"
		case '"':
			return "\\\""
		case '\'':
			return "\\'"
		}
		return printCharHexEscapeC(c)
	}
	return string(rune(c))
}

// unicodeNeedsEscape mirrors PrintLanguage::unicodeNeedsEscape
// (printlanguage.cc:415-491) over the byte range a size-1 char can hold. The
// higher-plane branches (>= 0x100) are not reachable for a size-1 char constant
// and are collapsed to "escape"; wide-character rendering is out of scope here.
func unicodeNeedsEscape(c int) bool {
	if c < 0x20 { // C0 control characters
		return true
	}
	if c < 0x7f { // printable ASCII
		switch c {
		case 92, '"', '\'':
			return true
		}
		return false
	}
	if c < 0x100 {
		if c > 0xa0 { // printable code-points A1-FF
			return false
		}
		return true // DEL + C1 control characters
	}
	if c >= 0x2fa20 { // Beyond the last currently defined language
		return true
	}
	if c < 0x2000 {
		// Mongolian separators, arabic letter mark, ogham space mark
		return (c >= 0x180b && c <= 0x180e) || c == 0x61c || c == 0x1680
	}
	if c < 0x3000 {
		switch {
		case c < 0x2010: // white space and separators
			return true
		case c >= 0x2028 && c <= 0x202f: // white space and separators
			return true
		case c == 0x205f || c == 0x2060: // white space and word joiner
			return true
		case c >= 0x2066 && c <= 0x206f: // bidirectional markers
			return true
		}
		return false
	}
	if c < 0xe000 {
		// ideographic space; D7FC-D7FF unassigned and D800-DFFF surrogates
		return c == 0x3000 || c >= 0xd7fc
	}
	if c < 0xf900 {
		return true // private use
	}
	if c >= 0xfe00 && c <= 0xfe0f {
		return true // variation selectors
	}
	if c == 0xfeff {
		return true // zero width non-breaking space
	}
	if c >= 0xfff0 && c <= 0xffff {
		return c != 0xfffc && c != 0xfffd // interlinear specials
	}
	return false
}

// printCharHexEscapeC mirrors PrintC::printCharHexEscape (printc.cc:1575-1586).
func printCharHexEscapeC(c int) string {
	switch {
	case c < 256:
		return fmt.Sprintf("\\x%02x", c)
	case c < 65536:
		return fmt.Sprintf("\\x%04x", c)
	default:
		return fmt.Sprintf("\\x%08x", c)
	}
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
// C++ parity: PrintC::push_float (without force_scinote).
func renderFloatLiteral(bits uint64, size uint32) string {
	var f float64
	var neg bool
	switch size {
	case 4:
		f = float64(math.Float32frombits(uint32(bits)))
		neg = bits&0x80000000 != 0
	case 8:
		f = math.Float64frombits(bits)
		neg = bits>>63 != 0
	default:
		return fmt.Sprintf("0x%x", bits) // known mismatch: no FloatFormat for other sizes
	}
	switch {
	case math.IsInf(f, 0):
		if neg {
			return "-INFINITY"
		}
		return "INFINITY"
	case math.IsNaN(f):
		if neg {
			return "-NAN"
		}
		return "NAN"
	}
	token := floatPrintDecimal(f, size)
	if !strings.ContainsAny(token, ".e") {
		token += ".0" // Force token to look like a floating-point value
	}
	return token
}

// floatPrintDecimal prints host with the fewest digits that round-trip to the
// same value in the format, in ostream default notation (printf %g).
// C++ parity: FloatFormat::printDecimal + calcPrecision.
func floatPrintDecimal(host float64, size uint32) string {
	fracSize := 52.0
	if size <= 4 {
		fracSize = 23
	}
	minPrec := int(math.Floor(fracSize * 0.30103))
	maxPrec := int(math.Ceil((fracSize+1)*0.30103)) + 1
	for prec := minPrec; ; prec++ {
		res := strconv.FormatFloat(host, 'g', prec, 64)
		if prec == maxPrec {
			return res
		}
		bitSize := 64
		if size <= 4 {
			bitSize = 32
		}
		if rt, err := strconv.ParseFloat(res, bitSize); err == nil && rt == host {
			return res
		}
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
	s.opStack = append(s.opStack, op)
	defer func() { s.opStack = s.opStack[:len(s.opStack)-1] }()
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
		// C++ parity: PrintC::opCallother -- the user op's name applied to
		// inputs 1..n.
		if uop := s.fd.UserOps().GetOp(uint32(op.Input(0).Offset())); uop != nil && uop.Name() != "" {
			if uop.flags&UserOpFlagDisplayString != 0 { // display_string
				str := "\"badstring\""
				if ptr, ok := op.Output().Type().(*Pointer); ok && op.NumInput() > 1 {
					if lit, ok := s.fd.internalStringLiteral(op.Input(1).Offset(), ptr.Pointee()); ok {
						str = lit
					}
				}
				return s.lang.Atom(str), nil
			}
			return s.renderPseudoCall(uop.Name(), op, 1)
		}
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
		// option_hide_exts (on by default): when the extension is an implied
		// integer promotion for the consuming op, drop it and render the operand
		// alone. C++ parity: PrintC::opIntZext + isExtensionCastImplied.
		// A zero-extension reads as a plain cast only when the input is unsigned;
		// otherwise it stays an explicit ZEXT<in><out>(). C++ parity:
		// CastStrategyC::isZextCast, TypeOpIntZext::getOperatorName.
		if s.extensionIsCast(op, false) {
			if s.extensionCastHidden(op) {
				return s.renderHiddenFunc(op)
			}
			return s.renderCast(op)
		}
		return s.renderPseudoCall(fmt.Sprintf("ZEXT%d%d", op.Input(0).Size(), op.Output().Size()), op, 0)
	case CPUI_INT_SEXT:
		// option_hide_exts: same implied-promotion hiding as INT_ZEXT.
		// A sign-extension reads as a plain cast only when the input is signed.
		// C++ parity: CastStrategyC::isSextCast, TypeOpIntSext::getOperatorName.
		if s.extensionIsCast(op, true) {
			if s.extensionCastHidden(op) {
				return s.renderHiddenFunc(op)
			}
			return s.renderCast(op)
		}
		return s.renderPseudoCall(fmt.Sprintf("SEXT%d%d", op.Input(0).Size(), op.Output().Size()), op, 0)
	case CPUI_INT_ADD:
		return s.renderBinary(op, "+", cPrecAdd, ExprAssocLeft)
	case CPUI_INT_SUB:
		return s.renderBinary(op, "-", cPrecAdd, ExprAssocLeft)
	// The name carries the input size. C++ parity: TypeOpIntCarry /
	// TypeOpIntScarry / TypeOpIntSborrow::getOperatorName.
	case CPUI_INT_CARRY:
		return s.renderPseudoCall(fmt.Sprintf("CARRY%d", op.Input(0).Size()), op, 0)
	case CPUI_INT_SCARRY:
		return s.renderPseudoCall(fmt.Sprintf("SCARRY%d", op.Input(0).Size()), op, 0)
	case CPUI_INT_SBORROW:
		return s.renderPseudoCall(fmt.Sprintf("SBORROW%d", op.Input(0).Size()), op, 0)
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
		// An implied comparison input is printed with its negated token instead
		// of a leading "!". C++ parity: PrintC::opBoolNegate + checkPrintNegation
		// (negatetoken, OpToken::negate).
		if in := op.Input(0); in.IsImplied() && in.IsWritten() {
			def := in.Def()
			switch def.Code() {
			case CPUI_BOOL_NEGATE: // The negations cancel
				return s.renderVarnodeExpr(def.Input(0))
			case CPUI_INT_EQUAL, CPUI_FLOAT_EQUAL:
				return s.renderBinary(def, "!=", cPrecEquality, ExprAssocLeft)
			case CPUI_INT_NOTEQUAL, CPUI_FLOAT_NOTEQUAL:
				return s.renderBinary(def, "==", cPrecEquality, ExprAssocLeft)
			case CPUI_INT_LESS, CPUI_INT_SLESS, CPUI_FLOAT_LESS:
				return s.renderBinary(def, ">=", cPrecRelational, ExprAssocLeft)
			case CPUI_INT_LESSEQUAL, CPUI_INT_SLESSEQUAL, CPUI_FLOAT_LESSEQUAL:
				return s.renderBinary(def, ">", cPrecRelational, ExprAssocLeft)
			}
		}
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
		return s.renderPseudoCall("NAN", op, 0) // C++ parity: opFunc prints the TypeOp name
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
		return s.renderPseudoCall("ABS", op, 0)
	case CPUI_FLOAT_SQRT:
		return s.renderPseudoCall("SQRT", op, 0)
	case CPUI_FLOAT_INT2FLOAT:
		// An absorbed extension prints as the conversion of its input.
		// C++ parity: PrintC::opFloatInt2Float.
		if zextOp := int2FloatAbsorbZext(op); zextOp != nil {
			inner, err := s.renderVarnodeExpr(zextOp.Input(0))
			if err != nil {
				return ExprFragment{}, err
			}
			return s.lang.CastExpr(printedTypeString(s.normalizeTypeForDecl(op.Output().HighTypeDefFacing())), inner), nil
		}
		return s.renderCast(op)
	case CPUI_FLOAT_FLOAT2FLOAT:
		return s.renderCast(op)
	case CPUI_FLOAT_TRUNC:
		return s.renderCast(op)
	case CPUI_FLOAT_CEIL:
		return s.renderPseudoCall("CEIL", op, 0)
	case CPUI_FLOAT_FLOOR:
		return s.renderPseudoCall("FLOOR", op, 0)
	case CPUI_FLOAT_ROUND:
		return s.renderPseudoCall("ROUND", op, 0)
	case CPUI_MULTIEQUAL:
		return s.renderPseudoCall("MULTIEQUAL", op, 0)
	case CPUI_INDIRECT:
		return s.renderPseudoCall("INDIRECT", op, 0)
	case CPUI_PIECE:
		// C++ prints PIECE functionally under its size-suffixed operator name
		// (CONCAT44 etc). C++ parity: TypeOpPiece::getOperatorName via opFunc.
		return s.renderPseudoCall(pieceOperatorName(op), op, 0)
	case CPUI_SUBPIECE:
		// A truncating SUBPIECE that drops high bytes (offset 0) of an integer/
		// pointer renders as a plain cast, not SUBPIECE(). C++ parity:
		// CastStrategyC::isSubpieceCast via PrintC SUBPIECE emission.
		// Offset is treated little-endian (offset 0 = low bytes); endian-aware
		// adjustment (isSubpieceCastEndian) is a future generalization.
		if op.addlFlags&PcodeOpSpecialPrint != 0 {
			if expr, ok := s.renderSubpieceField(op); ok {
				return expr, nil
			}
		}
		if s.subpieceIsCast(op) {
			return s.renderCast(op)
		}
		// Functional printing uses the size-suffixed operator name (SUB84 etc),
		// never the raw opcode name. C++ parity: PrintC::opSubpiece -> opFunc ->
		// TypeOpSubpiece::getOperatorName.
		return s.renderPseudoCall(subpieceOperatorName(op), op, 0)
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

// nullPtrCastStr returns the pointer type a null constant in a comparison is
// cast to, or "" if this is not a null pointer comparison. Callers print the
// constant as a typecast over 0x0 (PrintC::typecast, breakable inside).
// Also returns which input index is the constant (to replace it).
func (s *printCState) nullPtrCastStr(op *PcodeOp) (castStr string, constIdx int) {
	if op.NumInput() < 2 {
		return "", -1
	}
	for ptrIdx := 0; ptrIdx <= 1; ptrIdx++ {
		cstIdx := 1 - ptrIdx
		ptrVn := op.Input(ptrIdx)
		cstVn := op.Input(cstIdx)
		if ptrVn == nil || cstVn == nil {
			continue
		}
		if !cstVn.IsConstant() || cstVn.Offset() != 0 {
			continue
		}
		// The constant takes the comparison's pointer type, which is what
		// the other side prints as (its CAST's output type when cast).
		// C++ parity: ActionSetCasts types the constant with the required
		// input type; PrintC::pushConstant prints (T *)0x0 from it.
		// A constant already typed as a pointer keeps its own type: a cast
		// between typedef-equivalent pointers (CHAR * vs char *) is not
		// needed, so castInput leaves it alone.
		ptrDt := cstVn.TypeReadFacing(nil)
		if _, isPtr := ptrDt.(*Pointer); !isPtr {
			ptrDt = ptrVn.TypeDefFacing()
		}
		if _, isPtr := ptrDt.(*Pointer); !isPtr {
			ptrDt = ptrVn.TypeReadFacing(nil)
			if _, isPtr := ptrDt.(*Pointer); !isPtr {
				continue
			}
		}
		return printedTypeString(s.normalizeTypeForDecl(ptrDt)), cstIdx
	}
	return "", -1
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
	// Null pointer comparison: render 0 as (ptr_type)0x0 when comparing a pointer with NULL.
	// C++ parity: PrintC renders pointer comparisons with explicit null pointer casts.
	if token == "==" || token == "!=" {
		if castStr, constIdx := s.nullPtrCastStr(op); castStr != "" {
			nullFrag := s.lang.CastExpr(castStr, s.lang.Atom("0x0"))
			if constIdx == 0 {
				left = nullFrag
			} else {
				right = nullFrag
			}
		}
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

// extensionIsCast reports whether an INT_SEXT (signed=true) or INT_ZEXT
// (signed=false) op should render as a plain cast rather than an explicit
// SEXT()/ZEXT(). C++ parity: CastStrategyC::isSextCast / isZextCast.
func (s *printCState) extensionIsCast(op *PcodeOp, signed bool) bool {
	if op.NumInput() < 1 {
		return false
	}
	out := op.Output()
	in0 := op.Input(0)
	if out == nil || in0 == nil {
		return false
	}
	outType := out.HighTypeDefFacing()
	inType := in0.HighTypeReadFacing(op)
	if signed {
		return sharedCastStrategyC.IsSextCast(outType, inType)
	}
	return sharedCastStrategyC.IsZextCast(outType, inType)
}

// renderHiddenFunc prints only the operand of op, remembering that a hidden
// operator token stands between it and its parent.
// C++ parity: PrintC::opHiddenFunc (pushOp(&hidden)).
func (s *printCState) renderHiddenFunc(op *PcodeOp) (ExprFragment, error) {
	frag, err := s.renderVarnodeExpr(op.Input(0))
	if err == nil && frag.Precedence != ExprPrecPrimary {
		frag.hidden = true
	}
	return frag, err
}

// extensionCastHidden reports whether an INT_ZEXT/INT_SEXT should be rendered as
// its bare operand (the extension hidden) because it is an implied integer
// promotion for its unique consumer. The consumer is the lone descendant of the
// extension output, matching the readOp Ghidra passes to opIntZext/opIntSext.
// C++ parity: PrintC::opIntZext gate (option_hide_exts && isExtensionCastImplied).
func (s *printCState) extensionCastHidden(op *PcodeOp) bool {
	if op.Output() == nil {
		return false
	}
	return sharedCastStrategyC.IsExtensionCastImplied(op, s.readOpOf(op))
}

// readOpOf is the op whose expression is being printed around op (the reader
// PrintC passes down as readOp), or nil when op is the statement root.
func (s *printCState) readOpOf(op *PcodeOp) *PcodeOp {
	n := len(s.opStack)
	if n >= 2 && s.opStack[n-1] == op {
		return s.opStack[n-2]
	}
	return nil
}

// subpieceIsCast reports whether a SUBPIECE op should render as a plain cast
// (offset 0, integer/pointer truncation) rather than an explicit SUBPIECE().
// C++ parity: CastStrategyC::isSubpieceCast (cast.cc:411).
func (s *printCState) subpieceIsCast(op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	off, ok := constantValue(op.Input(1))
	if !ok {
		return false
	}
	out := op.Output()
	in0 := op.Input(0)
	if out == nil || in0 == nil {
		return false
	}
	return sharedCastStrategyC.IsSubpieceCast(out.HighTypeDefFacing(), in0.HighTypeReadFacing(op), uint32(off))
}

func (s *printCState) renderCast(op *PcodeOp) (ExprFragment, error) {
	inner, err := s.renderVarnodeExpr(op.Input(0))
	if err != nil {
		return ExprFragment{}, err
	}
	dt := Datatype(nil)
	if out := op.Output(); out != nil {
		// C++ parity: PrintC::opCast pushes getOut()->getHighTypeDefFacing().
		dt = s.normalizeTypeForDecl(out.HighTypeDefFacing())
	}
	return s.lang.CastExpr(printedTypeString(dt), inner), nil
}

func (s *printCState) renderLoad(op *PcodeOp) (ExprFragment, error) {
	addrVn := op.Input(op.NumInput() - 1)

	// Subscript pattern: LOAD[INT_ADD(ptr, const_offset)] where ptr is a pointer.
	// Render as ptr[index] when const_offset is a multiple of the pointee size.
	// This handles the case where BatchA's RulePtrArith did not fire (pointer type
	// was unknown at BatchA time) but we now know ptr is a pointer.
	// C++ parity: PrintC renders PTRADD as subscript; we detect the INT_ADD pattern directly.
	// Only an implied pointer expression folds into the dereference; an
	// explicit pointer variable prints as itself (*piVar1).
	// C++ parity: PrintC::opLoad -> checkArrayDeref.
	if addrVn.IsImplied() {
		if frag, ok, err := s.renderDerefValue(addrVn); ok || err != nil {
			return frag, err
		}
	}

	ptr, err := s.renderVarnodeExpr(addrVn)
	if err != nil {
		return ExprFragment{}, err
	}
	return s.lang.UnaryExpr("*", cPrecUnary, ptr), nil
}

// tryRenderSubscript detects LOAD[INT_ADD(ptr, const_bytes)] where ptr has a
// pointer type, and renders the subscript as ptr[index].
// Returns (frag, true, nil) when the pattern matches, (zero, false, nil) otherwise.
func (s *printCState) tryRenderSubscript(addrVn *Varnode) (ExprFragment, bool, error) {
	if addrVn == nil {
		return ExprFragment{}, false, nil
	}
	def := addrVn.Def()
	// See through an implied COPY: RulePtrArith's buildTree leaves the LOAD address
	// as COPY(PTRADD(...)) when there is no extra additive term. Follow the COPY to
	// reach the PTRADD so the subscript renders.
	for def != nil && def.Code() == CPUI_COPY && def.NumInput() == 1 && def.Input(0) != nil && def.Input(0).IsImplied() {
		addrVn = def.Input(0)
		def = addrVn.Def()
	}
	if def == nil {
		return ExprFragment{}, false, nil
	}
	// PTRADD(base, index, scale) is the address of element `index`; a LOAD of it
	// renders as base[index]. The index input is already in element units (the
	// scale is divided out by RulePtrArith), so it maps straight to the subscript.
	if def.Code() == CPUI_PTRADD && def.NumInput() >= 2 {
		// The PTRADD is the reader of its base and index expressions.
		s.opStack = append(s.opStack, def)
		defer func() { s.opStack = s.opStack[:len(s.opStack)-1] }()
		baseVn := def.Input(0)
		idxVn := def.Input(1)
		// The base as the PTRADD reads it: a one-field structure resolves to
		// its pointer field.
		if _, ok := baseVn.TypeReadFacing(def).(*Pointer); !ok {
			return ExprFragment{}, false, nil
		}
		baseExpr, err := s.renderVarnodeExpr(baseVn)
		if err != nil {
			return ExprFragment{}, false, err
		}
		if idxVn.IsConstant() {
			// The index prints like any integer constant (radix by
			// PrintC::push_integer): param_1[0x28], not param_1[40].
			frag := s.lang.SubscriptExpr(baseExpr, s.lang.Atom(s.renderConstant(idxVn)))
			return frag, true, nil
		}
		idxExpr, err := s.renderVarnodeExpr(idxVn)
		if err != nil {
			return ExprFragment{}, false, err
		}
		frag := s.lang.SubscriptExpr(baseExpr, idxExpr)
		return frag, true, nil
	}
	if def.Code() != CPUI_INT_ADD || def.NumInput() < 2 {
		return ExprFragment{}, false, nil
	}
	// Find base (pointer) and constant offset in the INT_ADD inputs.
	baseVn, offsetVn := def.Input(0), def.Input(1)
	if !offsetVn.IsConstant() {
		baseVn, offsetVn = def.Input(1), def.Input(0)
		if !offsetVn.IsConstant() {
			return ExprFragment{}, false, nil
		}
	}
	ptrType, ok := baseVn.TypeReadFacing(nil).(*Pointer)
	if !ok {
		return ExprFragment{}, false, nil
	}
	pointeeSize := int64(ptrType.Pointee().Size())
	if pointeeSize <= 0 {
		return ExprFragment{}, false, nil
	}
	offsetBytes := int64(offsetVn.Offset())
	if offsetBytes <= 0 || offsetBytes%pointeeSize != 0 {
		return ExprFragment{}, false, nil
	}
	index := offsetBytes / pointeeSize
	baseExpr, err := s.renderVarnodeExpr(baseVn)
	if err != nil {
		return ExprFragment{}, false, err
	}
	frag := s.lang.SubscriptExpr(baseExpr, s.lang.Atom(formatIntegerLiteral(uint64(index), offsetVn.Size(), true)))
	return frag, true, nil
}

func (s *printCState) renderCall(op *PcodeOp, indirect bool) (ExprFragment, error) {
	if op.NumInput() == 0 {
		return s.lang.CallExpr(s.lang.Atom("func")), nil
	}
	callee, err := s.renderCallTarget(op, indirect)
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

// genericFunctionName names a callee the environment does not know: "func_"
// plus the raw address, zero-padded to the space's address width.
// C++ parity: printc.cc PrintC::genericFunctionName + AddrSpace::printRaw.
func genericFunctionName(addr address.Address) string {
	width := 2 * int(addr.Space.AddrSize)
	if width <= 0 {
		width = 8
	}
	return fmt.Sprintf("func_0x%0*x", width, addr.Offset)
}

func (s *printCState) renderCallTarget(op *PcodeOp, indirect bool) (ExprFragment, error) {
	vn := op.Input(0)
	if vn == nil {
		return s.lang.Atom("func"), nil
	}
	// A direct call prints its callee's display name, or the generic name of
	// its entry address when the environment knows no function there.
	// C++ parity: printc.cc PrintC::opCall (fspec branch) + genericFunctionName.
	if !indirect && s.fd != nil {
		if fc := s.fd.callSpecsForOp(op); fc != nil && fc.GetEntryAddress().Space != nil {
			if name := fc.GetName(); name != "" {
				return s.lang.Atom(s.minimalScopedNameAt(name, fc.GetEntryAddress())), nil
			}
			return s.lang.Atom(genericFunctionName(fc.GetEntryAddress())), nil
		}
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
	// C++ parity: PrintC::opPtradd (printc.cc:899). The non-value context emits a
	// plain pointer addition (binary_plus) of only getIn(0) and getIn(1); the
	// element scale getIn(2) is never printed, because C pointer arithmetic
	// scales by the pointee size implicitly and a surviving PTRADD always carries
	// scale == pointee AlignSize (RulePtraddUndo removes mismatched ones). The
	// value/subscript context (print_load_value/print_store_value -> '[]') is
	// handled in renderLoad's tryRenderSubscript, not here.
	return s.lang.BinaryExpr(base, "+", index, cPrecAdd, ExprAssocLeft), nil
}

func (s *printCState) renderPtrSub(op *PcodeOp) (ExprFragment, error) {
	base := op.Input(0)
	off := op.Input(1)
	if symExpr, ok := s.renderPtrSubSpacebaseSymbol(base, off, false); ok {
		return symExpr, nil
	}
	if fieldExpr, ok := s.renderPtrSubField(op, false); ok {
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

// renderPtrSubSpacebaseSymbol renders a PTRSUB off a spacebase register as a
// reference to the Symbol covering that frame/image offset -- "&__ImageBase" for
// the global spacebase, "aiStack_48" for a recovered stack array. Ghidra's
// opPtrsub reads the symbol from op->getIn(1)->getHigh()->getSymbol() in the
// TYPE_SPACEBASE branch; Gosleigh does not link Symbols onto the HighVariable of
// the PTRSUB offset constant, so the offset is resolved against the scopes
// directly at print time. Global scope first, ScopeLocal second: the same
// two-scope order Funcdata.ResolveSpacebaseSymbol uses for the C++
// TypeSpacebase::getSubType/getMap pair (action_extras.go:1061). The '&' is
// dropped for code/array symbol types, matching the C++ valueon handling.
// Returns false (falling through to the generic PTRSUB rendering) when the base
// is not a spacebase, the offset is not constant, or no symbol covers the
// address -- so every non-symbol path is unchanged.
// C++ parity: printc.cc PrintC::opPtrsub, TYPE_SPACEBASE branch (printc.cc:1076-1116).
func (s *printCState) renderPtrSubSpacebaseSymbol(base, off *Varnode, valueon bool) (ExprFragment, bool) {
	if base == nil || off == nil || !base.IsSpaceBase() || !off.IsConstant() {
		return ExprFragment{}, false
	}
	if s.fd == nil {
		return ExprFragment{}, false
	}
	// The space the spacebase points into. GetSpaceFromConst carries the binding
	// stamped by ActionConstantPtr (global) and Funcdata.Spacebase (stack);
	// AssociatedSpacebase is the direct binding Funcdata.Spacebase made when it
	// marked the base register.
	spc := base.GetSpaceFromConst()
	if spc == nil {
		spc = base.AssociatedSpacebase()
	}
	if spc == nil {
		return ExprFragment{}, false
	}
	probe := address.Address{Space: spc, Offset: off.Offset()}
	var entry *SymbolEntry
	if gs := s.fd.GetGlobalScope(); gs != nil {
		entry = gs.QueryContainer(probe, 1, address.Address{})
	}
	if entry == nil {
		if sl := s.fd.GetScopeLocal(); sl != nil && sl.SpaceID() == spc {
			entry = sl.QueryContainer(probe, 1, address.Address{})
		}
	}
	if entry == nil || entry.Symbol() == nil {
		// A location with no symbol (e.g. a saved-register slot the scope
		// does not map) prints as its raw address: "&stack0xfffffffc".
		// C++ parity: PrintC::opPtrsub symbol==null -> pushUnnamedLocation.
		if sl := s.fd.GetScopeLocal(); sl != nil && sl.SpaceID() == spc {
			raw := spc.Name + PrintRawAddr(address.Address{Space: spc, Offset: off.Offset()})
			if valueon {
				return s.lang.Atom(raw), true
			}
			return s.lang.UnaryExpr("&", cPrecUnary, s.lang.Atom(raw)), true
		}
		return ExprFragment{}, false
	}
	sym := entry.Symbol()
	// Only the whole-symbol case (offset 0) is rendered; a partial-symbol
	// reference would need pushPartialSymbol, which is not ported.
	if off.Offset() != entry.Addr().Offset {
		return ExprFragment{}, false
	}
	var name ExprFragment
	if sl := s.fd.GetScopeLocal(); sl != nil && sl.SpaceID() == spc {
		// A symbol of the use scope itself needs no qualification.
		// C++ parity: Symbol::getResolutionDepth (scope == useScope).
		name = s.lang.Atom(cppDisplayName(sym.Name()))
	} else {
		name = s.globalSymbolExpr(sym)
	}
	if sym.Category() == SymbolFakeInput || sym.Category() == SymbolFunctionParameter {
		// An unnamed stack-input Symbol prints as its parameter.
		for _, vn := range s.fd.GetVarnodeBank().AllVarnodes() {
			if vn.IsInput() && vn.Space() == spc && vn.Offset() == entry.Addr().Offset {
				name = s.lang.Atom(s.nameOf(vn))
				break
			}
		}
	}
	// Drop the '&' when the symbol is a code or array type (its name already
	// denotes the address); the value of an array is its first element.
	// C++ parity: opPtrsub TYPE_SPACEBASE (valueon / arrayvalue).
	if st := sym.Type(); st != nil {
		switch st.Metatype() {
		case TYPE_ARRAY:
			if valueon {
				return s.lang.SubscriptExpr(name, s.lang.Atom("0")), true
			}
			return name, true
		case TYPE_CODE:
			return name, true
		}
	}
	if valueon { // The symbol's value itself: no '&'
		return name, true
	}
	return s.lang.UnaryExpr("&", cPrecUnary, name), true
}

func (s *printCState) renderPtrSubField(op *PcodeOp, valueon bool) (ExprFragment, bool) {
	base, off := op.Input(0), op.Input(1)
	if base == nil || off == nil || !off.IsConstant() {
		return ExprFragment{}, false
	}
	// The pointer as this PTRSUB reads it: a one-field structure variable
	// resolves to its field here. C++ parity: opPtrsub
	// (in0->getHighTypeReadFacing(op)).
	ptrType, ok := base.TypeReadFacing(nil).(*Pointer)
	if !ok {
		ptrType, ok = base.HighTypeReadFacing(op).(*Pointer)
	}
	if !ok {
		return ExprFragment{}, false
	}
	if _, isArr := ptrType.Pointee().(*Array); isArr && off.Offset() == 0 {
		// PTRSUB(p,0) on a pointer to an array switches to a pointer to its
		// element: the array value itself, which decays. Even without valueon
		// it acts as a dereference. C++ parity: opPtrsub TYPE_ARRAY branch.
		var expr ExprFragment
		if isValueFlexible(base) { // EMIT ( )
			baseExpr, ok := s.renderPointerValue(base)
			if !ok {
				return ExprFragment{}, false
			}
			expr = baseExpr
		} else { // EMIT *( )
			baseExpr, err := s.renderVarnodeExpr(base)
			if err != nil {
				return ExprFragment{}, false
			}
			expr = s.lang.UnaryExpr("*", cPrecUnary, baseExpr)
		}
		if valueon { // A second dereference: ( )[0]
			expr = s.lang.SubscriptExpr(expr, s.lang.Atom("0"))
		}
		return expr, true
	}
	var field TypeField
	if u, isUnion := ptrType.Pointee().(*Union); isUnion {
		// The field is the one the PTRSUB resolves to.
		// C++ parity: opPtrsub TYPE_UNION (getUnionField(ptype,op,-1)).
		if off.Offset() != 0 {
			return ExprFragment{}, false
		}
		res := s.fd.getUnionField(ptrType, op, -1)
		if res == nil || res.fieldNum < 0 || res.fieldNum >= len(u.fields) {
			return ExprFragment{}, false
		}
		field = u.fields[res.fieldNum]
		return s.renderMemberField(base, field, valueon)
	}
	structType, ok := ptrType.Pointee().(*Struct)
	if !ok {
		return ExprFragment{}, false
	}
	field, ok = structType.FieldAt(int32(off.Offset()))
	if !ok {
		// No field holds the offset: Ghidra's default name for the gap.
		// C++ parity: opPtrsub (DataTypeComponent.getDefaultFieldName).
		suboff := int64(off.Offset())
		if suboff < 0 || suboff >= int64(structType.Size()) {
			return ExprFragment{}, false
		}
		field = TypeField{Name: fmt.Sprintf("field_0x%x", suboff), Offset: int32(suboff)}
	} else if field.Name == "" {
		return ExprFragment{}, false
	}
	return s.renderMemberField(base, field, valueon)
}

// renderMemberField prints the member selection of field off the pointer
// base: '.' on a value-flexible base, '->' otherwise, '&' unless valueon.
func (s *printCState) renderMemberField(base *Varnode, field TypeField, valueon bool) (ExprFragment, bool) {
	// An array field is printed without '&'; read as a value it is its
	// first element ([0]). C++ parity: opPtrsub arrayvalue.
	arrayvalue := false
	if _, isArr := field.Type.(*Array); isArr {
		arrayvalue = valueon
		valueon = true
	}
	var expr ExprFragment
	if isValueFlexible(base) {
		// The base is itself an implied PTRADD/PTRSUB: print its value form
		// and select the member with '.' (EMIT ( ).name).
		baseExpr, ok := s.renderPointerValue(base)
		if !ok {
			return ExprFragment{}, false
		}
		expr = s.lang.MemberExpr(baseExpr, ".", field.Name)
	} else {
		baseExpr, err := s.renderVarnodeExpr(base)
		if err != nil {
			return ExprFragment{}, false
		}
		expr = s.lang.MemberExpr(baseExpr, "->", field.Name) // EMIT ( )->name
	}
	if !valueon {
		expr = s.lang.UnaryExpr("&", cPrecUnary, expr)
	}
	if arrayvalue {
		expr = s.lang.SubscriptExpr(expr, s.lang.Atom("0"))
	}
	return expr, true
}

// compareMapOrder orders two declared variables as the local scope's map
// iterates their symbols: by storage space and last storage byte, then by
// the first address of the entry's use limit (none for an address-tied
// symbol). A
// variable whose symbol has no entry yet keys on its name representative,
// whose definition is the use point ActionNameVars maps it at.
// C++ parity: MapIterator over EntryMap (rangemap::insert places a record by
// AddrRange::operator<, last then subsort; SymbolEntry::getSubsort);
// Funcdata::linkSymbol (Varnode::getUsePoint).
func (s *printCState) compareMapOrder(a, b *Varnode) int {
	type mapKey struct {
		spc    uint16
		off    uint64
		useSpc uint16
		useOff uint64
	}
	keyOf := func(vn *Varnode) (mapKey, bool) {
		hv := vn.High()
		if hv == nil {
			return mapKey{}, false
		}
		if sym := hv.GetSymbol(); sym != nil && sym.NumEntries() > 0 {
			if e := sym.FirstWholeMap(); e != nil && e.addr.Space != nil {
				k := mapKey{spc: spaceOrder(e.addr.Space), off: e.addr.Offset + uint64(e.size) - 1}
				if len(e.useLimit) > 0 && e.useLimit[0].space != nil {
					k.useSpc, k.useOff = spaceOrder(e.useLimit[0].space), e.useLimit[0].first
				}
				return k, true
			}
		}
		// A variable held by a temporary maps to the stack Symbol of its
		// stack instance (address-tied: minimal subsort).
		if rep := hv.linkedRep; rep == nil || rep.Space() == nil || rep.Space().IsUnique() {
			if e := s.stackEntryOf(hv); e != nil {
				return mapKey{spc: spaceOrder(e.addr.Space), off: e.addr.Offset + uint64(e.Size()) - 1}, true
			}
		}
		rep := hv.linkedRep // The representative ActionNameVars linked the symbol at
		if rep == nil {
			rep = highNameRepresentative(hv)
		}
		if rep == nil || rep.Space() == nil {
			return mapKey{}, false
		}
		k := mapKey{spc: spaceOrder(rep.Space()), off: rep.Offset() + uint64(rep.Size()) - 1}
		if rep.IsAddrTied() {
			return k, true // An address-tied symbol has no use point: minimal subsort
		}
		if def := rep.Def(); def != nil && def.Addr().Space != nil {
			k.useSpc, k.useOff = spaceOrder(def.Addr().Space), def.Addr().Offset
		}
		return k, true
	}
	ka, oka := keyOf(a)
	kb, okb := keyOf(b)
	if !oka || !okb {
		return 0
	}
	switch {
	case ka.spc != kb.spc:
		return cmpUint16(ka.spc, kb.spc)
	case ka.off != kb.off:
		return cmpUint64(ka.off, kb.off)
	case ka.useSpc != kb.useSpc:
		return cmpUint16(ka.useSpc, kb.useSpc)
	}
	return cmpUint64(ka.useOff, kb.useOff)
}

// isValueFlexible reports an implied PTRSUB/PTRADD whose value can be printed
// directly ('.' member access, array subscript) instead of through a pointer.
// C++ parity: PrintC::isValueFlexible.
func isValueFlexible(vn *Varnode) bool {
	if vn == nil || !vn.IsImplied() || !vn.IsWritten() {
		return false
	}
	switch vn.Def().Code() {
	case CPUI_PTRSUB, CPUI_PTRADD:
		return true
	}
	return false
}

// renderPointerValue prints the object an implied PTRADD/PTRSUB points at
// (the print_load_value form): base[index] or base->field / base.field.
func (s *printCState) renderPointerValue(vn *Varnode) (ExprFragment, bool) {
	def := vn.Def()
	switch def.Code() {
	case CPUI_PTRADD:
		frag, ok, err := s.tryRenderSubscript(vn)
		if err != nil || !ok {
			return ExprFragment{}, false
		}
		return frag, true
	case CPUI_PTRSUB:
		// The value form of a symbol reference off a spacebase is the
		// symbol itself. C++ parity: opPtrsub TYPE_SPACEBASE with valueon.
		if expr, ok := s.renderPtrSubSpacebaseSymbol(def.Input(0), def.Input(1), true); ok {
			return expr, true
		}
		s.opStack = append(s.opStack, def)
		defer func() { s.opStack = s.opStack[:len(s.opStack)-1] }()
		return s.renderPtrSubField(def, true)
	}
	return ExprFragment{}, false
}

func (s *printCState) renderConditionOp(op *PcodeOp) (ExprFragment, error) {
	frag, err := s.renderBranchConditionFrag(op)
	if err != nil {
		return ExprFragment{}, err
	}
	// Force lowest precedence so an enclosing compound condition parenthesizes
	// this operand (unchanged behaviour), while keeping the operator/operand
	// strings so the emit path can break at the operator boundary.
	frag.Precedence = cPrecLowest
	return frag, nil
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

// mustRenderConditionFrag is the fragment form of mustRenderCondition: it keeps
// the outermost operator so emitConditionParen can wrap at the operator boundary.
func (s *printCState) mustRenderConditionFrag(bl *FlowBlock) ExprFragment {
	expr, err := s.renderCondition(bl)
	if err != nil {
		return s.lang.Atom("0")
	}
	return expr
}

// emitConditionParen emits a parenthesized condition, "(" cond ")", as an
// openParen/closeParen group around the condition's own token stream, so the
// pretty-printer can break at any operator inside the condition rather than only
// at the parenthesis. C++ parity: PrintC::emitBlockIf / emitBlockWhileDo wrap the
// condition in openParen(OPEN_PAREN) ... closeParen(CLOSE_PAREN,id) and emit the
// condition through the normal expression path, whose spaces(spacing,bump) calls
// in PrintLanguage::emitOp supply the break points (printlanguage.cc:333-338).
func (s *printCState) emitConditionParen(frag ExprFragment) {
	ge, ok := s.lang.Emitter().(GroupEmitter)
	if !ok {
		s.lang.Token("(")
		s.lang.EmitFragment(frag)
		s.lang.Token(")")
		return
	}
	id := ge.OpenParen("(")
	s.lang.EmitFragment(frag)
	ge.CloseParen(")", id)
}

// renderCondition renders a structured condition block the way C++ PrintC does
// under the only_branch modifier, MINUS the outermost parenthesis: every caller
// supplies that one itself (emitConditionParen, or an explicit "(" / ")" pair).
// That convention is faithful because in C++ the outermost paren of a condition
// always comes from the block being emitted -- opCbranch's openParen for a leaf
// (printc.cc:573), emitBlockCondition's openParen for a compound
// (printc.cc:2979) -- never from the enclosing "if"/"while" keyword.
func (s *printCState) renderCondition(bl *FlowBlock) (ExprFragment, error) {
	return s.renderConditionInner(bl, false)
}

// renderConditionInner is renderCondition with the comma_separate modifier
// tracked explicitly. PrintC::emitBlockCondition sets comma_separate on
// getBlock(1) only (printc.cc:2984) and it is inherited by everything emitted
// underneath, which is what suppresses the leaf parenthesis deeper in the right
// half: opCbranch computes "yesparen = !isSet(comma_separate)" (printc.cc:560).
func (s *printCState) renderConditionInner(bl *FlowBlock, commaSep bool) (ExprFragment, error) {
	if bl == nil {
		return s.lang.Atom("0"), nil
	}
	switch bl.Type() {
	case BlockConditionType:
		children := bl.StructuredChildren()
		if len(children) == 0 {
			return s.lang.Atom("0"), nil
		}
		if len(children) == 1 {
			return s.renderConditionInner(children[0], commaSep)
		}
		// C++ parity: PrintC::emitBlockCondition (printc.cc:2968) emits
		//   openParen ; block(0)->emit ; op ; openParen ; block(1)->emit ; ) ; )
		// so block(1) always carries an extra structural paren of its own, and
		// block(0) carries none beyond whatever it emits for itself. The joiner
		// is "&&" when the opcode is CPUI_BOOL_AND, else "||", matching the
		// getOpcode()==CPUI_BOOL_AND test.
		left, err := s.renderCondBlockFrag(children[0], commaSep)
		if err != nil {
			return ExprFragment{}, err
		}
		rightInner, err := s.renderCondBlockFrag(children[1], true)
		if err != nil {
			return ExprFragment{}, err
		}
		right := s.lang.GroupExpr(rightInner)
		op := "||"
		prec := cPrecLogicalOr
		if bc, ok := bl.Concrete().(*BlockCondition); ok && bc.opc == CPUI_BOOL_AND {
			op = "&&"
			prec = cPrecLogicalAnd
		}
		return s.lang.CondJoinExpr(left, op, right, prec, ExprAssocLeft), nil
	case BlockBasicType, BlockPlain:
		if commaSep {
			// emitBlockBasic under comma_separate joins the block's printable
			// statements with ", " and ends with the branch condition
			// (printc.cc:2839).
			frag := s.renderCondBlockCommaFrag(bl)
			frag.Precedence = cPrecLowest
			return frag, nil
		}
		basic := toBasic(bl)
		if basic == nil {
			return s.lang.Atom("0"), nil
		}
		for i := len(basic.Ops()) - 1; i >= 0; i-- {
			op := basic.Ops()[i]
			if op.Code() == CPUI_CBRANCH {
				frag, err := s.renderBranchConditionFrag(op)
				if err != nil {
					return ExprFragment{}, err
				}
				// Keep the operator/operand strings (for operator-boundary line
				// wrapping) but force lowest precedence so a compound parent
				// parenthesizes this operand (unchanged behaviour).
				frag.Precedence = cPrecLowest
				return frag, nil
			}
			if op.Output() != nil {
				return s.renderVarnodeExpr(op.Output())
			}
		}
		return s.lang.Atom("0"), nil
	case BlockListType:
		// C++ parity: emitBlockLs only_branch emits only getBlock(size-1)
		// (printc.cc:2919-2923) -- the final sub-block carries the branch condition;
		// earlier sub-blocks are the leading statements rendered by emitConditionLead.
		children := bl.StructuredChildren()
		if len(children) == 0 {
			return s.lang.Atom("0"), nil
		}
		return s.renderConditionInner(children[len(children)-1], commaSep)
	default:
		children := bl.StructuredChildren()
		if len(children) > 0 {
			return s.renderConditionInner(children[0], commaSep)
		}
		return s.lang.Atom("0"), nil
	}
}

// renderCondBlockFrag renders one half of a BlockCondition as C++
// "bl->emit(this)" would, INCLUDING the parenthesis that block emits for itself:
// a nested BlockCondition always opens one (printc.cc:2979); a leaf opens one
// through opCbranch unless comma_separate is set (printc.cc:560). The result is
// marked primary so the enclosing BinaryExpr adds nothing on top of it.
func (s *printCState) renderCondBlockFrag(bl *FlowBlock, commaSep bool) (ExprFragment, error) {
	inner, err := s.renderConditionInner(bl, commaSep)
	if err != nil {
		return ExprFragment{}, err
	}
	if commaSep && (bl == nil || bl.Type() != BlockConditionType) {
		// Keep the token structure (line breaking); the block needs no parens.
		inner.Precedence = ExprPrecPrimary
		return inner, nil
	}
	return s.lang.GroupExpr(inner), nil
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
		ops := basic.Ops()
		// The switch selector is the controlling input of the block's
		// BRANCHIND, mirroring C++ emitBlockSwitch emitting the switch block
		// with the only_branch modifier. Once ActionSwitchNorm folds in the
		// normalization, that input is the unnormalized switch variable, so the
		// header renders as e.g. switch(param_1) rather than the raw address
		// computation. C++ parity: printc.cc PrintC::emitBlockSwitch.
		if n := len(ops); n > 0 {
			last := ops[n-1]
			if last.Code() == CPUI_BRANCHIND && last.NumInput() > 0 {
				return s.renderVarnodeExpr(last.Input(0))
			}
		}
		for i := len(ops) - 1; i >= 0; i-- {
			op := ops[i]
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
	// A global's name is its symbol's; no local naming pass may override it.
	if e := s.fd.globalEntryOf(vn); e != nil {
		name, _ := s.globalVarnodeName(vn, e, nil, nil, -1)
		return name
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

// printName is how a variable prints in an expression: its name, through
// its symbol's type when it is only part of a local symbol.
func (s *printCState) printName(vn *Varnode) string {
	// A global prints through its own symbol (a piece with a symbol of its
	// own prints through that one). C++ parity: pushSymbolDetail with the
	// HighVariable's own symbol.
	// A written global resolves a single-field structure through its
	// defining op. C++ parity: pushSymbolDetail(vn,op,false) (slot -1).
	if e := s.fd.globalEntryOf(vn); e != nil {
		if vn.IsWritten() {
			name, _ := s.globalVarnodeName(vn, e, nil, vn.Def(), -1)
			return name
		}
		return s.nameOf(vn)
	}
	name, _ := s.localPieceName(vn, s.nameOf(vn), nil, vn.Def(), -1)
	return name
}

// printNameExpr is printName as an expression: a whole global symbol keeps
// its namespace path as separate tokens, so a long line may break after a
// '::'. C++ parity: PrintC::pushSymbol -> pushSymbolScope.
func (s *printCState) printNameExpr(vn *Varnode) ExprFragment {
	name := s.printName(vn)
	return s.globalNameExpr(vn, name)
}

// globalNameExpr returns the scoped expression of vn's global symbol when
// name prints that whole symbol, else name as a single atom.
func (s *printCState) globalNameExpr(vn *Varnode, name string) ExprFragment {
	e := s.fd.globalEntryOf(vn)
	if e == nil {
		// A piece of a global variable group prints through the whole
		// variable's symbol. C++ parity: pushSymbolDetail -> pushPartialSymbol.
		if root := groupRootOf(vn.High()); root != nil && root.high != nil {
			for _, in := range root.high.Instances() {
				if e = s.fd.globalEntryOf(in); e != nil {
					break
				}
			}
		}
	}
	if e != nil {
		if sym := e.Symbol(); sym != nil {
			if q := s.globalSymbolName(sym); strings.HasPrefix(name, q) {
				if expr := s.globalSymbolExpr(sym); expr.Text == q {
					return s.lang.PathExpr(expr, name[len(q):])
				}
			}
		}
		return s.lang.Atom(name)
	}
	// A local: its name up to the first path step.
	if i := strings.IndexAny(name, ".["); i > 0 && isPlainIdentifier(name[:i]) {
		return s.lang.PathExpr(s.lang.Atom(name[:i]), name[i:])
	}
	return s.lang.Atom(name)
}

// isPlainIdentifier reports a C identifier (no scope or template syntax).
func isPlainIdentifier(name string) bool {
	for i, c := range name {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return name != ""
}

// readExpr is a variable read: like printName, but a truncating piece of a
// symbol prints as a cast of the symbol to the variable's type.
// C++ parity: PrintC::pushVnExplicit -> pushSymbolDetail(vn,op,true).
func (s *printCState) readExpr(vn *Varnode) ExprFragment {
	var castTo Datatype
	if hv := vn.High(); hv != nil {
		castTo = hv.Type()
	}
	// The op reading vn, for a data-type that resolves per use.
	// C++ parity: pushSymbolDetail(vn,op,true) -> inslot = op->getSlot(vn).
	var rop *PcodeOp
	rslot := -1
	if n := len(s.opStack); n > 0 {
		rop = s.opStack[n-1]
		rslot = rop.GetSlot(vn)
	}
	var name string
	var cast Datatype
	if e := s.fd.globalEntryOf(vn); e != nil {
		name, cast = s.globalVarnodeName(vn, e, castTo, rop, rslot)
	} else {
		name, cast = s.localPieceName(vn, s.nameOf(vn), castTo, rop, rslot)
	}
	if cast != nil {
		return s.lang.CastExpr(printedTypeString(s.normalizeTypeForDecl(cast)), s.globalNameExpr(vn, name))
	}
	return s.globalNameExpr(vn, name)
}

// renderSubpieceField prints a SUBPIECE that RuleSubRight marked as a field
// extraction: a part of an explicit structured variable prints through the
// variable (auVar1[0x1f], auVar7._14_2_), a formal structure field as v.name.
// C++ parity: PrintC::opSubpiece special printing.
func (s *printCState) renderSubpieceField(op *PcodeOp) (ExprFragment, bool) {
	vn := op.Input(0)
	ct := vn.HighTypeReadFacing(op)
	if !isPieceStructured(ct) {
		return ExprFragment{}, false
	}
	sz := op.Output().Size()
	byteOff := int32(op.Input(1).Offset()) // TypeOpSubpiece::computeByteOffsetForComposite
	be := vn.Space() != nil && vn.Space().BigEndian
	if be {
		byteOff = vn.Size() - sz - byteOff
	}
	if vn.IsExplicit() {
		// The path starts at the Symbol's own data-type (a union resolves
		// its field per this read), not at the read-facing type.
		// C++ parity: opSubpiece -> pushPartialSymbol(sym, byteOff + symbol
		// offset, ..., op, slot).
		symType := ct
		symName := s.nameOf(vn)
		if e := s.fd.globalEntryOf(vn); e != nil && e.Symbol() != nil && e.Symbol().Type() != nil && vn.Space() == e.Addr().Space {
			symType = e.Symbol().Type()
			symName = s.globalSymbolName(e.Symbol()) // The path starts at the symbol itself
			byteOff += int32(vn.Offset() - e.Addr().Offset)
		}
		slot := 0
		if ct.NeedsResolution() {
			slot = 1 // Artificial slot for the initial resolution
		}
		// allowCast: a final truncating step prints as a cast to the output's
		// type. C++ parity: pushPartialSymbol(..., op->getOut(), ..., true).
		var castTo Datatype
		if hv := op.Output().High(); hv != nil {
			castTo = hv.Type()
		}
		name, cast := symbolPieceName(symName, symType, byteOff, sz, castTo, be, op, slot)
		if cast != nil {
			return s.lang.CastExpr(printedTypeString(s.normalizeTypeForDecl(cast)), s.globalNameExpr(vn, name)), true
		}
		return s.globalNameExpr(vn, name), true
	}
	if st, ok := ct.(*Struct); ok {
		if field, ok := st.FieldAt(byteOff); ok && field.Offset == byteOff && field.Type.Size() == sz && field.Name != "" {
			baseExpr, err := s.renderVarnodeExpr(vn)
			if err != nil {
				return ExprFragment{}, false
			}
			return s.lang.MemberExpr(baseExpr, ".", field.Name), true
		}
	}
	return ExprFragment{}, false
}

// localPieceName prints a stack varnode that is only part of its local
// symbol (an element of a local array) through the symbol's type.
// C++ parity: PrintC::pushSymbolDetail (pushPartialSymbol).
func (s *printCState) localPieceName(vn *Varnode, name string, castTo Datatype, rop *PcodeOp, rslot int) (string, Datatype) {
	// A piece of a VariableGroup prints as part of the group's whole variable
	// (pt.y). C++ parity: pushSymbolDetail -> pushPartialSymbol with
	// HighVariable::getSymbolOffset.
	sl := s.fd.GetScopeLocal()
	// A variable whose type needs resolution (a union, or a structure with
	// one field filling it) prints through the field resolved for this use.
	// C++ parity: pushSymbolDetail (symboloff -1 with a needsResolution
	// Symbol type -> pushPartialSymbol at offset 0).
	if hv := vn.High(); hv != nil && groupRootOf(hv) == nil && (sl == nil || vn.Space() != sl.SpaceID()) {
		if ht := hv.Type(); ht != nil && (ht.Metatype() == TYPE_STRUCT || ht.Metatype() == TYPE_UNION) && ht.NeedsResolution() && ht.Size() == vn.Size() {
			stackInst := false
			for _, in := range hv.Instances() {
				if sl != nil && in.Space() == sl.SpaceID() {
					stackInst = true
					break
				}
			}
			if !stackInst {
				return symbolPieceName(name, ht, 0, vn.Size(), castTo, vn.Space() != nil && vn.Space().BigEndian, rop, rslot)
			}
		}
	}
	if root := namedGroupRoot(vn.High(), sl); root != nil {
		if rvn := root.high.Instances(); len(rvn) > 0 {
			if rt := root.high.Type(); rt != nil {
				be := vn.Space() != nil && vn.Space().BigEndian
				rname := s.nameOf(rvn[0])
				off := int32(vn.High().piece.offset - root.offset)
				// The offset is into the Symbol's data-type, which may be
				// larger than the group (a structure only partly in it). The
				// root's storage is its stack instance, wherever that sits
				// among the instances (C++ high->getSymbol/getSymbolOffset).
				if sl != nil && sl.SpaceID() != nil {
					for _, w := range rvn {
						if w.Space() != sl.SpaceID() {
							continue
						}
						if e := sl.QueryContainer(w.Addr(), w.Size(), address.Address{}); e != nil && e.Symbol() != nil &&
							e.Symbol().Type() != nil && e.Symbol().Name() == rname {
							rt = e.Symbol().Type()
							off += int32(w.Offset() - e.Addr().Offset)
						}
						break
					}
				}
				return symbolPieceName(rname, rt, off, vn.Size(), castTo, be, rop, rslot)
			}
		}
	}
	if sl == nil || sl.SpaceID() == nil {
		return name, nil
	}
	// A varnode merged into the local from other storage sits where the
	// high's stack member sits (C++ high->getSymbolOffset).
	at := vn
	if vn.Space() != sl.SpaceID() {
		at = nil
		if hv := vn.High(); hv != nil {
			for _, w := range hv.Instances() {
				if w.Space() == sl.SpaceID() {
					at = w
					break
				}
			}
		}
		if at == nil {
			return name, nil
		}
	}
	e := sl.QueryContainer(at.Addr(), vn.Size(), address.Address{})
	if e == nil {
		// A variable bigger than its symbol prints as a mismatch (_name).
		// C++ parity: PrintC::pushSymbolDetail -> pushMismatchSymbol.
		e = sl.QueryContainer(at.Addr(), 1, address.Address{})
	}
	if e == nil || e.Symbol() == nil || e.Symbol().Type() == nil {
		return name, nil
	}
	if sym := e.Symbol(); sym.Name() != name {
		// A locked prototype's parameter Symbol carries no name in Gosleigh;
		// it is the parameter printed for the input at its storage.
		if sym.Name() != "" || sym.Category() != SymbolFunctionParameter {
			return name, nil
		}
		in := s.fd.GetVarnodeBank().FindInput(e.Size(), e.Addr())
		if in == nil || s.nameOf(in) != name {
			return name, nil
		}
	}
	off := int32(at.Offset() - e.Addr().Offset)
	if off != 0 && off+vn.Size() > e.Symbol().Type().Size() {
		// A piece past its symbol's end, not at its start, prints as the
		// varnode's own raw location (unique0x1000083a).
		// C++ parity: PrintC::pushMismatchSymbol -> pushUnnamedLocation.
		if sp := vn.Space(); sp != nil {
			return sp.Name + PrintRawAddr(vn.Addr()), nil
		}
	}
	return symbolPieceName(name, e.Symbol().Type(), off, vn.Size(), castTo, sl.SpaceID().BigEndian, rop, rslot)
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

// findParamCopyVarnode returns the param varnode if vn is a direct param varnode
// or a COPY of one. paramVns is the set of known parameter varnodes.
// Returns nil if vn is not an identity copy of a parameter.
//
// C++ parity: ActionReturnSplit detects phi inputs that are identity copies of params.
func (s *printCState) findParamCopyVarnode(vn *Varnode, paramVns map[*Varnode]bool) *Varnode {
	if vn == nil {
		return nil
	}
	// Check if vn itself is a param varnode.
	if paramVns[vn] {
		return vn
	}
	// Check if vn's defining op is a COPY of a param varnode.
	def := vn.Def()
	if def == nil || def.Code() != CPUI_COPY {
		return nil
	}
	src := def.Input(0)
	if src != nil && paramVns[src] {
		return src
	}
	return nil
}

// isParamName reports whether name is the declared name of a function parameter
// in this function. Used to skip re-declaring params that serve as return carriers.
func (s *printCState) isParamName(name string) bool {
	for _, vn := range s.params {
		if s.nameOf(vn) == name {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// hasPrintedUse reports whether vn is read by an op that prints: not a
// marker, not a prologue/epilogue register save.
func (s *printCState) hasPrintedUse(vn *Varnode) bool {
	for _, op := range vn.DescendIter() {
		if op == nil || op.IsDead() || op.IsMarker() {
			continue
		}
		return true
	}
	return false
}

// defaultNameWithType re-prefixes a default variable name (iVar3, puVar1)
// with the printNameBase of dt, keeping the number; other names are unchanged.
func defaultNameWithType(name string, dt Datatype) string {
	i := strings.Index(name, "Var")
	if i < 0 || dt == nil {
		return name
	}
	num := name[i+3:]
	if num == "" || strings.Trim(num, "0123456789") != "" || strings.Trim(name[:i], "abcdefghijklmnopqrstuvwxyz") != "" {
		return name
	}
	prefix := datatypeNameBase(dt)
	if prefix == "" {
		return name
	}
	return prefix + "Var" + num
}

// renameLocal renames every Varnode printed as old (and vn's variable).
func (s *printCState) renameLocal(vn *Varnode, old, renamed string) {
	for v, n := range s.names {
		if n == old {
			s.names[v] = renamed
		}
	}
	s.names[vn] = renamed
	if hv := vn.High(); hv != nil && hv.Name() == old {
		hv.SetName(renamed)
	}
}

// applySelfLockedParams lists the function's locked prototype parameters, in
// prototype order and with their own names, as the signature (the storage
// inputs exist from ActionPrototypeTypes). Every instance of a parameter's
// variable takes its name. C++ parity: PrintC::emitPrototypeInputs over the
// FuncProto's ProtoParameters of a locked prototype.
func (s *printCState) applySelfLockedParams() {
	fp := s.fd.GetFuncProto()
	if fp == nil || !fp.hostInputLocked {
		return
	}
	// A locked prototype is the whole signature, even when it is void.
	var params []*Varnode
	for _, slot := range fp.selfLocked {
		vn := s.fd.FindVarnodeInput(slot.Size, slot.Addr)
		if vn == nil {
			continue
		}
		params = append(params, vn)
		s.names[vn] = slot.Name
		if hv := vn.High(); hv != nil {
			hv.SetName(slot.Name)
			for _, inst := range hv.Instances() {
				s.names[inst] = slot.Name
			}
		}
	}
	s.params = params
}

// highHasWrittenInstance reports a live, written instance of hv.
func highHasWrittenInstance(hv *HighVariable, live map[*Varnode]struct{}) bool {
	for _, w := range hv.Instances() {
		if _, ok := live[w]; ok && w.IsWritten() {
			return true
		}
	}
	return false
}
