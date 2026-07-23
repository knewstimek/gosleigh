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

	// identityOps is the set of COPY ops that are identity assignments of a param
	// to the return carrier (e.g., "eax = param_3" when param_3 is the return value).
	// These ops are suppressed in emitOps since they are no-ops when the carrier is
	// renamed to the param's name.
	// C++ parity: ActionReturnSplit eliminates identity branches from the return path.
	identityOps map[*PcodeOp]bool
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
	if printer.ghidraFormat {
		decls.noCommaSpace = true
	}
	return &printCState{
		printer:             printer,
		fd:                  fd,
		emitter:             emitter,
		lang:                NewPrintLanguage(emitter),
		decls:               decls,
		names:               make(map[*Varnode]string),
		inline:              make(map[*PcodeOp]bool),
		emittedTypes:        make(map[uint64]bool),
		activeExpr:          make(map[*PcodeOp]bool),
		blockLabels:         make(map[*FlowBlock]string),
		prologueOps:         make(map[*PcodeOp]bool),
		prologueVarnodes:    make(map[*Varnode]bool),
		returnOnlyLocs:      make(map[locationKey]bool),
		identityOps:         make(map[*PcodeOp]bool),
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
		s.lang.Token(s.renderFunctionSignature(retType))
		s.lang.Newline()
		s.lang.Newline()
		s.lang.Token("{")
		s.lang.Newline()
		s.lang.Indent()
	} else {
		s.lang.OpenBlockAfter(func() {
			s.lang.Token(s.renderFunctionSignature(retType))
		})
	}
	// Apply post-ghost-rename param names to return-carrier varnodes detected in G5.
	// renderFunctionSignature has now updated param names (param_1 -> param_3 etc.),
	// so we can resolve the correct final name for the return carrier.
	s.finalizeReturnCarrierRenames()
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
		// Mirror emitLocalDeclarations: implied unique temps are not declared, but
		// an explicit unique (the loop-head snapshot iVar1) is, so it counts as a
		// visible local and earns the blank line before the body.
		if vn.Space() != nil && vn.Space().IsUnique() && !vn.IsExplicit() {
			continue
		}
		// Skip locals that were remapped to a param name (G5: no separate declaration).
		if s.isParamName(s.nameOf(vn)) {
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
		// ActionMergeCopy into a param HighVariable can still appear in locals for
		// the G5 identity-copy / return-carrier detection in renameReturnOnlyLocals.
		seenHV := make(map[*HighVariable]bool)
		for _, vn := range all {
			if vn == nil || vn.IsConstant() || vn.IsAnnotation() {
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
					if vn.Def() != nil && vn.Def().IsMarker() {
						// Name is already registered in s.names above (line: s.names[vn] = name).
						// Do NOT mark seenHV so that a non-marker SSA version of the same
						// HighVariable (e.g. the COPY that writes into this phi) can still
						// be added to locals as the declaration/statement representative.
						continue
					}
					if vn.Def() != nil && s.shouldInline(vn.Def()) {
						s.inline[vn.Def()] = true
					} else if !s.prologueVarnodes[vn] {
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
									} else {
										// Case 2 (TrimOpOutput COPY output): unique that feeds both an
										// INT_EQUAL/INT_NOTEQUAL (loop condition) and a COPY to a named
										// non-unique varnode (e.g. register:0x4 iVar1). Use the named
										// register varnode as the declaration representative so that
										// "int iVar1;" appears in the local declarations.
										// C++ parity: Ghidra's trimOpOutput preserves the original
										// register varnode as the COPY output, which is then declared
										// by the standard local-declaration path. Gosleigh inserts a
										// new unique as the COPY output, so we must lift it here.
										hasCondConsumer := false
										var namedRegRep *Varnode
										for _, desc := range vn.DescendIter() {
											if desc == nil {
												continue
											}
											if desc.Code() == CPUI_INT_EQUAL || desc.Code() == CPUI_INT_NOTEQUAL {
												hasCondConsumer = true
											} else if desc.Code() == CPUI_COPY {
												dout := desc.Output()
												if dout != nil && dout.Space() != nil && !dout.Space().IsUnique() {
													dname := ""
													if dhv := dout.High(); dhv != nil {
														dname = dhv.Name()
													}
													if dname != "" && !s.isMachineGeneratedName(dname) {
														namedRegRep = dout
													}
												}
											}
										}
										if hasCondConsumer && namedRegRep != nil {
											rep = namedRegRep
										}
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
								if hvNamed {
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
						}
						// Input varnodes with HV set: name is already in s.names (line above).
						// Declaration is provided by the written representative; skip here.
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
		s.markPhiReturnOnly()
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
	s.markPhiReturnOnly()
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
	if out.NumDescend() != 1 {
		// A varnode with several consumers is normally materialized as a named
		// temporary. The one exception is an IMPLIED multi-use varnode: PrintC
		// re-expands (term-duplicates) it at every use site instead of naming it.
		// ActionMarkImplied keeps a cheap expression implied when it is used a
		// small number of times (maxduplicate=2) and its cover is safe, so e.g.
		// "a >> 0x20" used twice renders inline at both sites (umulhi). An EXPLICIT
		// multi-use varnode stays materialized. C++ parity: PrintLanguage::
		// pushVnImplied recurses on isImplied() regardless of descendant count
		// (printlanguage.cc); ActionMarkImplied::apply (coreaction.cc) marks it.
		//
		// The single-descendant path below is a deliberately separate, older proxy
		// (default-inline for nd==1) retained unchanged: it over-inlines nd==1
		// explicit ops such as a loop-carried PTRADD/CAST that Ghidra also renders
		// inline (array indexing) but marks explicit via the phi/marker rule. Making
		// that path flag-faithful would require Ghidra-matching explicit/implied
		// marking of PTRADD/CAST in phi chains (heritage/merge territory) and would
		// leak a phantom declaration for those varnodes, so it is left as-is.
		if !out.IsImplied() {
			return false
		}
		switch op.Code() {
		case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_STORE, CPUI_RETURN,
			CPUI_MULTIEQUAL, CPUI_INDIRECT, CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER, CPUI_NEW:
			return false
		}
		return true
	}
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
	case CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER, CPUI_NEW:
		// A call output is always explicit (ActionMarkExplicit::baseExplicit returns
		// -1 for def->isCall(), coreaction.cc:3017), so its result is materialized as
		// a named statement (uVar1 = call(...); ... return uVar1;) rather than inlined
		// into the single consumer. C++ parity: baseExplicit isCall branch.
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
		// If vn is a free (stale) varnode (ActionDeadCode freed it after the return-value wiring),
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
			// Only a genuinely untyped (TYPE_UNKNOWN) carrier degrades to
			// undefined%d. A carrier typed by a real op (e.g. INT_AND -> TYPE_UINT)
			// keeps that type so the return type follows (e.g. ulonglong), matching
			// Ghidra, which infers the return type from the carrier's real type.
			if dt == nil || dt.Metatype() == TYPE_UNKNOWN {
				return sharedTypeFactory.GetBase(int32(vn.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", vn.Size()))
			}
		}
		dt := vn.TypeReadFacing(op)
		// Signature output type keeps the pre-cast signedness. In Ghidra the
		// function return type is fixed by ActionOutputPrototype
		// (coreaction.cc:4776 -> FuncProto::updateOutputTypes) from the return
		// Varnode's HighVariable type BEFORE ActionSetCasts runs
		// (universalAction order: outputprototype at coreaction.cc:5747, casts at
		// :5752). ActionSetCasts::castOutput may then promote the return Varnode's
		// display type from signed (TYPE_INT, e.g. an INT_ADD/INT_MULT
		// output-local) to unsigned (TYPE_UINT) so the body reads cast-free when
		// the value feeds an unsigned consumer -- but the signature is already
		// committed and does not follow that promotion. Measured on umulhi (Ghidra
		// 12.0.4): return Varnode high type is longlong at outputprototype and
		// ulonglong at end; signature stays `longlong`. Gosleigh derives the
		// signature at print time from the post-cast read-facing type, so undo the
		// SetCasts signedness promotion here by preferring the type captured on the
		// FuncProto output (ActionOutputPrototype, coreaction.go). Only the
		// signed->unsigned same-size case is corrected; a genuinely unsigned return
		// (e.g. INT_AND output-local TYPE_UINT) has an unsigned FuncProto output and
		// is left untouched.
		if dt != nil && dt.Metatype() == TYPE_UINT {
			if fp := s.fd.GetFuncProto(); fp != nil && fp.GetOutput() != nil {
				if fpOut := fp.GetOutput().Type(); fpOut != nil &&
					fpOut.Metatype() == TYPE_INT && fpOut.Size() == dt.Size() {
					dt = fpOut
				}
			}
		}
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
		// CDECL default: a 4-byte return value that was computed by arithmetic
		// (INT_ADD/INT_SUB/INT_MULT/INT_2COMP or similar) defaults to int when the
		// inferred type is still unknown. Pure constant-selection returns (a MULTIEQUAL
		// whose inputs are all constants, as in switch-like functions) stay undefined4.
		// C++ parity: Ghidra's CDECL prototype defaults return type to int for
		// accumulator/arithmetic functions; constant-selector functions stay undefined4.
		if dt == nil || dt.Metatype() == TYPE_UNKNOWN {
			if vn.Size() == 4 && hasArithmeticAncestor(vn, 4) {
				return sharedTypeFactory.GetBase(4, TYPE_INT, "int")
			}
			return sharedTypeFactory.GetBase(int32(vn.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", vn.Size()))
		}
		return dt
	}
	return sharedTypeFactory.GetVoid()
}

// hasArithmeticAncestor returns true if vn (or any varnode reachable from vn
// by following def chains up to maxDepth levels) is the output of an arithmetic
// operation with at least one non-constant input. This distinguishes computed
// values (counters, accumulators) from pure constant-selection returns.
// Used by inferReturnType to decide whether an unknown-typed return should
// default to int (CDECL convention) or stay undefined4 (constant-only path).
func hasArithmeticAncestor(vn *Varnode, maxDepth int) bool {
	return hasArithAnc(vn, maxDepth, make(map[*Varnode]bool))
}

func hasArithAnc(vn *Varnode, depth int, visited map[*Varnode]bool) bool {
	if vn == nil || depth < 0 || visited[vn] {
		return false
	}
	visited[vn] = true
	def := vn.Def()
	if def == nil {
		return false
	}
	switch def.Code() {
	case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_MULT, CPUI_INT_DIV, CPUI_INT_2COMP,
		CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR,
		CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT,
		CPUI_INT_SDIV, CPUI_INT_SREM, CPUI_INT_REM:
		// Arithmetic op -- check that at least one input is non-constant.
		for i := 0; i < def.NumInput(); i++ {
			in := def.Input(i)
			if in != nil && !in.IsConstant() {
				return true
			}
		}
	}
	// Recurse into defining op inputs (COPY, MULTIEQUAL, etc.).
	for i := 0; i < def.NumInput(); i++ {
		in := def.Input(i)
		if in != nil && !in.IsConstant() {
			if hasArithAnc(in, depth-1, visited) {
				return true
			}
		}
	}
	return false
}

func returnValue(op *PcodeOp) *Varnode {
	if op == nil || op.NumInput() == 0 {
		return nil
	}
	// C++ parity: PrintC::emitStatement CPUI_RETURN case (printc.cc line 781-784):
	//   if (op->numInput()>1) { pushVn(op->getIn(1), op, mods); }
	// input[0] is the return-address reference injected by the SLA (e.g. EIP/LR);
	// input[1] is the actual C return value wired by the return-value wiring.
	//
	// "return-value wiring" is ApplyGuardReturnsLive (Heritage::guardReturns +
	// dominance rename), which appends the return register to each RETURN as input[1].
	//
	// For raw p-code without SLA pre-processing (unit tests, etc.) RETURN may have
	// only input[0] which directly carries the C return value. In that case use input[0].
	//
	// The return-value wiring always appends to the end, so numInput>1 signals the full pipeline.
	var inp *Varnode
	if op.NumInput() > 1 {
		inp = op.Input(1)
	} else {
		inp = op.Input(0)
		// When the full pipeline ran (stripReturnIndirectRef + the return-value wiring),
		// input[0] is the zero-constant placeholder for the return address.
		// If the return-value wiring found no valid return value (void function), the RETURN
		// op has only this one constant input and no real return varnode exists.
		// Zero-constant specifically: stripReturnIndirectRef always substitutes 0.
		// Non-zero constants may appear in raw unit tests as legitimate return values.
		// C++ parity: Ghidra's RETURN has input[0]=retaddr, input[1]=retval when non-void.
		if inp != nil && inp.IsConstant() && inp.Offset() == 0 {
			return nil
		}
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
	}

	codeType := sharedTypeFactory.GetCode("", s.normalizeTypeForDecl(retType), allTypes, false)
	// Use s.decls (which has noCommaSpace set in ghidraFormat mode) instead of the
	// global CFuncSignatureString helper, which always uses a default CDeclRenderer.
	return s.decls.FunctionSignature(displayName, codeType, allNames)
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
		// Return-only carriers render with their genuinely inferred type. Ghidra
		// keeps the carrier's real type (ScopeInternal names it, buildVariableName
		// prints ct->printNameBase): a carrier fed by a real typed op (e.g. an
		// INT_AND -> TYPE_UINT) stays ulonglong, while one carrying only constants
		// (TYPE_UNKNOWN) prints as undefined%d. Only the genuinely untyped case is
		// coerced to undefined%d. C++ parity: database.cc buildVariableName.
		var dt Datatype
		if !vn.Space().IsUnique() && s.returnOnlyLocs[varnodeLocKey(vn)] {
			rt := vn.TypeDefFacing()
			if rt == nil || rt.Metatype() == TYPE_UNKNOWN {
				dt = sharedTypeFactory.GetBase(int32(vn.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", vn.Size()))
			} else {
				dt = s.normalizeTypeForDecl(rt)
			}
		} else if st := s.stackSymbolType(vn); st != nil {
			dt = st
		} else {
			dt = s.normalizeTypeForDecl(vn.TypeDefFacing())
		}
		decl := CDeclString(dt, name)
		s.lang.Statement(func() {
			s.lang.Token(decl)
		})
	}
}

// stackSymbolType returns the declaration data-type for a stack Varnode taken
// from its ScopeLocal SymbolEntry (built by RestructureVarnode from the committed
// Varnode types via RangeHint), or nil when the Varnode does not map to a stack
// Symbol. A TYPE_UNKNOWN symbol renders as undefined<size>, matching Ghidra's
// undefined stack locals. This is the STEP 4 declaration source: the symbol type
// is snapshotted at restructure time, so it does not leak the later-propagated
// Varnode type. C++ parity: PrintC::emitVarDecl uses sym->getType().
func (s *printCState) stackSymbolType(vn *Varnode) Datatype {
	if vn == nil || vn.Space() == nil || vn.Space().IsUnique() || s.fd == nil {
		return nil
	}
	sl := s.fd.GetScopeLocal()
	if sl == nil {
		return nil
	}
	e := sl.FindEntryAt(vn.Addr(), int32(vn.Size()))
	if e == nil || e.Symbol() == nil {
		return nil
	}
	st := e.Symbol().Type()
	if st == nil {
		return nil
	}
	if st.Metatype() == TYPE_UNKNOWN {
		return sharedTypeFactory.GetBase(int32(vn.Size()), TYPE_UNKNOWN, fmt.Sprintf("undefined%d", vn.Size()))
	}
	return s.normalizeTypeForDecl(st)
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
			// A size-1 signed integer is spelled "char", not "signed char":
			// Ghidra registers an ASCII "char" core type (TYPE_INT size 1,
			// chartype) that is preferred over any non-char int1 when filling
			// the size-1 TYPE_INT cache slot, so getBase(1,TYPE_INT) resolves
			// to "char" and that is the name every plain 1-byte signed value
			// prints with (golden never emits "signed char").
			// C++ parity: TypeFactory::cacheCoreTypes (type.cc:3645-3646, the
			// "Char is preferred over other int types" branch) plus the
			// setCoreType("char",1,TYPE_INT,true) registration (ghidra_arch.cc:340).
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
				return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "long")
			}
			return sharedTypeFactory.GetBase(base.Size(), TYPE_INT, "longlong")
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
				return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "ulong")
			}
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "ulonglong")
		default:
			return sharedTypeFactory.GetBase(base.Size(), TYPE_UINT, "uint")
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
	s.lang.Statement(func() {
		s.lang.Token("if")
		s.lang.Space()
		s.emitConditionParen(cond)
		s.lang.Space()
		s.emitGotoStatement(bl)
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
		if s.prologueOps[op] {
			continue
		}
		if s.identityOps[op] {
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
	if bl.Type() == BlockConditionType {
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
		return s.emitOps(basic, true)
	}
	return nil
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
			s.lang.Newline()
			s.lang.Indent()
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
	if elseChild.Type() == BlockIfType {
		return s.emitIfBlockChain(elseChild, true)
	}
	if s.ghidraFormat {
		// Ghidra format: "}\nelse {\n"
		// C++ parity: Ghidra PrintC emits "}\nelse {\n" for terminal else.
		s.lang.CloseBlock()
		s.lang.Token("else")
		s.lang.Space()
		s.lang.Token("{")
		s.lang.Newline()
		s.lang.Indent()
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
	condStr := s.renderCondBlockComma(children[0])
	s.lang.OpenBlockAfter(func() {
		s.lang.Token("while")
		s.lang.Space()
		s.lang.Token("(")
		s.lang.Token(condStr)
		s.lang.Token(")")
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

// renderCondBlockComma renders the condition block of a while-do loop in
// comma_separate mode. Printable non-CBRANCH ops are rendered as assignments
// separated by ", " and the final CBRANCH condition is appended last.
// Falls back to mustRenderCondition when there are no printable non-CBRANCH ops.
// C++ parity: PrintC::emitBlockBasic in setMod(comma_separate) mode +
// emitBlockWhileDo (printc.cc ~3186).
func (s *printCState) renderCondBlockComma(bl *FlowBlock) string {
	basic, ok := bl.Concrete().(*BlockBasic)
	if !ok {
		return s.mustRenderCondition(bl)
	}

	var parts []string
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
		if s.prologueOps[op] {
			continue
		}
		if s.identityOps[op] {
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
			if out.Space() != nil && out.Space().IsUnique() {
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
		partStr, err := s.renderForPartOp(op)
		if err != nil || partStr == "" {
			continue
		}
		parts = append(parts, partStr)
	}

	if cbranch != nil {
		condStr, err := s.renderBranchCondition(cbranch)
		if err == nil && condStr != "" {
			parts = append(parts, condStr)
		}
	} else {
		// No CBRANCH found: fall back to mustRenderCondition.
		parts = append(parts, s.mustRenderCondition(bl))
	}

	if len(parts) == 1 {
		return parts[0]
	}
	var sb strings.Builder
	for i, p := range parts {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(p)
	}
	return sb.String()
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

	initStr, err := s.renderForPartOp(initOp)
	if err != nil {
		return err
	}
	iterStr, err := s.renderForPartOp(iterOp)
	if err != nil {
		return err
	}
	condStr := s.mustRenderCondition(children[0])

	s.lang.OpenBlockAfter(func() {
		s.lang.Token("for")
		s.lang.Space()
		s.lang.Token("(")
		if initStr != "" {
			s.lang.Token(initStr)
		}
		s.lang.Token(";")
		s.lang.Space()
		s.lang.Token(condStr)
		s.lang.Token(";")
		s.lang.Space()
		s.lang.Token(iterStr)
		s.lang.Token(")")
	})
	if err := s.emitBlock(children[1]); err != nil {
		return err
	}
	s.lang.CloseBlock()
	return nil
}

// renderForPartOp renders a single op (iterate or initialize) as a C expression
// string suitable for use inside a for-loop header clause.
//
// Assignment ops render as "lhs = rhs".
// STORE ops render as "*ptr = rhs".
// Returns "" for nil ops.
//
// C++ parity: PrintC::emitForLoop calls emitExpression(op) for each part.
func (s *printCState) renderForPartOp(op *PcodeOp) (string, error) {
	if op == nil {
		return "", nil
	}
	if op.IsMarker() {
		return "", nil
	}
	switch op.Code() {
	case CPUI_STORE:
		lhs, err := s.renderStoreLHS(storePointer(op), cPrecAssign)
		if err != nil {
			return "", err
		}
		rhs, err := s.renderVarnode(storeValue(op), cPrecAssign)
		if err != nil {
			return "", err
		}
		return lhs + " = " + rhs, nil
	default:
		// ActionSetCasts has already inserted any required CPUI_CAST op, including
		// the for-iterate output cast (e.g. sum_list: the LOAD iterator's output is
		// cast to int*, and that CAST is the folded iterateOp here). renderOpExpr
		// renders the cast naturally, so no render-time cast synthesis is needed.
		rhs, err := s.renderOpExpr(op, cPrecAssign)
		if err != nil {
			return "", err
		}
		if op.Output() == nil {
			return rhs, nil
		}
		lhs := s.nameOf(op.Output())
		return lhs + " = " + rhs, nil
	}
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
	s.lang.OpenBlockAfter(func() {
		// Ghidra emits "switch(...)" with no space before the paren.
		s.lang.Token("switch")
		s.lang.Token("(")
		s.lang.Token(s.mustRenderSwitchSelector(children[0]))
		s.lang.Token(")")
	})
	cases := children[1:]
	for i, child := range cases {
		// PrintLanguage.Label appends the trailing ':' itself, so the label text
		// must not already carry one (otherwise "case 0::").
		label := fmt.Sprintf("case %d", i)
		if selectorHasDefault(children[0], i) {
			label = "default"
		}
		s.lang.Label(label)
		s.lang.Indent()
		if err := s.emitBlock(child); err != nil {
			return err
		}
		// Emit an explicit break for a case that formally exits the switch (its
		// structured block leaves via a single out-edge to the switch exit) and
		// is not the last case, which falls out of the switch anyway.
		// C++ parity: printc.cc PrintC::emitBlockSwitch (bl->isExit(i) &&
		// i != numCaseBlocks-1); BlockSwitch::addCase sets isexit = sizeOut()==1.
		if s.caseExits(child) && i != len(cases)-1 {
			s.lang.Statement(func() {
				s.lang.Token("break")
			})
		}
		s.lang.Dedent()
	}
	s.lang.CloseBlock()
	return nil
}

// caseExits reports whether a switch case's structured block formally exits the
// switch, i.e. its terminal basic block ends in an unconditional BRANCH to the
// shared switch exit. Ghidra renders that goto-to-exit as an explicit break. A
// case terminating in RETURN (or falling through with no terminator) does not
// need a break. This is the emit-time equivalent of C++
// BlockSwitch::addCase's isexit = (bl->sizeOut() == 1): the structuring pass
// collapses the case region and zeroes the FlowBlock out-edges, so the surviving
// terminal BRANCH op is the faithful signal for the single exit edge.
// C++ parity: block.cc BlockSwitch::addCase (block.cc:3514) +
// printc.cc PrintC::emitBlockSwitch.
func (s *printCState) caseExits(bl *FlowBlock) bool {
	if bl == nil {
		return false
	}
	switch bl.Type() {
	case BlockListType:
		children := bl.StructuredChildren()
		if len(children) > 0 {
			return s.caseExits(children[len(children)-1])
		}
	case BlockBasicType, BlockPlain:
		bb := toBasic(bl)
		if bb != nil && bb.NumOps() > 0 {
			return bb.Ops()[bb.NumOps()-1].Code() == CPUI_BRANCH
		}
	}
	return false
}

func selectorHasDefault(selector *FlowBlock, idx int) bool {
	if selector == nil || idx < 0 || idx >= selector.SizeOut() {
		return false
	}
	return selector.OutEdge(idx).Label&EdgeFlagDefaultSwitch != 0
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
	if basic := s.firstBasicChild(bl); basic != nil {
		if err := s.emitOps(basic, true); err != nil {
			return err
		}
	}
	s.lang.Statement(func() {
		s.emitGotoStatement(bl)
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
		s.emitGotoStatement(bl)
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
		// are emitted inside the for-loop header, not as body statements).
		// C++ parity: PrintC skips ops where PcodeOp::notPrinted() is true
		// (set by Funcdata::opMarkNonPrinting in BlockWhileDo::finalizePrinting).
		if op.HasFlag(PcodeOpNonPrinting) {
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
		// Skip identity COPY ops that are "param = param" assignments produced when
		// the return carrier is renamed to a parameter name. These are no-ops that
		// Ghidra eliminates via ActionReturnSplit.
		// C++ parity: ActionReturnSplit removes the identity branch of the phi.
		if s.identityOps[op] {
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
			// The same op's expression may still be inlined at the RETURN site via
			// findDefiningOpForFreeVarnode; suppress the stand-alone statement here.
			if out.IsFree() {
				continue
			}
		}
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
		// returnValue selects input[1] (the return-value wiring form) or input[0] (raw form).
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
	// If vn is free (its defining op was killed by ActionDeadCode after the return-value wiring
	// wired it into RETURN), try to find a live varnode at the same location that
	// carries the actual return expression.
	// This handles the pattern where the return-value wiring picks a SUBPIECE or SSA version
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
		case CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER, CPUI_NEW:
			// A call result is always explicit (ActionMarkExplicit::baseExplicit
			// isCall -> -1) and is materialized as its own statement
			// (uVar1 = call(...);), so the RETURN names it (return uVar1;) rather
			// than re-expanding the call expression. C++ parity: baseExplicit.
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
// input[1] when numInput>1 (the return-value wiring form), input[0] otherwise (raw form).
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
// at the same location as ref. This recovers the return value when the return-value wiring
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
		// Function parameter inputs (IsInput=true) count as real phi contributors
		// even though they have no defining op (Def()==nil).
		// Matches ActionMarkExplicit::baseExplicit returning -1 when a descendant
		// is a marker op -- the MULTIEQUAL output is always explicit when it has
		// multiple real inputs.
		var candidate *Varnode
		count := 0
		for i := 0; i < op.NumInput(); i++ {
			inp := op.Input(i)
			if inp == nil || inp.IsAnnotation() {
				continue
			}
			if (inp.Def() != nil && !inp.Def().IsDead()) || inp.IsInput() {
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
					nullFrag := s.lang.Atom(castStr)
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
	// Character constant: a read-facing char type prints as a single-quoted
	// character ('\0', 'A', '\n', ...). C++ parity: PrintC::pushConstant routes an
	// isCharPrint type to pushCharConstant (printc.cc:1813/1821 -> 1669).
	if lit, ok := renderCharConstant(vn, dt); ok {
		return lit
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
			if vn.Offset() == 0 {
				return "0"
			}
			return "1"
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
	if dt == nil || dt.Size() != 1 {
		return "", false
	}
	charLike := isCharPrintLike(dt)
	if !charLike {
		if base, ok := dt.(*Base); ok && base.Metatype() == TYPE_INT {
			charLike = true
		}
	}
	if !charLike {
		return "", false
	}
	val := vn.Offset() & 0xff
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
	return true
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
		// option_hide_exts (on by default): when the extension is an implied
		// integer promotion for the consuming op, drop it and render the operand
		// alone. C++ parity: PrintC::opIntZext + isExtensionCastImplied.
		if s.extensionCastHidden(op) {
			return s.renderVarnodeExpr(op.Input(0))
		}
		// A zero-extension reads as a plain cast only when the input is unsigned;
		// otherwise it stays an explicit ZEXT(). C++ parity: CastStrategyC::isZextCast.
		if s.extensionIsCast(op, false) {
			return s.renderCast(op)
		}
		return s.renderPseudoCall("ZEXT", op, 0)
	case CPUI_INT_SEXT:
		// option_hide_exts: same implied-promotion hiding as INT_ZEXT.
		if s.extensionCastHidden(op) {
			return s.renderVarnodeExpr(op.Input(0))
		}
		// A sign-extension reads as a plain cast only when the input is signed.
		// C++ parity: CastStrategyC::isSextCast.
		if s.extensionIsCast(op, true) {
			return s.renderCast(op)
		}
		return s.renderPseudoCall("SEXT", op, 0)
	case CPUI_INT_ADD:
		// C++ parity: cleanup-phase Rule2Comp2Sub converts INT_ADD(x, INT_2COMP(y))
		// to INT_SUB(x, y) before rendering. Mirror this at render time: when the
		// right-hand input is an inline INT_2COMP, fold into subtraction so we emit
		// "x - y" instead of "x + -y".
		if rhs := op.Input(1); rhs != nil {
			if def := rhs.Def(); def != nil && s.inline[def] && def.Code() == CPUI_INT_2COMP {
				left, err := s.renderVarnodeExpr(op.Input(0))
				if err != nil {
					return ExprFragment{}, err
				}
				inner, err := s.renderVarnodeExpr(def.Input(0))
				if err != nil {
					return ExprFragment{}, err
				}
				return s.lang.BinaryExpr(left, "-", inner, cPrecAdd, ExprAssocLeft), nil
			}
		}
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
		// A truncating SUBPIECE that drops high bytes (offset 0) of an integer/
		// pointer renders as a plain cast, not SUBPIECE(). C++ parity:
		// CastStrategyC::isSubpieceCast via PrintC SUBPIECE emission.
		// Offset is treated little-endian (offset 0 = low bytes); endian-aware
		// adjustment (isSubpieceCastEndian) is a future generalization.
		if s.subpieceIsCast(op) {
			return s.renderCast(op)
		}
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

// nullPtrCastStr returns the cast string for a null pointer in a comparison,
// or "" if this is not a null pointer comparison.
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
		ptrDt := ptrVn.TypeReadFacing(nil)
		if _, isPtr := ptrDt.(*Pointer); !isPtr {
			continue
		}
		return "(" + CTypeString(ptrDt) + ")0x0", cstIdx
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
			nullFrag := s.lang.Atom(castStr)
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
	outType := out.TypeReadFacing(nil)
	inType := in0.TypeReadFacing(nil)
	if signed {
		return sharedCastStrategyC.IsSextCast(outType, inType)
	}
	return sharedCastStrategyC.IsZextCast(outType, inType)
}

// extensionCastHidden reports whether an INT_ZEXT/INT_SEXT should be rendered as
// its bare operand (the extension hidden) because it is an implied integer
// promotion for its unique consumer. The consumer is the lone descendant of the
// extension output, matching the readOp Ghidra passes to opIntZext/opIntSext.
// C++ parity: PrintC::opIntZext gate (option_hide_exts && isExtensionCastImplied).
func (s *printCState) extensionCastHidden(op *PcodeOp) bool {
	out := op.Output()
	if out == nil {
		return false
	}
	readOp := out.LoneDescend()
	if readOp == nil {
		return false
	}
	return sharedCastStrategyC.IsExtensionCastImplied(op, readOp)
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
	return sharedCastStrategyC.IsSubpieceCast(out.TypeReadFacing(nil), in0.TypeReadFacing(nil), uint32(off))
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
	addrVn := op.Input(op.NumInput() - 1)

	// Subscript pattern: LOAD[INT_ADD(ptr, const_offset)] where ptr is a pointer.
	// Render as ptr[index] when const_offset is a multiple of the pointee size.
	// This handles the case where BatchA's RulePtrArith did not fire (pointer type
	// was unknown at BatchA time) but we now know ptr is a pointer.
	// C++ parity: PrintC renders PTRADD as subscript; we detect the INT_ADD pattern directly.
	if frag, ok, err := s.tryRenderSubscript(addrVn); ok || err != nil {
		return frag, err
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
	for def != nil && def.Code() == CPUI_COPY && def.NumInput() == 1 && def.Input(0) != nil {
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
		baseVn := def.Input(0)
		idxVn := def.Input(1)
		if _, ok := baseVn.TypeReadFacing(nil).(*Pointer); !ok {
			return ExprFragment{}, false, nil
		}
		baseExpr, err := s.renderVarnodeExpr(baseVn)
		if err != nil {
			return ExprFragment{}, false, err
		}
		if idxVn.IsConstant() {
			frag := s.lang.PostfixExpr(baseExpr, fmt.Sprintf("[%d]", int64(idxVn.Offset())))
			return frag, true, nil
		}
		idxExpr, err := s.renderVarnodeExpr(idxVn)
		if err != nil {
			return ExprFragment{}, false, err
		}
		frag := s.lang.PostfixExpr(baseExpr, "["+s.lang.ExprString(idxExpr, cPrecLowest, ExprPosNone, ExprAssocNone)+"]")
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
	frag := s.lang.PostfixExpr(baseExpr, fmt.Sprintf("[%d]", index))
	return frag, true, nil
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
	if symExpr, ok := s.renderPtrSubGlobalSymbol(base, off); ok {
		return symExpr, nil
	}
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

// renderPtrSubGlobalSymbol renders a PTRSUB off a global spacebase constant as a
// reference to the global symbol it resolves to (e.g. "&__ImageBase"). Ghidra's
// opPtrsub reads the symbol from op->getIn(1)->getHigh()->getSymbol() in the
// TYPE_SPACEBASE branch; Gosleigh has no global-symbol HighVariable linking yet,
// so the offset constant is resolved against the injected global scope directly
// at print time. The '&' is dropped for code/array symbol types, matching the
// C++ valueon handling. Returns false (falling through to the generic PTRSUB
// rendering) when the base is not a global spacebase, the offset is not
// constant, or no global symbol covers the address -- so the default
// (uninjected) path is unchanged.
// C++ parity: printc.cc PrintC::opPtrsub, TYPE_SPACEBASE branch (&name / name).
func (s *printCState) renderPtrSubGlobalSymbol(base, off *Varnode) (ExprFragment, bool) {
	if base == nil || off == nil || !base.IsSpaceBase() || !off.IsConstant() {
		return ExprFragment{}, false
	}
	if s.fd == nil {
		return ExprFragment{}, false
	}
	gs := s.fd.GetGlobalScope()
	if gs == nil {
		return ExprFragment{}, false
	}
	spc := base.GetSpaceFromConst()
	if spc == nil {
		return ExprFragment{}, false
	}
	entry := gs.QueryContainer(address.Address{Space: spc, Offset: off.Offset()}, 1, address.Address{})
	if entry == nil || entry.Symbol() == nil {
		return ExprFragment{}, false
	}
	sym := entry.Symbol()
	// Only the whole-symbol case (offset 0) is rendered; a partial-symbol
	// reference would need pushPartialSymbol, which is not ported.
	if off.Offset() != entry.Addr().Offset {
		return ExprFragment{}, false
	}
	name := s.lang.Atom(sym.Name())
	// Drop the '&' when the symbol is a code or array type (its name already
	// denotes the address). C++ parity: opPtrsub sets valueon for TYPE_CODE /
	// TYPE_ARRAY.
	if st := sym.Type(); st != nil {
		if m := st.Metatype(); m == TYPE_CODE || m == TYPE_ARRAY {
			return name, true
		}
	}
	return s.lang.UnaryExpr("&", cPrecUnary, name), true
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

// emitConditionParen emits a parenthesized condition, "(" cond ")", feeding the
// condition through EmitBrokenExpr so the pretty-printer can break at the
// outermost operator instead of at the parenthesis. C++ parity: PrintC emits the
// condition via emitExpression, whose operator break tokens (spaces(spacing,bump)
// in emitOp) are what Ghidra wraps at; the surrounding parens are openParen /
// closeParen groups that never themselves become the chosen break.
func (s *printCState) emitConditionParen(frag ExprFragment) {
	s.lang.Token("(")
	s.lang.EmitBrokenExpr(frag)
	s.lang.Token(")")
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
		if len(children) == 1 {
			return s.renderCondition(children[0])
		}
		// C++ parity: PrintC::emitBlockCondition (printc.cc:2968). block(0) is
		// emitted with only_branch (its condition only); block(1) with
		// comma_separate (its leading stores joined by ',' then its condition).
		// The joiner is "&&" when the opcode is CPUI_BOOL_AND, else "||", matching
		// the getOpcode()==CPUI_BOOL_AND test. Both operands render at the lowest
		// precedence so BinaryExpr parenthesizes them, as Ghidra does.
		left, err := s.renderCondition(children[0])
		if err != nil {
			return ExprFragment{}, err
		}
		right, err := s.renderConditionComma(children[1])
		if err != nil {
			return ExprFragment{}, err
		}
		op := "||"
		prec := cPrecLogicalOr
		if bc, ok := bl.Concrete().(*BlockCondition); ok && bc.opc == CPUI_BOOL_AND {
			op = "&&"
			prec = cPrecLogicalAnd
		}
		return s.lang.BinaryExpr(left, op, right, prec, ExprAssocLeft), nil
	case BlockBasicType, BlockPlain:
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
		return s.renderCondition(children[len(children)-1])
	default:
		children := bl.StructuredChildren()
		if len(children) > 0 {
			return s.renderCondition(children[0])
		}
		return s.lang.Atom("0"), nil
	}
}

// renderConditionComma renders a condition sub-block as the second operand of a
// compound condition, in comma_separate mode: a basic block emits its leading
// non-branch stores joined by ',' followed by its CBRANCH condition; a nested
// condition renders recursively as a compound condition. Rendered at the lowest
// precedence so the enclosing BinaryExpr wraps it in parentheses.
// C++ parity: PrintC::emitBlockCondition sets comma_separate on getBlock(1)
// (printc.cc:2984), which for a basic block emits statements comma-separated.
func (s *printCState) renderConditionComma(bl *FlowBlock) (ExprFragment, error) {
	if bl != nil && bl.Type() == BlockBasicType {
		return s.lang.Expr(s.renderCondBlockComma(bl), cPrecLowest), nil
	}
	return s.renderCondition(bl)
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
	//
	// Additionally handles self-referential MULTIEQUAL loops: Heritage SSA inserts
	// phi nodes for stack-pointer (ESP) at loop headers. These MULTIEQUALs are
	// self-referential (their output appears in their own descend list) and are
	// never consumed by meaningful C code. They are treated as vacuous (prologue)
	// consumers so the ESP write chain can be fully marked.
	// C++ parity: Ghidra ActionDeadCode propagates consume bits and detects
	// vacuously-consumed MULTIEQUAL cycles; we approximate at render time.
	isSelfReferentialMultiequal := func(consumer *PcodeOp) bool {
		if consumer.Code() != CPUI_MULTIEQUAL {
			return false
		}
		out := consumer.Output()
		if out == nil {
			return false
		}
		// A MULTIEQUAL is self-referential when its output is one of its own consumers.
		for _, grandConsumer := range out.DescendIter() {
			if grandConsumer == consumer {
				return true
			}
		}
		return false
	}

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
			// Check if every consumer of this op's output is a prologue op or a
			// self-referential MULTIEQUAL (vacuous ESP-loop phi node).
			allPrologue := true
			if out.NumDescend() == 0 {
				allPrologue = false // no consumers; don't suppress
			}
			for _, consumer := range out.DescendIter() {
				if s.prologueOps[consumer] {
					continue
				}
				// A self-referential MULTIEQUAL is vacuously consumed: its output
				// loops back to itself and does not flow into any real computation.
				if isSelfReferentialMultiequal(consumer) {
					continue
				}
				allPrologue = false
				break
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
// Example: after the return-value wiring, EAX has two consumers: IMUL (computation) and
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
						// Inline consumer is transparent, but hasReturnOrInline only fires
						// if the inline op reaches RETURN (not CBRANCH). Without this check,
						// a loop-condition inline op (INT_NOTEQUAL -> CBRANCH) falsely
						// suppresses the loop counter update (local_0 = local_0 - 1).
						// One-level lookahead: any direct consumer of the inline op is RETURN.
						if consumer.Output() != nil {
							for _, c2 := range consumer.Output().DescendIter() {
								if c2 != nil && c2.Code() == CPUI_RETURN {
									hasReturnOrInline = true
									break
								}
							}
						}
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

// markPhiReturnOnly marks MULTIEQUAL output varnodes as prologueVarnodes when
// their only consumers are return-chain ops or self-referential back-edges.
// This prevents architectural live-throughs (ESP_phi, EIP_phi in a loop) from
// appearing as local variable declarations.
//
// Must run after markReturnOnlyCopies so prologueOps and s.inline are fully set.
func (s *printCState) markPhiReturnOnly() {
	for _, op := range s.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_MULTIEQUAL {
			continue
		}
		out := op.Output()
		if out == nil || s.prologueVarnodes[out] {
			continue
		}
		// A phi output backed by a real ScopeLocal stack Symbol is always
		// declared by Ghidra regardless of varnode liveness: declarations are
		// Symbol-driven (PrintC::emitScopeVarDecls, printc.cc:2650 walks the
		// Symbol map). Suppressing it here would drop the declaration while the
		// body still names the variable (compile-broken C). Keep suppression
		// for register live-throughs (ESP_phi/EIP_phi) only.
		if s.stackSymbolType(out) != nil {
			continue
		}
		allTransparent := true
		hasReturnOrInline := false
		hasNonSelfConsumer := false
		for _, consumer := range out.DescendIter() {
			if consumer == nil {
				continue
			}
			// Skip self-referential back-edge: the MULTIEQUAL reads its own output
			// as one of its inputs (loop phi self-loop). Not a real consumer.
			if consumer == op {
				continue
			}
			hasNonSelfConsumer = true
			switch consumer.Code() {
			case CPUI_RETURN:
				hasReturnOrInline = true
			case CPUI_MULTIEQUAL, CPUI_INDIRECT:
				// Marker ops.
			default:
				if s.prologueOps[consumer] {
					// Already suppressed.
				} else if s.inline[consumer] {
					// One-level lookahead: does the inline op reach only RETURN?
					// If any non-RETURN consumer exists, this is not return-only.
					// C++ parity: Ghidra only marks phi as return-only when all uses
					// flow directly to the return value; indirect uses via loop phis
					// (COPY -> MULTIEQUAL -> loop) are not return-only.
					foundReturn := false
					foundNonReturn := false
					if consumer.Output() != nil {
						for _, c2 := range consumer.Output().DescendIter() {
							if c2 == nil {
								continue
							}
							if c2.Code() == CPUI_RETURN {
								foundReturn = true
							} else if c2.Code() != CPUI_MULTIEQUAL && c2.Code() != CPUI_INDIRECT {
								foundNonReturn = true
							}
						}
					}
					if foundReturn && !foundNonReturn {
						hasReturnOrInline = true
					} else {
						// Inline consumer that doesn't exclusively reach RETURN:
						// the phi output is used in a non-return context.
						allTransparent = false
					}
				} else if consumer.Output() != nil && consumer.Output().NumDescend() == 0 {
					// Dead-store consumer.
				} else {
					allTransparent = false
				}
			}
			if !allTransparent {
				break
			}
		}
		// Mark if: no real consumers (pure self-loop phi) OR all real consumers are
		// return-chain transparent. Either way the phi output carries no C-level info.
		if !hasNonSelfConsumer || (allTransparent && hasReturnOrInline) {
			s.prologueVarnodes[out] = true
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
		retOnlyKeys = append(retOnlyKeys, retOnlyEntry{key, prefix})
	}

	if len(retOnlyKeys) == 0 {
		return
	}

	// Ghidra assigns every default local name from a SINGLE shared counter
	// (database.cc ScopeInternal::buildVariableName: "Var" << index++), not a
	// per-prefix counter, and threads one base index through assignDefaultNames.
	// The return-value carrier is created last, so it continues the counter after
	// all other default-named locals: a function with a loop temp iVar1 numbers
	// its carrier uVar2, not uVar1. Seed the shared counter past the highest index
	// already used by a NON-carrier default local (iVarN/uVarN/lVarN/...).
	// C++ parity: database.cc buildVariableName + assignDefaultNames(int4 &base).
	carrierKeys := make(map[locationKey]bool, len(retOnlyKeys))
	for _, e := range retOnlyKeys {
		carrierKeys[e.key] = true
	}
	base := 0
	for _, vn := range s.locals {
		if carrierKeys[varnodeLocKey(vn)] {
			continue
		}
		if idx, ok := parseDefaultVarIndex(s.nameOf(vn)); ok && idx > base {
			base = idx
		}
	}

	// Build a location-key -> newName map using the shared counter.
	keyName := make(map[locationKey]string)
	for _, e := range retOnlyKeys {
		base++
		keyName[e.key] = fmt.Sprintf("%s%d", e.prefix, base)
	}

	// Apply new names to every non-unique varnode at those location keys, and
	// record the location as return-only. All SSA versions and body-op outputs
	// that share the carrier's storage (e.g. the else-branch INT_AND result in
	// the same register) must render under one name; scanning only s.locals would
	// miss the body-op outputs that are not declared locals.
	for _, vn := range s.fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsConstant() || vn.IsAnnotation() {
			continue
		}
		if vn.Space() != nil && vn.Space().IsUnique() {
			continue
		}
		// A function-input Varnode that merely shares storage with the return
		// carrier (e.g. a register parameter whose register is later reused as the
		// carrier) is a DISTINCT HighVariable and keeps its own name. Renaming by
		// location key alone would collapse it into the carrier's uVar name; the
		// carrier's own instances are always written (case results / MULTIEQUAL
		// outputs), never inputs, so skipping inputs never drops a real carrier
		// member. Without this a param (param_1 in the op_switch corpus) sharing
		// ECX with the accumulator would misrender as the carrier name.
		// C++ parity: names are per-HighVariable; a param's HighVariable is not the
		// carrier's, so ActionReturnSplit never renames it.
		if vn.IsInput() {
			continue
		}
		key := varnodeLocKey(vn)
		if newName, ok := keyName[key]; ok {
			s.names[vn] = newName
			s.returnOnlyLocs[key] = true
		}
	}
	// Also rename MULTIEQUAL outputs at return-only locations.
	// These are excluded from s.locals (marked as prologueVarnodes) but the
	// RETURN op still references them by name during C rendering.
	// C++ parity: ActionReturnSplit names the phi output directly when it is
	// the sole carrier of the return value through the phi network.
	for _, op := range s.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.Code() != CPUI_MULTIEQUAL {
			continue
		}
		out := op.Output()
		if out == nil || out.Space() == nil || out.Space().IsUnique() {
			continue
		}
		key := varnodeLocKey(out)
		if newName, ok := keyName[key]; ok {
			s.names[out] = newName
			s.returnOnlyLocs[key] = true
		}
	}

	// G5: Detect return-carrying MULTIEQUAL phi nodes with an identity-copy input
	// from a named parameter. When found, store the param varnode reference for
	// post-ghost-rename resolution in finalizeReturnCarrierRenames, and suppress
	// the identity assignment statement immediately.
	//
	// We store the param VARNODE (not the name string) because renderFunctionSignature
	// has not yet run -- param names will be ghost-offset later. finalizeReturnCarrierRenames
	// is called after renderFunctionSignature to apply the correct final param names.
	//
	// C++ parity: ActionReturnSplit in coreaction.cc detects when a phi input is
	// the identity of a parameter, making the parameter the direct return carrier.
	paramVnSet := make(map[*Varnode]bool)
	for _, pvn := range s.params {
		paramVnSet[pvn] = true
	}
	for _, op := range s.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.Code() != CPUI_MULTIEQUAL {
			continue
		}
		out := op.Output()
		if out == nil || out.Space() == nil || out.Space().IsUnique() {
			continue
		}
		key := varnodeLocKey(out)
		if _, isReturnCarrier := keyName[key]; !isReturnCarrier {
			continue
		}
		// Look for a phi input that is an identity copy of a param varnode.
		for i := 0; i < op.NumInput(); i++ {
			in := op.Input(i)
			if in == nil {
				continue
			}
			paramVn := s.findParamCopyVarnode(in, paramVnSet)
			if paramVn == nil {
				continue
			}
			// Store for post-ghost-rename: finalizeReturnCarrierRenames will apply the name.
			s.returnCarrierParams[key] = paramVn
			// Suppress the identity COPY op: it becomes "param = param" (no-op).
			if defOp := in.Def(); defOp != nil && defOp.Code() == CPUI_COPY {
				s.identityOps[defOp] = true
			}
			break
		}
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

// finalizeReturnCarrierRenames updates return-carrier varnodes to use the
// post-ghost-rename param name. This must run AFTER renderFunctionSignature
// has applied the ghost param offset (param_1 -> param_3 etc.).
//
// C++ parity: ActionReturnSplit renames the return carrier; ghost param offset
// is applied during signature rendering in Ghidra's PrintC.
func (s *printCState) finalizeReturnCarrierRenames() {
	for key, paramVn := range s.returnCarrierParams {
		newName := s.nameOf(paramVn)
		// Update locals at this location key.
		for _, vn := range s.locals {
			if vn.Space() != nil && !vn.Space().IsUnique() {
				if varnodeLocKey(vn) == key {
					s.names[vn] = newName
				}
			}
		}
		// Update MULTIEQUAL outputs at this location (prologueVarnodes, not in s.locals).
		for _, op := range s.fd.GetPcodeOpBank().AllOps() {
			if op == nil || op.Code() != CPUI_MULTIEQUAL || op.Output() == nil {
				continue
			}
			if varnodeLocKey(op.Output()) == key {
				s.names[op.Output()] = newName
			}
		}
	}
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

// parseDefaultVarIndex extracts N from a Ghidra default local name of the form
// <letter>Var<N> (iVar1, uVar12, lVar3, ...). Returns (0,false) for any other
// name (local_*, tmp_*, param_*, register names). Used to continue the shared
// default-name counter past names already assigned by ActionNameVars.
// C++ parity: the index parsed back out of buildVariableName's "<prefix>Var<N>".
func parseDefaultVarIndex(nm string) (int, bool) {
	// Single metatype letter, then "Var", then decimal digits.
	if len(nm) < 5 || nm[1:4] != "Var" {
		return 0, false
	}
	switch nm[0] {
	case 'i', 'u', 'l', 'f', 'b', 'c', 'd':
	default:
		return 0, false
	}
	digits := nm[4:]
	n := 0
	for i := 0; i < len(digits); i++ {
		ch := digits[i]
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
	}
	return n, true
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
	// A storage location backed by a mapped ScopeLocal symbol (an addrtied stack
	// local) is named by its symbol, never by the uVar/iVar/lVar return-carrier
	// convention. Ghidra only re-symbols UNMAPPED register/unique return carriers;
	// a mapped stack local keeps its symbol name even when its sole consumer is
	// the RETURN (e.g. max3's local_18). The check is location-based (FindOverlap)
	// rather than per-varnode (EntryForVarnode): renameReturnOnlyLocals also
	// renames MULTIEQUAL outputs by location key, so a sibling SSA version at the
	// same stack slot (lacking a vnMap attachment) must not seed the rename.
	// Register/unique carriers have no stack symbol -> FindOverlap returns nil ->
	// they still get the convention name.
	// C++ parity: ActionReturnSplit only names carriers not already tied to a
	// Symbol; ScopeInternal symbol names win for mapped storage.
	if sl := s.fd.GetScopeLocal(); sl != nil {
		if e := sl.FindOverlap(vn.Addr(), vn.Size()); e != nil && e.Symbol() != nil {
			return false
		}
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
			// Marker op: check if the marker's output exclusively reaches RETURN.
			// If the phi output has any non-RETURN consumer, this vn is not return-only.
			// C++ parity: ActionReturnSplit traces through phi nodes when determining
			// whether a varnode is a pure return-value carrier.
			if out := consumer.Output(); out != nil {
				phiAllReturn := true
				phiHasReturn := false
				for _, c2 := range out.DescendIter() {
					if c2 == nil || c2 == consumer {
						continue // skip self-referential back-edges
					}
					if c2.Code() == CPUI_RETURN {
						phiHasReturn = true
					} else {
						phiAllReturn = false
						break
					}
				}
				if !phiHasReturn || !phiAllReturn {
					return false
				}
				hasReturn = true
			}
		default:
			if s.prologueOps[consumer] {
				// Suppressed; transparent.
				continue
			}
			if s.inline[consumer] {
				// Inline consumer: trace one level deeper to verify it exclusively
				// reaches RETURN. If the inline op's output feeds anything other than
				// RETURN (e.g. a COPY -> MULTIEQUAL loop phi), this varnode is not
				// return-only.
				// C++ parity: Ghidra's ActionReturnSplit only renames varnodes that
				// are exclusively consumed by the return site -- loop phis break that.
				reachesNonReturn := false
				if consumer.Output() != nil {
					for _, c2 := range consumer.Output().DescendIter() {
						if c2 == nil {
							continue
						}
						switch c2.Code() {
						case CPUI_RETURN:
							// OK
						case CPUI_MULTIEQUAL, CPUI_INDIRECT:
							// Marker -- this inline feeds a phi; not return-only.
							reachesNonReturn = true
						default:
							if !s.prologueOps[c2] {
								reachesNonReturn = true
							}
						}
					}
				}
				if reachesNonReturn {
					return false
				}
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
