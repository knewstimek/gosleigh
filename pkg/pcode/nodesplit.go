package pcode

import "gosleigh/pkg/address"

// cloneBlockOps duplicates the p-code of a basic block into its split copy,
// performing the SSA surgery that keeps data-flow consistent: each cloned op
// gets a fresh output Varnode, cloned MULTIEQUALs are reduced to a COPY of the
// single moved in-edge value (and the original MULTIEQUAL loses that in-edge),
// and cloned op inputs are rewired to the cloned defs via origToClone.
//
// C++ parity: funcdata_block.cc CloneBlockOps.
type cloneBlockOps struct {
	data        *Funcdata
	cloneList   []cloneBlockEntry
	origToClone map[*PcodeOp]*PcodeOp
}

// cloneBlockEntry pairs a cloned op with the original it was copied from, in the
// order the ops appear in the source block.
// C++ parity: CloneBlockOps::cloneList entries (cloneOp, origOp).
type cloneBlockEntry struct {
	cloneOp *PcodeOp
	origOp  *PcodeOp
}

// buildOpCloneFlags / buildOpCloneAddlFlags mirror the exact flag subsets that
// C++ CloneBlockOps::buildOpClone carries onto the clone. Go's flag layout puts
// no_indirect_collapse in the additional word (C++ keeps it in the primary word),
// so it is folded into the additional mask here.
// C++ parity: funcdata_block.cc:963-970.
const buildOpCloneFlags = PcodeOpStartBasic | PcodeOpNoCollapse | PcodeOpStartMark |
	PcodeOpNonPrinting | PcodeOpHalt | PcodeOpBadInstruction | PcodeOpUnimplemented |
	PcodeOpNoReturn | PcodeOpMissing | PcodeOpIndirectCreation | PcodeOpIndirectStore |
	PcodeOpCalculatedBool | PcodeOpPtrFlow

const buildOpCloneAddlFlags = PcodeOpSpecialProp | PcodeOpSpecialPrint | PcodeOpIncidentalCopy |
	PcodeOpIsCpoolTransformed | PcodeOpStopTypePropagation | PcodeOpStoreUnmapped |
	PcodeOpNoIndirectCollapse

// buildVarnodeOutputFlags / buildVarnodeOutputAddlFlags mirror the Varnode flag
// subsets copied onto a cloned op's output.
// C++ parity: funcdata_block.cc:990-997.
const buildVarnodeOutputFlags = VarnodeExternRef | VarnodeVolatile | VarnodeIncidentalCopy |
	VarnodeReadOnly | VarnodePersist | VarnodeAddrTied | VarnodeAddrForce | VarnodeNoLocalAlias |
	VarnodeSpaceBase | VarnodeIndirectCreation | VarnodeReturnAddress | VarnodePrecisLo | VarnodePrecisHi

const buildVarnodeOutputAddlFlags = VarnodeWriteMask | VarnodePtrFlow | VarnodeStackStore

func newCloneBlockOps(data *Funcdata) *cloneBlockOps {
	return &cloneBlockOps{data: data, origToClone: make(map[*PcodeOp]*PcodeOp)}
}

// buildOpClone makes a basic clone of op copying its control-flow properties.
// A branch op is not cloned (returns nil); only CPUI_BRANCH is permitted as a
// branch in a split block.
// C++ parity: CloneBlockOps::buildOpClone (funcdata_block.cc:951).
func (c *cloneBlockOps) buildOpClone(op *PcodeOp) *PcodeOp {
	if op.IsBranch() {
		if op.Code() != CPUI_BRANCH {
			panic("Cannot duplicate 2-way or n-way branch in nodesplit")
		}
		return nil
	}
	dup := c.data.NewOp(op.NumInput(), op.Addr())
	c.data.OpSetOpcode(dup, op.Code())
	dup.SetFlag(op.flags & buildOpCloneFlags)
	dup.SetAdditionalFlag(op.addlFlags & buildOpCloneAddlFlags)
	c.cloneList = append(c.cloneList, cloneBlockEntry{cloneOp: dup, origOp: op})
	c.origToClone[op] = dup
	return dup
}

// buildVarnodeOutput clones the output Varnode of origOp onto cloneOp, copying
// the flag subset that survives duplication.
// C++ parity: CloneBlockOps::buildVarnodeOutput (funcdata_block.cc:981).
func (c *cloneBlockOps) buildVarnodeOutput(origOp, cloneOp *PcodeOp) {
	opvn := origOp.Output()
	if opvn == nil {
		return
	}
	newvn := c.data.NewVarnodeOut(opvn.Size(), opvn.Addr(), cloneOp)
	newvn.SetFlags(opvn.Flags() & buildVarnodeOutputFlags)
	newvn.SetAddlFlags(opvn.AddlFlags() & buildVarnodeOutputAddlFlags)
}

// cloneBlock clones every op of b into bprime, then patches the cloned inputs.
// C++ parity: CloneBlockOps::cloneBlock (funcdata_block.cc:1004).
func (c *cloneBlockOps) cloneBlock(b, bprime *BlockBasic, inedge int) {
	for _, origOp := range b.opSlice() {
		if origOp == nil {
			continue
		}
		cloneOp := c.buildOpClone(origOp)
		if cloneOp == nil {
			continue
		}
		c.buildVarnodeOutput(origOp, cloneOp)
		c.data.OpInsertEnd(cloneOp, bprime)
	}
	c.patchInputs(inedge)
}

// patchInputs maps input Varnodes of the original ops onto the cloned ops.
// MULTIEQUAL ops are special-cased: the clone keeps only the moved in-edge value
// (reduced to a COPY) and the original drops that in-edge; a resulting 1-input
// MULTIEQUAL also collapses to a COPY. Other inputs are shared, except constants
// (shared), annotations (re-created), and clone-local defs (rewired via
// origToClone). Free varnodes cannot be cloned.
// C++ parity: CloneBlockOps::patchInputs (funcdata_block.cc:1047).
func (c *cloneBlockOps) patchInputs(inedge int) {
	for pos := 0; pos < len(c.cloneList); pos++ {
		origOp := c.cloneList[pos].origOp
		cloneOp := c.cloneList[pos].cloneOp
		switch {
		case origOp.Code() == CPUI_MULTIEQUAL:
			cloneOp.SetNumInputs(1) // One edge now goes into the new block
			c.data.OpSetOpcode(cloneOp, CPUI_COPY)
			c.data.OpSetInput(cloneOp, origOp.Input(inedge), 0)
			c.data.OpRemoveInput(origOp, inedge) // One edge removed from original
			if origOp.NumInput() == 1 {
				c.data.OpSetOpcode(origOp, CPUI_COPY)
			}
		case origOp.Code() == CPUI_INDIRECT:
			panic("Can't clone INDIRECTs")
		case origOp.IsCall():
			panic("Can't clone CALLs")
		default:
			for i := 0; i < cloneOp.NumInput(); i++ {
				origVn := origOp.Input(i)
				var cloneVn *Varnode
				switch {
				case origVn.IsConstant():
					cloneVn = origVn
				case origVn.IsAnnotation():
					cloneVn = c.data.NewCodeRef(origVn.Addr())
				case origVn.IsFree():
					panic("Can't clone free varnode")
				default:
					if origVn.IsWritten() {
						if mapped, ok := c.origToClone[origVn.Def()]; ok {
							cloneVn = mapped.Output()
						} else {
							cloneVn = origVn
						}
					} else {
						cloneVn = origVn
					}
				}
				c.data.OpSetInput(cloneOp, cloneVn, i)
			}
		}
	}
}

// NewCodeRef creates an annotation Varnode encoding a code address, used to
// duplicate an annotation input during op cloning.
// C++ parity: Funcdata::newCodeRef (funcdata_varnode.cc:222).
func (fd *Funcdata) NewCodeRef(m address.Address) *Varnode {
	vn := fd.NewVarnode(1, m)
	vn.SetFlags(VarnodeAnnotation)
	return vn
}
