package pcode

import "gosleigh/pkg/address"

// Funcdata flags -- processing state bitmask.
// C++ parity: funcdata.hh Funcdata::Flags
const (
	FuncHighLevelOn        uint32 = 0x0001
	FuncBlocksGenerated    uint32 = 0x0002
	FuncBlocksUnreachable  uint32 = 0x0004
	FuncProcessingStarted  uint32 = 0x0008
	FuncProcessingComplete uint32 = 0x0010
	FuncTypeRecoveryOn     uint32 = 0x0020
	FuncNoCode             uint32 = 0x0080
	FuncUnimplPresent      uint32 = 0x0800
	FuncBadDataPresent     uint32 = 0x1000
)

// Funcdata is the central container for all data structures associated
// with decompiling a single function.
// C++ parity: funcdata.hh Funcdata
type Funcdata struct {
	flags       uint32
	name        string
	displayName string
	baseAddr    address.Address
	size        int32

	// Core data stores
	vbank VarnodeBank
	obank PcodeOpBank

	// Constant space for NewConstant
	constSpace *address.Space

	// TypeOp registry (one per opcode, shared)
	typeOps []TypeOp

	// Phase watermarks (Varnode creation indices)
	cleanUpIndex   uint32
	highLevelIndex uint32
	castPhaseIndex uint32

	// Minimum laned size
	minLanedSize uint32

	// Calling convention and local variable scope (set by ApplyCallingConvention).
	// Both are nil until a cspec is attached.
	// C++ parity: Funcdata::proto, Funcdata::localmap
	funcProto  *FuncProto
	scopeLocal *ScopeLocal
}

// NewFuncdata creates a Funcdata container for the named function.
// uniqSpace and uniqBase configure the unique/temp varnode allocator.
// constSpace is used for constant varnode creation.
// C++ parity: funcdata.cc Funcdata::Funcdata
func NewFuncdata(name string, addr address.Address, uniqSpace *address.Space, uniqBase uint64, constSpace *address.Space) *Funcdata {
	fd := &Funcdata{
		name:       name,
		baseAddr:   addr,
		constSpace: constSpace,
		typeOps:    RegisterTypeOps(),
	}
	// Initialize banks inline (avoid extra pointer indirection).
	// VarnodeBank needs the unique space for temp allocation.
	vb := NewVarnodeBank(uniqSpace, uniqBase)
	fd.vbank = *vb
	ob := NewPcodeOpBank()
	fd.obank = *ob
	return fd
}

// ---------------------------------------------------------------------------
// Getters
// ---------------------------------------------------------------------------

func (fd *Funcdata) Name() string                 { return fd.name }
func (fd *Funcdata) DisplayName() string          { return fd.displayName }
func (fd *Funcdata) SetDisplayName(n string)      { fd.displayName = n }
func (fd *Funcdata) BaseAddr() address.Address    { return fd.baseAddr }
func (fd *Funcdata) Size() int32                  { return fd.size }
func (fd *Funcdata) Flags() uint32                { return fd.flags }
func (fd *Funcdata) HasFlag(f uint32) bool        { return fd.flags&f != 0 }
func (fd *Funcdata) SetFlag(f uint32)             { fd.flags |= f }
func (fd *Funcdata) ClearFlag(f uint32)           { fd.flags &^= f }
func (fd *Funcdata) GetVarnodeBank() *VarnodeBank { return &fd.vbank }
func (fd *Funcdata) GetPcodeOpBank() *PcodeOpBank { return &fd.obank }

// GetFuncProto returns the calling convention prototype, or nil if not set.
// C++ parity: Funcdata::getFuncProto
func (fd *Funcdata) GetFuncProto() *FuncProto { return fd.funcProto }

// SetFuncProto attaches a calling convention prototype.
// C++ parity: Funcdata::getFuncProto (setter path)
func (fd *Funcdata) SetFuncProto(fp *FuncProto) { fd.funcProto = fp }

// GetScopeLocal returns the local variable scope, or nil if not set.
// C++ parity: Funcdata::getScopeLocal
func (fd *Funcdata) GetScopeLocal() *ScopeLocal { return fd.scopeLocal }

// SetScopeLocal attaches a local variable scope.
func (fd *Funcdata) SetScopeLocal(sl *ScopeLocal) { fd.scopeLocal = sl }

// ---------------------------------------------------------------------------
// Varnode creation
// C++ parity: funcdata_varnode.cc
// ---------------------------------------------------------------------------

// NewVarnode creates a free Varnode.
// C++ parity: Funcdata::newVarnode
func (fd *Funcdata) NewVarnode(size int32, loc address.Address) *Varnode {
	return fd.vbank.Create(size, loc)
}

// NewVarnodeOut creates a Varnode as the defined output of an op.
// C++ parity: Funcdata::newVarnodeOut
func (fd *Funcdata) NewVarnodeOut(size int32, loc address.Address, op *PcodeOp) *Varnode {
	vn := fd.vbank.CreateDef(size, loc, op)
	op.SetOutput(vn)
	return vn
}

// NewUniqueOut creates a temp Varnode (unique space) as output of an op.
// C++ parity: Funcdata::newUniqueOut
func (fd *Funcdata) NewUniqueOut(size int32, op *PcodeOp) *Varnode {
	vn := fd.vbank.CreateDefUnique(size, op)
	op.SetOutput(vn)
	return vn
}

// NewConstant creates a constant Varnode.
// C++ parity: Funcdata::newConstant
func (fd *Funcdata) NewConstant(size int32, val uint64) *Varnode {
	loc := address.Address{Space: fd.constSpace, Offset: val}
	return fd.vbank.Create(size, loc)
}

// SetInputVarnode promotes a free Varnode to SSA function input.
// C++ parity: Funcdata::setInputVarnode
func (fd *Funcdata) SetInputVarnode(vn *Varnode) *Varnode {
	fd.vbank.SetInput(vn)
	return vn
}

// DeleteVarnode removes a Varnode from the bank.
// The varnode must be free with no descendants.
// C++ parity: Funcdata::deleteVarnode
func (fd *Funcdata) DeleteVarnode(vn *Varnode) {
	fd.vbank.Destroy(vn)
}

// FindVarnodeInput finds an input varnode matching the given size and location.
// C++ parity: Funcdata::findVarnodeInput
func (fd *Funcdata) FindVarnodeInput(size int32, loc address.Address) *Varnode {
	return fd.vbank.FindInput(size, loc)
}

// NumVarnodes returns the total number of varnodes.
func (fd *Funcdata) NumVarnodes() int {
	return fd.vbank.NumVarnodes()
}

// ---------------------------------------------------------------------------
// PcodeOp creation
// C++ parity: funcdata_op.cc
// ---------------------------------------------------------------------------

// NewOp creates a new PcodeOp with the given number of inputs.
// The op starts on the dead list.
// C++ parity: Funcdata::newOp
func (fd *Funcdata) NewOp(numInputs int, addr address.Address) *PcodeOp {
	return fd.obank.Create(numInputs, addr)
}

// OpSetOpcode assigns an opcode to a PcodeOp via the TypeOp registry.
// C++ parity: Funcdata::opSetOpcode
func (fd *Funcdata) OpSetOpcode(op *PcodeOp, opc OpCode) {
	if int(opc) < len(fd.typeOps) && fd.typeOps[opc] != nil {
		op.SetOpcode(fd.typeOps[opc])
	}
}

// OpSetOutput wires a Varnode as the output of a PcodeOp.
// Updates both the op's output pointer and the varnode's def link.
// C++ parity: Funcdata::opSetOutput
func (fd *Funcdata) OpSetOutput(op *PcodeOp, vn *Varnode) {
	vn.SetDef(op)
	op.SetOutput(vn)
}

// OpSetInput wires a Varnode as an input of a PcodeOp at the given slot.
// Updates both the op's input slot and the varnode's descend list.
// C++ parity: Funcdata::opSetInput
func (fd *Funcdata) OpSetInput(op *PcodeOp, vn *Varnode, slot int) {
	op.SetInput(vn, slot)
	vn.AddDescend(op)
}

// OpUnsetOutput disconnects the output Varnode from a PcodeOp.
// Clears the varnode's def link and the op's output pointer.
// If the varnode is bank-managed (VarnodeWritten), it is properly removed
// from or transitioned in the VarnodeBank while its def is still valid for
// sorting -- clearing def before removal would corrupt CompareDefLoc.
// C++ parity: Funcdata::opUnsetOutput
func (fd *Funcdata) OpUnsetOutput(op *PcodeOp) {
	vn := op.Output()
	if vn == nil {
		return
	}
	op.SetOutput(nil)
	if vn.IsWritten() {
		// Varnode is in VarnodeBank's defTree. Must remove/transition while
		// vn.def is still valid so CompareDefLoc can sort during removal.
		if vn.NumDescend() == 0 {
			// No consumers: fully destroy from bank, then clear def.
			fd.vbank.Destroy(vn)
			vn.SetDef(nil)
		} else {
			// Still has consumers: transition to free so they remain valid.
			// MakeFree internally clears def and VarnodeWritten.
			fd.vbank.MakeFree(vn)
		}
		return
	}
	// Non-bank-managed varnode (free or directly assigned def): just clear.
	vn.SetDef(nil)
}

// OpUnsetInput disconnects an input Varnode from a PcodeOp at the given slot.
// Removes the op from the varnode's descend list and clears the slot.
// C++ parity: Funcdata::opUnsetInput
func (fd *Funcdata) OpUnsetInput(op *PcodeOp, slot int) {
	vn := op.Input(slot)
	if vn != nil {
		vn.EraseDescend(op)
		op.ClearInput(slot)
	}
}

// OpMarkAlive moves an op from dead to alive list.
// C++ parity: Funcdata::opMarkAlive (via PcodeOpBank::markAlive)
func (fd *Funcdata) OpMarkAlive(op *PcodeOp) {
	fd.obank.MarkAlive(op)
}

// OpMarkDead moves an op from alive to dead list.
// C++ parity: Funcdata::opMarkDead (via PcodeOpBank::markDead)
func (fd *Funcdata) OpMarkDead(op *PcodeOp) {
	fd.obank.MarkDead(op)
}

// OpDestroy destroys a PcodeOp and disconnects all its Varnodes.
// Removes the op from its parent basic block so it is no longer emitted.
// C++ parity: Funcdata::opDestroy
func (fd *Funcdata) OpDestroy(op *PcodeOp) {
	// Remove from parent basic block first so it is no longer iterable.
	// Ghidra: op->getParent()->removeOp(op)
	if p := op.Parent(); p != nil {
		p.RemoveOp(op)
	}
	// Disconnect output
	fd.OpUnsetOutput(op)
	// Disconnect all inputs
	for i := 0; i < op.NumInput(); i++ {
		fd.OpUnsetInput(op, i)
	}
	fd.obank.Destroy(op)
}

// FindOp looks up a PcodeOp by its SeqNum.
// C++ parity: Funcdata::findOp
func (fd *Funcdata) FindOp(seq SeqNum) *PcodeOp {
	return fd.obank.FindOp(seq)
}

// NumOps returns the total number of PcodeOps.
func (fd *Funcdata) NumOps() int {
	return fd.obank.NumOps()
}

// ---------------------------------------------------------------------------
// Heritage support methods
// C++ parity: funcdata.hh Funcdata (heritage-related)
// ---------------------------------------------------------------------------

// OpInsertBegin creates an op and inserts it at the beginning of a basic block.
// The op is marked alive and its parent is set.
// C++ parity: Funcdata::opInsertBegin
func (fd *Funcdata) OpInsertBegin(op *PcodeOp, bb *BlockBasic) {
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpBegin(op)
}

// OpInsertEnd creates an op and inserts it at the end of a basic block.
// The op is marked alive and its parent is set.
// C++ parity: Funcdata::opInsertEnd
func (fd *Funcdata) OpInsertEnd(op *PcodeOp, bb *BlockBasic) {
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpEnd(op)
}

// VarnodesBySpace returns all varnodes in the given address space.
func (fd *Funcdata) VarnodesBySpace(spc *address.Space) []*Varnode {
	return fd.vbank.BySpace(spc)
}

// VarnodesByRange returns all varnodes overlapping [addr, addr+size).
func (fd *Funcdata) VarnodesByRange(addr address.Address, size int32) []*Varnode {
	return fd.vbank.LocRange(addr, size)
}

// ConstSpace returns the constant address space.
func (fd *Funcdata) ConstSpace() *address.Space {
	return fd.constSpace
}
