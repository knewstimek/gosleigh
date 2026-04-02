package pcode

import "sync"

type funcdataBlockState struct {
	mu        sync.Mutex
	basic     *BlockGraph
	structure *BlockGraph
}

var globalFuncdataBlockState = struct {
	sync.Mutex
	byFunc map[*Funcdata]*funcdataBlockState
}{
	byFunc: make(map[*Funcdata]*funcdataBlockState),
}

func getFuncdataBlockState(data *Funcdata) *funcdataBlockState {
	globalFuncdataBlockState.Lock()
	defer globalFuncdataBlockState.Unlock()
	state := globalFuncdataBlockState.byFunc[data]
	if state == nil {
		state = &funcdataBlockState{}
		globalFuncdataBlockState.byFunc[data] = state
	}
	return state
}

func (fd *Funcdata) SetBasicBlocks(graph *BlockGraph) {
	state := getFuncdataBlockState(fd)
	state.mu.Lock()
	state.basic = graph
	state.mu.Unlock()
}

func (fd *Funcdata) GetBasicBlocks() *BlockGraph {
	state := getFuncdataBlockState(fd)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.basic
}

func (fd *Funcdata) SetStructureGraph(graph *BlockGraph) {
	state := getFuncdataBlockState(fd)
	state.mu.Lock()
	state.structure = graph
	state.mu.Unlock()
}

func (fd *Funcdata) GetStructure() *BlockGraph {
	state := getFuncdataBlockState(fd)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.structure == nil {
		state.structure = NewBlockGraph()
	}
	return state.structure
}

func (fd *Funcdata) getBasicBlocks() *BlockGraph {
	return fd.GetBasicBlocks()
}

func (fd *Funcdata) getStructure() *BlockGraph {
	return fd.GetStructure()
}

func (fd *Funcdata) installSwitchDefaults() {}

func cloneFlowBlock(src *FlowBlock) *FlowBlock {
	switch concrete := src.Concrete().(type) {
	case *BlockBasic:
		clone := NewBlockBasic()
		clone.SetType(src.Type())
		clone.flags = src.Flags()
		clone.ops = append(clone.ops, concrete.Ops()...)
		return &clone.FlowBlock
	default:
		clone := &FlowBlock{}
		clone.SetType(src.Type())
		clone.flags = src.Flags()
		clone.SetConcrete(clone)
		return clone
	}
}

func cloneBlockGraph(src *BlockGraph) *BlockGraph {
	if src == nil {
		return NewBlockGraph()
	}
	clone := NewBlockGraph()
	mapping := make(map[*FlowBlock]*FlowBlock, src.GetSize())
	for i := 0; i < src.GetSize(); i++ {
		orig := src.GetBlock(i)
		dup := cloneFlowBlock(orig)
		mapping[orig] = dup
		clone.AddBlock(dup)
	}
	for i := 0; i < src.GetSize(); i++ {
		orig := src.GetBlock(i)
		dup := mapping[orig]
		dup.SetIndex(orig.Index())
		dup.SetNumDesc(orig.NumDesc())
		for _, child := range orig.StructuredChildren() {
			dupChildren := append(dup.StructuredChildren(), mapping[child])
			dup.setStructuredChildren(dupChildren)
		}
		dup.setGotoEdgeIndex(orig.GotoEdgeIndex())
		dup.setOverflowSyntax(orig.HasOverflowSyntax())
		for j := 0; j < orig.SizeOut(); j++ {
			clone.AddEdge(dup, mapping[orig.getOut(j)], orig.OutEdge(j).Label)
		}
	}
	return clone
}

type ActionBlockStructure struct {
	ActionBase
}

func NewActionBlockStructure(group string) *ActionBlockStructure {
	act := &ActionBlockStructure{}
	act.ActionBase = NewActionBase(act, 0, "blockstructure", group)
	return act
}

func (a *ActionBlockStructure) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionBlockStructure(a.GetGroup())
}

func (a *ActionBlockStructure) Apply(data *Funcdata) int {
	graph := data.getStructure()
	if graph.GetSize() != 0 {
		return 0
	}
	data.installSwitchDefaults()
	basic := data.getBasicBlocks()
	if basic == nil {
		return 0
	}
	copyGraph := cloneBlockGraph(basic)
	data.SetStructureGraph(copyGraph)
	collapse := NewCollapseStructure(copyGraph)
	collapse.CollapseAll()
	a.count += collapse.GetChangeCount()
	return 0
}

type ActionFinalStructure struct {
	ActionBase
}

func NewActionFinalStructure(group string) *ActionFinalStructure {
	act := &ActionFinalStructure{}
	act.ActionBase = NewActionBase(act, 0, "finalstructure", group)
	return act
}

func (a *ActionFinalStructure) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionFinalStructure(a.GetGroup())
}

func (a *ActionFinalStructure) Apply(data *Funcdata) int {
	graph := data.getStructure()
	graph.OrderBlocks()
	graph.finalizePrinting(data)
	graph.scopeBreak(-1, -1)
	graph.markUnstructured()
	graph.markLabelBumpUp(false)
	return 0
}
