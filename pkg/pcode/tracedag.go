package pcode

import (
	"container/list"
	"sort"
)

// TraceDAG finds the edges of a DAG (or of one loop body) that are most
// likely unstructured gotos. Paths are traced forward from the roots; a
// BranchPoint opens where a path splits and retires once all of its paths
// merge again. When no trace can move, the worst-scoring edge is declared a
// likely goto and removed from consideration.
// C++ parity: blockaction.cc TraceDAG.
type TraceDAG struct {
	likelygoto        *[]FloatingEdge
	rootlist          []*FlowBlock
	activecount       int
	missedactivecount int
	activetrace       *list.List // of *blockTrace
	finishblock       *FlowBlock
}

// branchPoint is a block where traced paths split.
// C++ parity: TraceDAG::BranchPoint.
type branchPoint struct {
	parent  *branchPoint
	pathout int // index of the parent's path this lies on
	top     *FlowBlock
	paths   []*blockTrace
	depth   int
	ismark  bool
}

const (
	traceActive   = 1
	traceTerminal = 2 // all paths from here exit without merging back
)

// blockTrace is one path being pushed forward from a branchPoint.
// C++ parity: TraceDAG::BlockTrace.
type blockTrace struct {
	flags      uint32
	top        *branchPoint
	pathout    int
	bottom     *FlowBlock // current node along the path
	destnode   *FlowBlock // next node the trace tries to push into
	edgelump   int        // >1: the edge into destnode stands for several merged edges
	activeiter *list.Element
	derivedbp  *branchPoint
}

func (t *blockTrace) isActive() bool   { return t.flags&traceActive != 0 }
func (t *blockTrace) isTerminal() bool { return t.flags&traceTerminal != 0 }

// badEdgeScore rates an active trace as the unstructured edge.
// C++ parity: TraceDAG::BadEdgeScore.
type badEdgeScore struct {
	exitproto   *FlowBlock
	trace       *blockTrace
	distance    int
	terminal    int
	siblingedge int
}

func NewTraceDAG(likelygoto *[]FloatingEdge) *TraceDAG {
	return &TraceDAG{likelygoto: likelygoto, activetrace: list.New()}
}

func (t *TraceDAG) AddRoot(root *FlowBlock) { t.rootlist = append(t.rootlist, root) }

func (t *TraceDAG) SetFinishBlock(bl *FlowBlock) { t.finishblock = bl }

// C++ parity: TraceDAG::BranchPoint::BranchPoint(BlockTrace *).
func newBranchPoint(parenttrace *blockTrace) *branchPoint {
	bp := &branchPoint{
		parent:  parenttrace.top,
		depth:   parenttrace.top.depth + 1,
		pathout: parenttrace.pathout,
		top:     parenttrace.destnode,
	}
	for i := 0; i < bp.top.SizeOut(); i++ {
		if !bp.top.isLoopDAGOut(i) {
			continue
		}
		bp.paths = append(bp.paths, &blockTrace{
			top:      bp,
			pathout:  len(bp.paths),
			bottom:   bp.top,
			destnode: bp.top.getOut(i),
			edgelump: 1,
		})
	}
	return bp
}

// markPath toggles the marks from bp up to the root.
func (bp *branchPoint) markPath() {
	for cur := bp; cur != nil; cur = cur.parent {
		cur.ismark = !cur.ismark
	}
}

// distance counts the branch points between bp and op2 through their common
// ancestor; bp's path must be marked.
func (bp *branchPoint) distance(op2 *branchPoint) int {
	for cur := op2; cur != nil; cur = cur.parent {
		if cur.ismark {
			return (bp.depth - cur.depth) + (op2.depth - cur.depth)
		}
	}
	return bp.depth + op2.depth + 1
}

// compareFinal reports whether op2 is a more likely unstructured edge.
func (s *badEdgeScore) compareFinal(op2 *badEdgeScore) bool {
	if s.siblingedge != op2.siblingedge {
		return op2.siblingedge < s.siblingedge
	}
	if s.terminal != op2.terminal {
		return s.terminal < op2.terminal
	}
	if s.distance != op2.distance {
		return s.distance < op2.distance
	}
	return s.trace.top.depth < op2.trace.top.depth
}

// less groups scores by exit block, then branch point, then path.
func (s *badEdgeScore) less(op2 *badEdgeScore) bool {
	a, b := s.exitproto.Index(), op2.exitproto.Index()
	if a != b {
		return a < b
	}
	a, b = -1, -1
	if tb := s.trace.top.top; tb != nil {
		a = tb.Index()
	}
	if tb := op2.trace.top.top; tb != nil {
		b = tb.Index()
	}
	if a != b {
		return a < b
	}
	return s.trace.pathout < op2.trace.pathout
}

// removeTrace records the trace's edge as a likely goto and drops it.
func (t *TraceDAG) removeTrace(trace *blockTrace) {
	*t.likelygoto = append(*t.likelygoto, NewFloatingEdge(trace.bottom, trace.destnode))
	trace.destnode.SetVisitCount(trace.destnode.VisitCount() + int32(trace.edgelump))
	parentbp := trace.top
	if trace.bottom != parentbp.top {
		// Past the branch: the trace now just terminates (it stays active).
		trace.flags |= traceTerminal
		trace.bottom = nil
		trace.destnode = nil
		trace.edgelump = 0
		return
	}
	t.removeActive(trace)
	for i := trace.pathout + 1; i < len(parentbp.paths); i++ {
		moved := parentbp.paths[i]
		moved.pathout--
		if moved.derivedbp != nil {
			moved.derivedbp.pathout--
		}
		parentbp.paths[i-1] = moved
	}
	parentbp.paths = parentbp.paths[:len(parentbp.paths)-1]
}

// processExitConflict scores traces that exit to the same block.
func processExitConflict(group []*badEdgeScore) {
	for i, start := range group {
		if i+1 == len(group) {
			break
		}
		startbp := start.trace.top
		startbp.markPath()
		for _, other := range group[i+1:] {
			if startbp == other.trace.top {
				start.siblingedge++
				other.siblingedge++
			}
			dist := startbp.distance(other.trace.top)
			if start.distance == -1 || start.distance > dist {
				start.distance = dist
			}
			if other.distance == -1 || other.distance > dist {
				other.distance = dist
			}
		}
		startbp.markPath()
	}
}

// selectBadEdge picks the active trace most likely to be unstructured.
func (t *TraceDAG) selectBadEdge() *blockTrace {
	var scores []*badEdgeScore
	for e := t.activetrace.Front(); e != nil; e = e.Next() {
		tr := e.Value.(*blockTrace)
		if tr.isTerminal() {
			continue
		}
		if tr.top.top == nil && tr.bottom == nil {
			continue // never remove virtual edges
		}
		s := &badEdgeScore{trace: tr, exitproto: tr.destnode, distance: -1}
		if tr.destnode.SizeOut() == 0 {
			s.terminal = 1
		}
		scores = append(scores, s)
	}
	// list::sort is stable.
	sort.SliceStable(scores, func(i, j int) bool { return scores[i].less(scores[j]) })
	start := 0
	for i := 1; i <= len(scores); i++ {
		if i == len(scores) || scores[i].exitproto != scores[start].exitproto {
			if i-start > 1 {
				processExitConflict(scores[start:i])
			}
			start = i
		}
	}
	maxs := scores[0]
	for _, s := range scores[1:] {
		if maxs.compareFinal(s) {
			maxs = s
		}
	}
	return maxs.trace
}

func (t *TraceDAG) insertActive(trace *blockTrace) {
	trace.activeiter = t.activetrace.PushBack(trace)
	trace.flags |= traceActive
	t.activecount++
}

func (t *TraceDAG) removeActive(trace *blockTrace) {
	t.activetrace.Remove(trace.activeiter)
	trace.activeiter = nil
	trace.flags &^= traceActive
	t.activecount--
}

// checkOpen reports whether every DAG edge into the trace's next node has
// been reached, so the trace can push into it.
func (t *TraceDAG) checkOpen(trace *blockTrace) bool {
	if trace.isTerminal() {
		return false
	}
	isroot := false
	if trace.top.depth == 0 {
		if trace.bottom == nil {
			return true // the artificial root opens its first level
		}
		isroot = true
	}
	bl := trace.destnode
	if bl == t.finishblock && !isroot {
		return false
	}
	ignore := trace.edgelump + int(bl.VisitCount())
	count := 0
	for i := 0; i < bl.SizeIn(); i++ {
		if bl.isLoopDAGIn(i) {
			count++
			if count > ignore {
				return false
			}
		}
	}
	return true
}

// openBranch pushes the trace into its next node, which becomes a new
// BranchPoint. Returns the trace to continue from.
func (t *TraceDAG) openBranch(parent *blockTrace) *list.Element {
	nb := newBranchPoint(parent)
	parent.derivedbp = nb
	if len(nb.paths) == 0 {
		parent.derivedbp = nil
		parent.flags |= traceTerminal
		parent.bottom = nil
		parent.destnode = nil
		parent.edgelump = 0
		return parent.activeiter
	}
	t.removeActive(parent)
	for _, p := range nb.paths {
		t.insertActive(p)
	}
	return nb.paths[0].activeiter
}

// checkRetirement reports whether all paths of the trace's BranchPoint have
// merged into a single exit block (returned) or terminated.
func (t *TraceDAG) checkRetirement(trace *blockTrace) (*FlowBlock, bool) {
	if trace.pathout != 0 {
		return nil, false
	}
	bp := trace.top
	if bp.depth == 0 {
		for _, cur := range bp.paths {
			if !cur.isActive() || !cur.isTerminal() {
				return nil, false
			}
		}
		return nil, true
	}
	var outblock *FlowBlock
	for _, cur := range bp.paths {
		if !cur.isActive() {
			return nil, false
		}
		if cur.isTerminal() || outblock == cur.destnode {
			continue
		}
		if outblock != nil {
			return nil, false
		}
		outblock = cur.destnode
	}
	return outblock, true
}

// retireBranch collapses a BranchPoint back into its parent trace.
func (t *TraceDAG) retireBranch(bp *branchPoint, exitblock *FlowBlock) *list.Element {
	var edgeoutBl *FlowBlock
	edgelumpSum := 0
	for _, cur := range bp.paths {
		if !cur.isTerminal() {
			edgelumpSum += cur.edgelump
			if edgeoutBl == nil {
				edgeoutBl = cur.bottom
			}
		}
		t.removeActive(cur)
	}
	if bp.depth == 0 {
		return t.activetrace.Front()
	}
	if bp.parent != nil {
		pt := bp.parent.paths[bp.pathout]
		pt.derivedbp = nil
		if edgeoutBl == nil {
			pt.flags |= traceTerminal
			pt.bottom = nil
			pt.destnode = nil
			pt.edgelump = 0
		} else {
			pt.bottom = edgeoutBl
			pt.destnode = exitblock
			pt.edgelump = edgelumpSum
		}
		t.insertActive(pt)
		return pt.activeiter
	}
	return t.activetrace.Front()
}

// Initialize creates the virtual root BranchPoint over all roots.
func (t *TraceDAG) Initialize() {
	root := &branchPoint{pathout: -1}
	for _, bl := range t.rootlist {
		tr := &blockTrace{top: root, pathout: len(root.paths), destnode: bl, edgelump: 1}
		root.paths = append(root.paths, tr)
		t.insertActive(tr)
	}
}

// PushBranches pushes the traces through the DAG, removing edges as needed.
func (t *TraceDAG) PushBranches() {
	cur := t.activetrace.Front()
	t.missedactivecount = 0
	for t.activecount > 0 {
		if cur == nil {
			cur = t.activetrace.Front()
		}
		curtrace := cur.Value.(*blockTrace)
		if t.missedactivecount >= t.activecount {
			t.removeTrace(t.selectBadEdge())
			cur = t.activetrace.Front()
			t.missedactivecount = 0
		} else if exitblock, ok := t.checkRetirement(curtrace); ok {
			cur = t.retireBranch(curtrace.top, exitblock)
			t.missedactivecount = 0
		} else if t.checkOpen(curtrace) {
			cur = t.openBranch(curtrace)
			t.missedactivecount = 0
		} else {
			t.missedactivecount++
			cur = cur.Next()
		}
	}
	for _, e := range *t.likelygoto {
		e.bottom.SetVisitCount(0)
	}
}
