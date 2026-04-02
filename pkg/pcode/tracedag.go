package pcode

type TraceDAG struct {
	likelygoto  *[]FloatingEdge
	rootlist    []*FlowBlock
	finishblock *FlowBlock
}

func NewTraceDAG(likelygoto *[]FloatingEdge) *TraceDAG {
	return &TraceDAG{likelygoto: likelygoto}
}

func (t *TraceDAG) AddRoot(root *FlowBlock) {
	if root != nil {
		t.rootlist = append(t.rootlist, root)
	}
}

func (t *TraceDAG) SetFinishBlock(bl *FlowBlock) {
	t.finishblock = bl
}

func (t *TraceDAG) Initialize() {}

type dagEdge struct {
	from *FlowBlock
	to   *FlowBlock
}

func (t *TraceDAG) PushBranches() {
	nodes := make(map[*FlowBlock]struct{})
	edges := make([]dagEdge, 0)
	stack := append([]*FlowBlock(nil), t.rootlist...)
	seen := make(map[*FlowBlock]struct{})
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[cur]; ok {
			continue
		}
		seen[cur] = struct{}{}
		nodes[cur] = struct{}{}
		for i := 0; i < cur.SizeOut(); i++ {
			if !cur.isLoopDAGOut(i) {
				continue
			}
			next := cur.getOut(i)
			edges = append(edges, dagEdge{from: cur, to: next})
			nodes[next] = struct{}{}
			if next != t.finishblock {
				stack = append(stack, next)
			}
		}
	}
	if len(nodes) == 0 {
		return
	}

	index := 0
	stackNodes := make([]*FlowBlock, 0)
	onStack := make(map[*FlowBlock]bool)
	indices := make(map[*FlowBlock]int)
	lowlink := make(map[*FlowBlock]int)
	adj := make(map[*FlowBlock][]*FlowBlock)
	for _, edge := range edges {
		adj[edge.from] = append(adj[edge.from], edge.to)
	}

	var strongConnect func(*FlowBlock)
	strongConnect = func(v *FlowBlock) {
		indices[v] = index
		lowlink[v] = index
		index++
		stackNodes = append(stackNodes, v)
		onStack[v] = true

		for _, w := range adj[v] {
			if _, ok := indices[w]; !ok {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] && indices[w] < lowlink[v] {
				lowlink[v] = indices[w]
			}
		}

		if lowlink[v] != indices[v] {
			return
		}

		component := make([]*FlowBlock, 0)
		for {
			w := stackNodes[len(stackNodes)-1]
			stackNodes = stackNodes[:len(stackNodes)-1]
			onStack[w] = false
			component = append(component, w)
			if w == v {
				break
			}
		}
		if len(component) == 1 {
			node := component[0]
			selfLoop := false
			for _, w := range adj[node] {
				if w == node {
					selfLoop = true
					break
				}
			}
			if !selfLoop {
				return
			}
		}
		componentSet := make(map[*FlowBlock]struct{}, len(component))
		for _, node := range component {
			componentSet[node] = struct{}{}
		}
		var candidate *dagEdge
		for i := range edges {
			edge := &edges[i]
			if _, ok := componentSet[edge.from]; !ok {
				continue
			}
			if _, ok := componentSet[edge.to]; !ok {
				continue
			}
			if candidate == nil || edge.from.Index() > candidate.from.Index() {
				candidate = edge
			}
		}
		if candidate != nil {
			*t.likelygoto = append(*t.likelygoto, NewFloatingEdge(candidate.from, candidate.to))
		}
	}

	for node := range nodes {
		if _, ok := indices[node]; !ok {
			strongConnect(node)
		}
	}
}
