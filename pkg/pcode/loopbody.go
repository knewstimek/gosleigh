package pcode

import "sort"

type LoopBody struct {
	head           *FlowBlock
	tails          []*FlowBlock
	depth          int
	uniquecount    int
	exitblock      *FlowBlock
	exitedges      []FloatingEdge
	immedContainer *LoopBody
}

func NewLoopBody(head *FlowBlock) *LoopBody {
	return &LoopBody{head: head}
}

func (l *LoopBody) GetHead() *FlowBlock {
	return l.head
}

func (l *LoopBody) AddTail(bl *FlowBlock) {
	l.tails = append(l.tails, bl)
}

func (l *LoopBody) GetExitBlock() *FlowBlock {
	return l.exitblock
}

func (l *LoopBody) Depth() int {
	return l.depth
}

func (l *LoopBody) Update(graph *FlowBlock) *FlowBlock {
	for l.head != nil && l.head.Parent() != graph && l.head.Parent() != nil {
		l.head = l.head.Parent()
	}
	for i, tail := range l.tails {
		for tail != nil && tail.Parent() != graph && tail.Parent() != nil {
			tail = tail.Parent()
		}
		l.tails[i] = tail
		if tail != l.head {
			return tail
		}
	}
	if l.head == nil {
		return nil
	}
	for i := l.head.SizeOut() - 1; i >= 0; i-- {
		if l.head.getOut(i) == l.head {
			return l.head
		}
	}
	return nil
}

func (l *LoopBody) extendToContainer(container *LoopBody, body *[]*FlowBlock) {
	i := 0
	if !container.head.isMark() {
		container.head.setMark()
		*body = append(*body, container.head)
		i = 1
	}
	for _, tail := range container.tails {
		if !tail.isMark() {
			tail.setMark()
			*body = append(*body, tail)
		}
	}
	if l.head != container.head {
		for k := 0; k < l.head.SizeIn(); k++ {
			if l.head.isGotoIn(k) {
				continue
			}
			bl := l.head.getIn(k)
			if bl.isMark() {
				continue
			}
			bl.setMark()
			*body = append(*body, bl)
		}
	}

	for i < len(*body) {
		curblock := (*body)[i]
		i++
		for k := 0; k < curblock.SizeIn(); k++ {
			if curblock.isGotoIn(k) {
				continue
			}
			bl := curblock.getIn(k)
			if bl.isMark() {
				continue
			}
			bl.setMark()
			*body = append(*body, bl)
		}
	}
}

func (l *LoopBody) FindBase(body *[]*FlowBlock) {
	l.head.setMark()
	*body = append(*body, l.head)
	for _, tail := range l.tails {
		if !tail.isMark() {
			tail.setMark()
			*body = append(*body, tail)
		}
	}
	l.uniquecount = len(*body)
	i := 1
	for i < len(*body) {
		curblock := (*body)[i]
		i++
		for k := 0; k < curblock.SizeIn(); k++ {
			if curblock.isGotoIn(k) {
				continue
			}
			bl := curblock.getIn(k)
			if bl.isMark() {
				continue
			}
			bl.setMark()
			*body = append(*body, bl)
		}
	}
}

func (l *LoopBody) Extend(body *[]*FlowBlock) {
	trial := make([]*FlowBlock, 0)
	i := 0
	for i < len(*body) {
		bl := (*body)[i]
		i++
		for j := 0; j < bl.SizeOut(); j++ {
			if bl.isGotoOut(j) {
				continue
			}
			curbl := bl.getOut(j)
			if curbl.isMark() || curbl == l.exitblock {
				continue
			}
			count := curbl.VisitCount()
			if count == 0 {
				trial = append(trial, curbl)
			}
			count++
			curbl.SetVisitCount(count)
			if int(count) == curbl.SizeIn() {
				curbl.setMark()
				*body = append(*body, curbl)
			}
		}
	}
	for _, block := range trial {
		block.SetVisitCount(0)
	}
}

func (l *LoopBody) FindExit(body []*FlowBlock) {
	trialExit := make([]*FlowBlock, 0)
	for _, tail := range l.tails {
		for i := 0; i < tail.SizeOut(); i++ {
			if tail.isGotoOut(i) {
				continue
			}
			curbl := tail.getOut(i)
			if !curbl.isMark() {
				if l.immedContainer == nil {
					l.exitblock = curbl
					return
				}
				trialExit = append(trialExit, curbl)
			}
		}
	}

	for i, bl := range body {
		if i > 0 && i < l.uniquecount {
			continue
		}
		for j := 0; j < bl.SizeOut(); j++ {
			if bl.isGotoOut(j) {
				continue
			}
			curbl := bl.getOut(j)
			if !curbl.isMark() {
				if l.immedContainer == nil {
					l.exitblock = curbl
					return
				}
				trialExit = append(trialExit, curbl)
			}
		}
	}

	l.exitblock = nil
	if len(trialExit) == 0 {
		return
	}
	if l.immedContainer != nil {
		extension := make([]*FlowBlock, 0)
		l.extendToContainer(l.immedContainer, &extension)
		for _, bl := range trialExit {
			if bl.isMark() {
				l.exitblock = bl
				break
			}
		}
		ClearMarks(extension)
	}
}

func (l *LoopBody) OrderTails() {
	if len(l.tails) <= 1 || l.exitblock == nil {
		return
	}
	prefIndex := -1
	for idx, tail := range l.tails {
		for j := 0; j < tail.SizeOut(); j++ {
			if tail.getOut(j) == l.exitblock {
				prefIndex = idx
				break
			}
		}
		if prefIndex >= 0 {
			break
		}
	}
	if prefIndex <= 0 {
		return
	}
	l.tails[0], l.tails[prefIndex] = l.tails[prefIndex], l.tails[0]
}

func (l *LoopBody) LabelExitEdges(body []*FlowBlock) {
	l.exitedges = l.exitedges[:0]
	toExitBlock := make([]*FlowBlock, 0)
	for i := l.uniquecount; i < len(body); i++ {
		curblock := body[i]
		for k := 0; k < curblock.SizeOut(); k++ {
			if curblock.isGotoOut(k) {
				continue
			}
			bl := curblock.getOut(k)
			if bl == l.exitblock {
				toExitBlock = append(toExitBlock, curblock)
				continue
			}
			if !bl.isMark() {
				l.exitedges = append(l.exitedges, NewFloatingEdge(curblock, bl))
			}
		}
	}
	if l.head != nil {
		for k := 0; k < l.head.SizeOut(); k++ {
			if l.head.isGotoOut(k) {
				continue
			}
			bl := l.head.getOut(k)
			if bl == l.exitblock {
				toExitBlock = append(toExitBlock, l.head)
				continue
			}
			if !bl.isMark() {
				l.exitedges = append(l.exitedges, NewFloatingEdge(l.head, bl))
			}
		}
	}
	for i := len(l.tails) - 1; i >= 0; i-- {
		curblock := l.tails[i]
		if curblock == l.head {
			continue
		}
		for k := 0; k < curblock.SizeOut(); k++ {
			if curblock.isGotoOut(k) {
				continue
			}
			bl := curblock.getOut(k)
			if bl == l.exitblock {
				toExitBlock = append(toExitBlock, curblock)
				continue
			}
			if !bl.isMark() {
				l.exitedges = append(l.exitedges, NewFloatingEdge(curblock, bl))
			}
		}
	}
	for _, bl := range toExitBlock {
		l.exitedges = append(l.exitedges, NewFloatingEdge(bl, l.exitblock))
	}
}

func (l *LoopBody) LabelContainments(body []*FlowBlock, looporder []*LoopBody) {
	containList := make([]*LoopBody, 0)
	for _, curblock := range body {
		if curblock == l.head {
			continue
		}
		subloop := FindLoopBody(curblock, looporder)
		if subloop != nil {
			containList = append(containList, subloop)
			subloop.depth++
		}
	}
	for _, lb := range containList {
		if lb.immedContainer == nil || lb.immedContainer.depth < l.depth {
			lb.immedContainer = l
		}
	}
}

func (l *LoopBody) EmitLikelyEdges(likely *[]FloatingEdge, graph *FlowBlock) {
	for l.head != nil && l.head.Parent() != graph && l.head.Parent() != nil {
		l.head = l.head.Parent()
	}
	if l.exitblock != nil {
		for l.exitblock.Parent() != graph && l.exitblock.Parent() != nil {
			l.exitblock = l.exitblock.Parent()
		}
	}
	for i, tail := range l.tails {
		for tail.Parent() != graph && tail.Parent() != nil {
			tail = tail.Parent()
		}
		l.tails[i] = tail
		if tail == l.exitblock {
			l.exitblock = nil
		}
	}
	var holdIn *FlowBlock
	var holdOut *FlowBlock
	for i := range l.exitedges {
		inbl, outedge := l.exitedges[i].GetCurrentEdge(graph)
		if inbl == nil {
			continue
		}
		outbl := inbl.getOut(outedge)
		if i == len(l.exitedges)-1 && outbl == l.exitblock {
			holdIn = inbl
			holdOut = outbl
			break
		}
		*likely = append(*likely, NewFloatingEdge(inbl, outbl))
	}
	for i := len(l.tails) - 1; i >= 0; i-- {
		if holdIn != nil && i == 0 {
			*likely = append(*likely, NewFloatingEdge(holdIn, holdOut))
		}
		tail := l.tails[i]
		for j := 0; j < tail.SizeOut(); j++ {
			if tail.getOut(j) == l.head {
				*likely = append(*likely, NewFloatingEdge(tail, l.head))
			}
		}
	}
}

func (l *LoopBody) SetExitMarks(graph *FlowBlock) {
	for i := range l.exitedges {
		inloop, outedge := l.exitedges[i].GetCurrentEdge(graph)
		if inloop != nil {
			inloop.setLoopExit(outedge)
		}
	}
}

func (l *LoopBody) ClearExitMarks(graph *FlowBlock) {
	for i := range l.exitedges {
		inloop, outedge := l.exitedges[i].GetCurrentEdge(graph)
		if inloop != nil {
			inloop.clearLoopExit(outedge)
		}
	}
}

func MergeIdenticalHeads(looporder []*LoopBody) []*LoopBody {
	if len(looporder) == 0 {
		return looporder
	}
	i := 0
	j := i + 1
	curbody := looporder[i]
	for j < len(looporder) {
		nextbody := looporder[j]
		j++
		if nextbody.head == curbody.head {
			curbody.AddTail(nextbody.tails[0])
			nextbody.head = nil
		} else {
			i++
			looporder[i] = nextbody
			curbody = nextbody
		}
	}
	i++
	return looporder[:i]
}

func CompareLoopEnds(a, b *LoopBody) bool {
	aindex := a.head.Index()
	bindex := b.head.Index()
	if aindex != bindex {
		return aindex < bindex
	}
	return a.tails[0].Index() < b.tails[0].Index()
}

func CompareLoopHead(a *LoopBody, looptop *FlowBlock) int {
	aindex := a.head.Index()
	bindex := looptop.Index()
	if aindex != bindex {
		if aindex < bindex {
			return -1
		}
		return 1
	}
	return 0
}

func FindLoopBody(looptop *FlowBlock, looporder []*LoopBody) *LoopBody {
	min := 0
	max := len(looporder) - 1
	for min <= max {
		mid := (min + max) / 2
		comp := CompareLoopHead(looporder[mid], looptop)
		if comp == 0 {
			return looporder[mid]
		}
		if comp < 0 {
			min = mid + 1
		} else {
			max = mid - 1
		}
	}
	return nil
}

func SortLoopBodiesByDepth(loopbodies []LoopBody) {
	sort.SliceStable(loopbodies, func(i, j int) bool {
		return loopbodies[i].depth > loopbodies[j].depth
	})
}
