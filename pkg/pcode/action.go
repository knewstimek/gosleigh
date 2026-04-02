package pcode

import (
	"sort"
	"strings"
	"sync"
)

// ActionGroupList is the named group set used to derive root actions.
// C++ parity: action.hh ActionGroupList
type ActionGroupList struct {
	list map[string]struct{}
}

// NewActionGroupList constructs a group set from the provided names.
func NewActionGroupList(groups ...string) ActionGroupList {
	res := ActionGroupList{list: make(map[string]struct{}, len(groups))}
	for _, group := range groups {
		if group == "" {
			continue
		}
		res.list[group] = struct{}{}
	}
	return res
}

// Contains reports whether the group is present.
func (g ActionGroupList) Contains(name string) bool {
	if g.list == nil {
		return false
	}
	_, ok := g.list[name]
	return ok
}

// Add inserts a group name and reports whether it was new.
func (g *ActionGroupList) Add(name string) bool {
	if name == "" {
		return false
	}
	if g.list == nil {
		g.list = make(map[string]struct{})
	}
	_, exists := g.list[name]
	g.list[name] = struct{}{}
	return !exists
}

// Remove deletes a group name and reports whether it existed.
func (g *ActionGroupList) Remove(name string) bool {
	if g.list == nil {
		return false
	}
	_, exists := g.list[name]
	delete(g.list, name)
	return exists
}

// Clone makes a deep copy of the group list.
func (g ActionGroupList) Clone() ActionGroupList {
	res := NewActionGroupList()
	for name := range g.list {
		res.list[name] = struct{}{}
	}
	return res
}

// Names returns the groups in lexical order.
func (g ActionGroupList) Names() []string {
	names := make([]string, 0, len(g.list))
	for name := range g.list {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Action behavior flags.
// C++ parity: action.hh Action::ruleflags
const (
	ActionRuleRepeatApply   uint32 = 1 << 2
	ActionRuleOncePerFunc   uint32 = 1 << 3
	ActionRuleOneActPerFunc uint32 = 1 << 4
	ActionRuleDebug         uint32 = 1 << 5
	ActionRuleWarningsOn    uint32 = 1 << 6
	ActionRuleWarningsGiven uint32 = 1 << 7
)

// Action execution status flags.
// C++ parity: action.hh Action::statusflags
const (
	ActionStatusStart uint32 = 1 << iota
	ActionStatusBreakStartHit
	ActionStatusRepeat
	ActionStatusMid
	ActionStatusEnd
	ActionStatusActionBreak
)

// Action breakpoint flags.
// C++ parity: action.hh Action::breakflags
const (
	ActionBreakStart uint32 = 1 << iota
	ActionBreakTemporaryStart
	ActionBreakAction
	ActionBreakTemporaryAction
)

// Action is the shared execution contract for transformation passes.
// C++ parity: action.hh Action
type Action interface {
	actionBase() *ActionBase
	Perform(*Funcdata) int
	SetBreakPoint(uint32, string) bool
	ClearBreakPoints()
	SetWarning(bool, string) bool
	DisableRule(string) bool
	EnableRule(string) bool
	GetName() string
	GetGroup() string
	GetStatus() uint32
	GetNumTests() uint32
	GetNumApply() uint32
	Clone(ActionGroupList) Action
	Reset(*Funcdata)
	ResetStats()
	Apply(*Funcdata) int
	GetSubAction(string) Action
	GetSubRule(string) Rule
}

// ActionBase carries the shared Action bookkeeping and state machine.
// C++ parity: action.hh/cc Action
type ActionBase struct {
	self Action

	lcount int
	count  int

	status     uint32
	breakpoint uint32
	flags      uint32

	countTests uint32
	countApply uint32

	name      string
	basegroup string
}

// NewActionBase constructs the common Action state.
func NewActionBase(self Action, flags uint32, name string, group string) ActionBase {
	return ActionBase{
		self:      self,
		flags:     flags,
		status:    ActionStatusStart,
		name:      name,
		basegroup: group,
	}
}

func (a *ActionBase) actionBase() *ActionBase {
	return a
}

// GetName returns the action name.
func (a *ActionBase) GetName() string {
	return a.name
}

// GetGroup returns the action group.
func (a *ActionBase) GetGroup() string {
	return a.basegroup
}

// GetStatus returns the current execution status.
func (a *ActionBase) GetStatus() uint32 {
	return a.status
}

// GetNumTests returns the number of perform-entry attempts.
func (a *ActionBase) GetNumTests() uint32 {
	return a.countTests
}

// GetNumApply returns the number of successful apply attempts.
func (a *ActionBase) GetNumApply() uint32 {
	return a.countApply
}

// MatchGroup applies the C++ clone gate for group membership.
func (a *ActionBase) MatchGroup(groups ActionGroupList) bool {
	if a.basegroup == "" {
		return true
	}
	return groups.Contains(a.basegroup)
}

func (a *ActionBase) turnOnWarnings() {
	a.flags |= ActionRuleWarningsOn
}

func (a *ActionBase) turnOffWarnings() {
	a.flags &^= ActionRuleWarningsOn
}

func (a *ActionBase) issueWarning(data *Funcdata) {
	if a.flags&(ActionRuleWarningsOn|ActionRuleWarningsGiven) != ActionRuleWarningsOn {
		return
	}
	a.flags |= ActionRuleWarningsGiven
	data.emitActionMessage("WARNING: Applied action " + a.name)
}

func (a *ActionBase) checkStartBreak() bool {
	if a.breakpoint&(ActionBreakStart|ActionBreakTemporaryStart) == 0 {
		return false
	}
	a.breakpoint &^= ActionBreakTemporaryStart
	return true
}

func (a *ActionBase) checkActionBreak() bool {
	if a.breakpoint&(ActionBreakAction|ActionBreakTemporaryAction) == 0 {
		return false
	}
	a.breakpoint &^= ActionBreakTemporaryAction
	return true
}

// Perform drives the C++ Action::perform state machine.
func (a *ActionBase) Perform(data *Funcdata) int {
	for {
		var res int
		ranApply := false
		switch a.status {
		case ActionStatusStart:
			a.count = 0
			if a.checkStartBreak() {
				a.status = ActionStatusBreakStartHit
				return -1
			}
			a.countTests++
			a.lcount = a.count
			res = a.self.Apply(data)
			ranApply = true
		case ActionStatusBreakStartHit, ActionStatusRepeat:
			a.lcount = a.count
			res = a.self.Apply(data)
			ranApply = true
		case ActionStatusMid:
			res = a.self.Apply(data)
			ranApply = true
		case ActionStatusEnd:
			return 0
		case ActionStatusActionBreak:
			// Resume exactly like the C++ action-break path: do not re-run apply,
			// warnings, apply counters, or breakpoint checks before repeat logic.
		default:
			a.status = ActionStatusStart
			continue
		}
		if ranApply {
			if res < 0 {
				a.status = ActionStatusMid
				return res
			}
			if a.lcount < a.count {
				a.issueWarning(data)
				a.countApply++
				if a.checkActionBreak() {
					a.status = ActionStatusActionBreak
					return -1
				}
			}
		}

		a.status = ActionStatusRepeat
		if a.lcount < a.count && a.flags&ActionRuleRepeatApply != 0 {
			continue
		}
		break
	}

	if a.flags&(ActionRuleOncePerFunc|ActionRuleOneActPerFunc) != 0 {
		if a.count > 0 || a.flags&ActionRuleOncePerFunc != 0 {
			a.status = ActionStatusEnd
		} else {
			a.status = ActionStatusStart
		}
	} else {
		a.status = ActionStatusStart
	}

	return a.count
}

// SetBreakPoint resolves a nested action or rule path and sets the breakpoint.
func (a *ActionBase) SetBreakPoint(tp uint32, specify string) bool {
	if target := a.self.GetSubAction(specify); target != nil {
		target.actionBase().breakpoint |= tp
		return true
	}
	if rule := a.self.GetSubRule(specify); rule != nil {
		rule.SetBreak(tp)
		return true
	}
	return false
}

// ClearBreakPoints clears direct breakpoints on this action.
func (a *ActionBase) ClearBreakPoints() {
	a.breakpoint = 0
}

// SetWarning toggles warnings on a nested action or rule.
func (a *ActionBase) SetWarning(val bool, specify string) bool {
	if target := a.self.GetSubAction(specify); target != nil {
		if val {
			target.actionBase().turnOnWarnings()
		} else {
			target.actionBase().turnOffWarnings()
		}
		return true
	}
	if rule := a.self.GetSubRule(specify); rule != nil {
		if val {
			rule.TurnOnWarnings()
		} else {
			rule.TurnOffWarnings()
		}
		return true
	}
	return false
}

// DisableRule resolves and disables a nested rule.
func (a *ActionBase) DisableRule(specify string) bool {
	rule := a.self.GetSubRule(specify)
	if rule == nil {
		return false
	}
	rule.SetDisable()
	return true
}

// EnableRule resolves and enables a nested rule.
func (a *ActionBase) EnableRule(specify string) bool {
	rule := a.self.GetSubRule(specify)
	if rule == nil {
		return false
	}
	rule.ClearDisable()
	return true
}

// Reset prepares the action for a new function.
func (a *ActionBase) Reset(*Funcdata) {
	a.status = ActionStatusStart
	a.flags &^= ActionRuleWarningsGiven
}

// ResetStats clears test/apply counters.
func (a *ActionBase) ResetStats() {
	a.countTests = 0
	a.countApply = 0
}

// GetSubAction matches this action by name.
func (a *ActionBase) GetSubAction(specify string) Action {
	if a.name == specify {
		return a.self
	}
	return nil
}

// GetSubRule defaults to no nested rules.
func (a *ActionBase) GetSubRule(string) Rule {
	return nil
}

func nextSpecifyTerm(specify string) (string, string) {
	index := strings.IndexByte(specify, ':')
	if index < 0 {
		return specify, ""
	}
	return specify[:index], specify[index+1:]
}

// ActionGroup executes child actions in order.
// C++ parity: action.hh/cc ActionGroup
type ActionGroup struct {
	ActionBase
	list  []Action
	state int
}

// NewActionGroup constructs an empty group action.
func NewActionGroup(flags uint32, name string) *ActionGroup {
	group := &ActionGroup{}
	group.ActionBase = NewActionBase(group, flags, name, "")
	return group
}

// AddAction appends a child action to the group.
func (g *ActionGroup) AddAction(action Action) {
	if action == nil {
		return
	}
	g.list = append(g.list, action)
}

// ClearBreakPoints clears breakpoints on the group and all children.
func (g *ActionGroup) ClearBreakPoints() {
	for _, action := range g.list {
		action.ClearBreakPoints()
	}
	g.ActionBase.ClearBreakPoints()
}

// Clone derives a new group by cloning members accepted by the group list.
func (g *ActionGroup) Clone(groups ActionGroupList) Action {
	var cloned *ActionGroup
	for _, action := range g.list {
		next := action.Clone(groups)
		if next == nil {
			continue
		}
		if cloned == nil {
			cloned = NewActionGroup(g.flags, g.name)
		}
		cloned.AddAction(next)
	}
	if cloned == nil {
		return nil
	}
	return cloned
}

// Reset prepares the group and its children for a new function.
func (g *ActionGroup) Reset(data *Funcdata) {
	g.state = 0
	g.ActionBase.Reset(data)
	for _, action := range g.list {
		action.Reset(data)
	}
}

// ResetStats clears group and child statistics.
func (g *ActionGroup) ResetStats() {
	g.ActionBase.ResetStats()
	for _, action := range g.list {
		action.ResetStats()
	}
}

// Apply performs child actions in order, preserving mid-action resume state.
func (g *ActionGroup) Apply(data *Funcdata) int {
	if g.status != ActionStatusMid {
		g.state = 0
	}
	for g.state < len(g.list) {
		res := g.list[g.state].Perform(data)
		if res > 0 {
			g.count += res
			if g.checkActionBreak() {
				g.state++
				return -1
			}
		} else if res < 0 {
			return -1
		}
		g.state++
	}
	return 0
}

// GetSubAction resolves ':' paths across nested child actions.
func (g *ActionGroup) GetSubAction(specify string) Action {
	token, remain := nextSpecifyTerm(specify)
	search := specify
	if g.name == token {
		if remain == "" {
			return g
		}
		search = remain
	}
	var match Action
	matches := 0
	for _, action := range g.list {
		target := action.GetSubAction(search)
		if target == nil {
			continue
		}
		match = target
		matches++
		if matches > 1 {
			return nil
		}
	}
	return match
}

// GetSubRule resolves ':' paths across nested child actions.
func (g *ActionGroup) GetSubRule(specify string) Rule {
	token, remain := nextSpecifyTerm(specify)
	search := specify
	if g.name == token {
		if remain == "" {
			return nil
		}
		search = remain
	}
	var match Rule
	matches := 0
	for _, action := range g.list {
		target := action.GetSubRule(search)
		if target == nil {
			continue
		}
		match = target
		matches++
		if matches > 1 {
			return nil
		}
	}
	return match
}

// ActionRestartGroup reruns its child group when restart is requested.
// C++ parity: action.hh/cc ActionRestartGroup
type ActionRestartGroup struct {
	ActionGroup
	maxRestarts int
	curStart    int
}

// NewActionRestartGroup constructs a restart-aware action group.
func NewActionRestartGroup(flags uint32, name string, maxRestarts int) *ActionRestartGroup {
	group := &ActionRestartGroup{maxRestarts: maxRestarts}
	group.ActionGroup = ActionGroup{ActionBase: NewActionBase(group, flags, name, "")}
	return group
}

// Clone derives a restart-aware group from the configured group list.
func (g *ActionRestartGroup) Clone(groups ActionGroupList) Action {
	var cloned *ActionRestartGroup
	for _, action := range g.list {
		next := action.Clone(groups)
		if next == nil {
			continue
		}
		if cloned == nil {
			cloned = NewActionRestartGroup(g.flags, g.name, g.maxRestarts)
		}
		cloned.AddAction(next)
	}
	if cloned == nil {
		return nil
	}
	return cloned
}

// Reset prepares the restart counters and children for a new function.
func (g *ActionRestartGroup) Reset(data *Funcdata) {
	g.curStart = 0
	g.ActionGroup.Reset(data)
}

// Apply executes the group and restarts it while Funcdata requests more work.
func (g *ActionRestartGroup) Apply(data *Funcdata) int {
	if g.curStart == -1 {
		return 0
	}
	for {
		res := g.ActionGroup.Apply(data)
		if res != 0 {
			return res
		}
		if !data.HasRestartPending() {
			g.curStart = -1
			return 0
		}
		if data.IsJumptableRecoveryOn() {
			return 0
		}
		g.curStart++
		if g.curStart > g.maxRestarts {
			data.warningHeader("Exceeded maximum restarts with more pending")
			g.curStart = -1
			return 0
		}
		data.clearAnalysis()
		for _, action := range g.list {
			action.Reset(data)
		}
		g.state = 0
		g.status = ActionStatusStart
	}
}

// ActionPool applies opcode-filtered rules across the whole function.
// C++ parity: action.hh/cc ActionPool
type ActionPool struct {
	ActionBase
	allRules   []Rule
	perOp      [][]Rule
	opState    []*PcodeOp
	currentOp  *PcodeOp
	currentSeq SeqNum
	ruleIndex  int
}

// NewActionPool constructs an empty rule pool.
func NewActionPool(flags uint32, name string) *ActionPool {
	pool := &ActionPool{perOp: make([][]Rule, int(CPUI_MAX)+1)}
	pool.ActionBase = NewActionBase(pool, flags, name, "")
	return pool
}

// AddRule registers a rule for each opcode it claims.
func (p *ActionPool) AddRule(rule Rule) {
	if rule == nil {
		return
	}
	p.allRules = append(p.allRules, rule)
	for _, opcode := range rule.GetOpList() {
		if int(opcode) < 0 || int(opcode) >= len(p.perOp) {
			continue
		}
		p.perOp[opcode] = append(p.perOp[opcode], rule)
	}
}

func (p *ActionPool) rulesFor(opcode OpCode) []Rule {
	if int(opcode) < 0 || int(opcode) >= len(p.perOp) {
		return nil
	}
	return p.perOp[opcode]
}

// ClearBreakPoints clears breakpoints on the pool and all registered rules.
func (p *ActionPool) ClearBreakPoints() {
	for _, rule := range p.allRules {
		rule.ClearBreakPoints()
	}
	p.ActionBase.ClearBreakPoints()
}

// Clone derives a new pool with the rules accepted by the group list.
func (p *ActionPool) Clone(groups ActionGroupList) Action {
	var cloned *ActionPool
	for _, rule := range p.allRules {
		next := rule.Clone(groups)
		if next == nil {
			continue
		}
		if cloned == nil {
			cloned = NewActionPool(p.flags, p.name)
		}
		cloned.AddRule(next)
	}
	if cloned == nil {
		return nil
	}
	return cloned
}

// Reset prepares the pool and every rule for a new function.
func (p *ActionPool) Reset(data *Funcdata) {
	p.opState = nil
	p.currentOp = nil
	p.currentSeq = SeqNum{}
	p.ruleIndex = 0
	p.ActionBase.Reset(data)
	for _, rule := range p.allRules {
		rule.Reset(data)
	}
}

// ResetStats clears the pool and rule statistics.
func (p *ActionPool) ResetStats() {
	p.ActionBase.ResetStats()
	for _, rule := range p.allRules {
		rule.ResetStats()
	}
}

func (p *ActionPool) rescanOps(data *Funcdata) {
	p.opState = data.allOpsOrdered()
}

func (p *ActionPool) syncCurrentOp(data *Funcdata, includeCurrent bool) {
	p.rescanOps(data)
	p.currentOp = nil
	if includeCurrent {
		for _, op := range p.opState {
			if SeqNumEqual(op.Seq(), p.currentSeq) {
				p.currentOp = op
				return
			}
			if SeqNumLess(p.currentSeq, op.Seq()) {
				p.currentOp = op
				return
			}
		}
		return
	}
	for _, op := range p.opState {
		if SeqNumLess(p.currentSeq, op.Seq()) {
			p.currentOp = op
			return
		}
	}
}

func (p *ActionPool) beginTraversal(data *Funcdata) {
	p.rescanOps(data)
	if len(p.opState) == 0 {
		p.currentOp = nil
		p.currentSeq = SeqNum{}
		return
	}
	p.currentOp = p.opState[0]
	p.currentSeq = p.currentOp.Seq()
}

func (p *ActionPool) processOp(data *Funcdata) int {
	op := p.currentOp
	if op == nil {
		p.ruleIndex = 0
		return 0
	}
	p.currentSeq = op.Seq()
	if op.IsDead() {
		data.opDeadAndGone(op)
		p.ruleIndex = 0
		p.syncCurrentOp(data, false)
		return 0
	}
	currentOpcode := op.Code()
	rules := p.rulesFor(currentOpcode)
	for p.ruleIndex < len(rules) {
		rule := rules[p.ruleIndex]
		p.ruleIndex++
		if rule.IsDisabled() {
			continue
		}
		base := rule.ruleBase()
		base.countTests++
		res := rule.ApplyOp(op, data)
		if res > 0 {
			base.countApply++
			p.count += res
			base.issueWarning(data)
			if rule.CheckActionBreak() {
				return -1
			}
			if op.IsDead() {
				break
			}
			if currentOpcode != op.Code() {
				currentOpcode = op.Code()
				p.ruleIndex = 0
				rules = p.rulesFor(currentOpcode)
			}
		} else if currentOpcode != op.Code() {
			data.emitActionMessage("ERROR: Rule " + rule.GetName() + " changed op without returning result of 1!")
			currentOpcode = op.Code()
			p.ruleIndex = 0
			rules = p.rulesFor(currentOpcode)
		}
	}
	p.ruleIndex = 0
	p.syncCurrentOp(data, false)
	return 0
}

// Apply visits every op in sequence and gives matching rules a chance to fire.
func (p *ActionPool) Apply(data *Funcdata) int {
	if p.status != ActionStatusMid {
		p.beginTraversal(data)
		p.ruleIndex = 0
	} else {
		p.syncCurrentOp(data, true)
	}
	for p.currentOp != nil {
		if p.processOp(data) != 0 {
			return -1
		}
	}
	return 0
}

// GetSubRule resolves ':' paths to a rule in this pool.
func (p *ActionPool) GetSubRule(specify string) Rule {
	token, remain := nextSpecifyTerm(specify)
	search := specify
	if p.name == token {
		if remain == "" {
			return nil
		}
		search = remain
	}
	var match Rule
	matches := 0
	for _, rule := range p.allRules {
		if rule.GetName() != search {
			continue
		}
		match = rule
		matches++
		if matches > 1 {
			return nil
		}
	}
	return match
}

const actionDatabaseUniversalName = "universal"

// ActionDatabase stores root actions and the group lists used to derive them.
// C++ parity: action.hh/cc ActionDatabase
type ActionDatabase struct {
	currentAct     Action
	currentActName string
	groupMap       map[string]ActionGroupList
	actionMap      map[string]Action
}

// NewActionDatabase constructs an empty action database.
func NewActionDatabase() *ActionDatabase {
	return &ActionDatabase{
		groupMap:  make(map[string]ActionGroupList),
		actionMap: make(map[string]Action),
	}
}

// ResetDefaults drops all derived roots while preserving the universal action.
func (db *ActionDatabase) ResetDefaults() {
	universal := db.actionMap[actionDatabaseUniversalName]
	db.actionMap = make(map[string]Action)
	if universal != nil {
		db.actionMap[actionDatabaseUniversalName] = universal
	}
	db.groupMap = make(map[string]ActionGroupList)
	db.currentAct = nil
	db.currentActName = ""
}

// RegisterAction binds a root action name to an action instance.
func (db *ActionDatabase) RegisterAction(name string, action Action) {
	if db.actionMap == nil {
		db.actionMap = make(map[string]Action)
	}
	if action == nil {
		delete(db.actionMap, name)
		return
	}
	db.actionMap[name] = action
}

// RegisterUniversal installs the source tree used for derived roots.
func (db *ActionDatabase) RegisterUniversal(action Action) {
	db.RegisterAction(actionDatabaseUniversalName, action)
}

// GetCurrent returns the selected root action.
func (db *ActionDatabase) GetCurrent() Action {
	return db.currentAct
}

// GetCurrentName returns the selected root action name.
func (db *ActionDatabase) GetCurrentName() string {
	return db.currentActName
}

// GetGroup returns a cloned copy of the named group list.
func (db *ActionDatabase) GetGroup(name string) (ActionGroupList, bool) {
	group, ok := db.groupMap[name]
	if !ok {
		return ActionGroupList{}, false
	}
	return group.Clone(), true
}

// SetCurrent selects an existing root or lazily derives one from the universal action.
func (db *ActionDatabase) SetCurrent(name string) Action {
	db.currentActName = name
	if _, ok := db.groupMap[name]; ok {
		db.currentAct = db.DeriveAction(actionDatabaseUniversalName, name)
		return db.currentAct
	}
	db.currentAct = db.actionMap[name]
	return db.currentAct
}

// ToggleAction adds or removes a group from a root and re-derives it.
func (db *ActionDatabase) ToggleAction(group string, baseGroup string, val bool) Action {
	if val {
		db.AddToGroup(group, baseGroup)
	} else {
		db.RemoveFromGroup(group, baseGroup)
	}
	action := db.DeriveAction(actionDatabaseUniversalName, group)
	if db.currentActName == group {
		db.currentAct = action
	}
	return action
}

// SetGroup replaces the group list associated with a root name.
func (db *ActionDatabase) SetGroup(group string, names ...string) {
	if db.groupMap == nil {
		db.groupMap = make(map[string]ActionGroupList)
	}
	db.groupMap[group] = NewActionGroupList(names...)
	delete(db.actionMap, group)
}

// CloneGroup copies one group definition to another root name.
func (db *ActionDatabase) CloneGroup(oldName string, newName string) bool {
	group, ok := db.groupMap[oldName]
	if !ok {
		return false
	}
	db.groupMap[newName] = group.Clone()
	delete(db.actionMap, newName)
	return true
}

// AddToGroup adds a named group to a root definition.
func (db *ActionDatabase) AddToGroup(group string, baseGroup string) bool {
	current := db.groupMap[group]
	added := current.Add(baseGroup)
	db.groupMap[group] = current
	if added {
		delete(db.actionMap, group)
	}
	return added
}

// RemoveFromGroup removes a named group from a root definition.
func (db *ActionDatabase) RemoveFromGroup(group string, baseGroup string) bool {
	current := db.groupMap[group]
	removed := current.Remove(baseGroup)
	db.groupMap[group] = current
	if removed {
		delete(db.actionMap, group)
	}
	return removed
}

// DeriveAction clones a root from the named base action and group definition.
func (db *ActionDatabase) DeriveAction(baseAction string, group string) Action {
	if action, ok := db.actionMap[group]; ok {
		return action
	}
	groupList, ok := db.groupMap[group]
	if !ok {
		return nil
	}
	base := db.actionMap[baseAction]
	if base == nil {
		return nil
	}
	derived := base.Clone(groupList)
	if derived != nil {
		db.actionMap[group] = derived
	}
	return derived
}

type funcdataActionState struct {
	mu                 sync.Mutex
	restartPending     bool
	jumptableRecovery  bool
	analysisClearCount int
	messages           []string
}

var globalFuncdataActionState = struct {
	mu     sync.Mutex
	byFunc map[*Funcdata]*funcdataActionState
}{
	byFunc: make(map[*Funcdata]*funcdataActionState),
}

func getFuncdataActionState(data *Funcdata) *funcdataActionState {
	globalFuncdataActionState.mu.Lock()
	defer globalFuncdataActionState.mu.Unlock()
	state, ok := globalFuncdataActionState.byFunc[data]
	if ok {
		return state
	}
	state = &funcdataActionState{}
	globalFuncdataActionState.byFunc[data] = state
	return state
}

func (data *Funcdata) emitActionMessage(msg string) {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	state.messages = append(state.messages, msg)
	state.mu.Unlock()
}

func (data *Funcdata) warningHeader(msg string) {
	data.emitActionMessage(msg)
}

func (data *Funcdata) clearAnalysis() {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	state.analysisClearCount++
	state.restartPending = false
	state.mu.Unlock()
}

// ActionMessages returns recorded warning and error messages.
func (data *Funcdata) ActionMessages() []string {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	defer state.mu.Unlock()
	messages := make([]string, len(state.messages))
	copy(messages, state.messages)
	return messages
}

// ClearActionMessages discards recorded warning and error messages.
func (data *Funcdata) ClearActionMessages() {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	state.messages = nil
	state.mu.Unlock()
}

// AnalysisClearCount reports how many restart resets were requested.
func (data *Funcdata) AnalysisClearCount() int {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.analysisClearCount
}

// SetRestartPending toggles the restart request flag.
func (data *Funcdata) SetRestartPending(val bool) {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	state.restartPending = val
	state.mu.Unlock()
}

// HasRestartPending reports whether a restart has been requested.
func (data *Funcdata) HasRestartPending() bool {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.restartPending
}

// SetJumptableRecoveryOn toggles restart suppression during jumptable recovery.
func (data *Funcdata) SetJumptableRecoveryOn(val bool) {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	state.jumptableRecovery = val
	state.mu.Unlock()
}

// IsJumptableRecoveryOn reports whether restart suppression is active.
func (data *Funcdata) IsJumptableRecoveryOn() bool {
	state := getFuncdataActionState(data)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.jumptableRecovery
}

func (data *Funcdata) opDeadAndGone(op *PcodeOp) {
	if op == nil {
		return
	}
	if data.FindOp(op.Seq()) != op {
		return
	}
	data.OpDestroy(op)
}

func (data *Funcdata) allOpsOrdered() []*PcodeOp {
	ops := data.GetPcodeOpBank().AllOps()
	sort.Slice(ops, func(i int, j int) bool {
		return SeqNumLess(ops[i].Seq(), ops[j].Seq())
	})
	return ops
}
