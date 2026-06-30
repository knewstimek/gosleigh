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

// ---------------------------------------------------------------------------
// Universal action build -- ports ActionDatabase::buildDefaultGroups and
// ActionDatabase::universalAction from coreaction.cc (lines 5430-5756).
//
// The universal action is the canonical analysis pipeline used by Ghidra's
// decompiler; derived roots like "decompile", "normalize", and "paramid" are
// produced by filtering the universal action against a named group list.
//
// C++ parity: coreaction.cc ActionDatabase::universalAction
// ---------------------------------------------------------------------------

// BuildDefaultGroups installs the canonical group lists (decompile, jumptable,
// normalize, paramid, register, firstpass).  Mirrors the const char *[] arrays
// in coreaction.cc ActionDatabase::buildDefaultGroups.
//
// C++ parity: coreaction.cc ActionDatabase::buildDefaultGroups
func (db *ActionDatabase) BuildDefaultGroups() {
	db.SetGroup("decompile",
		"base", "protorecovery", "protorecovery_a", "deindirect", "localrecovery",
		"deadcode", "typerecovery", "stackptrflow",
		"blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
		"cleanup", "splitcopy", "splitpointer", "merge", "dynamic", "casts", "analysis",
		"fixateglobals", "fixateproto", "constsequence", "bitfields",
		"segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
		"unreachable", "subvar", "floatprecision",
		"conditionalexe")

	db.SetGroup("jumptable",
		"base", "noproto", "localrecovery", "deadcode", "stackptrflow",
		"stackvars", "analysis", "segment", "subvar", "normalizebranches", "conditionalexe")

	db.SetGroup("normalize",
		"base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
		"deadcode", "stackptrflow", "normalanalysis",
		"stackvars", "deadcontrolflow", "analysis", "fixateproto", "nodejoin",
		"unreachable", "subvar", "floatprecision", "normalizebranches",
		"conditionalexe")

	db.SetGroup("paramid",
		"base", "protorecovery", "protorecovery_b", "deindirect", "localrecovery",
		"deadcode", "typerecovery", "stackptrflow", "siganalysis",
		"stackvars", "deadcontrolflow", "analysis", "fixateproto",
		"unreachable", "subvar", "floatprecision",
		"conditionalexe")

	db.SetGroup("register", "base", "analysis", "subvar")
	db.SetGroup("firstpass", "base")
}

// BuildUniversalAction constructs the full universal Action and registers it
// with the database under the name "universal".  The returned Action is the
// raw tree before any group-list filtering; SetCurrent("decompile") will then
// derive a filtered copy.
//
// The action layout follows coreaction.cc ActionDatabase::universalAction
// EXACTLY -- the order of addAction / addRule calls determines analysis order
// and is parity-critical.  Do not reorder, add, or remove entries without
// updating the corresponding C++ reference.
//
// extraPoolRules is the per-architecture rule set normally drained from
// Architecture::extra_pool_rules; pass nil for a generic build.
//
// C++ parity: coreaction.cc ActionDatabase::universalAction (lines 5471-5756)
func (db *ActionDatabase) BuildUniversalAction(extraPoolRules []Rule) Action {
	act := NewActionRestartGroup(ActionRuleOncePerFunc, "universal", 1)

	act.AddAction(NewActionStart("base"))
	act.AddAction(NewActionConstbase("base"))
	act.AddAction(NewActionNormalizeSetup("normalanalysis"))
	act.AddAction(NewActionDefaultParams("base"))
	// ActionParamShiftStart: not yet ported (Ghidra-specific paramshift group).
	act.AddAction(NewActionExtraPopSetup("base"))
	act.AddAction(NewActionPrototypeTypes("protorecovery"))
	act.AddAction(NewActionFuncLink("protorecovery"))
	act.AddAction(NewActionFuncLinkOutOnly("noproto"))

	// ----- fullloop -----
	actfullloop := NewActionGroup(ActionRuleRepeatApply, "fullloop")

	// ----- mainloop -----
	actmainloop := NewActionGroup(ActionRuleRepeatApply, "mainloop")
	actmainloop.AddAction(NewActionUnreachable("base"))
	actmainloop.AddAction(NewActionVarnodeProps("base"))
	actmainloop.AddAction(NewActionHeritage("base"))
	actmainloop.AddAction(NewActionParamDouble("protorecovery"))
	actmainloop.AddAction(NewActionSegmentize("base"))
	actmainloop.AddAction(NewActionInternalStorage("base"))
	actmainloop.AddAction(NewActionForceGoto("blockrecovery"))
	actmainloop.AddAction(NewActionDirectWrite("protorecovery_a", true))
	actmainloop.AddAction(NewActionDirectWrite("protorecovery_b", false))
	actmainloop.AddAction(NewActionActiveParam("protorecovery"))
	// Wire the function return value (Heritage::guardReturns + dominance rename) once
	// per function, after the first ActionHeritage pass resolved register/stack SSA.
	// In C++ guardReturns runs inside ActionHeritage every pass; Gosleigh isolates it
	// here to avoid disturbing the persistent heritage engine's loop snapshots.
	actmainloop.AddAction(NewActionGuardReturns("protorecovery"))
	actmainloop.AddAction(NewActionReturnRecovery("protorecovery"))
	// ActionParamShiftStop: not yet ported (paramshift).
	actmainloop.AddAction(NewActionRestrictLocal("localrecovery")) // before dead code removed
	actmainloop.AddAction(NewActionDeadCode("deadcode"))
	actmainloop.AddAction(NewActionDynamicMapping("dynamic")) // before restructure / infertypes
	actmainloop.AddAction(NewActionRestructureVarnode("localrecovery"))
	actmainloop.AddAction(NewActionSpacebase("base")) // before infertypes / nonzeromask
	actmainloop.AddAction(NewActionNonzeroMask("analysis"))
	actmainloop.AddAction(NewActionInferTypes("typerecovery"))

	// ----- stackstall (inner repeat group) -----
	actstackstall := NewActionGroup(ActionRuleRepeatApply, "stackstall")

	// ----- oppool1 (large rule pool) -----
	actprop := NewActionPool(ActionRuleRepeatApply, "oppool1")
	actprop.AddRule(NewRuleEarlyRemoval("deadcode"))
	actprop.AddRule(NewRuleTermOrder("analysis"))
	actprop.AddRule(NewRuleSelectCse("analysis"))
	actprop.AddRule(NewRuleCollectTerms("analysis"))
	actprop.AddRule(NewRulePullsubMulti("analysis"))
	actprop.AddRule(NewRulePullsubIndirect("analysis"))
	// C++ RulePushMulti (coreaction.cc:5529, oplist=CPUI_MULTIEQUAL) is faithfully
	// ported as RulePushMultiME, not the misc NewRulePushMulti (which triggers on
	// arithmetic ops). This pushes a 2-branch MULTIEQUAL of functionally-equal ops
	// (e.g. MULTIEQUAL(a!=0, b!=0)) into the merge block as MULTIEQUAL(a,b)!=0, so a
	// joined loop condition inlines (iVar1 != 0) instead of materializing a boolean.
	actprop.AddRule(NewRulePushMultiME("nodejoin"))
	actprop.AddRule(NewRuleSborrow("analysis"))
	actprop.AddRule(NewRuleScarry("analysis"))
	actprop.AddRule(NewRuleIntLessEqual("analysis"))
	actprop.AddRule(NewRuleTrivialArith("analysis"))
	actprop.AddRule(NewRuleTrivialBool("analysis"))
	actprop.AddRule(NewRuleTrivialShift("analysis"))
	actprop.AddRule(NewRuleSignShift("analysis"))
	actprop.AddRule(NewRuleTestSign("analysis"))
	actprop.AddRule(NewRuleIdentityEl("analysis"))
	actprop.AddRule(NewRuleOrMask("analysis"))
	actprop.AddRule(NewRuleAndMask("analysis"))
	actprop.AddRule(NewRuleOrConsume("analysis"))
	actprop.AddRule(NewRuleOrCollapse("analysis"))
	actprop.AddRule(NewRuleAndOrLump("analysis"))
	actprop.AddRule(NewRuleShiftBitops("analysis"))
	actprop.AddRule(NewRuleRightShiftAnd("analysis"))
	actprop.AddRule(NewRuleNotDistribute("analysis"))
	actprop.AddRule(NewRuleHighOrderAnd("analysis"))
	actprop.AddRule(NewRuleAndDistribute("analysis"))
	actprop.AddRule(NewRuleAndCommute("analysis"))
	actprop.AddRule(NewRuleAndPiece("analysis"))
	actprop.AddRule(NewRuleAndZext("analysis"))
	actprop.AddRule(NewRuleAndCompare("analysis"))
	actprop.AddRule(NewRuleDoubleSub("analysis"))
	actprop.AddRule(NewRuleDoubleShift("analysis"))
	actprop.AddRule(NewRuleDoubleArithShift("analysis"))
	actprop.AddRule(NewRuleConcatShift("analysis"))
	actprop.AddRule(NewRuleLeftRight("analysis"))
	actprop.AddRule(NewRuleShiftCompare("analysis"))
	actprop.AddRule(NewRuleShift2Mult("analysis"))
	actprop.AddRule(NewRuleShiftPiece("analysis"))
	actprop.AddRule(NewRuleMultiCollapse("analysis"))
	actprop.AddRule(NewRuleIndirectCollapse("analysis"))
	actprop.AddRule(NewRule2Comp2Mult("analysis"))
	actprop.AddRule(NewRuleSub2Add("analysis"))
	actprop.AddRule(NewRuleCarryElim("analysis"))
	actprop.AddRule(NewRuleBxor2NotEqual("analysis"))
	actprop.AddRule(NewRuleLess2Zero("analysis"))
	actprop.AddRule(NewRuleLessEqual2Zero("analysis"))
	actprop.AddRule(NewRuleSLess2Zero("analysis"))
	actprop.AddRule(NewRuleEqual2Zero("analysis"))
	actprop.AddRule(NewRuleEqual2Constant("analysis"))
	actprop.AddRule(NewRuleThreeWayCompare("analysis"))
	actprop.AddRule(NewRuleXorCollapse("analysis"))
	actprop.AddRule(NewRuleAddMultCollapse("analysis"))
	actprop.AddRule(NewRuleCollapseConstants("analysis"))
	actprop.AddRule(NewRuleTransformCPool("analysis"))
	actprop.AddRule(NewRulePropagateCopy("analysis"))
	actprop.AddRule(NewRuleZextEliminate("analysis"))
	actprop.AddRule(NewRuleSlessToLess("analysis"))
	actprop.AddRule(NewRuleZextSless("analysis"))
	actprop.AddRule(NewRuleBitUndistribute("analysis"))
	actprop.AddRule(NewRuleBooleanUndistribute("analysis"))
	actprop.AddRule(NewRuleBooleanDedup("analysis"))
	actprop.AddRule(NewRuleBoolZext("analysis"))
	actprop.AddRule(NewRuleBooleanNegate("analysis"))
	actprop.AddRule(NewRuleLogic2Bool("analysis"))
	actprop.AddRule(NewRuleSubExtComm("analysis"))
	actprop.AddRule(NewRuleSubCommute("analysis"))
	actprop.AddRule(NewRuleConcatCommute("analysis"))
	actprop.AddRule(NewRuleConcatZext("analysis"))
	actprop.AddRule(NewRuleZextCommute("analysis"))
	actprop.AddRule(NewRuleZextShiftZext("analysis"))
	actprop.AddRule(NewRuleShiftAnd("analysis"))
	actprop.AddRule(NewRuleConcatZero("analysis"))
	actprop.AddRule(NewRuleConcatLeftShift("analysis"))
	actprop.AddRule(NewRuleSubZext("analysis"))
	actprop.AddRule(NewRuleSubCancel("analysis"))
	actprop.AddRule(NewRuleShiftSub("analysis"))
	actprop.AddRule(NewRuleHumptyDumpty("analysis"))
	actprop.AddRule(NewRuleDumptyHump("analysis"))
	actprop.AddRule(NewRuleHumptyOr("analysis"))
	actprop.AddRule(NewRuleNegateIdentity("analysis"))
	actprop.AddRule(NewRuleSubNormal("analysis"))
	actprop.AddRule(NewRulePositiveDiv("analysis"))
	actprop.AddRule(NewRuleDivTermAdd("analysis"))
	actprop.AddRule(NewRuleDivTermAdd2("analysis"))
	actprop.AddRule(NewRuleDivOpt("analysis"))
	actprop.AddRule(NewRuleSignForm("analysis"))
	actprop.AddRule(NewRuleSignForm2("analysis"))
	actprop.AddRule(NewRuleSignDiv2("analysis"))
	actprop.AddRule(NewRuleDivChain("analysis"))
	actprop.AddRule(NewRuleSignNearMult("analysis"))
	actprop.AddRule(NewRuleModOpt("analysis"))
	actprop.AddRule(NewRuleSignMod2nOpt("analysis"))
	actprop.AddRule(NewRuleSignMod2nOpt2("analysis"))
	actprop.AddRule(NewRuleSignMod2Opt("analysis"))
	actprop.AddRule(NewRuleSwitchSingle("analysis"))
	actprop.AddRule(NewRuleCondNegate("analysis"))
	actprop.AddRule(NewRuleBoolNegate("analysis"))
	actprop.AddRule(NewRuleLessEqual("analysis"))
	actprop.AddRule(NewRuleLessNotEqual("analysis"))
	actprop.AddRule(NewRuleLessOne("analysis"))
	actprop.AddRule(NewRuleRangeMeld("analysis"))
	actprop.AddRule(NewRuleFloatRange("analysis"))
	actprop.AddRule(NewRulePiece2Zext("analysis"))
	actprop.AddRule(NewRulePiece2Sext("analysis"))
	actprop.AddRule(NewRulePopcountBoolXor("analysis"))
	actprop.AddRule(NewRuleXorSwap("analysis"))
	actprop.AddRule(NewRuleLzcountShiftBool("analysis"))
	actprop.AddRule(NewRuleFloatSign("analysis"))
	actprop.AddRule(NewRuleOrCompare("analysis"))
	actprop.AddRule(NewRuleSubvarAnd("subvar"))
	actprop.AddRule(NewRuleSubvarSubpiece("subvar"))
	actprop.AddRule(NewRuleSplitFlow("subvar"))
	actprop.AddRule(NewRulePtrFlow("subvar")) // C++ takes (group, conf); Go signature has no conf
	actprop.AddRule(NewRuleSubvarCompZero("subvar"))
	actprop.AddRule(NewRuleSubvarShift("subvar"))
	actprop.AddRule(NewRuleSubvarZext("subvar"))
	actprop.AddRule(NewRuleSubvarSext("subvar"))
	actprop.AddRule(NewRuleNegateNegate("analysis"))
	actprop.AddRule(NewRuleConditionalMove("conditionalexe"))
	actprop.AddRule(NewRuleOrPredicate("conditionalexe"))
	actprop.AddRule(NewRuleFuncPtrEncoding("analysis"))
	actprop.AddRule(NewRuleSubfloatConvert("floatprecision"))
	actprop.AddRule(NewRuleFloatCast("floatprecision"))
	actprop.AddRule(NewRuleIgnoreNan("floatprecision"))
	actprop.AddRule(NewRuleUnsigned2Float("analysis"))
	actprop.AddRule(NewRuleInt2FloatCollapse("analysis"))
	actprop.AddRule(NewRulePtraddUndo("typerecovery"))
	actprop.AddRule(NewRulePtrsubUndo("typerecovery"))
	actprop.AddRule(NewRuleSegment("segment"))
	actprop.AddRule(NewRulePiecePathology("protorecovery"))
	actprop.AddRule(NewRuleDoubleLoad("doubleload"))
	actprop.AddRule(NewRuleDoubleStore("doubleprecis"))
	actprop.AddRule(NewRuleDoubleIn("doubleprecis"))
	actprop.AddRule(NewRuleDoubleOut("doubleprecis"))
	for _, r := range extraPoolRules {
		actprop.AddRule(r)
	}

	actstackstall.AddAction(actprop)
	actstackstall.AddAction(NewActionLaneDivide("base"))
	actstackstall.AddAction(NewActionMultiCse("analysis"))
	actstackstall.AddAction(NewActionShadowVar("analysis"))
	actstackstall.AddAction(NewActionDeindirect("deindirect"))
	actstackstall.AddAction(NewActionStackPtrFlow("stackptrflow"))
	actmainloop.AddAction(actstackstall)

	actmainloop.AddAction(NewActionRedundBranch("deadcontrolflow"))
	actmainloop.AddAction(NewActionBlockStructure("blockrecovery"))
	actmainloop.AddAction(NewActionConstantPtr("typerecovery"))

	// ----- oppool2 (smaller pool) -----
	actprop2 := NewActionPool(ActionRuleRepeatApply, "oppool2")
	actprop2.AddRule(NewRulePushPtr("typerecovery"))
	actprop2.AddRule(NewRuleStructOffset0("typerecovery"))
	actprop2.AddRule(NewRulePtrArith("typerecovery"))
	// RuleIndirectConcat: commented out in C++ source.
	actprop2.AddRule(NewRuleLoadVarnode("stackvars"))
	actprop2.AddRule(NewRuleStoreVarnode("stackvars"))
	actmainloop.AddAction(actprop2)

	actmainloop.AddAction(NewActionDeterminedBranch("unreachable"))
	actmainloop.AddAction(NewActionUnreachable("unreachable"))
	actmainloop.AddAction(NewActionNodeJoin("nodejoin"))
	actmainloop.AddAction(NewActionConditionalExe("conditionalexe"))
	actmainloop.AddAction(NewActionConditionalConst("analysis"))

	actfullloop.AddAction(actmainloop)
	actfullloop.AddAction(NewActionLikelyTrash("protorecovery"))
	actfullloop.AddAction(NewActionDirectWrite("protorecovery_a", true))
	actfullloop.AddAction(NewActionDirectWrite("protorecovery_b", false))
	actfullloop.AddAction(NewActionDeadCode("deadcode"))
	actfullloop.AddAction(NewActionDoNothing("deadcontrolflow"))
	actfullloop.AddAction(NewActionSwitchNorm("switchnorm"))
	actfullloop.AddAction(NewActionReturnSplit("returnsplit"))
	actfullloop.AddAction(NewActionUnjustifiedParams("protorecovery"))
	actfullloop.AddAction(NewActionStartTypes("typerecovery"))
	actfullloop.AddAction(NewActionActiveReturn("protorecovery"))

	act.AddAction(actfullloop)

	act.AddAction(NewActionMappedLocalSync("localrecovery"))
	act.AddAction(NewActionStartCleanUp("cleanup"))

	// ----- cleanup pool -----
	actcleanup := NewActionPool(ActionRuleRepeatApply, "cleanup")
	actcleanup.AddRule(NewRuleMultNegOne("cleanup"))
	actcleanup.AddRule(NewRuleAddUnsigned("cleanup"))
	actcleanup.AddRule(NewRule2Comp2Sub("cleanup"))
	actcleanup.AddRule(NewRuleDumptyHumpLate("cleanup"))
	actcleanup.AddRule(NewRuleSubRight("cleanup"))
	actcleanup.AddRule(NewRuleFloatSignCleanup("cleanup"))
	actcleanup.AddRule(NewRuleExpandLoad("cleanup"))
	actcleanup.AddRule(NewRulePtrsubCharConstant("cleanup"))
	actcleanup.AddRule(NewRuleExtensionPush("cleanup"))
	actcleanup.AddRule(NewRulePieceStructure("cleanup"))
	actcleanup.AddRule(NewRuleSplitCopy("splitcopy"))
	actcleanup.AddRule(NewRuleSplitLoad("splitpointer"))
	actcleanup.AddRule(NewRuleSplitStore("splitpointer"))
	actcleanup.AddRule(NewRuleStringCopy("constsequence"))
	actcleanup.AddRule(NewRuleStringStore("constsequence"))
	actcleanup.AddRule(NewRuleBitFieldStore("bitfields"))
	actcleanup.AddRule(NewRuleBitFieldOut("bitfields"))
	actcleanup.AddRule(NewRuleBitFieldLoad("bitfields"))
	actcleanup.AddRule(NewRuleBitFieldIn("bitfields"))
	actcleanup.AddRule(NewRulePullAbsorb("bitfields"))
	actcleanup.AddRule(NewRuleInsertAbsorb("bitfields"))
	act.AddAction(actcleanup)

	act.AddAction(NewActionPreferComplement("blockrecovery"))
	act.AddAction(NewActionStructureTransform("blockrecovery"))
	act.AddAction(NewActionNormalizeBranches("normalizebranches"))
	act.AddAction(NewActionAssignHigh("merge"))
	act.AddAction(NewActionMergeRequired("merge"))
	act.AddAction(NewActionMarkExplicit("merge"))
	act.AddAction(NewActionMarkImplied("merge")) // BEFORE general merging
	act.AddAction(NewActionMergeMultiEntry("merge"))
	act.AddAction(NewActionMergeCopy("merge"))
	act.AddAction(NewActionDominantCopy("merge"))
	act.AddAction(NewActionDynamicSymbols("dynamic"))
	act.AddAction(NewActionMarkIndirectOnly("merge")) // after required, before speculative
	act.AddAction(NewActionMergeAdjacent("merge"))
	act.AddAction(NewActionMergeType("merge"))
	act.AddAction(NewActionHideShadow("merge"))
	act.AddAction(NewActionCopyMarker("merge"))
	act.AddAction(NewActionOutputPrototype("localrecovery"))
	act.AddAction(NewActionInputPrototype("fixateproto"))
	act.AddAction(NewActionMapGlobals("fixateglobals"))
	act.AddAction(NewActionDynamicSymbols("dynamic"))
	act.AddAction(NewActionNameVars("merge"))
	act.AddAction(NewActionSetCasts("casts"))
	act.AddAction(NewActionFinalStructure("blockrecovery"))
	// ActionForLoops folds while-do blocks into for-loops. In C++ this transform
	// happens at print time (BlockWhileDo::finalTransform in block.cc), so it is not
	// a member of universalAction; Gosleigh models it as a terminal once-per-func
	// action (the same one the production driver runs last). It must follow
	// FinalStructure (needs the final BlockWhileDo tree), SetCasts (for-iterate ops
	// may carry an inserted CAST), and the merge/naming phase (tryMarkForLoop's
	// cross-variable COPY rejection inspects post-merge HighVariables).
	act.AddAction(NewActionForLoops("analysis"))
	act.AddAction(NewActionPrototypeWarnings("protorecovery"))
	act.AddAction(NewActionStop("base"))

	db.RegisterUniversal(act)
	return act
}
