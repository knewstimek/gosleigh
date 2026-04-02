package pcode

// Rule mirrors the decompiler's per-op transformation contract.
// C++ parity: action.hh Rule
type Rule interface {
	ruleBase() *RuleBase
	GetName() string
	GetGroup() string
	GetNumTests() uint32
	GetNumApply() uint32
	SetBreak(uint32)
	ClearBreak(uint32)
	ClearBreakPoints()
	TurnOnWarnings()
	TurnOffWarnings()
	IsDisabled() bool
	SetDisable()
	ClearDisable()
	CheckActionBreak() bool
	GetBreakPoint() uint32
	Clone(ActionGroupList) Rule
	GetOpList() []OpCode
	ApplyOp(*PcodeOp, *Funcdata) int
	Reset(*Funcdata)
	ResetStats()
}

const (
	RuleTypeDisable uint32 = 1 << iota
	RuleTypeDebug
	RuleWarningsOn
	RuleWarningsGiven
)

// RuleBase carries the shared Rule bookkeeping and toggles.
// C++ parity: action.hh/cc Rule
type RuleBase struct {
	flags      uint32
	breakpoint uint32
	name       string
	basegroup  string
	countTests uint32
	countApply uint32
}

// NewRuleBase constructs the shared Rule state.
func NewRuleBase(group string, flags uint32, name string) RuleBase {
	return RuleBase{
		flags:     flags,
		name:      name,
		basegroup: group,
	}
}

func (r *RuleBase) ruleBase() *RuleBase {
	return r
}

// GetName returns the rule name.
func (r *RuleBase) GetName() string {
	return r.name
}

// GetGroup returns the rule group.
func (r *RuleBase) GetGroup() string {
	return r.basegroup
}

// GetNumTests returns the number of attempted applications.
func (r *RuleBase) GetNumTests() uint32 {
	return r.countTests
}

// GetNumApply returns the number of successful applications.
func (r *RuleBase) GetNumApply() uint32 {
	return r.countApply
}

// SetBreak enables a breakpoint on this rule.
func (r *RuleBase) SetBreak(tp uint32) {
	r.breakpoint |= tp
}

// ClearBreak clears the specified breakpoint bits.
func (r *RuleBase) ClearBreak(tp uint32) {
	r.breakpoint &^= tp
}

// ClearBreakPoints clears all breakpoints on the rule.
func (r *RuleBase) ClearBreakPoints() {
	r.breakpoint = 0
}

// TurnOnWarnings enables warning emission when the rule applies.
func (r *RuleBase) TurnOnWarnings() {
	r.flags |= RuleWarningsOn
}

// TurnOffWarnings disables warning emission.
func (r *RuleBase) TurnOffWarnings() {
	r.flags &^= RuleWarningsOn
}

// IsDisabled reports whether the rule is disabled.
func (r *RuleBase) IsDisabled() bool {
	return r.flags&RuleTypeDisable != 0
}

// SetDisable disables the rule.
func (r *RuleBase) SetDisable() {
	r.flags |= RuleTypeDisable
}

// ClearDisable enables the rule.
func (r *RuleBase) ClearDisable() {
	r.flags &^= RuleTypeDisable
}

// CheckActionBreak reports and clears a temporary action breakpoint.
func (r *RuleBase) CheckActionBreak() bool {
	if r.breakpoint&(ActionBreakAction|ActionBreakTemporaryAction) == 0 {
		return false
	}
	r.breakpoint &^= ActionBreakTemporaryAction
	return true
}

// GetBreakPoint returns the active breakpoint mask.
func (r *RuleBase) GetBreakPoint() uint32 {
	return r.breakpoint
}

// CloneAllowed applies the group-membership gate used by concrete clone methods.
func (r *RuleBase) CloneAllowed(groups ActionGroupList) bool {
	if r.basegroup == "" {
		return true
	}
	return groups.Contains(r.basegroup)
}

// GetOpList defaults to all opcodes.
func (r *RuleBase) GetOpList() []OpCode {
	ops := make([]OpCode, 0, int(CPUI_MAX))
	for i := 0; i < int(CPUI_MAX); i++ {
		ops = append(ops, OpCode(i))
	}
	return ops
}

// ApplyOp is the base no-match implementation.
func (r *RuleBase) ApplyOp(*PcodeOp, *Funcdata) int {
	return 0
}

// Reset clears per-function warning state.
func (r *RuleBase) Reset(*Funcdata) {
	r.flags &^= RuleWarningsGiven
}

// ResetStats clears test/apply counters.
func (r *RuleBase) ResetStats() {
	r.countTests = 0
	r.countApply = 0
}

func (r *RuleBase) issueWarning(data *Funcdata) {
	if r.flags&(RuleWarningsOn|RuleWarningsGiven) != RuleWarningsOn {
		return
	}
	r.flags |= RuleWarningsGiven
	data.emitActionMessage("WARNING: Applied rule " + r.name)
}
