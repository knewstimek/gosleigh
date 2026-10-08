package bridge

import (
	"math/bits"
	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// HostVarnode names a storage location by space name.
type HostVarnode struct {
	Space  string
	Offset uint64
	Size   int32
	// SpaceRef names the address space a LOAD/STORE operand selects
	// (<spaceid name=..>); the operand is then that space's selector constant.
	SpaceRef string
}

// HostInjectOp is one p-code op of a host-compiled injection payload.
type HostInjectOp struct {
	Code pcode.OpCode
	Out  *HostVarnode
	In   []HostVarnode
}

// HostInjection is a call-fixup payload the host compiled for one call site
// (Java PcodeInjectLibraryJava): the ops replace the CALL.
type HostInjection struct {
	Name   string // the call-fixup name, e.g. security_check_cookie
	Callee string // the callee's display name
	Ops    []HostInjectOp
}

// applyInjections replaces the CALL at each injected call site with the
// host's payload ops, in place, and returns the warning texts to record.
// Spaces are resolved by name against the spaces the function's p-code uses.
// TODO known mismatch: a payload whose flow does not fall through
// (xrefControlFlow) is not handled; call-fixups here are straight-line.
// C++ parity: FlowInfo::injectPcode -> injectSubFunction -> doInjection.
func applyInjections(records []instructionRecord, injections map[uint64]HostInjection, constSpace *address.Space) []string {
	if len(injections) == 0 {
		return nil
	}
	spaces := map[string]*address.Space{}
	note := func(sp *address.Space) {
		if sp != nil {
			spaces[sp.Name] = sp
		}
	}
	note(constSpace)
	for _, r := range records {
		for _, op := range r.translation.Ops {
			if op.Output != nil {
				note(op.Output.Space)
			}
			for _, in := range op.Inputs {
				note(in.Space)
			}
		}
	}
	vd := func(h HostVarnode) (pcode.VarnodeData, bool) {
		if h.SpaceRef != "" {
			// The space selector of LOAD/STORE input 0: a constant holding the
			// space index, as SLEIGH lowering builds it. C++ parity:
			// PcodeOpRaw space operand (AddrSpace* as a constant).
			sp := spaces[h.SpaceRef]
			if sp == nil || constSpace == nil {
				return pcode.VarnodeData{}, false
			}
			return pcode.VarnodeData{Space: constSpace, Offset: uint64(sp.Index), Size: uint32(bits.UintSize / 8)}, true
		}
		sp := spaces[h.Space]
		if sp == nil {
			return pcode.VarnodeData{}, false
		}
		return pcode.VarnodeData{Space: sp, Offset: h.Offset, Size: uint32(h.Size)}, true
	}
	var warnings []string
	for _, ri := range flowOrder(records) {
		tr := &records[ri].translation
		inj, ok := injections[tr.Address.Offset]
		if !ok {
			continue
		}
		ci := -1
		for i, op := range tr.Ops {
			if op.OpCode == pcode.CPUI_CALL {
				ci = i
			}
		}
		if ci < 0 {
			continue
		}
		call := tr.Ops[ci]
		var payload []pcode.RawOp
		good := true
		for k, hop := range inj.Ops {
			raw := pcode.RawOp{SeqNum: call.SeqNum, OpCode: hop.Code}
			raw.SeqNum.Order = call.SeqNum.Order + uint64(k)
			if hop.Out != nil {
				out, ok := vd(*hop.Out)
				if !ok {
					good = false
					break
				}
				raw.Output = &out
			}
			for _, in := range hop.In {
				v, ok := vd(in)
				if !ok {
					good = false
					break
				}
				raw.Inputs = append(raw.Inputs, v)
			}
			payload = append(payload, raw)
		}
		if !good || len(payload) == 0 {
			continue
		}
		ops := append([]pcode.RawOp(nil), tr.Ops[:ci]...)
		ops = append(ops, payload...)
		tr.Ops = append(ops, tr.Ops[ci+1:]...)
		warnings = append(warnings, "Function: "+inj.Callee+" replaced with injection: "+inj.Name)
	}
	return warnings
}

// flowOrder lists the records in the order flow following decodes them: a
// stack of addresses where each instruction pushes its branch target, then
// its fall-through, so the fall-through runs on and the latest target comes
// next. Calls are injected in this order. Records flow does not reach keep
// their collection order at the end.
// C++ parity: FlowInfo::fallthru / processInstruction / newAddress
// (addrlist is a stack) feeding FlowInfo::injectlist.
func flowOrder(records []instructionRecord) []int {
	if len(records) == 0 {
		return nil
	}
	at := make(map[address.Address]int, len(records))
	for i, r := range records {
		at[r.translation.Address] = i
	}
	seen := make([]bool, len(records))
	order := make([]int, 0, len(records))
	stack := []address.Address{records[0].translation.Address}
	for len(stack) > 0 {
		a := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		i, ok := at[a]
		if !ok || seen[i] {
			continue
		}
		seen[i] = true
		order = append(order, i)
		f := records[i].flow
		if f.hasDirect {
			stack = append(stack, f.directTarget)
		}
		if f.hasFallthrough {
			stack = append(stack, f.fallthroughAddr)
		}
	}
	for i := range records {
		if !seen[i] {
			order = append(order, i)
		}
	}
	return order
}
