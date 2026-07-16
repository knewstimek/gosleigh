// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import (
	"fmt"

	"gosleigh/pkg/address"
)

// This file ports the single-op execution surface of Ghidra's EmulatePcodeOp
// (emulateutil.cc) and the path-stepping loop of EmulateFunction::emulatePath
// (jumptable.cc:216) needed by jump-table address recovery. It emulates one
// data-flow path from a switch value to a BRANCHIND input over a local Varnode
// value map, reading the load image for LOAD ops. Control-flow ops on the path
// throw (Go: return an error) exactly as in Ghidra, since the outer loop -- not
// the emulator -- drives flow. This is the computational core; wiring it into
// JumpBasic model recovery / address-table construction is a later phase.
//
// Intentional deviations from direct C++ translation:
//   - C++ exceptions (LowlevelError / DataUnavailError) become Go errors.
//   - EmulatePcodeOp and EmulateFunction are merged into one Go type (there is
//     no separate memory-state emulator to share the base with).
//   - Big-endian load images are not handled (scope is x86-64, little-endian);
//     getLoadImageValue documents the omission.

// getVarnodeValue returns the emulated value of vn: its constant offset if
// constant, its recorded value if seen, otherwise a read from the load image.
// C++ parity: EmulateFunction::getVarnodeValue (emulateutil.cc:179).
func (e *EmulateFunction) getVarnodeValue(vn *Varnode) (uint64, error) {
	if vn.IsConstant() {
		return vn.Offset(), nil
	}
	if v, ok := e.varnodeMap[vn]; ok {
		return v, nil
	}
	return e.getLoadImageValue(vn.Space(), vn.Offset(), vn.Size())
}

// setVarnodeValue records the emulated value of vn.
// C++ parity: EmulateFunction::setVarnodeValue (emulateutil.cc:194).
func (e *EmulateFunction) setVarnodeValue(vn *Varnode, val uint64) {
	if e.varnodeMap == nil {
		e.varnodeMap = make(map[*Varnode]uint64)
	}
	e.varnodeMap[vn] = val
}

// getLoadImageValue reads sz bytes at (spc,off) from the load image via the
// Funcdata hook, returning them as a little-endian value masked to sz bytes.
// A nil hook means the load image is unavailable and LOAD emulation is not
// supported (preserving the pre-B2 behavior for callers that never set it).
// Big-endian spaces are not supported (out of scope: x86-64 is little-endian).
// C++ parity: EmulatePcodeOp::getLoadImageValue (emulateutil.cc:30).
func (e *EmulateFunction) getLoadImageValue(spc *address.Space, off uint64, sz int32) (uint64, error) {
	reader := e.fd.ImageReader()
	if reader == nil {
		return 0, fmt.Errorf("%w: no load image reader (LOAD emulation unsupported)", JumptableRecoveryError)
	}
	if spc != nil && spc.BigEndian {
		return 0, fmt.Errorf("%w: big-endian load image not supported", JumptableRecoveryError)
	}
	res, err := reader(address.Address{Space: spc, Offset: off}, int(sz))
	if err != nil {
		return 0, err
	}
	res &= maskForSize(sz)
	return res, nil
}

// executeUnary evaluates the current unary op and stores its result.
// C++ parity: EmulatePcodeOp::executeUnary (emulateutil.cc:47).
func (e *EmulateFunction) executeUnary() error {
	op := e.currentOp
	in1, err := e.getVarnodeValue(op.Input(0))
	if err != nil {
		return err
	}
	out := evalUnary(op.Code(), in1, op.Input(0).Size(), op.Output().Size())
	e.setVarnodeValue(op.Output(), out)
	return nil
}

// executeBinary evaluates the current binary op and stores its result.
// C++ parity: EmulatePcodeOp::executeBinary (emulateutil.cc:56).
func (e *EmulateFunction) executeBinary() error {
	op := e.currentOp
	in1, err := e.getVarnodeValue(op.Input(0))
	if err != nil {
		return err
	}
	in2, err := e.getVarnodeValue(op.Input(1))
	if err != nil {
		return err
	}
	out := evalBinary(op.Code(), in1, in2, op.Input(0).Size(), op.Output().Size())
	e.setVarnodeValue(op.Output(), out)
	return nil
}

// executeLoad reads the load image at the computed address, records a
// LoadTable entry when collecting, and stores the loaded value.
// C++ parity: EmulateFunction::executeLoad (jumptable.cc:113) merged with
// EmulatePcodeOp::executeLoad (emulateutil.cc:66).
func (e *EmulateFunction) executeLoad() error {
	op := e.currentOp
	off, err := e.getVarnodeValue(op.Input(1))
	if err != nil {
		return err
	}
	spc := op.Input(0).GetSpaceFromConst()
	if spc == nil {
		return fmt.Errorf("%w: LOAD without a resolved space", JumptableRecoveryError)
	}
	// AddrSpace::addressToByte scales the word-addressed offset to bytes.
	wordSize := uint64(1)
	if spc.WordSize > 0 {
		wordSize = uint64(spc.WordSize)
	}
	off *= wordSize
	sz := op.Output().Size()
	res, err := e.getLoadImageValue(spc, off, sz)
	if err != nil {
		return err
	}
	if e.loadPoints != nil {
		*e.loadPoints = append(*e.loadPoints, NewLoadTableSingle(address.Address{Space: spc, Offset: off}, sz))
	}
	e.setVarnodeValue(op.Output(), res)
	return nil
}

// executeCbranch returns whether the current CBRANCH is taken, honoring the
// boolean-flip bit carried by syntax-tree p-code.
// C++ parity: EmulatePcodeOp::executeCbranch (emulateutil.cc:87).
func (e *EmulateFunction) executeCbranch() (bool, error) {
	cond, err := e.getVarnodeValue(e.currentOp.Input(1))
	if err != nil {
		return false, err
	}
	return (cond != 0) != e.currentOp.HasFlag(PcodeOpBooleanFlip), nil
}

// executeMultiequal resolves the MULTIEQUAL to the input coming from the block
// last executed. C++ parity: EmulatePcodeOp::executeMultiequal
// (emulateutil.cc:96).
func (e *EmulateFunction) executeMultiequal() error {
	op := e.currentOp
	bl := op.Parent()
	if bl == nil || e.lastOp == nil {
		return fmt.Errorf("%w: could not execute MULTIEQUAL", JumptableRecoveryError)
	}
	lastBl := e.lastOp.Parent()
	if lastBl == nil {
		return fmt.Errorf("%w: could not execute MULTIEQUAL", JumptableRecoveryError)
	}
	i := bl.GetInIndex(&lastBl.FlowBlock)
	if i < 0 || i >= op.NumInput() {
		return fmt.Errorf("%w: could not execute MULTIEQUAL", JumptableRecoveryError)
	}
	val, err := e.getVarnodeValue(op.Input(i))
	if err != nil {
		return err
	}
	e.setVarnodeValue(op.Output(), val)
	return nil
}

// executeIndirect treats the INDIRECT as a copy of its first input, matching
// Ghidra's assumption for jump-table emulation.
// C++ parity: EmulatePcodeOp::executeIndirect (emulateutil.cc:112).
func (e *EmulateFunction) executeIndirect() error {
	op := e.currentOp
	val, err := e.getVarnodeValue(op.Input(0))
	if err != nil {
		return err
	}
	e.setVarnodeValue(op.Output(), val)
	return nil
}

// fallthruOp records the current op as the last executed one so a following
// MULTIEQUAL can select the correct incoming edge.
// C++ parity: EmulateFunction::fallthruOp (jumptable.cc:200).
func (e *EmulateFunction) fallthruOp() { e.lastOp = e.currentOp }

// setCurrentOp selects the op to be executed next.
// C++ parity: EmulatePcodeOp::setCurrentOp (emulateutil.hh:81).
func (e *EmulateFunction) setCurrentOp(op *PcodeOp) { e.currentOp = op }

// executeCurrentOp dispatches the current op to the matching execute routine.
// Control-flow ops that end a basic block error out (the path stepper, not the
// emulator, drives flow); calls and no-op markers fall through.
// C++ parity: Emulate::executeCurrentOp (emulate.cc:143).
func (e *EmulateFunction) executeCurrentOp() error {
	op := e.currentOp
	switch op.Code() {
	case CPUI_LOAD:
		if err := e.executeLoad(); err != nil {
			return err
		}
		e.fallthruOp()
	case CPUI_STORE:
		// Nowhere to store (no memory state); ignore, as in EmulatePcodeOp.
		e.fallthruOp()
	case CPUI_BRANCH, CPUI_BRANCHIND, CPUI_RETURN:
		return fmt.Errorf("%w: branch encountered emulating jumptable calculation", JumptableRecoveryError)
	case CPUI_CBRANCH:
		taken, err := e.executeCbranch()
		if err != nil {
			return err
		}
		if taken {
			return fmt.Errorf("%w: branch encountered emulating jumptable calculation", JumptableRecoveryError)
		}
		e.fallthruOp()
	case CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER:
		// Calls presumably do not affect the final address.
		e.fallthruOp()
	case CPUI_MULTIEQUAL:
		if err := e.executeMultiequal(); err != nil {
			return err
		}
		e.fallthruOp()
	case CPUI_INDIRECT:
		if err := e.executeIndirect(); err != nil {
			return err
		}
		e.fallthruOp()
	case CPUI_CPOOLREF, CPUI_NEW:
		// Ignored (constant-pool / new object) as in EmulatePcodeOp.
		e.fallthruOp()
	case CPUI_SEGMENTOP:
		return fmt.Errorf("%w: SEGMENTOP emulation not supported", JumptableRecoveryError)
	default:
		// Non-special op: unary or binary by input count.
		if op.NumInput() == 1 {
			if err := e.executeUnary(); err != nil {
				return err
			}
		} else {
			if err := e.executeBinary(); err != nil {
				return err
			}
		}
		e.fallthruOp()
	}
	return nil
}

// EmulatePath flows val from the starting point to the common end-point of the
// path set, returning the value at the BRANCHIND input (pathMeld op 0, in 0).
// The meld ops are ordered with the BRANCHIND at index 0 and the switch value
// source at the highest index; execution runs from startop's index down to 1.
// C++ parity: EmulateFunction::emulatePath (jumptable.cc:216).
func (e *EmulateFunction) EmulatePath(val uint64, pathMeld *PathMeld, startop *PcodeOp, startvn *Varnode) (uint64, error) {
	n := pathMeld.NumOps()
	i := 0
	for ; i < n; i++ {
		if pathMeld.Op(i) == startop {
			break
		}
	}
	if startop.Code() == CPUI_MULTIEQUAL { // Starting on a MULTIEQUAL
		j := 0
		for ; j < startop.NumInput(); j++ {
			if startop.Input(j) == startvn {
				break
			}
		}
		if j == startop.NumInput() || i == 0 {
			return 0, fmt.Errorf("%w: cannot start jumptable emulation with unresolved MULTIEQUAL", JumptableRecoveryError)
		}
		// Emulate as if we just came from that branch: the MULTIEQUAL output
		// becomes the new start value and we advance to the next op.
		startvn = startop.Output()
		i--
		startop = pathMeld.Op(i)
	}
	if i == n {
		return 0, fmt.Errorf("%w: bad jumptable emulation", JumptableRecoveryError)
	}
	if !startvn.IsConstant() {
		e.setVarnodeValue(startvn, val)
	}
	for i > 0 {
		curop := pathMeld.Op(i)
		i--
		e.setCurrentOp(curop)
		if err := e.executeCurrentOp(); err != nil {
			// Record the faithful warning text (Ghidra JumpBasic::emulatePath throws
			// LowlevelError("Could not emulate address calculation at " << curop),
			// which Funcdata::stageJumpTable turns into a warning comment attached to
			// the BRANCHIND). The address is printed with AddrSpace::printRaw.
			// C++ parity: jumptable.cc:248.
			e.failMsg = "Could not emulate address calculation at " + PrintRawAddr(curop.Addr())
			return 0, fmt.Errorf("could not emulate address calculation at %s: %w", curop.Addr(), err)
		}
	}
	invn := pathMeld.Op(0).Input(0)
	return e.getVarnodeValue(invn)
}
