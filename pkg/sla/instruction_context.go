package sla

import (
	"fmt"

	"gosleigh/pkg/address"
)

// ObtainPcodeContextRequest wraps the original obtainContext(..., pcode) plus the
// follow-up applyCommits() call used by oneInstruction().
type ObtainPcodeContextRequest struct {
	Context ObtainContextRequest
	Commits ApplyCommitsHooks
}

// ObtainPcodeContext mirrors the oneInstruction() context-preparation sequence:
// obtainContext(..., pcode) followed by applyCommits().
func ObtainPcodeContext(cache *DisassemblyCache, req ObtainPcodeContextRequest) (*ParserContext, error) {
	req.Context.TargetState = ParseStatePcode
	ctx, err := ObtainContext(cache, req.Context)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, fmt.Errorf("obtain pcode context: nil parser context")
	}
	if err := ctx.ApplyCommits(req.Commits); err != nil {
		return nil, err
	}
	bindLazyN2Context(cache, req, ctx)
	return ctx, nil
}

func bindLazyN2Context(cache *DisassemblyCache, req ObtainPcodeContextRequest, ctx *ParserContext) {
	if ctx == nil {
		return
	}
	// Mirrors ParserContext::setAddr() and getN2addr() semantics in context.cc/context.hh:
	// clear stale next2 on reuse, then derive lazily from next instruction decode.
	ctx.SetN2addr(address.Address{})
	ctx.SetN2addrResolver(func() (address.Address, bool) {
		if cache == nil || ctx == nil {
			return address.Address{}, false
		}
		nextAddr, ok := pcodeFallthroughAddr(ctx)
		if !ok {
			return address.Address{}, false
		}
		constSpace := ctx.GetConstSpace()
		if constSpace == nil {
			constSpace = req.Context.ConstantSpace
		}
		nextCtx, err := ObtainContext(cache, ObtainContextRequest{
			Address:       nextAddr,
			TargetState:   ParseStateDisassembly,
			ConstantSpace: constSpace,
			Hooks:         req.Context.Hooks,
		})
		if err != nil || nextCtx == nil {
			// Keep inst_next2 unavailable when adjacent disassembly is unavailable.
			return address.Address{}, false
		}
		return next2addrFromContext(nextCtx)
	})
}

func pcodeFallthroughAddr(ctx *ParserContext) (address.Address, bool) {
	if ctx == nil {
		return address.Address{}, false
	}
	if length := ctx.GetLength(); length > 0 {
		// Mirrors oneInstruction() using getLength()-based fallOffset to avoid stale naddr.
		return ctx.GetAddr().Add(uint64(length)), true
	}
	nextAddr := ctx.GetNaddr()
	if nextAddr.IsInvalid() {
		return address.Address{}, false
	}
	return nextAddr, true
}

func next2addrFromContext(nextCtx *ParserContext) (address.Address, bool) {
	if nextCtx == nil {
		return address.Address{}, false
	}
	if length := nextCtx.GetLength(); length > 0 {
		return nextCtx.GetAddr().Add(uint64(length)), true
	}
	if n2 := nextCtx.GetNaddr(); !n2.IsInvalid() {
		return n2, true
	}
	return address.Address{}, false
}
