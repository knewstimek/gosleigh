package sla

import (
	"errors"
	"fmt"

	"gosleigh/pkg/address"
)

var ErrObtainContextUnimplemented = errors.New("obtain context step is unimplemented")

func normalizeObtainContextUnimpl(err error) error {
	if err == nil {
		return nil
	}
	var uerr *UnimplError
	if errors.As(err, &uerr) {
		return err
	}
	if errors.Is(err, ErrObtainContextUnimplemented) {
		return newUnimplError(ErrObtainContextUnimplemented, err.Error())
	}
	return err
}

// ObtainContextHooks carries promotion callbacks for parse-state escalation.
type ObtainContextHooks struct {
	Resolve        func(ctx *ParserContext) error
	ResolveHandles func(ctx *ParserContext) error
}

// ObtainContextRequest describes one cache lookup / creation request.
type ObtainContextRequest struct {
	Address       address.Address
	TargetState   ParseState
	ConstantSpace *address.Space
	Hooks         ObtainContextHooks
}

// ObtainContext mirrors the original Sleigh::obtainContext shell.
func ObtainContext(cache *DisassemblyCache, req ObtainContextRequest) (*ParserContext, error) {
	if cache == nil {
		return nil, fmt.Errorf("obtain context: disassembly cache is nil")
	}
	if err := validateParseState(req.TargetState); err != nil {
		return nil, err
	}

	ctx, err := cache.ObtainParserContext(req.Address, req.ConstantSpace)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, fmt.Errorf("obtain context: nil parser context")
	}
	if ctx.GetAddr() != req.Address {
		// Mirrors DisassemblyCache::getParserContext()/ParserContext::setAddr() addressing rules:
		// the obtained context must be keyed to the requested address before promotion.
		ctx.SetAddr(req.Address)
		ctx.SetParserState(ParseStateUninitialized)
		ctx.SetN2addr(address.Address{})
	}
	if ctx.GetParserState() == ParseStateUninitialized {
		// Mirrors ParserContext::setAddr() in context.hh clearing cached inst_next2 on reuse.
		ctx.SetN2addr(address.Address{})
	}

	if parseStateAtLeast(ctx.GetParserState(), req.TargetState) {
		return ctx, nil
	}

	if req.TargetState >= ParseStateDisassembly {
		if err := promoteToDisassembly(ctx, req.Hooks.Resolve); err != nil {
			return nil, normalizeObtainContextUnimpl(err)
		}
	}
	if req.TargetState >= ParseStatePcode {
		if err := promoteToPcode(ctx, req.Hooks.ResolveHandles); err != nil {
			return nil, normalizeObtainContextUnimpl(err)
		}
	}

	if !parseStateAtLeast(ctx.GetParserState(), req.TargetState) {
		return nil, newUnimplError(
			ErrObtainContextUnimplemented,
			fmt.Sprintf("target parse state %d not reached for %v", req.TargetState, req.Address),
		)
	}
	return ctx, nil
}

func validateParseState(state ParseState) error {
	switch state {
	case ParseStateUninitialized, ParseStateDisassembly, ParseStatePcode:
		return nil
	default:
		return fmt.Errorf("obtain context: invalid target parse state %d", state)
	}
}

func parseStateAtLeast(current, target ParseState) bool {
	return current >= target
}

func promoteToDisassembly(ctx *ParserContext, resolve func(ctx *ParserContext) error) error {
	if ctx == nil {
		return newUnimplError(ErrObtainContextUnimplemented, "nil parser context for disassembly promotion")
	}
	if ctx.GetParserState() >= ParseStateDisassembly {
		return nil
	}
	if resolve == nil {
		return newUnimplError(ErrObtainContextUnimplemented, "disassembly promotion requires a resolve hook")
	}
	if err := resolve(ctx); err != nil {
		return normalizeObtainContextUnimpl(err)
	}
	if ctx.GetParserState() < ParseStateDisassembly {
		return newUnimplError(ErrObtainContextUnimplemented, "disassembly promotion did not reach the requested state")
	}
	return nil
}

func promoteToPcode(ctx *ParserContext, resolveHandles func(ctx *ParserContext) error) error {
	if ctx == nil {
		return newUnimplError(ErrObtainContextUnimplemented, "nil parser context for pcode promotion")
	}
	if ctx.GetParserState() >= ParseStatePcode {
		return nil
	}
	if ctx.GetParserState() < ParseStateDisassembly {
		return newUnimplError(ErrObtainContextUnimplemented, "pcode promotion requires disassembly promotion first")
	}
	if resolveHandles == nil {
		return newUnimplError(ErrObtainContextUnimplemented, "pcode promotion requires a resolve handles hook")
	}
	if err := resolveHandles(ctx); err != nil {
		return normalizeObtainContextUnimpl(err)
	}
	if ctx.GetParserState() < ParseStatePcode {
		return newUnimplError(ErrObtainContextUnimplemented, "pcode promotion did not reach the requested state")
	}
	return nil
}
