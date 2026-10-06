// Copyright 2026 The Gosleigh Authors
// Licensed under the Apache License, Version 2.0.

package pcode

import (
	"strings"
	"unicode"
)

// Ghidra's DecompileResults prints the C token tree through a PrettyPrinter
// that cleans function-name, variable, type, field and label tokens with an
// IllegalCharCppTransformer; the C++ core itself emits the raw names. This
// file reproduces that transform for the same token kinds.
// C++ (Java) parity: ghidra.app.decompiler.PrettyPrinter.getText and
// ghidra.program.model.symbol.IllegalCharCppTransformer.

const (
	cppAfterFirst = 1 // Legal after the first character
	cppTemplate   = 2 // Legal as part of template parameters
	cppOperator   = 4 // Legal after the "operator" keyword
	cppFirst      = 8 // Legal as the first character
)

var cppLegalChars = func() [128]int {
	var t [128]int
	t['_'] = cppAfterFirst | cppTemplate | cppOperator | cppFirst
	for c := '0'; c <= '9'; c++ {
		t[c] = cppAfterFirst | cppTemplate | cppOperator
	}
	for _, c := range "*([])&" {
		t[c] = cppTemplate | cppOperator
	}
	t[':'] = cppTemplate
	t[','] = cppTemplate
	for _, c := range "+-|=!/%^" {
		t[c] = cppOperator
	}
	t['~'] = cppTemplate | cppOperator | cppFirst
	return t
}()

// cppDisplayName replaces characters that are illegal in a C++ symbol with
// '_'. C++ (Java) parity: IllegalCharCppTransformer.simplify.
func cppDisplayName(input string) string {
	var out []rune
	templateDepth := 0
	runes := []rune(input)
	for i, c := range runes {
		if unicode.IsLetter(c) {
			continue
		}
		switch c {
		case '<':
			templateDepth++
			continue
		case '>':
			if templateDepth--; templateDepth < 0 {
				templateDepth = 0
			}
			continue
		}
		if c < 128 {
			if val := cppLegalChars[c]; val != 0 {
				if val&cppAfterFirst != 0 && i > 0 {
					continue // Legal after the first character
				}
				if val&cppFirst != 0 && i == 0 {
					continue // Legal as the first character
				}
				if val&cppTemplate != 0 && templateDepth > 0 {
					continue // Legal as a template parameter
				}
				if val&cppOperator != 0 && i >= 8 && i <= 10 && strings.HasPrefix(input, "operator") {
					continue
				}
			}
		}
		if out == nil {
			out = append([]rune(nil), runes...)
		}
		out[i] = '_' // Illegal character
	}
	if out == nil {
		return input
	}
	return string(out)
}
