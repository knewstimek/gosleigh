package analysis

import (
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// Enhanced is the preset of everything beyond Ghidra that has been measured
// not to change any function Ghidra already decompiles correctly (the realexe
// goldens, DIFFERENCES.md). A host that wants better output than Ghidra's
// without choosing extensions one by one makes one per Program and applies it
// to every function; new extensions join the preset once they pass the same
// measurement, so the host needs no change.
type Enhanced struct {
	reads *CalleeReads
}

// NewEnhanced returns the preset for prog. It caches per-program analysis
// results, so make one per Program and reuse it.
func NewEnhanced(prog *decomp.Program) *Enhanced {
	return &Enhanced{reads: NewCalleeReads(prog)}
}

// Apply switches fn to the preset.
func (e *Enhanced) Apply(fn *decomp.Function) {
	fn.Extensions = pcode.Extensions{
		NestedPieceTrials:  true,
		NarrowFloatReturns: true,
		NaNExactCompares:   true,
		BitCastSyntax:      true,
		FloatLoads:         true,
	}
	fn.CalleeReads = e.reads
}
