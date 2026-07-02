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

import "os"

// faithfulStackEnabled reports whether the faithful spacebase stack-recovery
// path is active. When true, the bespoke ActionStackPtrFlow is disabled and
// stack access is recovered exclusively through the C++-faithful chain:
// Funcdata.Spacebase (ActionSpacebase) -> RuleSub2Add/RuleCollapseConstants/
// RuleAddMultCollapse offset accumulation -> RuleLoadVarnode/RuleStoreVarnode
// (correctSpacebase/vnSpacebase). When false (the default), behavior is exactly
// as before: the bespoke pass owns stack recovery and this whole path is dormant.
//
// This is an INC-1 increment gate. The faithful path is not yet a full
// replacement (indexed rsp+i*stride arrays still require the later
// discoverIndexedStackPointers work, and ScopeLocal/type-snapshot timing for the
// mid-mainloop stack varnodes is not yet aligned), so it is opt-in until proven.
func faithfulStackEnabled() bool {
	return os.Getenv("GOSLEIGH_FAITHFUL_STACK") == "1"
}
