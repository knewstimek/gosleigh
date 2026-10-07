"""Copy ghidra-ref's decompiler sources to local/cppharness/src and add the
debug-harness patches. ghidra-ref itself is never modified.

Patches (all inert unless used):
- ifacedecomp.cc: `load function @<hexaddr>` finds the recorded function in any
  scope, so a capture keeps its prototype (templated scope names contain '::'
  and do not resolve by name; `load addr` makes a fresh function).
- action.cc: env ACT_TRACE=1 prints `ACT <action> <count>` at the end of every
  Action::perform that changed something (compare with Go RULE_TRACE=1 ACTION).
"""
import glob, os, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
REF = os.path.join(ROOT, "ghidra-ref", "Ghidra", "Features", "Decompiler", "src", "decompile", "cpp")
DST = os.path.join(ROOT, "local", "cppharness", "src")


def patch(name, old, new):
	p = os.path.join(DST, name)
	s = open(p, encoding="utf-8").read()
	assert s.count(old) == 1, (name, old[:60])
	s = s.replace(old, new)
	if "#include <cstdio>" not in s:
		s = "#include <cstdio>\n#include <cstdlib>\n" + s
	open(p, "w", encoding="utf-8", newline="").write(s)


def main():
	os.makedirs(DST, exist_ok=True)
	for pat in ("*.cc", "*.hh", "*.h"):
		for f in glob.glob(os.path.join(REF, pat)):
			shutil.copy(f, DST)
	patch("ifacedecomp.cc", '''  string basename;
  Scope *funcscope = dcp->conf->symboltab->resolveScopeFromSymbolName(funcname,"::",basename,(Scope *)0);''',
'''  if (funcname.size() > 2 && funcname[0] == '@') {	// Debug harness: @<hexaddr> finds the function in any scope
    uintb off = strtoull(funcname.c_str() + 1, (char **)0, 16);
    Address addr(dcp->conf->getDefaultCodeSpace(), off);
    vector<Scope *> stack;
    stack.push_back(dcp->conf->symboltab->getGlobalScope());
    dcp->fd = (Funcdata *)0;
    while (!stack.empty() && dcp->fd == (Funcdata *)0) {
      Scope *sc = stack.back();
      stack.pop_back();
      dcp->fd = sc->findFunction(addr);
      for (ScopeMap::const_iterator it = sc->childrenBegin(); it != sc->childrenEnd(); ++it)
        stack.push_back((*it).second);
    }
    if (dcp->fd == (Funcdata *)0)
      throw IfaceExecutionError("No function at: "+funcname);
    if (!dcp->fd->hasNoCode())
      dcp->followFlow(*status->optr,0);
    return;
  }
  string basename;
  Scope *funcscope = dcp->conf->symboltab->resolveScopeFromSymbolName(funcname,"::",basename,(Scope *)0);''')
	patch("action.cc", '''  else
    status = status_start;

  return count;
}''', '''  else
    status = status_start;

  if (count > 0 && getenv("ACT_TRACE") != (char *)0) fprintf(stderr, "ACT %s %d\\n", getName().c_str(), count);
  return count;
}''')
	print("patched sources ->", DST)


if __name__ == "__main__":
	main()
