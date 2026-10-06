"""Audit Go rule ports against ghidra-ref C++.

usage: py -3 tools/ruleaudit.py            # rank rules by C++ applyOp lines - Go apply lines
       py -3 tools/ruleaudit.py NAME ...   # print the Go apply body next to the C++ applyOp

A large gap usually means the Go rule is an approximation of (or a different
transform than) the C++ one. Run from the repository root.
"""
import re, glob, sys
R = 'ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/'
def rd(p):
    return open(p, encoding='utf-8', errors='replace').read().replace('\r\n', '\n')
cpp = ''.join(rd(f) for f in glob.glob(R + '*.cc'))
hh = ''.join(rd(f) for f in glob.glob(R + '*.hh'))
cbody = {}
for m in re.finditer(r'^int4 (Rule\w+)::applyOp\(PcodeOp \*op, *Funcdata &data\)\s*\{(.*?)\n\}\n', cpp, re.S | re.M):
    cbody[m.group(1)] = m.group(2)
cname = {}
for m in re.finditer(r'(Rule\w+)\(const string &g\)\s*:\s*Rule\(\s*g\s*,\s*[\w|:]+\s*,\s*"(\w+)"\s*\)', hh):
    cname[m.group(2)] = m.group(1)
gofiles = [f for f in glob.glob('pkg/pcode/*.go') if not f.endswith('_test.go')]
src = ''.join(rd(f) for f in gofiles)
funcs = {}
for m in re.finditer(r'^func (?:\(\w+ \*(\w+)\) )?(\w+)\([^\n]*\{\n(.*?)\n\}\n', src, re.S | re.M):
    funcs[(m.group(1) or '', m.group(2))] = m.group(3)
rows = []
for m in re.finditer(r'r := &(\w+)\{\}\n\s*r\.batchRule = newBatchRule\(group, "(\w+)", [^\n]*?, (r\.\w+|\w+), ', src):
    typ, nm, fn = m.group(1), m.group(2), m.group(3)
    body = funcs.get((typ, fn[2:])) if fn.startswith('r.') else funcs.get(('', fn))
    gl = body.count('\n') + 1 if body else -1
    cls = cname.get(nm)
    cl = cbody[cls].count('\n') if cls in cbody else -1
    rows.append((cl - gl if gl >= 0 and cl >= 0 else -999, nm, cls, gl, cl))
if len(sys.argv) > 1:
    for nm in sys.argv[1:]:
        for m in re.finditer(r'r := &(\w+)\{\}\n\s*r\.batchRule = newBatchRule\(group, "' + nm + r'", [^\n]*?, (r\.\w+|\w+), ', src):
            typ, fn = m.group(1), m.group(2)
            body = funcs.get((typ, fn[2:])) if fn.startswith('r.') else funcs.get(('', fn))
            print('=====', nm, typ, fn)
            print(body)
            print('----- C++', cname.get(nm))
            print(cbody.get(cname.get(nm), ''))
    sys.exit()
rows.sort(reverse=True)
for r in rows:
    print(r)
