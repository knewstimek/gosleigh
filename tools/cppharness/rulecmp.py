"""Compare how often each rule fires, C++ vs Go, for one realexe golden index.
Rules whose counts differ point at the divergent rewrite.

usage: py -3 tools/cppharness/rulecmp.py local/realexe/<work> INDEX
"""
import collections, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, 'tools', 'realexe'))
import realexe  # noqa: E402

work, idx = sys.argv[1], sys.argv[2]
out = subprocess.run([sys.executable, os.path.join(HERE, 'hx.py'), work, idx, 'pre:trace address', 'pre:trace enable', 'print C'],
	capture_output=True, text=True).stdout
cpp = collections.Counter(m.group(1) for m in re.finditer(r'^DEBUG \d+: (\S+)', out, re.M))

w = os.path.join(ROOT, work)
m = json.load(open(os.path.join(w, 'meta.json')))
sla, pspec, cspec = realexe.ARCH_SPECS[m['machine']]
args = [os.path.join(w, 'goldengap.exe'), '-goldens', os.path.join(w, 'goldens.json'), '-pe', m['exe'],
	'-sla', sla, '-pspec', pspec, '-cspec', cspec, '-max-instructions', '20000',
	'-symbols', os.path.join(w, 'symbols.json'), '-host-captures', os.path.join(w, 'captures'), '-index', idx]
r = subprocess.run(args, capture_output=True, text=True, env=dict(os.environ, RULE_TRACE='1'), timeout=120)
go = collections.Counter(mm.group(1) for mm in re.finditer(r'^RULE (\S+) @', r.stderr, re.M))
names = sorted(set(cpp) | set(go), key=lambda n: -abs(cpp[n] - go[n]))
for n in names:
	if cpp[n] != go[n]:
		print('%-24s c++ %4d  go %4d' % (n, cpp[n], go[n]))
