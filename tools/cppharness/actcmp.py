"""Diff the sequence of actions that changed something, C++ vs Go, for one
realexe golden index. The first differing line is where the two pipelines
diverge.

usage: py -3 tools/cppharness/actcmp.py local/realexe/<work> INDEX
Needs local/cppharness/decomp_dbg.exe and <work>/goldengap.exe.
"""
import difflib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, 'tools', 'realexe'))
import realexe  # noqa: E402

work, idx = sys.argv[1], sys.argv[2]
env = dict(os.environ, ACT_TRACE='1')
cpp = subprocess.run([sys.executable, os.path.join(HERE, 'hx.py'), work, idx, 'print C'],
	capture_output=True, text=True, env=env).stdout.splitlines()
cpp = [l[4:] for l in cpp if l.startswith('ACT ')]

w = os.path.join(ROOT, work)
m = json.load(open(os.path.join(w, 'meta.json')))
sla, pspec, cspec = realexe.ARCH_SPECS[m['machine']]
args = [os.path.join(w, 'goldengap.exe'), '-goldens', os.path.join(w, 'goldens.json'), '-pe', m['exe'],
	'-sla', sla, '-pspec', pspec, '-cspec', cspec, '-max-instructions', '20000',
	'-symbols', os.path.join(w, 'symbols.json'), '-host-captures', os.path.join(w, 'captures'), '-index', idx]
r = subprocess.run(args, capture_output=True, text=True, env=dict(os.environ, RULE_TRACE='1'), timeout=120)
go = [l[7:] for l in r.stderr.splitlines() if l.startswith('ACTION ')]
for l in difflib.unified_diff(cpp, go, 'c++', 'go', lineterm='', n=1):
	print(l)
