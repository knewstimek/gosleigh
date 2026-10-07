"""Run the C++ harness on one realexe golden index.

usage: py -3 tools/cppharness/hx.py local/realexe/<work> INDEX [CMD ...]
CMDs run after `decompile` (default: print raw); a CMD starting with 'pre:'
runs before it (e.g. 'pre:trace address', 'pre:trace enable',
'pre:trace propagation on'). Useful after: 'print C', 'print map',
'print high NAME', 'print tree varnode'.
The harness is local/cppharness/decomp_dbg.exe (tools/cppharness/build.py),
or DBG_EXE. The function is loaded with `load function @addr`, which keeps the
prototype the capture recorded.
"""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
work, idx = sys.argv[1], int(sys.argv[2])
cmds = sys.argv[3:] or ['print raw']
g = json.load(open(os.path.join(ROOT, work, 'goldens.json'), encoding='utf-8'))['functions'][idx]
entry = g['entry']
cap = os.path.join(ROOT, work, 'captures', '%x.xml' % entry)
if not os.path.exists(cap):
	cap = os.path.join(ROOT, work, 'captures', '%08x.xml' % entry)
lines = ['restore ' + cap.replace('\\', '/'), 'load function @%x' % entry]
lines += [c[4:] for c in cmds if c.startswith('pre:')]
lines.append('decompile')
lines += [c for c in cmds if not c.startswith('pre:')]
lines.append('quit')
exe = os.environ.get('DBG_EXE', os.path.join(ROOT, 'local', 'cppharness', 'decomp_dbg.exe'))
env = dict(os.environ, SLEIGHHOME=os.environ.get('SLEIGHHOME', 'C:/ghidra12'))
r = subprocess.run([exe], input='\n'.join(lines) + '\n', text=True, capture_output=True, env=env, timeout=300)
sys.stdout.write(r.stdout)
sys.stdout.write(r.stderr)
