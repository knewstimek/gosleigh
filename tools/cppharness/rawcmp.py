"""Compare Go against the C++ decompiler core on the raw bytes of a GenGoldens JSON.

The Ghidra goldens also carry what the Java layer and the full program image
supplied (relocated call targets, global symbols, Program-DB stack variables),
which the corpus tests cannot feed from bytes alone. This runs the C++ harness
on exactly the same bytes Go sees (loaded at address 0), so a mismatch here is
a decompiler-core difference rather than a missing-environment one.

Normalization: the C++ core names unmapped stack slots uStack_N/uStackX_N where
Go (without a localdb) uses the Java names local_N/local_resN, and the two
printers break long lines at different widths, so lines are joined.

usage: py -3 tools/cppharness/rawcmp.py testdata/<corpus>/x64_goldens.json [name ...]
Needs local/cppharness/decomp_dbg.exe and an x64 capture to graft the bytes
into (RAWCMP_TEMPLATE, default: the first local/realexe/private-sample capture).
"""
import difflib, glob, json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def template():
	t = os.environ.get('RAWCMP_TEMPLATE')
	if not t:
		caps = sorted(glob.glob(os.path.join(ROOT, 'local', 'realexe', 'private-sample', 'captures', '*.xml')))
		if not caps:
			sys.exit('no x64 capture template; set RAWCMP_TEMPLATE')
		t = caps[0]
	return open(t, encoding='utf-8').read()


def norm(c, name):
	c = c.replace('func_0x00000000', name)
	c = re.sub(r'\b[a-z]*StackX_([0-9a-f]+)', r'local_res\1', c)
	c = re.sub(r'\b[a-z]*Stack_([0-9a-f]+)', r'local_\1', c)
	return ' '.join(l.strip() for l in c.splitlines() if l.strip())


def cpp_c(exe, tmpl, hexs, tmpdir):
	chunk = '\n'.join(hexs[i:i + 32] for i in range(0, len(hexs), 32))
	t = re.sub(r'<bytechunk space="ram" offset="0x[0-9a-f]+" readonly="true">.*?</bytechunk>',
		lambda m: '<bytechunk space="ram" offset="0x0" readonly="true">\n%s\n</bytechunk>' % chunk, tmpl, flags=re.S)
	xp = os.path.join(tmpdir, 'rawcmp.xml')
	open(xp, 'w', encoding='utf-8').write(t)
	cmds = ['restore ' + xp.replace('\\', '/'), 'load addr 0x0', 'decompile', 'print C', 'quit']
	r = subprocess.run([exe], input='\n'.join(cmds) + '\n', text=True, capture_output=True,
		env=dict(os.environ, SLEIGHHOME=os.environ.get('SLEIGHHOME', 'C:/ghidra12')), timeout=300)
	m = re.search(r'\[decomp\]> print C\n(.*?)\[decomp\]> quit', r.stdout, re.S)
	return m.group(1) if m else r.stdout


def main():
	golden = sys.argv[1]
	only = set(sys.argv[2:])
	fns = json.load(open(golden))['functions']
	exe = os.environ.get('DBG_EXE', os.path.join(ROOT, 'local', 'cppharness', 'decomp_dbg.exe'))
	tmpl = template()
	tmpdir = tempfile.mkdtemp(prefix='rawcmp')
	ssad = os.path.join(tmpdir, 'ssadump.exe')
	subprocess.run(['go', 'build', '-o', ssad, './cmd/ssadump'], cwd=ROOT, check=True)
	ok, bad = 0, []
	for f in fns:
		name = f['name']
		if only and name not in only:
			continue
		cc = cpp_c(exe, tmpl, f['bytes'], tmpdir)
		g = subprocess.run([ssad, '-golden', golden, '-func', name, '-print-c'], cwd=ROOT,
			capture_output=True, text=True, timeout=300)
		gm = re.search(r'--- print C ---\n(.*?)\nBasic Block', g.stdout + g.stderr, re.S)
		gc = gm.group(1) if gm else g.stdout + g.stderr
		a, b = norm(cc, name), norm(gc, name)
		if a == b:
			ok += 1
			continue
		bad.append(name)
		if only:
			print('=====', name)
			for l in difflib.unified_diff(cc.splitlines(), gc.splitlines(), 'c++', 'go', lineterm='', n=1):
				print(l)
	print('C++ core parity: %d/%d%s' % (ok, ok + len(bad), ('  mismatch: ' + ' '.join(bad)) if bad else ''))


if __name__ == '__main__':
	main()
