"""gates.py -- run every golden gate and print one summary line per gate.

Gates (all must hold before landing an engine change):
  - go test ./...                      (unit + always-on goldens)
  - env-gated golden maps in pkg/loader (X64_CORPUS/X64_CORPUS2/X64_BREADTH/
    X64_SWITCH/TREE_MAP), summarized by their "N/M match" lines
  - x64_auto via tools/goldengap (gosleigh_out.json regenerated, then diffed)

Usage: py -3 tools/gates.py [--quick]   (--quick skips go test ./...)
"""
import concurrent.futures
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENV_GATES = ["X64_CORPUS", "X64_CORPUS2", "X64_BREADTH", "X64_SWITCH", "TREE_MAP"]
SUMMARY = re.compile(r"(\d+/\d+ match|MAP:.*|--- FAIL.*|panic:.*)", re.I)


def run(cmd, env=None, timeout=1800):
	r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env, timeout=timeout)
	return r.returncode, r.stdout + r.stderr


def gate_unit():
	# go test's cache keeps unchanged packages instant; env reads are part of
	# the cache key, so cached results are never stale.
	rc, out = run(["go", "test", "./...", "-timeout", "60s"])
	bad = [l for l in out.splitlines() if l.startswith(("FAIL", "--- FAIL", "panic"))]
	lines = ["go test ./...: %s" % ("green" if rc == 0 else "RED")] + ["   " + l for l in bad[:10]]
	return rc == 0, lines


def gate_loader():
	env = dict(os.environ)
	for g in ENV_GATES:
		env[g] = "1"
	rc, out = run(["go", "test", "./pkg/loader/", "-count=1", "-v", "-timeout", "60s",
		"-run", "GoldenMap|TreeFullGoldenMap"], env=env)
	seen, lines = set(), []
	for l in out.splitlines():
		m = SUMMARY.search(l)
		if m and m.group(1) not in seen:
			seen.add(m.group(1))
			lines.append("loader: " + l.strip())
	return rc == 0, lines


def gate_x64_auto():
	gg = os.path.join(HERE, "goldengap", "goldengap.py")
	rc, _ = run([sys.executable, gg, "run"])
	rc2, out = run([sys.executable, gg, "report"])
	line = next((l for l in out.splitlines() if l.startswith("report:")), "report: ?")
	return rc == 0 and rc2 == 0, ["x64_auto " + line]


def main():
	gates = [gate_loader, gate_x64_auto]
	if "--quick" not in sys.argv:
		gates.insert(0, gate_unit)
	# The gates are independent processes: run them side by side.
	with concurrent.futures.ThreadPoolExecutor(max_workers=len(gates)) as pool:
		results = list(pool.map(lambda g: g(), gates))
	ok = True
	for good, lines in results:
		ok &= good
		for l in lines:
			print(l)
	sys.exit(0 if ok else 1)


if __name__ == "__main__":
	main()
