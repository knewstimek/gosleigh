"""difffn.py -- decompile sampled goldens with the current tree and diff them.

Usage: py -3 tools/realexe/difffn.py --work DIR IDX [IDX ...]

Builds cmd/goldengap into <work>/goldengap_dev.exe and prints a unified diff
(golden vs Gosleigh, leading whitespace stripped) per index. A quick look at
what the next gap is, without a full measure run.
"""
import argparse
import difflib
import json
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import realexe  # noqa: E402


def main():
	p = argparse.ArgumentParser()
	p.add_argument("--work", required=True)
	p.add_argument("idx", nargs="+", type=int)
	a = p.parse_args()
	work = os.path.abspath(a.work)
	meta = realexe.load_meta(work)
	sla, pspec, cspec = (os.path.join(ROOT, x) for x in realexe.ARCH_SPECS[meta["machine"]])
	exe = os.path.join(work, "goldengap_dev.exe")
	subprocess.run(["go", "build", "-o", exe, "./cmd/goldengap"], cwd=ROOT, check=True)
	goldens = os.path.join(work, "goldens.json")
	gf = json.load(open(goldens, encoding="utf-8"))["functions"]
	args = ["-goldens", goldens, "-pe", meta["exe"], "-sla", sla, "-pspec", pspec, "-cspec", cspec,
		"-max-instructions", "20000", "-mem-limit-mb", "2048"]
	sym = os.path.join(work, "symbols.json")
	if os.path.isfile(sym):
		args += ["-symbols", sym]
	cap = os.path.join(work, "captures")
	if os.path.isdir(cap):
		args += ["-host-captures", cap]
	for i in a.idx:
		r = subprocess.run([exe] + args + ["-index", str(i)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
		try:
			got = json.loads(r.stdout)["functions"][0]
			out = got.get("output") or got.get("error", "")
		except Exception:
			out = "RUN-ERR rc=%d %s" % (r.returncode, r.stderr[-200:])
		want = [l.strip() for l in gf[i]["c"].splitlines() if l.strip()]
		have = [l.strip() for l in out.splitlines() if l.strip()]
		print("===== [%d] %s (%d bytes)" % (i, gf[i]["name"], gf[i].get("size", 0)))
		if want == have:
			print("MATCH")
			continue
		for line in difflib.unified_diff(want, have, "ghidra", "gosleigh", n=1, lineterm=""):
			print(line)


if __name__ == "__main__":
	main()
