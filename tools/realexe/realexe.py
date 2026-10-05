"""realexe.py -- measure Gosleigh against Ghidra on functions of a real PE.

The goldengap corpora are tiny /Od functions decompiled in base-0 isolation.
This tool samples functions from a real, fully linked executable instead and
decompiles them with the image mapped at its linked VMAs, so calls, globals
and jump tables resolve the way they do in real use.

Ghidra analysis of a large binary is slow, so it runs once into a persistent
project; sampling re-opens that project with -noanalysis. analyze snapshots
the binary (plus same-stem .pdb/.map) into <work>/bin and every later step
reads only that snapshot, so rebuilding the source binary cannot desync the
corpus. Everything lives under the work directory (default
local/realexe/<exe stem>/, gitignored) -- third-party binaries and their
decompiled output must not be committed.

Usage:
    py -3 tools/realexe/realexe.py analyze <exe> [--work DIR]
    py -3 tools/realexe/realexe.py sample  [--work DIR] [--n 200] [--seed 1] [--max-bytes 4096]
    py -3 tools/realexe/realexe.py run     [--work DIR] [--timeout 30]
    py -3 tools/realexe/realexe.py report  [--work DIR]

PDB is deliberately disabled for the golden (DisablePdb.java): Gosleigh does
not read PDB, so a PDB-named golden would never match.
"""

import argparse
import difflib
import hashlib
import re
import json
import shutil
import os
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "goldengap"))
import goldengap  # noqa: E402

HEADLESS = r"C:\ghidra12\support\analyzeHeadless.bat"
PROJ_NAME = "realexe"

# PE machine -> (sla, pspec, cspec), relative to REPO_ROOT.
ARCH_SPECS = {
	0x014C: ("pkg/sla/testdata/x86-packed.sla", "testdata/sla/x86.pspec", "testdata/sla/x86win.cspec"),
	0x8664: ("pkg/sla/testdata/x86-64-packed.sla", "testdata/sla/x86-64.pspec", "testdata/sla/x86-64-win.cspec"),
}


def pe_machine(path):
	with open(path, "rb") as f:
		head = f.read(0x400)
	(pe_off,) = struct.unpack_from("<I", head, 0x3C)
	if head[pe_off:pe_off + 4] != b"PE\0\0":
		raise SystemExit("not a PE file: %s" % path)
	(machine,) = struct.unpack_from("<H", head, pe_off + 4)
	return machine


def default_work(exe):
	stem = os.path.splitext(os.path.basename(exe))[0].lower()
	return os.path.join(REPO_ROOT, "local", "realexe", stem)


def meta_path(work):
	return os.path.join(work, "meta.json")


def load_meta(work):
	p = meta_path(work)
	if not os.path.isfile(p):
		raise SystemExit("no %s -- run `analyze <exe>` first" % p)
	return goldengap.load_json(p)


def resolve_work(args):
	if args.work:
		return os.path.abspath(args.work)
	root = os.path.join(REPO_ROOT, "local", "realexe")
	subs = [d for d in os.listdir(root) if os.path.isfile(meta_path(os.path.join(root, d)))] if os.path.isdir(root) else []
	if len(subs) != 1:
		raise SystemExit("pass --work (found %d work dirs under %s)" % (len(subs), root))
	return os.path.join(root, subs[0])


def headless(cmd, log_path, timeout):
	print("> " + " ".join(cmd))
	print("  log: " + log_path)
	with open(log_path, "w", encoding="utf-8", errors="replace") as log:
		try:
			r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
		except subprocess.TimeoutExpired:
			print("TIMEOUT after %ss" % timeout)
			return 1
	return r.returncode


def sha256(path):
	h = hashlib.sha256()
	with open(path, "rb") as f:
		for chunk in iter(lambda: f.read(1 << 20), b""):
			h.update(chunk)
	return h.hexdigest()


def snapshot(exe, work):
	"""Copy the exe plus same-stem .pdb/.map into work/bin. The source is a
	build output that gets overwritten by every rebuild, while the Ghidra
	project and goldens are frozen at analysis time -- reading the live path
	later would silently decompile different bytes than the golden."""
	bindir = os.path.join(work, "bin")
	os.makedirs(bindir, exist_ok=True)
	src_dir = os.path.dirname(exe)
	stem = os.path.splitext(os.path.basename(exe))[0].lower()
	files = {}
	for name in os.listdir(src_dir):
		base, ext = os.path.splitext(name)
		if base.lower() == stem and ext.lower() in (".exe", ".dll", ".pdb", ".map"):
			dst = os.path.join(bindir, name)
			shutil.copy2(os.path.join(src_dir, name), dst)
			files[name] = sha256(dst)
	return os.path.join(bindir, os.path.basename(exe)), files


def do_analyze(exe, work):
	exe = os.path.abspath(exe)
	machine = pe_machine(exe)
	if machine not in ARCH_SPECS:
		raise SystemExit("unsupported PE machine 0x%x" % machine)
	proj = os.path.join(work, "ghidra")
	os.makedirs(proj, exist_ok=True)
	exe, files = snapshot(exe, work)
	with open(meta_path(work), "w", encoding="utf-8") as f:
		json.dump({"exe": exe, "machine": machine, "program": os.path.basename(exe),
			"sha256": files}, f, indent=2)
	rc = headless([
		HEADLESS, proj, PROJ_NAME,
		"-import", exe, "-overwrite",
		"-scriptPath", HERE,
		"-preScript", "DisablePdb.java",
		"-analysisTimeoutPerFile", "14400",
	], os.path.join(work, "analyze.log"), timeout=4 * 3600)
	print("analyze: returncode %d" % rc)
	return rc == 0


def do_sample(work, n, seed, max_bytes):
	meta = load_meta(work)
	out = os.path.join(work, "goldens.json")
	rc = headless([
		HEADLESS, os.path.join(work, "ghidra"), PROJ_NAME,
		"-process", meta["program"], "-noanalysis", "-readOnly",
		"-scriptPath", HERE,
		"-postScript", "GenSample.java", out, str(n), str(seed), str(max_bytes),
	], os.path.join(work, "sample.log"), timeout=3 * 3600)
	ok = rc == 0 and os.path.isfile(out)
	print("sample: %s -- %s" % ("OK" if ok else "FAILED", out))
	return ok


def run_one(binary, base_args, idx, name, timeout_s):
	"""Decompile golden #idx in its own process; map every failure mode to a
	funcResult so one runaway function cannot sink the batch."""
	t0 = time.time()
	try:
		r = subprocess.run([binary] + base_args + ["-index", str(idx)],
			capture_output=True, text=True, timeout=timeout_s)
	except subprocess.TimeoutExpired:
		return {"name": name, "output": "", "error": "TIMEOUT: exceeded %ds" % timeout_s}, timeout_s
	dt = time.time() - t0
	if r.returncode == 3:
		return {"name": name, "output": "", "error": "MEMLIMIT: heap limit exceeded"}, dt
	if r.returncode != 0:
		tail = (r.stderr or "").strip().splitlines()[-1:] or ["no stderr"]
		return {"name": name, "output": "", "error": "CRASH: rc=%d %s" % (r.returncode, tail[0])}, dt
	return json.loads(r.stdout)["functions"][0], dt


def do_run(work, timeout_s, mem_mb, fresh):
	meta = load_meta(work)
	want = meta.get("sha256", {}).get(os.path.basename(meta["exe"]))
	if want != sha256(meta["exe"]):
		raise SystemExit("snapshot %s does not match the analyzed sha256 -- re-run analyze" % meta["exe"])
	sla, pspec, cspec = (os.path.join(REPO_ROOT, p) for p in ARCH_SPECS[meta["machine"]])
	binary = os.path.join(work, "goldengap.exe")
	rc, _, _ = goldengap.run_cmd(["go", "build", "-o", binary, "./cmd/goldengap"], cwd=REPO_ROOT, timeout=600)
	if rc != 0:
		return False

	goldens = os.path.join(work, "goldens.json")
	fns = goldengap.load_json(goldens)["functions"]
	# Results are appended per function so an interrupted run resumes; the
	# jsonl is keyed by golden index because auto-names are not guaranteed unique.
	jsonl = os.path.join(work, "results.jsonl")
	done = {}
	if fresh and os.path.isfile(jsonl):
		os.remove(jsonl)
	if os.path.isfile(jsonl):
		with open(jsonl, encoding="utf-8") as f:
			for line in f:
				rec = json.loads(line)
				done[rec["index"]] = rec
	args = ["-goldens", goldens, "-pe", meta["exe"], "-sla", sla, "-pspec", pspec,
		"-cspec", cspec, "-max-instructions", "20000", "-mem-limit-mb", str(mem_mb)]
	symbols = os.path.join(work, "symbols.json")
	if os.path.isfile(symbols):
		args += ["-symbols", symbols] # the host symbol table (HostScope)
	with open(jsonl, "a", encoding="utf-8") as f:
		for i, fn in enumerate(fns):
			if i in done:
				continue
			res, dt = run_one(binary, args, i, fn["name"], timeout_s)
			rec = {"index": i, "secs": round(dt, 2), **res}
			f.write(json.dumps(rec) + "\n")
			f.flush()
			done[i] = rec
			status = rec.get("error", "").split(":")[0] or "ok"
			print("[%d/%d] %s %s %.1fs" % (i + 1, len(fns), fn["name"], status, dt), flush=True)

	out = {"functions": [{k: done[i][k] for k in ("name", "output", "error") if k in done[i]} for i in range(len(fns))]}
	with open(os.path.join(work, "gosleigh_out.json"), "w", encoding="utf-8") as f:
		json.dump(out, f, indent=2)
	return True


def size_bucket(size):
	for lim in (32, 64, 128, 256, 512, 1024, 2048):
		if size <= lim:
			return "<=%d" % lim
	return ">2048"


def do_report(work):
	goldens = os.path.join(work, "goldens.json")
	summary = goldengap.do_report(
		goldens, os.path.join(work, "gosleigh_out.json"),
		os.path.join(work, "GAPMAP.md"), os.path.join(work, "gapmap.json"),
		title="real-exe gap map",
	)
	gf = goldengap.load_json(goldens)["functions"]
	got = goldengap.load_json(os.path.join(work, "gosleigh_out.json"))["functions"]
	by_bucket = defaultdict(Counter)
	sims = defaultdict(list)
	for g, r, out in zip(gf, summary["functions"], got):
		k = size_bucket(g.get("size", 0))
		b = by_bucket[k]
		b["total"] += 1
		if r["tags"] == ["MATCH"]:
			b["match"] += 1
		if "ENGINE-ERR" in r["tags"]:
			b["err"] += 1
		sims[k].append(similarity(g["c"], out.get("output") or ""))
	# sim = token-sequence similarity (difflib ratio, 0..1) after collapsing
	# whitespace: a progress signal that moves before exact matches do.
	print("")
	print("%-8s %6s %6s %6s %6s" % ("bytes", "total", "match", "err", "sim"))
	order = ["<=32", "<=64", "<=128", "<=256", "<=512", "<=1024", "<=2048", ">2048"]
	for k in order:
		if k in by_bucket:
			c = by_bucket[k]
			print("%-8s %6d %6d %6d %6.3f" % (k, c["total"], c["match"], c["err"], sum(sims[k]) / len(sims[k])))
	allsim = [s for v in sims.values() for s in v]
	print("%-8s %6d %6d %6s %6.3f" % ("all", len(allsim), sum(c["match"] for c in by_bucket.values()), "", sum(allsim) / len(allsim)))
	return True


TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+|\S")


def similarity(want, got):
	a, b = TOKEN.findall(want), TOKEN.findall(got)
	if not a and not b:
		return 1.0
	return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def main():
	p = argparse.ArgumentParser(description="real-PE golden gap measurement")
	sub = p.add_subparsers(dest="cmd", required=True)
	pa = sub.add_parser("analyze")
	pa.add_argument("exe")
	pa.add_argument("--work")
	ps = sub.add_parser("sample")
	ps.add_argument("--work")
	ps.add_argument("--n", type=int, default=200)
	ps.add_argument("--seed", type=int, default=1)
	ps.add_argument("--max-bytes", type=int, default=4096)
	pr = sub.add_parser("run")
	pr.add_argument("--work")
	pr.add_argument("--timeout", type=int, default=30, help="per-function seconds")
	pr.add_argument("--mem-mb", type=int, default=2048, help="per-function Go heap limit")
	pr.add_argument("--fresh", action="store_true", help="discard results.jsonl instead of resuming")
	pp = sub.add_parser("report")
	pp.add_argument("--work")
	pm = sub.add_parser("measure", help="run --fresh + report (the progress metric)")
	pm.add_argument("--work")
	pm.add_argument("--timeout", type=int, default=30)
	pm.add_argument("--mem-mb", type=int, default=2048)
	args = p.parse_args()

	if args.cmd == "analyze":
		work = os.path.abspath(args.work) if args.work else default_work(args.exe)
		ok = do_analyze(args.exe, work)
	elif args.cmd == "sample":
		ok = do_sample(resolve_work(args), args.n, args.seed, args.max_bytes)
	elif args.cmd == "run":
		ok = do_run(resolve_work(args), args.timeout, args.mem_mb, args.fresh)
	elif args.cmd == "measure":
		work = resolve_work(args)
		ok = do_run(work, args.timeout, args.mem_mb, True) and do_report(work)
	else:
		ok = do_report(resolve_work(args))
	sys.exit(0 if ok else 1)


if __name__ == "__main__":
	main()
