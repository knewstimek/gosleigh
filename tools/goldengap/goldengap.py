"""goldengap.py -- one-command golden-gap tool for Gosleigh.

Automates: add a C function to an auto-growing corpus -> compile it with MSVC
-> generate a Ghidra 12 headless golden (name/entry/bytes/decompiled C) ->
run the same bytes through the Gosleigh decompile pipeline (cmd/goldengap) ->
diff the two C outputs (indent-insensitive) -> auto-classify the gap by token
kind -> write a markdown gap map + JSON summary.

None of this touches pkg/ engine code: cmd/goldengap/main.go only calls the
existing public bridge/loader API, exactly like pkg/loader/x64_corpus2_diag_test.go
already does.

Usage:
    py -3 tools/goldengap/goldengap.py add <name> <c_file_or_inline_code>
    py -3 tools/goldengap/goldengap.py gen
    py -3 tools/goldengap/goldengap.py run
    py -3 tools/goldengap/goldengap.py report
    py -3 tools/goldengap/goldengap.py all
    py -3 tools/goldengap/goldengap.py validate-corpus2

See tools/goldengap/README.md for the full walkthrough.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import classify  # noqa: E402  (path-adjusted import, see sys.path.insert above)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))

DEFAULT_DIR = os.path.join(REPO_ROOT, "testdata", "x64_auto")
CORPUS2_DIR = os.path.join(REPO_ROOT, "testdata", "x64_corpus2")

DEFAULT_SLA = os.path.join(REPO_ROOT, "pkg", "sla", "testdata", "x86-64-packed.sla")
DEFAULT_PSPEC = os.path.join(REPO_ROOT, "testdata", "sla", "x86-64.pspec")
DEFAULT_CSPEC = os.path.join(REPO_ROOT, "testdata", "sla", "x86-64-win.cspec")

CORPUS_SKELETON_FILES = ("build.py", "run_ghidra.py", "GenGoldens.java")


def run_cmd(cmd, cwd=None, timeout=120, label=""):
	print("> " + " ".join(str(c) for c in cmd))
	try:
		r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
	except subprocess.TimeoutExpired:
		print("TIMEOUT after %ss: %s" % (timeout, label))
		return 1, "", "timeout"
	if r.stdout:
		sys.stdout.write(r.stdout)
	if r.stderr:
		sys.stderr.write(r.stderr)
	return r.returncode, r.stdout, r.stderr


def load_json(path):
	with open(path, "r", encoding="utf-8") as f:
		return json.load(f)


# ---------------------------------------------------------------------------
# gen / add: MSVC compile + Ghidra headless golden generation.
# ---------------------------------------------------------------------------


def ensure_corpus_skeleton(corpus_dir):
	os.makedirs(corpus_dir, exist_ok=True)
	for fname in CORPUS_SKELETON_FILES:
		dst = os.path.join(corpus_dir, fname)
		if os.path.isfile(dst):
			continue
		src = os.path.join(CORPUS2_DIR, fname)
		with open(src, "r", encoding="utf-8") as f:
			content = f.read()
		with open(dst, "w", encoding="utf-8") as f:
			f.write(content)
		print("skeleton: copied %s -> %s" % (fname, dst))
	corpus_c = os.path.join(corpus_dir, "corpus.c")
	if not os.path.isfile(corpus_c):
		header = (
			"/* x86-64 auto corpus for tools/goldengap/goldengap.py.\n"
			" *\n"
			" * Populated incrementally via `goldengap.py add <name> <file_or_code>`.\n"
			" * Compiled with MSVC cl /c /Od /GS- (Windows x64 ABI). Pipeline cloned from\n"
			" * testdata/x64_corpus2 (build.py/run_ghidra.py/GenGoldens.java unchanged,\n"
			" * self-relative to this directory).\n"
			" */\n\n"
		)
		with open(corpus_c, "w", encoding="utf-8") as f:
			f.write(header)
		print("skeleton: created %s" % corpus_c)


def do_gen(corpus_dir):
	ensure_corpus_skeleton(corpus_dir)
	build_py = os.path.join(corpus_dir, "build.py")
	run_ghidra_py = os.path.join(corpus_dir, "run_ghidra.py")

	rc, _, _ = run_cmd([sys.executable, build_py], timeout=90, label="build.py")
	if rc != 0:
		print("gen: build.py FAILED")
		return False

	rc, _, _ = run_cmd([sys.executable, run_ghidra_py], timeout=300, label="run_ghidra.py")
	goldens = os.path.join(corpus_dir, "x64_goldens.json")
	if rc != 0 or not os.path.isfile(goldens):
		print("gen: FAILED -- %s not produced (headless returncode %d)" % (goldens, rc))
		return False
	print("gen: OK -- %s" % goldens)
	return True


def do_add(corpus_dir, name, source):
	ensure_corpus_skeleton(corpus_dir)
	if os.path.isfile(source):
		with open(source, "r", encoding="utf-8") as f:
			code = f.read()
	else:
		code = source

	corpus_c = os.path.join(corpus_dir, "corpus.c")
	with open(corpus_c, "r", encoding="utf-8") as f:
		existing = f.read()

	if re.search(r"\b%s\s*\(" % re.escape(name), existing):
		print("add: '%s' already present in corpus.c, skipping insert" % name)
	else:
		block = "\n/* added via goldengap add: %s */\n%s\n" % (name, code.strip())
		with open(corpus_c, "a", encoding="utf-8") as f:
			f.write(block)
		print("add: appended '%s' to %s" % (name, corpus_c))

	if not do_gen(corpus_dir):
		return False

	goldens_path = os.path.join(corpus_dir, "x64_goldens.json")
	gf = load_json(goldens_path)
	names = [fn["name"] for fn in gf["functions"]]
	if name not in names:
		print("add: ERROR -- '%s' not found in regenerated goldens %s" % (name, names))
		return False
	print("add: confirmed '%s' present in golden functions" % name)
	return True


# ---------------------------------------------------------------------------
# run: drive cmd/goldengap (the Gosleigh side of the diff).
# ---------------------------------------------------------------------------


def do_run(goldens_path, out_path):
	if not os.path.isfile(goldens_path):
		print("run: ERROR -- golden file not found: %s" % goldens_path)
		return False
	cmd = [
		"go", "run", "./cmd/goldengap",
		"-goldens", goldens_path,
		"-sla", DEFAULT_SLA,
		"-pspec", DEFAULT_PSPEC,
		"-cspec", DEFAULT_CSPEC,
		"-out", out_path,
	]
	rc, _, _ = run_cmd(cmd, cwd=REPO_ROOT, timeout=240, label="cmd/goldengap")
	if rc != 0:
		print("run: FAILED (cmd/goldengap returncode %d)" % rc)
		return False
	print("run: OK -- %s" % out_path)
	return True


# ---------------------------------------------------------------------------
# report: diff + classify + gap map.
# ---------------------------------------------------------------------------


def render_gapmap_md(title, note, records, match_count, tag_counts):
	lines = [
		"# %s" % title,
		"",
		note,
		"",
		"%d/%d MATCH (indent-insensitive)." % (match_count, len(records)),
		"",
		"## 함수별 분류",
		"",
		"| 함수 | 태그 | 근거 |",
		"|---|---|---|",
	]
	for r in records:
		tags = ", ".join(r["tags"])
		ev_lines = []
		for t in r["tags"]:
			for e in r["evidence"].get(t, []):
				ev_lines.append("%s: %s" % (t, e))
		ev = "<br>".join(ev_lines) if ev_lines else "-"
		lines.append("| `%s` | %s | %s |" % (r["name"], tags, ev))
	lines.append("")
	lines.append("## 태그 분포")
	lines.append("")
	for tag in sorted(tag_counts):
		lines.append("- %s: %d" % (tag, tag_counts[tag]))
	lines.append("")
	return "\n".join(lines) + "\n"


def classify_functions(goldens_path, gosleigh_out_path):
	gf = load_json(goldens_path)
	rf = load_json(gosleigh_out_path)
	got_by_name = {f["name"]: f for f in rf["functions"]}

	records = []
	for fn in gf["functions"]:
		name = fn["name"]
		got_entry = got_by_name.get(name)
		if got_entry is None:
			result = {
				"tags": ["ENGINE-ERR"],
				"evidence": {"ENGINE-ERR": ["missing from Gosleigh run output"]},
			}
		else:
			err = got_entry.get("error") or ""
			result = classify.classify_entry(fn["c"], got_entry.get("output", ""), engine_error=err)
		records.append(
			{
				"name": name,
				"entry": fn.get("entry"),
				"tags": result["tags"],
				"evidence": result["evidence"],
			}
		)
	return records


def do_report(goldens_path, gosleigh_out_path, out_md_path, out_json_path, title="Golden Gap Map"):
	records = classify_functions(goldens_path, gosleigh_out_path)

	tag_counts = Counter()
	for r in records:
		for t in r["tags"]:
			tag_counts[t] += 1
	match_count = sum(1 for r in records if r["tags"] == ["MATCH"])

	summary = {
		"functions": records,
		"summary": {
			"total": len(records),
			"match": match_count,
			"tag_counts": dict(tag_counts),
		},
	}
	with open(out_json_path, "w", encoding="utf-8") as f:
		json.dump(summary, f, ensure_ascii=True, indent=2)

	note = (
		"goldengap.py 자동 생성 문서 (수동 편집 금지 -- "
		"`py -3 tools/goldengap/goldengap.py report`로 재생성)."
	)
	md = render_gapmap_md(title, note, records, match_count, tag_counts)
	with open(out_md_path, "w", encoding="utf-8") as f:
		f.write(md)

	print("report: %d/%d MATCH" % (match_count, len(records)))
	for r in records:
		print("  [%s] %s" % (r["name"], ",".join(r["tags"])))
	print("report: wrote %s and %s" % (out_md_path, out_json_path))
	return summary


# ---------------------------------------------------------------------------
# validate-corpus2: classifier acceptance check against the human P1-P8 map
# in testdata/x64_corpus2/README.md.
# ---------------------------------------------------------------------------

# Human classification transcribed from testdata/x64_corpus2/README.md
# (P1..P8 groups). Values are (group_label, [expected_auto_tags]). An empty
# tag list means "no clean category" -- the README gap does not correspond
# to any single class in this classifier's vocabulary (a known limitation,
# reported honestly instead of forcing a fit).
HUMAN_MAP = {
	"dowhile_scan": ("P1 (struct)", ["STRUCT"]),
	"find_pair": ("P1 (struct)", ["STRUCT"]),
	"parse_steps": ("P1 (struct)", ["STRUCT"]),
	"clamp3": ("P1 (struct)", ["STRUCT"]),
	"bump_scores": ("P2 (wrap)", ["WRAP"]),
	"umulhi": ("P3 (temp propagation)", ["TEMP"]),
	"sum_via_pp": ("P3/P5 (temp + ptr scale)", ["TEMP", "PTR"]),
	"gate": ("P3/P4 (temp + De Morgan)", ["TEMP"]),
	"add_pt": ("P5 (struct register packing)", ["TYPECAST"]),
	"helper_sum": ("P6 (stack param)", []),
	"caller": ("P7 (call target/reloc)", ["CALL"]),
	"faverage": ("P8 (FP unported)", ["FP"]),
	"divmix": ("MATCH", ["MATCH"]),
}


def render_corpus2_compare_md(records):
	lines = [
		"",
		"## corpus2 사람 분류(P1~P8) 대조",
		"",
		"testdata/x64_corpus2/README.md의 사람 분류와 이 분류기의 자동 태그를 비교한다.",
		"",
		"| 함수 | 사람 분류 (README) | 자동 태그 | 일치 |",
		"|---|---|---|---|",
	]
	hit = 0
	total = 0
	for r in records:
		name = r["name"]
		human_label, expected = HUMAN_MAP.get(name, ("(no README entry)", None))
		auto_tags = r["tags"]
		if expected is None:
			verdict = "N/A"
		elif not expected:
			verdict = "N/A (no clean category -- known classifier limitation)"
		else:
			total += 1
			if set(expected) & set(auto_tags):
				verdict = "MATCH"
				hit += 1
			else:
				verdict = "MISS"
		lines.append(
			"| `%s` | %s | %s | %s |" % (name, human_label, ", ".join(auto_tags), verdict)
		)
	lines.append("")
	lines.append(
		"대조 가능 %d건 중 %d건 일치 (N/A 항목은 이름 기준 분류 체계가 달라 대조 제외)."
		% (total, hit)
	)
	lines.append("")
	return "\n".join(lines) + "\n", hit, total


def do_validate_corpus2(skip_run):
	goldens_path = os.path.join(CORPUS2_DIR, "x64_goldens.json")
	gosleigh_out_path = os.path.join(DEFAULT_DIR, "corpus2_gosleigh_out.json")
	out_md_path = os.path.join(DEFAULT_DIR, "CORPUS2_GAPMAP.md")
	out_json_path = os.path.join(DEFAULT_DIR, "corpus2_gapmap.json")

	os.makedirs(DEFAULT_DIR, exist_ok=True)

	if not (skip_run and os.path.isfile(gosleigh_out_path)):
		if not do_run(goldens_path, gosleigh_out_path):
			return False

	summary = do_report(
		goldens_path, gosleigh_out_path, out_md_path, out_json_path,
		title="corpus2 gap map (classifier validation)",
	)

	compare_md, hit, total = render_corpus2_compare_md(summary["functions"])
	with open(out_md_path, "a", encoding="utf-8") as f:
		f.write(compare_md)

	print("")
	print("validate-corpus2: %d/%d human-labeled functions match the auto classifier" % (hit, total))
	print("validate-corpus2: wrote %s" % out_md_path)
	return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_argparser():
	p = argparse.ArgumentParser(description="Gosleigh golden-gap one-command tool")
	sub = p.add_subparsers(dest="cmd", required=True)

	p_add = sub.add_parser("add", help="append a function to the auto corpus and regenerate")
	p_add.add_argument("name", help="function name (must appear in the source)")
	p_add.add_argument("source", help="path to a .c file, or inline C source text")
	p_add.add_argument("--dir", default=DEFAULT_DIR, help="corpus directory (default testdata/x64_auto)")

	p_gen = sub.add_parser("gen", help="MSVC compile + Ghidra headless -> x64_goldens.json")
	p_gen.add_argument("--dir", default=DEFAULT_DIR)

	p_run = sub.add_parser("run", help="run the Gosleigh CLI over a golden JSON")
	p_run.add_argument("--dir", default=DEFAULT_DIR)
	p_run.add_argument("--goldens", default=None, help="override golden JSON path")
	p_run.add_argument("--out", default=None, help="override Gosleigh output JSON path")

	p_report = sub.add_parser("report", help="diff + classify + write gap map")
	p_report.add_argument("--dir", default=DEFAULT_DIR)
	p_report.add_argument("--goldens", default=None)
	p_report.add_argument("--gosleigh-out", default=None)
	p_report.add_argument("--out-md", default=None)
	p_report.add_argument("--out-json", default=None)
	p_report.add_argument("--title", default="Golden Gap Map")

	p_all = sub.add_parser("all", help="gen + run + report")
	p_all.add_argument("--dir", default=DEFAULT_DIR)

	p_val = sub.add_parser(
		"validate-corpus2",
		help="classify testdata/x64_corpus2 (read-only) and compare to its README P1-P8 map",
	)
	p_val.add_argument(
		"--skip-run", action="store_true",
		help="reuse an existing corpus2_gosleigh_out.json instead of re-running the Go CLI",
	)

	return p


def main():
	args = build_argparser().parse_args()

	if args.cmd == "add":
		ok = do_add(args.dir, args.name, args.source)
	elif args.cmd == "gen":
		ok = do_gen(args.dir)
	elif args.cmd == "run":
		goldens = args.goldens or os.path.join(args.dir, "x64_goldens.json")
		out = args.out or os.path.join(args.dir, "gosleigh_out.json")
		ok = do_run(goldens, out)
	elif args.cmd == "report":
		goldens = args.goldens or os.path.join(args.dir, "x64_goldens.json")
		gosleigh_out = args.gosleigh_out or os.path.join(args.dir, "gosleigh_out.json")
		out_md = args.out_md or os.path.join(args.dir, "GAPMAP.md")
		out_json = args.out_json or os.path.join(args.dir, "gapmap.json")
		do_report(goldens, gosleigh_out, out_md, out_json, title=args.title)
		ok = True
	elif args.cmd == "all":
		ok = do_gen(args.dir)
		if ok:
			goldens = os.path.join(args.dir, "x64_goldens.json")
			out = os.path.join(args.dir, "gosleigh_out.json")
			ok = do_run(goldens, out)
		if ok:
			out_md = os.path.join(args.dir, "GAPMAP.md")
			out_json = os.path.join(args.dir, "gapmap.json")
			do_report(goldens, out, out_md, out_json)
	elif args.cmd == "validate-corpus2":
		ok = do_validate_corpus2(args.skip_run)
	else:
		ok = False

	sys.exit(0 if ok else 1)


if __name__ == "__main__":
	main()
