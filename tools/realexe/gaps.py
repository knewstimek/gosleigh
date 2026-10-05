"""gaps.py -- bucket the remaining real-binary mismatches by first difference.

Usage: py -3 tools/realexe/gaps.py --work DIR [--show KIND]

Reads <work>/goldens.json + results.jsonl (from realexe run/measure) and
classifies each non-matching function by what differs, so the next fix can be
picked by frequency:
  wrap      only whitespace / line breaks differ (pretty-printer)
  sig       the declaration line differs
  decl      only local declarations differ
  body      statements differ
  error     engine error / timeout
--show KIND lists the indices of that kind.
"""
import argparse
import collections
import json
import os
import re


def norm_lines(s):
	return [l.strip() for l in s.splitlines() if l.strip()]


def is_decl(line):
	return re.match(r"^[A-Za-z_][\w\s\*]*\s+\**[A-Za-z_]\w*(\s*\[\d+\])?;$", line) is not None


def classify(want, got, err):
	if err:
		return "error"
	w, g = norm_lines(want), norm_lines(got)
	if w == g:
		return "match"
	if re.sub(r"\s+", "", want) == re.sub(r"\s+", "", got):
		return "wrap"
	if not w or not g or w[0] != g[0]:
		return "sig"
	wd = [l for l in w if not is_decl(l)]
	gd = [l for l in g if not is_decl(l)]
	if wd == gd:
		return "decl"
	return "body"


def main():
	p = argparse.ArgumentParser()
	p.add_argument("--work", required=True)
	p.add_argument("--show")
	a = p.parse_args()
	gf = json.load(open(os.path.join(a.work, "goldens.json"), encoding="utf-8"))["functions"]
	res = {}
	for line in open(os.path.join(a.work, "results.jsonl"), encoding="utf-8"):
		r = json.loads(line)
		res[r["index"]] = r
	kinds = collections.defaultdict(list)
	for i, g in enumerate(gf):
		r = res.get(i, {})
		kinds[classify(g["c"], r.get("output") or "", r.get("error"))].append(i)
	for k in ("match", "wrap", "decl", "sig", "body", "error"):
		print("%-6s %4d" % (k, len(kinds[k])))
	if a.show:
		print(a.show, kinds[a.show])


if __name__ == "__main__":
	main()
