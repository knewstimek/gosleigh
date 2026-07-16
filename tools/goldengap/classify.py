"""Gap auto-classifier: buckets a Gosleigh-vs-Ghidra-golden C diff into token-kind
classes so a human does not have to eyeball every mismatch by hand.

This is a heuristic layer, not a parser: it works on regex/token-multiset
comparisons over the two decompiled C strings. Multiple tags may apply to one
function (the design explicitly allows this -- see GOAL T1). When nothing
matches, the honest answer is UNKNOWN; the heuristics are deliberately not
tuned post-hoc to force a match against any particular corpus (that would
defeat the point of an independent classifier).

Categories (see goal doc "gap 자동분류" section for the human-language spec):
  MATCH    - byte-identical after indent-insensitive normalization
  WRAP     - token stream identical, only line-wrap/newline differs
  STRUCT   - dangling goto / do-while / loop-exit structuring gap
  TYPECAST - cast token or undefined4/CONCAT/SUBPIECE count differs
  PTR      - raw pointer-arithmetic scale (*8/*4/...) present where golden has none
  TEMP     - extra/missing temp-like identifiers (uVarN/local_N/tmp_N/...)
  CALL     - lost call target/args/return (fake call, or golden call missing)
  FP       - float/double/XMM loss, including a collapsed empty body
  NAMING   - identical token structure, only identifier names differ
  UNKNOWN  - none of the above fired
  ENGINE-ERR - the Gosleigh CLI itself failed for this function (not a class
               from the goal spec; a practical escape hatch for hard failures)
"""

import re
from collections import Counter

# ---------------------------------------------------------------------------
# Normalization (mirrors pkg/loader's normGhidraC: CRLF->LF, strip per-line
# leading indentation, trim as a whole -- indentation parity is a separate,
# already-known gap and must not pollute the class diff).
# ---------------------------------------------------------------------------


def norm(s):
	s = s.replace("\r\n", "\n")
	lines = s.split("\n")
	lines = [ln.lstrip(" \t") for ln in lines]
	return "\n".join(lines).strip()


_TOKEN_RE = re.compile(
	r"[A-Za-z_]\w*"
	r"|0[xX][0-9a-fA-F]+"
	r"|\d+\.\d+[fF]?"
	r"|\d+[uUlL]*"
	r"|->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|::"
	r"|[^\sA-Za-z0-9_]"
)


def tokenize(s):
	return _TOKEN_RE.findall(s)


_CAST_TYPE_RE = re.compile(
	r"\(\s*(?:unsigned\s+)?"
	r"(undefined1|undefined2|undefined4|undefined8|undefined|byte|char|short|"
	r"int|long|longlong|ulonglong|uint|ulong|ushort|uchar|float|double|void|code)"
	r"\s*\**\s*\)"
)
_CONCAT_RE = re.compile(r"CONCAT\d\d|SUBPIECE\d+_\d+")
_TEMPVAR_RE = re.compile(
	r"\b(?:[a-zA-Z]{1,4}Var[0-9]+|local_[0-9a-fA-F]+|tmp_[0-9]+|"
	r"extraout_\w+|in_stack_\w+|aStack_[0-9a-fA-F]+|auStack_[0-9a-fA-F]+)\b"
)
_KEYWORDS_RE_PART = (
	"if|else|for|while|do|return|break|continue|goto|switch|case|default|"
	"sizeof|struct|union|typedef|void|int|long|short|char|float|double|"
	"unsigned|signed|const|static|extern|volatile|register|inline"
)
_CALL_SKIP = {
	"if", "for", "while", "do", "switch", "return", "sizeof",
}

# Ghidra/Gosleigh primitive type-name vocabulary excluded from NAMING
# alpha-renaming (these are structural, not "this run's variable names").
_TYPE_WORDS = {
	"undefined", "undefined1", "undefined2", "undefined4", "undefined8",
	"byte", "char", "short", "int", "long", "longlong", "ulonglong",
	"uint", "ulong", "ushort", "uchar", "float", "double", "void", "code",
	"unsigned", "signed", "const", "static", "extern", "volatile",
	"if", "else", "for", "while", "do", "return", "break", "continue",
	"goto", "switch", "case", "default", "sizeof", "struct", "union",
	"typedef", "true", "false", "bool", "register", "inline",
}


def _re_words(words):
	return re.compile(r"\b(?:%s)\b" % "|".join(words))


# ---------------------------------------------------------------------------
# Per-class heuristics. Each returns a (possibly empty) list of human-readable
# evidence strings; a non-empty list means the tag fires.
# ---------------------------------------------------------------------------


def check_struct(want_n, got_n):
	evidence = []
	goto_targets = set(re.findall(r"\bgoto\s+(\w+)\s*;", got_n))
	labels = set(re.findall(r"(?m)^(\w+):", got_n))
	dangling = sorted(goto_targets - labels)
	if dangling:
		evidence.append("dangling goto target(s) in output: " + ", ".join(dangling))
	for kw in ("do", "while", "for", "break", "continue"):
		wc = len(re.findall(r"\b%s\b" % kw, want_n))
		gc = len(re.findall(r"\b%s\b" % kw, got_n))
		if wc != gc:
			evidence.append("keyword '%s': want=%d got=%d" % (kw, wc, gc))
	return evidence


def check_typecast(want_n, got_n):
	evidence = []
	wc = Counter(_CAST_TYPE_RE.findall(want_n))
	gc = Counter(_CAST_TYPE_RE.findall(got_n))
	for k in sorted(set(wc) | set(gc)):
		w, g = wc.get(k, 0), gc.get(k, 0)
		if w != g:
			evidence.append("cast (%s): want=%d got=%d" % (k, w, g))
	wconcat = len(_CONCAT_RE.findall(want_n))
	gconcat = len(_CONCAT_RE.findall(got_n))
	if wconcat != gconcat:
		evidence.append("CONCAT/SUBPIECE: want=%d got=%d" % (wconcat, gconcat))
	return evidence


def check_ptr(want_n, got_n):
	evidence = []
	for scale in ("2", "4", "8", "16"):
		wc = len(re.findall(r"\*\s*%s\b" % scale, want_n))
		gc = len(re.findall(r"\*\s*%s\b" % scale, got_n))
		if gc > wc:
			evidence.append("raw pointer scale '* %s': want=%d got=%d" % (scale, wc, gc))
	return evidence


def check_temp(want_n, got_n):
	evidence = []
	wset = set(_TEMPVAR_RE.findall(want_n))
	gset = set(_TEMPVAR_RE.findall(got_n))
	if len(gset) > len(wset):
		extra = sorted(gset - wset)
		evidence.append(
			"extra temp/local identifiers in output (%d vs %d): %s"
			% (len(gset), len(wset), ", ".join(extra[:8]))
		)
	elif len(wset) > len(gset):
		missing = sorted(wset - gset)
		evidence.append(
			"fewer temp/local identifiers than golden (%d vs %d), missing: %s"
			% (len(gset), len(wset), ", ".join(missing[:8]))
		)
	return evidence


def check_call(want_n, got_n):
	evidence = []
	fake_calls = sorted(set(re.findall(r"\b(local_[0-9a-fA-F]+|tmp_[0-9]+)\s*\(", got_n)))
	if fake_calls:
		evidence.append("suspicious call target(s) in output: " + ", ".join(fake_calls))
	want_calls = Counter(
		m for m in re.findall(r"\b([A-Za-z_]\w*)\s*\(", want_n) if m not in _CALL_SKIP
	)
	got_calls = Counter(
		m for m in re.findall(r"\b([A-Za-z_]\w*)\s*\(", got_n) if m not in _CALL_SKIP
	)
	missing = sorted(set(want_calls) - set(got_calls))
	if missing:
		evidence.append("call(s) present in golden but missing in output: " + ", ".join(missing))
	return evidence


_FLOAT_KW_RE = re.compile(r"\b(?:float|double)\b")
_FLOAT_LIT_RE = re.compile(r"\b\d+\.\d+[fF]?\b")


def check_fp(want_n, got_n):
	evidence = []
	w_has = bool(_FLOAT_KW_RE.search(want_n)) or bool(_FLOAT_LIT_RE.search(want_n))
	g_has = bool(_FLOAT_KW_RE.search(got_n)) or bool(_FLOAT_LIT_RE.search(got_n))
	if w_has and not g_has:
		evidence.append("golden uses float/double, output has none (FP subsystem gap)")
		want_toks = tokenize(want_n)
		got_toks = tokenize(got_n)
		if len(got_toks) < max(6, len(want_toks) // 3):
			evidence.append(
				"output drastically smaller than golden (%d vs %d tokens) -- stub/empty body"
				% (len(got_toks), len(want_toks))
			)
	return evidence


def _canonicalize(tokens):
	mapping = {}
	out = []
	ident_re = re.compile(r"^[A-Za-z_]\w*$")
	for t in tokens:
		if ident_re.match(t) and t not in _TYPE_WORDS:
			if t not in mapping:
				mapping[t] = "ID%d" % (len(mapping) + 1)
			out.append(mapping[t])
		else:
			out.append(t)
	return out


def check_naming(want_n, got_n):
	wt = tokenize(want_n)
	gt = tokenize(got_n)
	if len(wt) != len(gt):
		return []
	if _canonicalize(wt) == _canonicalize(gt):
		return ["identical token structure; only identifier names differ"]
	return []


_CHECKS = [
	("STRUCT", check_struct),
	("TYPECAST", check_typecast),
	("PTR", check_ptr),
	("TEMP", check_temp),
	("CALL", check_call),
	("FP", check_fp),
]


def classify(want_c, got_c):
	"""Classify a Gosleigh output (got_c) against a Ghidra golden (want_c).

	Returns {"tags": [...], "evidence": {tag: [str, ...]}}. MATCH and WRAP are
	mutually exclusive with every other tag (there is nothing left to
	classify once the text is equal at that granularity); the rest may
	co-occur.
	"""
	want_n = norm(want_c)
	got_n = norm(got_c)
	if want_n == got_n:
		return {"tags": ["MATCH"], "evidence": {"MATCH": ["byte-identical (indent-insensitive)"]}}

	want_ws = re.sub(r"\s+", " ", want_n).strip()
	got_ws = re.sub(r"\s+", " ", got_n).strip()
	if want_ws == got_ws:
		return {
			"tags": ["WRAP"],
			"evidence": {"WRAP": ["token stream identical; only line-wrap/newline differs"]},
		}

	tags = []
	evidence = {}
	for name, fn in _CHECKS:
		ev = fn(want_n, got_n)
		if ev:
			tags.append(name)
			evidence[name] = ev

	if not tags:
		ev = check_naming(want_n, got_n)
		if ev:
			tags.append("NAMING")
			evidence["NAMING"] = ev

	if not tags:
		tags.append("UNKNOWN")
		evidence["UNKNOWN"] = ["no heuristic matched -- manual review needed"]

	return {"tags": tags, "evidence": evidence}


def classify_entry(want_c, got_c, engine_error=None):
	"""classify() wrapper that special-cases a hard engine failure."""
	if engine_error:
		return {"tags": ["ENGINE-ERR"], "evidence": {"ENGINE-ERR": [engine_error]}}
	return classify(want_c, got_c)
