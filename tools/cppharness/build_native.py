"""Build the Ghidra decompiler process (decompile.exe) from ghidra-ref.

usage: py -3 tools/cppharness/build_native.py

Compiles ghidra-ref as is (Makefile target ghidra_opt: CORE + DECCORE + GHIDRA)
into local/ghidra_head/decompile.exe. Dropped into a copy of the Ghidra install
(Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe), the Java side then
decompiles with the same C++ core the Go port and the harness follow, so
goldens and ghidra-ref cannot drift apart.
Needs MSVC 2022 (vcvarsall). ONLY=tu1,tu2 recompiles just those units.
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import build  # noqa: E402  (shared MSVC helpers and source lists)

SRC = os.path.join(ROOT, "ghidra-ref", "Ghidra", "Features", "Decompiler", "src", "decompile", "cpp")
BUILD = os.path.join(ROOT, "local", "ghidra_head")
OBJ = os.path.join(BUILD, "obj")
EXE = os.path.join(BUILD, "decompile.exe")

GHIDRA = ("ghidra_arch inject_ghidra ghidra_translate loadimage_ghidra typegrp_ghidra "
	"database_ghidra ghidra_context cpool_ghidra ghidra_process comment_ghidra "
	"string_ghidra signature_ghidra").split()
NAMES = build.CORE + build.DECCORE + GHIDRA


def main():
	build.BUILD, build.OBJ = BUILD, OBJ
	env = build.vc_env()
	cl = build.find_cl(env)
	os.makedirs(OBJ, exist_ok=True)
	srcs = [os.path.join(SRC, n + ".cc") for n in NAMES]
	only = os.environ.get("ONLY")
	if only:
		keep = set(only.split(","))
		srcs = [s for s in srcs if os.path.splitext(os.path.basename(s))[0] in keep]
	flags = ["/nologo", "/c", "/MP", "/EHsc", "/std:c++14", "/O2", "/D_WINDOWS", "/DNOMINMAX",
		"/Zc:__cplusplus", "/wd4267", "/wd4244", "/wd4018", "/wd4996", "/MT", "/Fo" + OBJ + os.sep]
	rsp = os.path.join(BUILD, "compile.rsp")
	with open(rsp, "w") as f:
		f.write(" ".join(flags) + "\n" + "".join('"%s"\n' % s for s in srcs))
	print("compile", len(srcs))
	build.run(cl, ["@" + rsp], env)
	lrsp = os.path.join(BUILD, "link.rsp")
	with open(lrsp, "w") as f:
		f.write('/nologo /MT /Fe"%s"\n' % EXE)
		f.write("".join('"%s"\n' % os.path.join(OBJ, n + ".obj") for n in NAMES))
	build.run(cl, ["@" + lrsp], env)
	print("BUILD OK ->", EXE)


if __name__ == "__main__":
	main()
