"""Build an instrumented C++ decomp_dbg harness from a patched copy of ghidra-ref.

usage: py -3 tools/cppharness/build.py [--fresh]

Sources: local/cppharness/src (copied from ghidra-ref and patched by
patch_src.py on --fresh or when missing). Output: local/cppharness/decomp_dbg.exe.
Defines: CPUI_DEBUG, OPACTION_DEBUG (`trace address` + `trace enable` print each
rule application), TYPEPROP_DEBUG (`trace propagation on`).
Set ONLY=tu1,tu2 to recompile just those translation units before linking.
Needs MSVC 2022 (vcvarsall x86) and vcpkg zlib x86-windows-static.
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(ROOT, "local", "cppharness", "src")
BUILD = os.path.join(ROOT, "local", "cppharness")
OBJ = os.path.join(BUILD, "obj")
EXE = os.path.join(BUILD, "decomp_dbg.exe")
VCVARSALL = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
ZLIB_INC = r"C:\vcpkg\installed\x86-windows-static\include"
ZLIB_LIB = r"C:\vcpkg\installed\x86-windows-static\lib\zlib.lib"

CORE = "xml marshal space float address pcoderaw translate opcodes globalcontext".split()
DECCORE = ("capability architecture options graph cover block cast typeop database cpool "
	"comment stringmanage modelrules fspec action loadimage grammar varnode op type "
	"variable varmap jumptable emulate emulateutil flow userop expression multiprecision "
	"funcdata funcdata_block funcdata_op funcdata_varnode unionresolve pcodeinject "
	"heritage prefersplit rangeutil ruleaction subflow blockaction merge double "
	"transform constseq bitfield coreaction condexe override dynamic crc32 prettyprint "
	"printlanguage printc printjava memstate opbehavior paramid signature").split()
# bfd_arch, loadimage_bfd, analyzesigs and codedata need binutils BFD (not on MSVC)
EXTRA = ("callgraph ifacedecomp ifaceterm inject_sleigh interface "
	"libdecomp loadimage_xml raw_arch rulecompile sleigh_arch testfunction unify xml_arch").split()
SLEIGH = ("sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern "
	"semantics context slaformat compression filemanage").split()
NAMES = CORE + DECCORE + EXTRA + SLEIGH + ["consolemain"]


def vc_env():
	os.makedirs(BUILD, exist_ok=True)
	bat = os.path.join(BUILD, "_dumpenv.bat")
	with open(bat, "w") as f:
		f.write('@echo off\r\ncall "%s" x86 >nul\r\nset\r\n' % VCVARSALL)
	out = subprocess.run(["cmd", "/c", bat], capture_output=True, text=True)
	env = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
	if "INCLUDE" not in env:
		sys.exit("vcvarsall failed")
	return env


def find_cl(env):
	for d in env.get("PATH", "").split(os.pathsep):
		p = os.path.join(d, "cl.exe")
		if os.path.exists(p):
			return p
	sys.exit("cl.exe not found")


def run(cl, args, env):
	r = subprocess.run([cl] + args, cwd=OBJ, env=env, capture_output=True, text=True)
	sys.stdout.write(r.stdout[-6000:])
	sys.stdout.write(r.stderr[-6000:])
	if r.returncode != 0:
		sys.exit("failed rc=%d" % r.returncode)


def main():
	if "--fresh" in sys.argv or not os.path.isdir(SRC):
		subprocess.run([sys.executable, os.path.join(HERE, "patch_src.py")], check=True)
	env = vc_env()
	cl = find_cl(env)
	os.makedirs(OBJ, exist_ok=True)
	srcs = [os.path.join(SRC, n + ".cc") for n in NAMES]
	only = os.environ.get("ONLY")
	if only:
		keep = set(only.split(","))
		srcs = [s for s in srcs if os.path.splitext(os.path.basename(s))[0] in keep]
	flags = ["/nologo", "/c", "/MP", "/EHsc", "/std:c++14", "/O2", "/D_WINDOWS", "/DNOMINMAX",
		"/DCPUI_DEBUG", "/DOPACTION_DEBUG", "/DTYPEPROP_DEBUG", "/Zc:__cplusplus",
		"/wd4267", "/wd4244", "/wd4018", "/wd4996", "/MT", "/I" + ZLIB_INC, "/Fo" + OBJ + os.sep]
	rsp = os.path.join(BUILD, "compile.rsp")
	with open(rsp, "w") as f:
		f.write(" ".join(flags) + "\n" + "".join('"%s"\n' % s for s in srcs))
	print("compile", len(srcs))
	run(cl, ["@" + rsp], env)
	lrsp = os.path.join(BUILD, "link.rsp")
	with open(lrsp, "w") as f:
		f.write('/nologo /MT /Fe"%s"\n' % EXE)
		f.write("".join('"%s"\n' % os.path.join(OBJ, n + ".obj") for n in NAMES))
		f.write('"%s"\n' % ZLIB_LIB)
	run(cl, ["@" + lrsp], env)
	print("BUILD OK ->", EXE)


if __name__ == "__main__":
	main()
