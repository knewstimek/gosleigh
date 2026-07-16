import os, sys, subprocess

SRC = r"D:\News\Business\Gosleigh\ghidra-ref\Ghidra\Features\Decompiler\src\decompile\cpp"
BUILD = r"C:\Users\News\AppData\Local\Temp\claude\D--News-Business-Gosleigh\092ef17d-f2a4-4a3c-abe9-363bef582af1\scratchpad\decomp_build"
OBJ = os.path.join(BUILD, "obj")
VCVARSALL = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
ZLIB_INC = r"C:\vcpkg\installed\x86-windows-static\include"
ZLIB_LIB = r"C:\vcpkg\installed\x86-windows-static\lib\zlib.lib"
EXE = os.path.join(BUILD, "decomp_dbg.exe")

CORE = "xml marshal space float address pcoderaw translate opcodes globalcontext".split()
DECCORE = ("capability architecture options graph cover block cast typeop database cpool "
    "comment stringmanage modelrules fspec action loadimage grammar varnode op type "
    "variable varmap jumptable emulate emulateutil flow userop expression multiprecision "
    "funcdata funcdata_block funcdata_op funcdata_varnode unionresolve pcodeinject "
    "heritage prefersplit rangeutil ruleaction subflow blockaction merge double "
    "transform constseq bitfield coreaction condexe override dynamic crc32 prettyprint "
    "printlanguage printc printjava memstate opbehavior paramid signature").split()
# EXTRA minus bfd_arch, loadimage_bfd, analyzesigs, codedata
# (all four require binutils BFD / bfd.h, unavailable on MSVC; the two command
#  modules analyzesigs+codedata are optional and pull in loadimage_bfd.hh)
EXTRA = ("callgraph ifacedecomp ifaceterm inject_sleigh interface "
    "libdecomp loadimage_xml raw_arch rulecompile sleigh_arch testfunction unify xml_arch").split()
SLEIGH = ("sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern "
    "semantics context slaformat compression filemanage").split()
SPECIAL = ["consolemain"]

NAMES = CORE + DECCORE + EXTRA + SLEIGH + SPECIAL
# de-dup preserving order
seen = set(); ordered = []
for n in NAMES:
    if n in seen:
        print("DUP:", n)
        continue
    seen.add(n); ordered.append(n)

srcs = []
missing = []
for n in ordered:
    p = os.path.join(SRC, n + ".cc")
    if not os.path.exists(p):
        missing.append(n)
    srcs.append(p)
if missing:
    print("MISSING SOURCES:", missing)
    sys.exit(2)
print("TU count:", len(srcs))

os.makedirs(OBJ, exist_ok=True)

def get_env():
    # dump vcvarsall x86 environment via a wrapper .bat (avoids nested-quote mangling)
    bat = os.path.join(BUILD, "_dumpenv.bat")
    with open(bat, "w") as f:
        f.write("@echo off\r\n")
        f.write('call "%s" x86 >nul\r\n' % VCVARSALL)
        f.write("set\r\n")
    out = subprocess.run(["cmd", "/c", bat], capture_output=True, text=True)
    env = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    if "INCLUDE" not in env:
        print("vcvars failed:\n", out.stdout[-2000:], out.stderr[-2000:])
        sys.exit(3)
    return env

env = get_env()

def find_exe(name, env):
    for d in env.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    print("cannot find", name, "in vcvars PATH"); sys.exit(5)

CL = find_exe("cl.exe", env)
print("cl.exe:", CL)

CFLAGS = ["/nologo", "/c", "/MP", "/EHsc", "/std:c++14", "/O2",
          "/D_WINDOWS", "/DNOMINMAX", "/DCPUI_DEBUG",
          "/Zc:__cplusplus", "/wd4267", "/wd4244", "/wd4018", "/wd4996",
          "/MT", "/I" + ZLIB_INC, "/Fo" + OBJ + os.sep]

# compile via response file
rsp = os.path.join(BUILD, "compile.rsp")
with open(rsp, "w") as f:
    f.write(" ".join('"%s"' % s if " " in s else s for s in CFLAGS))
    f.write("\n")
    for s in srcs:
        f.write('"%s"\n' % s)

print("=== COMPILE ===")
r = subprocess.run([CL, "@" + rsp], cwd=OBJ, env=env, capture_output=True, text=True)
print(r.stdout[-8000:])
if r.stderr.strip():
    print("--- STDERR ---")
    print(r.stderr[-8000:])
if r.returncode != 0:
    print("COMPILE FAILED rc=%d" % r.returncode)
    sys.exit(r.returncode)

objs = [os.path.join(OBJ, n + ".obj") for n in ordered]
missobj = [o for o in objs if not os.path.exists(o)]
if missobj:
    print("MISSING OBJS:", missobj)
    sys.exit(4)

print("=== LINK ===")
lrsp = os.path.join(BUILD, "link.rsp")
with open(lrsp, "w") as f:
    f.write("/nologo /MT /Fe" + '"%s"\n' % EXE)
    for o in objs:
        f.write('"%s"\n' % o)
    f.write('"%s"\n' % ZLIB_LIB)
r = subprocess.run([CL, "@" + lrsp], cwd=OBJ, env=env, capture_output=True, text=True)
print(r.stdout[-8000:])
if r.stderr.strip():
    print("--- STDERR ---")
    print(r.stderr[-8000:])
if r.returncode != 0:
    print("LINK FAILED rc=%d" % r.returncode)
    sys.exit(r.returncode)
print("BUILD OK ->", EXE, os.path.exists(EXE))
