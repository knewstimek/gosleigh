"""Compile breadth.c to a Windows x64 COFF object with MSVC cl /c /Od.

Run: py -3 testdata/x64_breadth/build.py
Produces breadth.obj next to breadth.c. Prints function symbols + reloc check.
Mirror of testdata/x64_corpus/build.py for the breadth (struct/2d/switch) set.
"""
import subprocess
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MSVC = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.38.33130\bin\Hostx64\x64"
CL = os.path.join(MSVC, "cl.exe")
DUMPBIN = os.path.join(MSVC, "dumpbin.exe")
SRC = os.path.join(HERE, "breadth.c")
OBJ = os.path.join(HERE, "breadth.obj")


def run(cmd, **kw):
    print(">", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    r = run([CL, "/nologo", "/Od", "/GS-", "/c", SRC, "/Fo" + OBJ], cwd=HERE)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print("COMPILE FAILED")
        sys.exit(1)
    print("OK obj:", OBJ, os.path.getsize(OBJ), "bytes")
    # Confirm machine type + relocations (jump tables introduce .rdata relocs).
    r2 = run([DUMPBIN, "/headers", "/relocations", OBJ])
    out = r2.stdout
    for line in out.splitlines():
        low = line.lower()
        if ("machine" in low or "relocations" in line or ".text" in line
                or ".rdata" in line or "rel32" in low or "addr32" in low
                or "dir32" in low or "symbol name" in low):
            print(line.rstrip())


if __name__ == "__main__":
    main()
