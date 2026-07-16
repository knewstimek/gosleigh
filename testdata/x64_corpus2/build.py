"""Compile corpus.c to a Windows x64 COFF object with MSVC cl /c /Od.

Run: py -3 testdata/x64_corpus/build.py
Produces corpus.obj next to corpus.c. Prints function symbols + reloc check.
"""
import subprocess
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MSVC = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.38.33130\bin\Hostx64\x64"
CL = os.path.join(MSVC, "cl.exe")
DUMPBIN = os.path.join(MSVC, "dumpbin.exe")
SRC = os.path.join(HERE, "corpus.c")
OBJ = os.path.join(HERE, "corpus.obj")


def run(cmd, **kw):
    print(">", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main():
    # /Od no optimization, /c compile only, /GS- no stack cookies (keeps bytes
    # clean and self-contained), /Gd __cdecl default (x64 ignores, uses MS ABI).
    r = run([CL, "/nologo", "/Od", "/GS-", "/c", SRC, "/Fo" + OBJ], cwd=HERE)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print("COMPILE FAILED")
        sys.exit(1)
    print("OK obj:", OBJ, os.path.getsize(OBJ), "bytes")
    # Confirm machine type + relocations.
    r2 = run([DUMPBIN, "/headers", "/relocations", OBJ])
    out = r2.stdout
    # Print just the function-relevant reloc summary lines.
    for line in out.splitlines():
        if "machine" in line.lower() or "RELOCATIONS" in line or ".text" in line:
            print(line.rstrip())


if __name__ == "__main__":
    main()
