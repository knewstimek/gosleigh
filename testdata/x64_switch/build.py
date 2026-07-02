"""Compile AND link switch.c into a fully-linked PE32+ .exe with MSVC.

Run: py -3 testdata/x64_switch/build.py

Unlike testdata/x64_breadth/build.py (which stops at /c and emits a .obj fed to
the tree as raw base-0 bytes), this produces a real executable: the link step
resolves the image base and materializes the switch jump table in .rdata with
image-relative entries. That is the input on which Ghidra recovers a true
switch, so it is also the input the loader/recovery path must eventually handle.

Freestanding link: /ENTRY:entry + /NODEFAULTLIB so no CRT / Windows SDK library
is required (switch.c has no imports). Only the MSVC bin dir is needed on PATH
for link.exe; no vcvars environment is set up.

Prints the .exe size, then a dumpbin summary of sections + the switch jump
table's home section (.rdata) and its base relocations.
"""
import subprocess
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MSVC = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.38.33130\bin\Hostx64\x64"
CL = os.path.join(MSVC, "cl.exe")
LINK = os.path.join(MSVC, "link.exe")
DUMPBIN = os.path.join(MSVC, "dumpbin.exe")
SRC = os.path.join(HERE, "switch.c")
OBJ = os.path.join(HERE, "switch.obj")
EXE = os.path.join(HERE, "switch.exe")


def run(cmd, **kw):
    print(">", " ".join(cmd))
    # link.exe/dumpbin.exe resolve sibling DLLs from their own dir; ensure the
    # MSVC bin dir is on PATH so the freestanding link needs no vcvars.
    env = dict(os.environ)
    env["PATH"] = MSVC + os.pathsep + env.get("PATH", "")
    return subprocess.run(cmd, capture_output=True, text=True, env=env, **kw)


def main():
    # --- compile (no link) ---
    r = run([CL, "/nologo", "/Od", "/GS-", "/c", SRC, "/Fo" + OBJ], cwd=HERE)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print("COMPILE FAILED")
        sys.exit(1)

    # --- link into a freestanding PE32+ .exe (no CRT, no imports) ---
    r = run([
        LINK, "/nologo",
        "/ENTRY:entry",
        "/SUBSYSTEM:CONSOLE",
        "/NODEFAULTLIB",
        "/FIXED:NO",          # keep the base relocation table (jump-table RVAs)
        "/OUT:" + EXE,
        OBJ,
    ], cwd=HERE)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print("LINK FAILED")
        sys.exit(1)
    print("OK exe:", EXE, os.path.getsize(EXE), "bytes")

    # --- inspect: headers, sections, and the jump-table relocations ---
    r2 = run([DUMPBIN, "/headers", "/relocations", EXE])
    out = r2.stdout
    keep = ("machine", "magic", "image base", "section", ".text",
            ".rdata", "size of raw data", "virtual address", "base relocations",
            "summary")
    for line in out.splitlines():
        low = line.lower()
        if any(k in low for k in keep):
            print(line.rstrip())

    # --- disassemble op_switch region hint: show the jump-table symbol/section ---
    r3 = run([DUMPBIN, "/disasm:nobytes", EXE])
    dis = r3.stdout
    # Print the op_switch prologue + the indirect jmp that consumes the table.
    show = False
    printed = 0
    for line in dis.splitlines():
        low = line.lower()
        if "op_switch" in low:
            show = True
        if show:
            print(line.rstrip())
            printed += 1
            if "jmp" in low and ("qword" in low or "rax" in low or "rdx" in low
                                 or "rcx" in low or "r8" in low):
                # continue a few lines past the indirect jump then stop
                pass
            if printed > 40:
                break


if __name__ == "__main__":
    main()
