"""Run Ghidra 12 headless to analyze switch.exe -> x64_switch_goldens.json.

Run: py -3 testdata/x64_switch/run_ghidra.py

Imports the fully-linked PE32+ executable (not a raw .obj), so Ghidra resolves
the image base and recovers the .text jump table into a genuine `switch`
statement. Reuses GenGoldens.java from ../x64_corpus (generic dumper). Requires
C:\\ghidra12 (analyzeHeadless) + JDK 21.

The .exe is stripped (freestanding /NODEFAULTLIB link, no COFF symbols), so
Ghidra names the switch function FUN_140001000; the golden is keyed by that
auto-name. Structural switch recovery does not depend on the name.
"""
import subprocess
import os
import sys
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(HERE), "x64_corpus")  # GenGoldens.java lives here
HEADLESS = r"C:\ghidra12\support\analyzeHeadless.bat"
EXE = os.path.join(HERE, "switch.exe")
OUT = os.path.join(HERE, "x64_switch_goldens.json")


def main():
    if not os.path.exists(EXE):
        print("missing switch.exe -- run build.py first")
        sys.exit(1)
    proj = tempfile.mkdtemp(prefix="ghidra_x64sw_")
    try:
        cmd = [
            HEADLESS, proj, "x64switch",
            "-import", EXE,
            "-scriptPath", CORPUS,
            "-postScript", "GenGoldens.java", OUT,
            "-deleteProject",
        ]
        print(">", " ".join(cmd))
        r = subprocess.run(cmd, capture_output=True, text=True)
        for line in (r.stdout + r.stderr).splitlines():
            low = line.lower()
            if any(k in low for k in ("dumped", "wrote", "error", "exception",
                                      "compiler", "language", "processor",
                                      "import", "fail", "switch")):
                print(line.rstrip())
        if r.returncode != 0:
            print("HEADLESS returncode", r.returncode)
        print("exists out:", os.path.exists(OUT))
    finally:
        shutil.rmtree(proj, ignore_errors=True)


if __name__ == "__main__":
    main()
