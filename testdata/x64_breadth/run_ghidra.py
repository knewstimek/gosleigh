"""Run Ghidra 12 headless to analyze breadth.obj -> x64_breadth_goldens.json.

Run: py -3 testdata/x64_breadth/run_ghidra.py
Reuses GenGoldens.java from ../x64_corpus (generic dumper). Requires
C:\\ghidra12 (analyzeHeadless) + JDK 21.
"""
import subprocess
import os
import sys
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(HERE), "x64_corpus")  # GenGoldens.java lives here
HEADLESS = r"C:\ghidra12\support\analyzeHeadless.bat"
OBJ = os.path.join(HERE, "breadth.obj")
OUT = os.path.join(HERE, "x64_breadth_goldens.json")


def main():
    if not os.path.exists(OBJ):
        print("missing breadth.obj -- run build.py first")
        sys.exit(1)
    proj = tempfile.mkdtemp(prefix="ghidra_x64b_")
    try:
        cmd = [
            HEADLESS, proj, "x64breadth",
            "-import", OBJ,
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
                                      "import", "fail")):
                print(line.rstrip())
        if r.returncode != 0:
            print("HEADLESS returncode", r.returncode)
        print("exists out:", os.path.exists(OUT))
    finally:
        shutil.rmtree(proj, ignore_errors=True)


if __name__ == "__main__":
    main()
