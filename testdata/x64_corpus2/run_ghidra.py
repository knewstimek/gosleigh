"""Run Ghidra headless to analyze corpus.obj and dump goldens to x64_goldens.json.

Run: py -3 testdata/x64_corpus/run_ghidra.py
Requires C:\\ghidra12 (analyzeHeadless) + JDK 21 (Ghidra finds it).
"""
import subprocess
import os
import sys
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HEADLESS = r"C:\ghidra12\support\analyzeHeadless.bat"
OBJ = os.path.join(HERE, "corpus.obj")
OUT = os.path.join(HERE, "x64_goldens.json")


def main():
    if not os.path.exists(OBJ):
        print("missing corpus.obj -- run build.py first")
        sys.exit(1)
    proj = tempfile.mkdtemp(prefix="ghidra_x64_")
    try:
        cmd = [
            HEADLESS, proj, "x64corpus",
            "-import", OBJ,
            "-scriptPath", HERE,
            "-postScript", "GenGoldens.java", OUT,
            "-deleteProject",
        ]
        print(">", " ".join(cmd))
        r = subprocess.run(cmd, capture_output=True, text=True)
        # Surface the analyzer + script output (filter the noisy classpath lines).
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
