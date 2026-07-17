"""run_cpp.py -- drive tools/decomp_dbg.exe against a savefile and capture
`print raw` output.

Pipes a small console script (restore/load function/decompile/print raw/quit)
into tools/decomp_dbg.exe's stdin and returns its stdout. This is the C++ core
ground-truth side of tools/ssadiff/ssadiff.py.

decomp_dbg.exe is gitignored and only exists in the main repository checkout
(see tools/BUILD_NOTES.md), not in a worktree -- pass its absolute path via
--decomp-dbg when running from a worktree.

Usage (library, called from ssadiff.py):
    text = run_print_raw(decomp_dbg_path, savefile_path, func_name, sleighhome)

Usage (standalone):
    py -3 tools/ssadiff/run_cpp.py --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe \
        --savefile /tmp/sum_to_n.xml --func sum_to_n
"""

import argparse
import os
import subprocess
import sys
import tempfile

# Marker lines bracketing the "print raw" command's own output in the
# decomp_dbg console transcript, so callers can slice out just that section
# without also capturing the "restore"/"decompile"/"quit" echo lines.
_PRINT_RAW_CMD = "print raw"
_QUIT_CMD = "quit"


def build_script(savefile_path, func_name):
    """Return the decomp_dbg console script text: restore, select the
    function, decompile, dump raw p-code, quit."""
    return "restore {savefile}\nload function {func}\ndecompile\n{print_raw}\n{quit}\n".format(
        savefile=savefile_path, func=func_name, print_raw=_PRINT_RAW_CMD, quit=_QUIT_CMD
    )


def run_print_raw(decomp_dbg_path, savefile_path, func_name, sleighhome, timeout=60):
    """Run decomp_dbg.exe -i <script> and return (full_stdout, raw_section).

    raw_section is the slice of stdout between the "print raw" command echo
    and the next command prompt -- i.e. just the SSA dump text, with the
    leading "0\\n" (BlockGraph's own top-level printHeader index line) and
    trailing blank stripped.
    """
    if not os.path.isfile(decomp_dbg_path):
        raise FileNotFoundError("decomp_dbg.exe not found: %s" % decomp_dbg_path)
    if not sleighhome:
        raise RuntimeError(
            "SLEIGHHOME is required (Ghidra install root -- see tools/BUILD_NOTES.md). "
            "Set the SLEIGHHOME environment variable or pass --sleighhome."
        )

    script_text = build_script(savefile_path, func_name)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="ascii") as f:
        f.write(script_text)
        script_path = f.name

    env = dict(os.environ)
    env["SLEIGHHOME"] = sleighhome

    try:
        proc = subprocess.run(
            [decomp_dbg_path, "-i", script_path],
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    finally:
        try:
            os.remove(script_path)
        except OSError:
            pass

    stdout = proc.stdout or ""
    if proc.returncode != 0:
        raise RuntimeError(
            "decomp_dbg.exe exited %d\n--- stdout ---\n%s\n--- stderr ---\n%s"
            % (proc.returncode, stdout, proc.stderr or "")
        )

    raw_section = _extract_print_raw_section(stdout)
    return stdout, raw_section


def _extract_print_raw_section(stdout):
    """Slice out the text printed in response to the "print raw" command.

    decomp_dbg echoes each command after its "init> " prompt, so the output
    looks like:
        init> print raw
        <raw dump...>
        init> quit
    We find the line that IS the "print raw" echo and take everything up to
    the next "init> " prompt (the "quit" echo).
    """
    lines = stdout.splitlines()
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == _PRINT_RAW_CMD or stripped.endswith("> " + _PRINT_RAW_CMD):
            start = i + 1
            break
    if start is None:
        return ""
    end = len(lines)
    for i in range(start, len(lines)):
        if lines[i].startswith("init>") or lines[i].strip().startswith("init>"):
            end = i
            break
    section_lines = lines[start:end]
    # The first line is BlockGraph's own top-level printHeader (just the
    # graph's own index, e.g. "0") -- not part of any basic block. Drop it if
    # present so raw_section starts at the first "Basic Block" header, same
    # shape as pkg/pcode.DumpSSA's output.
    if section_lines and section_lines[0].strip().isdigit():
        section_lines = section_lines[1:]
    return "\n".join(section_lines).strip("\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--decomp-dbg", required=True, help="path to tools/decomp_dbg.exe (main repo, absolute)")
    ap.add_argument("--savefile", required=True, help="path to a savefile XML (see capture.py)")
    ap.add_argument("--func", required=True, help="function name (matches the savefile's <function name=...>)")
    ap.add_argument("--sleighhome", default=os.environ.get("SLEIGHHOME", ""), help="Ghidra install root")
    args = ap.parse_args(argv)

    try:
        full_stdout, raw_section = run_print_raw(args.decomp_dbg, args.savefile, args.func, args.sleighhome)
    except Exception as exc:  # noqa: BLE001 -- CLI top-level error reporting
        print("run_cpp.py: %s" % exc, file=sys.stderr)
        return 1

    print(raw_section)
    return 0


if __name__ == "__main__":
    sys.exit(main())
