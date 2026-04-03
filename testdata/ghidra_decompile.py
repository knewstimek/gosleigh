# Ghidra headless helper for test_6502.bin.
# Usage from the repository root:
#
#	analyzeHeadless <project_dir> golden6502 \
#		-import testdata/test_6502.bin \
#		-loader BinaryLoader \
#		-processor 6502:LE:16:default \
#		-loader-baseAddr 0x0000 \
#		-scriptPath testdata \
#		-postScript ghidra_decompile.py testdata/golden_6502.c 0x0000
#
# If analyzeHeadless is unavailable, keep this script for a manual rerun later.

from ghidra.app.decompiler import DecompInterface
from java.io import FileWriter


def require_program():
	program = currentProgram
	if program is None:
		raise RuntimeError("currentProgram is not available")
	return program


def require_function(program, entry_addr):
	listing = program.getListing()
	function = listing.getFunctionAt(entry_addr)
	if function is None:
		createFunction(entry_addr, "entry")
		function = listing.getFunctionAt(entry_addr)
	if function is None:
		raise RuntimeError("no function defined at %s" % entry_addr)
	return function


def decompile_function(program, function):
	interface = DecompInterface()
	interface.openProgram(program)
	result = interface.decompileFunction(function, 60, monitor)
	if not result.decompileCompleted():
		raise RuntimeError("decompilation did not complete")
	decompiled = result.getDecompiledFunction()
	if decompiled is None:
		raise RuntimeError("no decompiled function returned")
	return decompiled.getC()


def write_output(path, text):
	writer = FileWriter(path)
	try:
		writer.write(text)
	finally:
		writer.close()


def main():
	args = getScriptArgs()
	if len(args) < 1:
		raise RuntimeError("expected output path argument")
	output_path = args[0]
	entry_offset = 0
	if len(args) > 1:
		entry_offset = int(args[1], 0)

	program = require_program()
	entry_addr = toAddr(entry_offset)
	function = require_function(program, entry_addr)
	c_text = decompile_function(program, function)
	write_output(output_path, c_text)
	print("wrote decompiled C to %s" % output_path)


if __name__ == "__main__":
	main()
