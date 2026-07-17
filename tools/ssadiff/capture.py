"""capture.py -- generate a decomp_dbg.exe savefile XML for one golden function.

Builds an xml_savefile (the format tools/decomp_dbg.exe `restore` loads) from a
single GenGoldens-schema golden JSON entry (testdata/x64_corpus/x64_goldens.json
and friends): function name + raw instruction bytes. This is a *generic*
unlocked-prototype template -- unlike tools/captures/debug_op_switch.xml (which
injects a locked prototype + merge="false" symbols for a specific op_switch
investigation), this template provides no parameter/local symbols at all, so
decomp_dbg recovers them the same way Gosleigh's own pipeline does: from
scratch, under a pinned calling-convention model only.

The function bytes are mapped at "ram" offset 0x0, matching the base address
Gosleigh's loader.EngineBuilder uses for these per-function golden byte slices
(see cmd/ssadump). Mapping both sides at the same base means real instruction
addresses in the two "print raw" dumps are directly comparable (see
tools/ssadiff/ssadiff.py), not just structurally similar.

Usage (library, called from ssadiff.py):
    xml_text = build_savefile(name="sum_to_n", bytes_hex="894c2408...")

Usage (standalone, for inspecting/regenerating a capture by hand):
    py -3 tools/ssadiff/capture.py --golden testdata/x64_corpus/x64_goldens.json \
        --func sum_to_n --out /tmp/sum_to_n.xml
"""

import argparse
import json
import os
import sys

# CORETYPES_XML is the fixed base-type table every decomp_dbg savefile needs.
# Copied verbatim from tools/captures/debug_op_switch.xml: it is
# byte-content-independent (just the standard Ghidra core type IDs), so every
# generated capture reuses the same block.
CORETYPES_XML = """<coretypes>
  <type name="uint3" size="3" metatype="uint" id="0xc0000000000000c0"/>
  <type name="uint5" size="5" metatype="uint" id="0xc0000000000000c1"/>
  <type name="code" size="1" metatype="code" id="0xe000000000000001"/>
  <type name="uint6" size="6" metatype="uint" id="0xc0000000000000c2"/>
  <type name="double" size="8" metatype="float" id="0xc000000000000082"/>
  <type name="uint7" size="7" metatype="uint" id="0xc0000000000000c3"/>
  <type name="uint" size="4" metatype="uint" id="0xc0000000000000c4"/>
  <type name="float10" size="10" metatype="float" id="0xc000000000000084"/>
  <type name="float16" size="16" metatype="float" id="0xc000000000000085"/>
  <type name="float2" size="2" metatype="float" id="0xc000000000000086"/>
  <type name="ulonglong" size="8" metatype="uint" id="0xc0000000000000c7"/>
  <type name="ushort" size="2" metatype="uint" id="0xc0000000000000c8"/>
  <type name="void" size="0" metatype="void" id="0xc0000000000000c9"/>
  <type name="float" size="4" metatype="float" id="0xc00000000000008a"/>
  <type name="wchar32" size="4" metatype="int" utf="true" id="0xc0000000000000cc"/>
  <type name="wchar_t" size="2" metatype="int" utf="true" id="0xc0000000000000cd"/>
  <type name="int16" size="16" metatype="int" id="0xc000000000000090"/>
  <type name="int3" size="3" metatype="int" id="0xc000000000000091"/>
  <type name="int5" size="5" metatype="int" id="0xc000000000000092"/>
  <type name="int6" size="6" metatype="int" id="0xc000000000000093"/>
  <type name="int7" size="7" metatype="int" id="0xc000000000000094"/>
  <type name="int" size="4" metatype="int" id="0xc000000000000095"/>
  <type name="longlong" size="8" metatype="int" id="0xc00000000000009a"/>
  <type name="short" size="2" metatype="int" id="0xc0000000000000a8"/>
  <type name="sbyte" size="1" metatype="int" id="0xc0000000000000a9"/>
  <type name="undefined1" size="1" metatype="unknown" id="0xc0000000000000b4"/>
  <type name="undefined2" size="2" metatype="unknown" id="0xc0000000000000b5"/>
  <type name="undefined3" size="3" metatype="unknown" id="0xc0000000000000b6"/>
  <type name="undefined4" size="4" metatype="unknown" id="0xc0000000000000b7"/>
  <type name="undefined5" size="5" metatype="unknown" id="0xc0000000000000b8"/>
  <type name="undefined6" size="6" metatype="unknown" id="0xc0000000000000b9"/>
  <type name="bool" size="1" metatype="bool" id="0xc000000000000079"/>
  <type name="undefined7" size="7" metatype="unknown" id="0xc0000000000000ba"/>
  <type name="byte" size="1" metatype="uint" id="0xc00000000000007a"/>
  <type name="undefined8" size="8" metatype="unknown" id="0xc0000000000000bb"/>
  <type name="char" size="1" metatype="int" char="true" id="0xc00000000000007b"/>
  <type name="uint16" size="16" metatype="uint" id="0xc0000000000000bf"/>
</coretypes>"""

# CONTEXT_POINTS_XML pins the x86-64 long-mode decode context at the mapped
# base address. Copied verbatim from tools/captures/debug_op_switch.xml
# (generic x64 context bits, not specific to that capture's bytes).
CONTEXT_POINTS_XML_TEMPLATE = """<context_points>

<context_pointset space="ram" offset="{base_hex}">
  <set name="longMode" val="1"/>
  <set name="reserved" val="0"/>
  <set name="addrsize" val="2"/>
  <set name="bit64" val="1"/>
  <set name="opsize" val="1"/>
  <set name="segover" val="0"/>
  <set name="highseg" val="0"/>
  <set name="protectedMode" val="0"/>
  <set name="mandover" val="0"/>
  <set name="repneprefx" val="0"/>
  <set name="xacquireprefx" val="0"/>
  <set name="prefix_f2" val="0"/>
  <set name="repprefx" val="0"/>
  <set name="xreleaseprefx" val="0"/>
  <set name="prefix_f3" val="0"/>
  <set name="prefix_66" val="0"/>
  <set name="rexWRXBprefix" val="0"/>
  <set name="rexWprefix" val="0"/>
  <set name="rexRprefix" val="0"/>
  <set name="rexXprefix" val="0"/>
  <set name="rexBprefix" val="0"/>
  <set name="rexprefix" val="0"/>
  <set name="vexMode" val="0"/>
  <set name="evexL" val="0"/>
  <set name="evexLp" val="0"/>
  <set name="suffix3D" val="0"/>
  <set name="vexL" val="0"/>
  <set name="evexV5" val="0"/>
  <set name="evexVp" val="0"/>
  <set name="vexVVVV" val="0"/>
  <set name="vexHighV" val="0"/>
  <set name="instrPhase" val="0"/>
  <set name="lockprefx" val="0"/>
  <set name="vexMMMMM" val="0"/>
  <set name="evexRp" val="0"/>
  <set name="evexB" val="0"/>
  <set name="evexZ" val="0"/>
  <set name="evexAAA" val="0"/>
  <set name="evexD8Type" val="0"/>
  <set name="evexTType" val="0"/>
  <set name="evexDisp8" val="0"/>
  <set name="evexBType" val="0"/>
  <set name="reservedHigh" val="0"/>
</context_pointset>
<tracked_pointset space="ram" offset="{base_hex}">
  <set space="register" offset="0x118" size="8" val="0xff00000000"/>
  <set space="register" offset="0x20a" size="1" val="0x0"/>
</tracked_pointset>
<tracked_pointset space="ram" offset="{base_hex}">
  <set space="register" offset="0x118" size="8" val="0xff00000000"/>
  <set space="register" offset="0x20a" size="1" val="0x0"/>
</tracked_pointset></context_points>"""


def build_savefile(name, bytes_hex, base_offset=0):
    """Return the xml_savefile text for one function, unlocked prototype
    except for the x86-64 Windows fastcall calling-convention model (matching
    the cspec Gosleigh's own pipeline uses -- see cmd/ssadump defaults).
    """
    base_hex = "0x%x" % base_offset
    bytes_hex = bytes_hex.strip()

    return """<xml_savefile name="{name}" target="default" adjustvma="0">
<binaryimage arch="x86:LE:64:default:windows">
<bytechunk space="ram" offset="{base_hex}" readonly="true">
{bytes_hex}
</bytechunk>
</binaryimage>

{coretypes}<save_state>

<typegrp structalign="4"/><db scopeidbyname="false">
<scope name="" id="0x0">
<symbollist>

<mapsym>
  <function id="0x1" name="{name}" size="1">
    <addr space="ram" offset="{base_hex}"/>
    <localdb lock="false" main="stack">
      <scope name="{name}">
        <parent id="0x0"/>
        <rangelist/>
        <symbollist/>
      </scope>
    </localdb>
    <prototype extrapop="8" model="__fastcall" modellock="true">
      <returnsym>
        <addr space="register" offset="0x0" size="4"/>
        <type name="undefined4" id="0xc0000000000000b7" metatype="unknown" size="4"/>
      </returnsym>
    </prototype>
  </function>
  <addr space="ram" offset="{base_hex}" size="1"/>
  <rangelist/>
</mapsym></symbollist>
</scope>
</db>
{context_points}

<commentdb/>
<optionslist>
  <readonly>on</readonly>
  <setlanguage>c-language</setlanguage>
  <protoeval>default</protoeval>
</optionslist></save_state>
</xml_savefile>
""".format(
        name=name,
        base_hex=base_hex,
        bytes_hex=bytes_hex,
        coretypes=CORETYPES_XML,
        context_points=CONTEXT_POINTS_XML_TEMPLATE.format(base_hex=base_hex),
    )


def load_golden_entry(golden_path, func_name):
    """Read a GenGoldens-schema golden JSON file and return the entry dict
    (name/entry/bytes/c) whose "name" matches func_name, or None."""
    with open(golden_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for entry in data.get("functions", []):
        if entry.get("name") == func_name:
            return entry
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--golden", required=True, help="path to a GenGoldens-schema golden JSON file")
    ap.add_argument("--func", required=True, help="function name to extract")
    ap.add_argument("--out", required=True, help="output savefile XML path")
    ap.add_argument("--base", default="0x0", help="ram offset to map the function bytes at (default 0x0)")
    args = ap.parse_args(argv)

    entry = load_golden_entry(args.golden, args.func)
    if entry is None:
        print("capture.py: function %r not found in %s" % (args.func, args.golden), file=sys.stderr)
        return 1

    base_offset = int(args.base, 0)
    xml_text = build_savefile(entry["name"], entry["bytes"], base_offset)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(xml_text)
    print("capture.py: wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
