# SPDX-License-Identifier: Apache-2.0
"""Export a binary's functions, calls, strings and xrefs as JSON for
`bhf binary adapter --adapter angr`, which maps them into its report.

Usage: angr_export.py <binary> <out.json> <most entries of each list>

CFGFast recovers the functions and the call graph of the main object only
(no shared libraries are loaded), with its data and cross references. The
addresses are angr's; the export records the base angr mapped the object at
and the base it was linked at, which bhf uses to move them back.
"""

import json
import logging
import sys


def section_of(obj, address):
    section = obj.find_section_containing(address)
    return section.name if section is not None else None


def export(binary, limit):
    import angr

    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    project = angr.Project(binary, auto_load_libs=False, load_debug_info=False)
    cfg = project.analyses.CFGFast(
        normalize=True, data_references=True, cross_references=True
    )
    main = project.loader.main_object
    callgraph = project.kb.functions.callgraph

    functions = []
    for function in project.kb.functions.values():
        if len(functions) >= limit:
            break
        # Imports resolve to stubs in the extern object; the PLT entry in the
        # binary is the import.
        if not main.contains_addr(function.addr):
            continue
        callees = set()
        if not function.is_plt and function.addr in callgraph:
            for callee in callgraph.successors(function.addr):
                name = (
                    project.kb.functions[callee].name
                    if callee in project.kb.functions
                    else None
                )
                # angr's stand-ins for a call or jump it could not resolve.
                if name and not name.startswith("Unresolvable"):
                    callees.add(name)
        functions.append(
            {
                "name": function.name,
                "entry": function.addr,
                "size": function.size,
                "plt": function.is_plt,
                "calls": sorted(callees),
            }
        )

    strings = []
    for item in cfg.memory_data.values():
        if len(strings) >= limit:
            break
        if item.sort not in ("string", "unicode") or not item.content:
            continue
        if not main.contains_addr(item.address):
            continue
        encoding = "utf-16-le" if item.sort == "unicode" else "latin-1"
        strings.append(
            {
                "address": item.address,
                "value": item.content.decode(encoding, errors="replace"),
                "section": section_of(main, item.address),
            }
        )

    xrefs = []
    for references in project.kb.xrefs.xrefs_by_ins_addr.values():
        for reference in references:
            if len(xrefs) >= limit:
                break
            if reference.ins_addr is None or reference.dst is None:
                continue
            xrefs.append(
                {
                    "from": reference.ins_addr,
                    "to": reference.dst,
                    "type": reference.type_string,
                }
            )
    # Direct calls, which the xref store does not hold: one per call site.
    for function in project.kb.functions.values():
        if not main.contains_addr(function.addr):
            continue
        for site in function.get_call_sites():
            if len(xrefs) >= limit:
                break
            target = function.get_call_target(site)
            if target is None or not main.contains_addr(target):
                continue
            block = project.factory.block(site)
            xrefs.append(
                {
                    "from": block.instruction_addrs[-1]
                    if block.instruction_addrs
                    else site,
                    "to": target,
                    "type": "call",
                }
            )

    return {
        "mapped_base": main.mapped_base,
        "linked_base": main.linked_base,
        "functions": functions,
        "strings": strings,
        "xrefs": xrefs,
    }


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: angr_export.py <binary> <out.json> <most entries>")
    binary, out, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
    result = export(binary, limit)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(result, handle)


if __name__ == "__main__":
    main()
