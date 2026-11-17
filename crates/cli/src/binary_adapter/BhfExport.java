// SPDX-License-Identifier: Apache-2.0
// Exports a program's functions (with the functions each calls), defined
// strings and the references between its loaded blocks as JSON, for `bhf
// binary adapter --adapter ghidra`, which maps them into its report.
// Arguments: the JSON file to write, and the most entries of each list.
//@category bhf

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class BhfExport extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: BhfExport.java <out.json> <max entries>");
        }
        int max = Integer.parseInt(args[1]);
        Program program = currentProgram;
        Options info = program.getOptions(Program.PROGRAM_INFO);
        String linkedBase = info.contains("ELF Original Image Base")
                ? info.getString("ELF Original Image Base", null)
                : null;
        try (Writer out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.write("{\"image_base\":" + quote(hex(program.getImageBase())));
            out.write(",\"linked_base\":" + (linkedBase == null ? "null" : quote(linkedBase)));

            out.write(",\"functions\":[");
            int count = 0;
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && count < max) {
                monitor.checkCancelled();
                Function function = functions.next();
                StringBuilder calls = new StringBuilder();
                for (Function callee : function.getCalledFunctions(monitor)) {
                    calls.append(calls.length() == 0 ? "" : ",").append(quote(callee.getName()));
                }
                out.write((count == 0 ? "" : ",") + "{\"name\":" + quote(function.getName())
                        + ",\"entry\":" + quote(hex(function.getEntryPoint()))
                        + ",\"size\":" + function.getBody().getNumAddresses()
                        + ",\"signature\":" + quote(function.getPrototypeString(false, false))
                        + ",\"thunk\":" + function.isThunk()
                        + ",\"external\":" + !loaded(program, function.getEntryPoint())
                        + ",\"calls\":[" + calls + "]}");
                count++;
            }

            out.write("],\"strings\":[");
            count = 0;
            DataIterator data = program.getListing().getDefinedData(true);
            while (data.hasNext() && count < max) {
                monitor.checkCancelled();
                Data item = data.next();
                if (!item.hasStringValue() || item.getValue() == null) {
                    continue;
                }
                MemoryBlock block = program.getMemory().getBlock(item.getAddress());
                out.write((count == 0 ? "" : ",") + "{\"address\":" + quote(hex(item.getAddress()))
                        + ",\"value\":" + quote(item.getValue().toString())
                        + ",\"block\":" + (block == null ? "null" : quote(block.getName()))
                        + ",\"loaded\":" + loaded(program, item.getAddress()) + "}");
                count++;
            }

            out.write("],\"references\":[");
            count = 0;
            ReferenceIterator references =
                    program.getReferenceManager().getReferenceIterator(program.getMinAddress());
            while (references.hasNext() && count < max) {
                monitor.checkCancelled();
                Reference reference = references.next();
                if (!loaded(program, reference.getFromAddress())
                        || !loaded(program, reference.getToAddress())) {
                    continue;
                }
                out.write((count == 0 ? "" : ",") + "{\"from\":" + quote(hex(reference.getFromAddress()))
                        + ",\"to\":" + quote(hex(reference.getToAddress()))
                        + ",\"type\":" + quote(reference.getReferenceType().getName()) + "}");
                count++;
            }
            out.write("]}\n");
        }
    }

    /**
     * Whether an address is in one of the binary's loaded blocks: not in a
     * non-loaded section (.comment, .symtab) and not in the artificial
     * EXTERNAL block, where Ghidra puts an import's own function beside its
     * PLT thunk.
     */
    private static boolean loaded(Program program, Address address) {
        MemoryBlock block = address.isMemoryAddress() ? program.getMemory().getBlock(address) : null;
        return block != null && block.isLoaded()
                && !MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName());
    }

    private static String hex(Address address) {
        return "0x" + Long.toHexString(address.getOffset());
    }

    private static String quote(String text) {
        if (text == null) {
            return "null";
        }
        StringBuilder quoted = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': quoted.append("\\\""); break;
                case '\\': quoted.append("\\\\"); break;
                case '\n': quoted.append("\\n"); break;
                case '\r': quoted.append("\\r"); break;
                case '\t': quoted.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        quoted.append(String.format("\\u%04x", (int) c));
                    } else {
                        quoted.append(c);
                    }
            }
        }
        return quoted.append('"').toString();
    }
}
