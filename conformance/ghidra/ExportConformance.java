// Trusted informed-entry diagnostic. Never shipped in the agent bundle.
// @category SRE.Conformance
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOpAST;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public class ExportConformance extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2)
            throw new IllegalArgumentException("output.json target-relative-address");
        long offset = Long.parseUnsignedLong(args[1], 16);
        Address entry = currentProgram.getImageBase().add(offset);
        Function function = getFunctionAt(entry);
        if (function == null) {
            disassemble(entry);
            function = createFunction(entry, "conformance_target");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema", "sre-ghidra-v1");
        result.put("analysis_mode", "informed-entry");
        result.put("ghidra_version", ghidra.framework.Application.getApplicationVersion());
        result.put("entry", entry.toString());
        DecompInterface decompiler = new DecompInterface();
        try {
            if (function == null || !decompiler.openProgram(currentProgram))
                throw new IllegalStateException("cannot identify/open target");
            DecompileResults decompiled =
                decompiler.decompileFunction(function, 90, monitor);
            if (!decompiled.decompileCompleted() ||
                decompiled.getDecompiledFunction() == null) {
                result.put("status", "decompiler_error");
                result.put("error", decompiled.getErrorMessage());
            } else {
                result.put("status", "ok");
                result.put("c", decompiled.getDecompiledFunction().getC());
                ArrayList<String> pcode = new ArrayList<>();
                java.util.Iterator<PcodeOpAST> operations =
                    decompiled.getHighFunction().getPcodeOps();
                while (operations.hasNext())
                    pcode.add(operations.next().toString());
                result.put("high_pcode", pcode);
                result.put("blocks", decompiled.getHighFunction().getBasicBlocks().size());
            }
        } finally {
            decompiler.dispose();
        }
        Files.writeString(Path.of(args[0]),
            new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
