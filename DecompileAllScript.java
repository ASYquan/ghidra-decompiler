// Ghidra Decompilation Script
// @category Decompiler
// @description Decompiles all functions in a binary to a single output file

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAllScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get output file from script arguments
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length == 0) {
            println("Error: No output file specified");
            return;
        }

        String outputPath = scriptArgs[0];
        File outputFile = new File(outputPath);

        println("Starting decompilation process...");
        println("Output file: " + outputPath);

        // Initialize decompiler
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);

        if (!decompiler.openProgram(currentProgram)) {
            println("Decompiler failed to open program");
            return;
        }

        // Open output file
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));

        // Write header
        writer.println("/*");
        writer.println(" * Ghidra Decompilation Output");
        writer.println(" * Binary: " + currentProgram.getName());
        writer.println(" * Executable Format: " + currentProgram.getExecutableFormat());
        writer.println(" * Architecture: " + currentProgram.getLanguage().getProcessor());
        writer.println(" */");
        writer.println();

        // Get all functions
        FunctionManager functionManager = currentProgram.getFunctionManager();
        int totalFunctions = functionManager.getFunctionCount();
        int decompiled = 0;
        int failed = 0;

        println("Total functions to decompile: " + totalFunctions);

        // Iterate through all functions
        for (Function function : functionManager.getFunctions(true)) {
            monitor.checkCanceled();

            String functionName = function.getName();
            println("Decompiling: " + functionName + " @ " + function.getEntryPoint());

            try {
                // Decompile function
                DecompileResults results = decompiler.decompileFunction(function, 30, monitor);

                if (results != null && results.decompileCompleted()) {
                    DecompiledFunction decompiledFunc = results.getDecompiledFunction();
                    String decompiledCode = decompiledFunc.getC();

                    // Write to output file
                    writer.println("// Function: " + functionName);
                    writer.println("// Address: " + function.getEntryPoint());
                    writer.println("// Size: " + function.getBody().getNumAddresses() + " bytes");
                    writer.println();
                    writer.println(decompiledCode);
                    writer.println();
                    writer.println("// " + "-".repeat(70));
                    writer.println();

                    decompiled++;
                } else {
                    writer.println("// Failed to decompile: " + functionName);
                    writer.println("// Address: " + function.getEntryPoint());
                    if (results != null) {
                        writer.println("// Error: " + results.getErrorMessage());
                    }
                    writer.println();
                    failed++;
                }

            } catch (Exception e) {
                println("Error decompiling " + functionName + ": " + e.getMessage());
                writer.println("// Exception decompiling: " + functionName);
                writer.println("// Error: " + e.getMessage());
                writer.println();
                failed++;
            }
        }

        // Write summary
        writer.println("/*");
        writer.println(" * Decompilation Summary");
        writer.println(" * Total functions: " + totalFunctions);
        writer.println(" * Successfully decompiled: " + decompiled);
        writer.println(" * Failed: " + failed);
        writer.println(" */");

        writer.close();
        decompiler.dispose();

        println("Decompilation complete!");
        println("Successfully decompiled: " + decompiled + "/" + totalFunctions);
        println("Output written to: " + outputPath);
    }
}
