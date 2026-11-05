// Export the current program to Ghidra's XML format.
//
// Usage:
//   -postScript ExportGhidraXml.java <output.xml>

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.XmlExporter;
import java.io.File;
import java.io.IOException;

public class ExportGhidraXml extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException(
                "usage: ExportGhidraXml.java <output.xml>");
        }

        File output = new File(args[0]).getAbsoluteFile();
        XmlExporter exporter = new XmlExporter();

        if (!exporter.export(output, currentProgram, null, monitor)) {
            throw new IOException("XML export failed for " + currentProgram.getName());
        }

        println("Wrote Ghidra XML export to " + output);
    }
}
