// Qualification-only fault injection: a real Ghidra analyzer throws; no target executes.
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PackweirThrow extends HeadlessScript {
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        String fault = arguments.length == 0 ? "throw" : arguments[0];
        if (!fault.equals("throw") && !fault.equals("logged_failure")) throw new IllegalArgumentException("unknown qualification analyzer fault");
        Analyzer throwing = new AbstractAnalyzer("PackweirThrowingAnalyzer", "real qualification failure", AnalyzerType.BYTE_ANALYZER) {
            { setPriority(AnalysisPriority.LOW_PRIORITY); setDefaultEnablement(true); setSupportsOneTimeAnalysis(); }
            public boolean canAnalyze(Program program) { return true; }
            public boolean added(Program program, AddressSetView addresses, TaskMonitor monitor, MessageLog log) throws CancelledException {
                if (fault.equals("logged_failure")) {
                    log.appendMsg("PackweirQualificationAnalyzer", "PACKWEIR_QUALIFICATION_REAL_ANALYZER_LOGGED_FAILURE");
                    return false;
                }
                throw new RuntimeException("PACKWEIR_QUALIFICATION_REAL_ANALYZER_THROW");
            }
        };
        AutoAnalysisManager.getAnalysisManager(currentProgram).scheduleOneTimeAnalysis(throwing, currentProgram.getMemory());
    }
}
