// Trusted Ghidra headless instrumentation. Package bytes never select scripts.
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.DefaultErrorLogger;
import ghidra.util.ErrorLogger;
import ghidra.util.Msg;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class PackweirPre extends HeadlessScript {
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2) throw new IllegalArgumentException("diagnostic/profile paths required");
        List<String> errors = Collections.synchronizedList(new ArrayList<String>());
        List<String> warnings = Collections.synchronizedList(new ArrayList<String>());
        storeHeadlessValue("packweir.errors", errors);
        storeHeadlessValue("packweir.warnings", warnings);
        storeHeadlessValue("packweir.instrumented", Boolean.TRUE);
        Capture capture = new Capture(arguments[0], errors, warnings);
        Msg.setErrorLogger(capture);
        JsonObject profile = JsonParser.parseString(Files.readString(Path.of(arguments[1]))).getAsJsonObject();
        JsonObject options = profile.getAsJsonObject("analysis_options");
        if (options == null || !options.keySet().equals(Set.of("PDB Universal")) ||
                !options.get("PDB Universal").isJsonPrimitive() || !options.get("PDB Universal").getAsJsonPrimitive().isBoolean() ||
                options.get("PDB Universal").getAsBoolean()) {
            throw new IllegalArgumentException("qualified profile must explicitly leave external PDB analysis unrequested");
        }
        currentProgram.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES).setBoolean("PDB Universal", false);
        // Ghidra clears this log immediately AFTER notifying analysis-ended
        // listeners. Reading it only in a post-script silently loses failures.
        AutoAnalysisManager.getAnalysisManager(currentProgram).addListener((manager, cancelled) -> {
            if (manager.getMessageLog().hasMessages())
                capture.internal("MessageLog", manager.getMessageLog().toString());
            String status = manager.getMessageLog().getStatus();
            if (status != null && !status.isBlank()) capture.internal("status", status);
            if (cancelled) capture.internal("cancellation", "automatic analysis was cancelled");
        });
        storeHeadlessValue("packweir.analysis_listener", Boolean.TRUE);
    }

    private static class Capture extends DefaultErrorLogger implements ErrorLogger {
        private final String path;
        private final List<String> errors;
        private final List<String> warnings;
        private final Gson gson = new Gson();
        Capture(String path, List<String> errors, List<String> warnings) {
            this.path = path; this.errors = errors; this.warnings = warnings;
        }
        void internal(String origin, String message) {
            // MessageLog has no severity type; unknown internal messages cannot
            // establish complete coverage. Never pass them to a warning waiver.
            if (message.length() > 3900) message = message.substring(0, 3900) + " [internal diagnostic truncated]";
            error("AutoAnalysisManager." + origin, "Ghidra internal analysis " + origin + ": " + message);
        }
        private synchronized void capture(String level, Object source, Object message, Throwable thrown) {
            String value = String.valueOf(message);
            if (thrown != null) value += " | " + thrown.getClass().getName() + ": " + thrown.getMessage();
            if (value.length() > 4000) value = value.substring(0, 4000) + " [diagnostic truncated]";
            List<String> target = level.equals("error") ? errors : warnings;
            if (target.size() < 63) target.add(value);
            else if (target.size() == 63) target.add("diagnostic limit exceeded");
            try (Writer writer = new OutputStreamWriter(new FileOutputStream(path, true), StandardCharsets.UTF_8)) {
                Map<String,String> event = new TreeMap<String,String>();
                event.put("level", level); event.put("source", String.valueOf(source)); event.put("message", value);
                writer.write(gson.toJson(event)); writer.write("\n");
            } catch (IOException failure) {
                if (errors.size() < 64) errors.add("structured diagnostic persistence failed");
            }
        }
        @Override public void error(Object source, Object message) { capture("error",source,message,null); super.error(source,message); }
        @Override public void error(Object source, Object message, Throwable thrown) { capture("error",source,message,thrown); super.error(source,message,thrown); }
        @Override public void warn(Object source, Object message) { capture("warning",source,message,null); super.warn(source,message); }
        @Override public void warn(Object source, Object message, Throwable thrown) { capture("warning",source,message,thrown); super.warn(source,message,thrown); }
    }
}
