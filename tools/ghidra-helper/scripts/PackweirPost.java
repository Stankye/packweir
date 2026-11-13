// Real Ghidra API exports. Never emulates or executes the input program.
import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class PackweirPost extends HeadlessScript {
    private JsonObject profile;
    private final JsonArray observations = new JsonArray();
    private final JsonArray outputs = new JsonArray();
    private final List<String> errors = new ArrayList<String>();
    private final List<String> warnings = new ArrayList<String>();
    private byte[] original;
    private String subject;
    private boolean truncated = false;
    private int outputBytes = 0;
    private final List<long[]> xorSpans = new ArrayList<long[]>();
    private int decoded = 0;

    private static String hash(byte[] bytes) throws Exception {
        byte[] value = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder text = new StringBuilder(); for (byte item : value) text.append(String.format("%02x", item & 255));
        return text.toString();
    }
    private int limit(String name) { return profile.get(name).getAsInt(); }
    private void error(String value) { if(errors.size()<64) errors.add(value.length()>4096 ? value.substring(0,4096) : value); }
    private void observe(String kind, String name, String value) {
        if (observations.size() >= limit("max_observations")) { truncated=true; return; }
        if (name.length()>128) { name=name.substring(0,128); truncated=true; }
        if (value.length()>8192) { value=value.substring(0,8192); truncated=true; }
        JsonObject item=new JsonObject(); item.addProperty("kind",kind); item.addProperty("name",name);
        item.addProperty("value",value.isEmpty()?"(empty)":value); observations.add(item);
    }
    private boolean output(String kind, String media, String operation, String version, byte[] bytes, JsonObject parameters, long offset, long length) throws Exception {
        if (bytes.length==0) { error("empty actual "+kind+" export"); return false; }
        if (outputBytes + bytes.length > limit("max_output_bytes") || outputs.size()>=256) { truncated=true; return false; }
        String outputHash=hash(bytes);
        // Equal content can have different operations, function entries, or
        // original-file spans. Keep every bounded descriptor; CAS deduplicates
        // bytes separately from these distinct provenance records.
        if (offset<0 || length<=0 || offset+length>original.length) throw new IllegalArgumentException("invalid original byte span");
        byte[] source=Arrays.copyOfRange(original,(int)offset,(int)(offset+length));
        JsonObject span=new JsonObject(); span.addProperty("offset",offset); span.addProperty("length",length); span.addProperty("sha256",hash(source));
        JsonArray spans=new JsonArray(); spans.add(span);
        JsonObject derivation=new JsonObject(); derivation.addProperty("operation",operation); derivation.addProperty("version",version);
        derivation.addProperty("input_sha256",subject); derivation.add("parameters",parameters); derivation.add("source_spans",spans);
        JsonObject item=new JsonObject(); item.addProperty("kind",kind); item.addProperty("media_type",media); item.addProperty("sha256",outputHash);
        item.addProperty("size",bytes.length); item.addProperty("data_base64",Base64.getEncoder().encodeToString(bytes)); item.add("derivation",derivation);
        outputBytes+=bytes.length; outputs.add(item); return true;
    }
    private boolean decodeRegion(long offset, long length, String keyHex, String selector) throws Exception {
        observe("xor_candidate",selector,"original file offset="+offset+" length="+length+" key_hex="+keyHex);
        if(!keyHex.matches("(?:[0-9a-f]{2}){1,32}")) { error("XOR region key must be 1..32 bytes of lowercase hexadecimal"); return false; }
        if(offset<0 || length<=0 || length>limit("max_xor_bytes") || offset>original.length || length>original.length-offset) {
            error("XOR region exceeds the qualified original-file bounds"); return false;
        }
        for(long[] span:xorSpans) if(offset<span[0]+span[1] && span[0]<offset+length) {
            error("XOR selectors have overlapping original-file regions"); return false;
        }
        if(decoded>=8) { error("XOR region count exceeds eight"); return false; }
        xorSpans.add(new long[]{offset,length}); decoded++;
        byte[] encoded=Arrays.copyOfRange(original,(int)offset,(int)(offset+length));
        byte[] key=HexFormat.of().parseHex(keyHex); byte[] plain=new byte[encoded.length];
        for(int index=0;index<plain.length;index++) plain[index]=(byte)(encoded[index]^key[index%key.length]);
        JsonObject parameters=new JsonObject(); parameters.addProperty("key_hex",keyHex);
        return output("decoded_bytes","application/octet-stream","xor.decode","1",plain,parameters,offset,length);
    }
    @SuppressWarnings("unchecked")
    public void run() throws Exception {
        String[] arguments=getScriptArgs();
        if(arguments.length!=3) throw new IllegalArgumentException("input/report/profile paths required");
        original=Files.readAllBytes(Path.of(arguments[0])); subject=hash(original);
        profile=JsonParser.parseString(Files.readString(Path.of(arguments[2]))).getAsJsonObject();
        if(original.length>limit("max_file_bytes")) throw new IllegalArgumentException("input exceeds qualified bound");
        boolean instrumented=Boolean.TRUE.equals(getStoredHeadlessValue("packweir.instrumented"));
        if(!instrumented) error("trusted pre-analysis instrumentation was not installed");
        if(!Boolean.TRUE.equals(getStoredHeadlessValue("packweir.analysis_listener"))) error("trusted before-clear analysis listener was not installed");
        String engine=Application.getApplicationVersion();
        if(!engine.equals("12.2")) error("unexpected actual Ghidra engine version: "+engine);
        String runtime=System.getProperty("java.runtime.version","");
        if(!runtime.startsWith("25.0.5+8")) error("unexpected actual JDK runtime: "+runtime);
        String language=currentProgram.getLanguageID().getIdAsString();
        String compiler=currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        observe("language","language_id",language); observe("compiler","compiler_spec_id",compiler);
        observe("note","java.runtime.version",runtime); observe("note","ghidra.version",engine);
        observe("note","declared_analysis_options",profile.getAsJsonObject("analysis_options").toString());
        observe("header","format",currentProgram.getExecutableFormat());
        observe("header","image_base",currentProgram.getImageBase().toString());
        observe("header","pointer_bytes",Integer.toString(currentProgram.getDefaultPointerSize()));
        observe("header","memory_blocks",Integer.toString(currentProgram.getMemory().getBlocks().length));
        for(MemoryBlock block:currentProgram.getMemory().getBlocks()) {
            observe("section",block.getName(),"address="+block.getStart()+" size="+block.getSize()+" read="+block.isRead()+" write="+block.isWrite()+" execute="+block.isExecute());
        }
        SymbolIterator symbols=currentProgram.getSymbolTable().getAllSymbols(true); int symbolCount=0;
        while(symbols.hasNext()) {
            Symbol symbol=symbols.next(); if(symbolCount++>=256) { truncated=true; break; }
            observe("symbol",symbol.getName(),"address="+symbol.getAddress()+" type="+symbol.getSymbolType()+" external="+symbol.isExternal());
        }
        int strings=0;
        for(int index=0;index<original.length;) {
            int start=index; while(index<original.length && original[index]>=32 && original[index]<=126) index++;
            if(index-start>=4) {
                if(strings++>=limit("max_strings")) { truncated=true; break; }
                int end=Math.min(index,start+limit("max_string_bytes"));
                observe("string","file:0x"+Integer.toHexString(start),new String(original,start,end-start,StandardCharsets.US_ASCII));
                if(end<index) truncated=true;
            }
            index++;
        }
        List<Function> functions=new ArrayList<Function>(); FunctionIterator iterator=currentProgram.getFunctionManager().getFunctions(true);
        while(iterator.hasNext()) { Function function=iterator.next(); if(!function.isExternal() && !function.isThunk()) functions.add(function); }
        int total=functions.size(), completed=0, failed=0; boolean timedOut=analysisTimeoutOccurred();
        if(total>limit("max_functions")) truncated=true;
        DecompInterface decompiler=new DecompInterface();
        DecompileOptions options=new DecompileOptions(); decompiler.setOptions(options);
        decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(true); decompiler.setSimplificationStyle("decompile");
        boolean opened=decompiler.openProgram(currentProgram);
        if(!opened) error("native decompiler failed to open program: "+decompiler.getLastMessage());
        try {
            for(Function function:functions.subList(0,Math.min(total,limit("max_functions")))) {
                monitor.checkCancelled();
                observe("function",function.getName(),"entry="+function.getEntryPoint()+" body_bytes="+function.getBody().getNumAddresses());
                if(!opened) { failed++; continue; }
                DecompileResults result=decompiler.decompileFunction(function,limit("decompile_timeout_seconds"),monitor);
                String diagnostic=result.getErrorMessage();
                if(!result.decompileCompleted() || result.isTimedOut() || result.isCancelled() || diagnostic!=null && !diagnostic.isBlank()) {
                    failed++; timedOut|=result.isTimedOut(); error("decompiler "+function.getEntryPoint()+": "+diagnostic); continue;
                }
                HighFunction high=result.getHighFunction(); DecompiledFunction code=result.getDecompiledFunction();
                if(high==null || code==null) { failed++; error("native decompiler returned no actual C/pcode for "+function.getEntryPoint()); continue; }
                JsonObject parameters=new JsonObject(); parameters.addProperty("function_entry",function.getEntryPoint().toString());
                byte[] c=code.getC().getBytes(StandardCharsets.UTF_8);
                StringBuilder pcode=new StringBuilder(); Iterator<PcodeOpAST> operations=high.getPcodeOps();
                while(operations.hasNext()) { PcodeOpAST operation=operations.next(); pcode.append(operation.getSeqnum().getTarget()).append(" ").append(PcodeOp.getMnemonic(operation.getOpcode())).append(" ").append(operation).append("\n"); if(pcode.length()>limit("max_output_bytes")) { truncated=true; break; } }
                boolean cExport=output("decompiled_c","text/x-c","ghidra.decompile",engine,c,parameters,0,original.length);
                boolean pExport=output("pcode","text/plain","ghidra.pcode",engine,pcode.toString().getBytes(StandardCharsets.UTF_8),parameters,0,original.length);
                if(cExport && pExport) completed++; else failed++;
            }
        } finally { decompiler.dispose(); }
        String xorStatus="complete";
        JsonArray regions=profile.getAsJsonArray("xor_regions");
        if(regions==null || regions.size()>8) { error("trusted profile must specify at most eight explicit XOR regions"); xorStatus="error"; }
        else for(JsonElement element:regions) {
            try {
                JsonObject region=element.getAsJsonObject();
                if(!region.keySet().equals(Set.of("offset","length","key_hex"))) throw new IllegalArgumentException("XOR region requires exact offset/length/key_hex fields");
                long offset=region.get("offset").getAsBigDecimal().longValueExact(), length=region.get("length").getAsBigDecimal().longValueExact();
                if(!decodeRegion(offset,length,region.get("key_hex").getAsString(),"trusted_profile_region")) xorStatus="error";
            } catch(RuntimeException exception) { error("invalid trusted-profile XOR region: "+exception.getMessage()); xorStatus="error"; }
        }
        JsonObject frame=profile.has("qualification_xor_frame") && !profile.get("qualification_xor_frame").isJsonNull() ? profile.getAsJsonObject("qualification_xor_frame") : null;
        for(MemoryBlock block:currentProgram.getMemory().getBlocks()) {
            if(frame==null || !block.getName().equals(frame.get("section").getAsString())) continue;
            observe("xor_candidate","qualification_frame",block.getName()+"; file-backed fixture selector; address="+block.getStart());
            if(block.isExecute() || !block.isInitialized()) { error("XOR selector is not initialized non-executable data"); xorStatus="error"; continue; }
            boolean mappedSource=false;
            for(MemoryBlockSourceInfo source:block.getSourceInfos()) {
                if(!source.contains(block.getStart()) || source.getFileBytes().isEmpty()) continue;
                mappedSource=true;
                long relative=source.getFileBytesOffset(block.getStart());
                long offset=source.getFileBytes().get().getFileOffset()+relative;
                if(relative<0 || offset<0 || offset+4>original.length) { error("XOR selector has no exact original file mapping"); xorStatus="error"; break; }
                long size=Integer.toUnsignedLong(ByteBuffer.wrap(original,(int)offset,4).order(ByteOrder.LITTLE_ENDIAN).getInt());
                if(size==0 || size>limit("max_xor_bytes") || offset+4+size>original.length || size+4>source.getLength()) { error("XOR frame length exceeds its qualified original file region"); xorStatus="error"; break; }
                byte[] encoded=Arrays.copyOfRange(original,(int)offset+4,(int)(offset+4+size));
                byte[] mapped=new byte[(int)size]; currentProgram.getMemory().getBytes(block.getStart().add(4),mapped);
                if(!Arrays.equals(encoded,mapped)) { error("XOR memory and original-file bytes disagree"); xorStatus="error"; break; }
                if(!decodeRegion(offset+4,size,frame.get("key_hex").getAsString(),"qualification_frame")) xorStatus="error";
                break;
            }
            if(!mappedSource) { error("XOR qualification frame has no exact original-file mapping"); xorStatus="error"; }
        }
        if(getStoredHeadlessValue("packweir.errors") instanceof List<?>) for(Object value:(List<?>)getStoredHeadlessValue("packweir.errors")) error(String.valueOf(value));
        if(getStoredHeadlessValue("packweir.warnings") instanceof List<?>) for(Object value:(List<?>)getStoredHeadlessValue("packweir.warnings")) if(warnings.size()<64) warnings.add(String.valueOf(value));
        boolean complete=errors.isEmpty() && !timedOut && !truncated && total>0 && completed==total && failed==0 && xorStatus.equals("complete");
        JsonObject capabilities=new JsonObject(); String functionStatus=completed==total && failed==0 && total>0 && !timedOut && !truncated ? "complete":"incomplete";
        capabilities.addProperty("decompile",functionStatus); capabilities.addProperty("pcode",functionStatus); capabilities.addProperty("decode_xor",xorStatus);
        JsonObject report=new JsonObject(); report.addProperty("status",complete?"complete":"incomplete"); report.addProperty("timed_out",timedOut);
        report.add("errors",new Gson().toJsonTree(errors)); report.add("warnings",new Gson().toJsonTree(warnings));
        report.addProperty("language_id",language); report.addProperty("compiler_spec_id",compiler); report.add("capabilities",capabilities);
        report.addProperty("functions_total",total); report.addProperty("functions_decompiled",completed); report.addProperty("functions_failed",failed);
        report.addProperty("export_truncated",truncated); report.add("observations",observations); report.add("outputs",outputs);
        Files.writeString(Path.of(arguments[1]),new GsonBuilder().disableHtmlEscaping().serializeNulls().create().toJson(report),StandardCharsets.UTF_8);
    }
}
