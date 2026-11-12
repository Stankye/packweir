using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.ApplicationInspector.Commands;
using Microsoft.ApplicationInspector.RulesEngine;

static class Program
{
    internal const string HelperVersion = "1";
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 12
    };

    static int Main(string[] args)
    {
        if (args.SequenceEqual(new[] { "--version" }))
        {
            Console.WriteLine("packweir-ossgadget-helper 1; Microsoft.CST.OSSGadget.CLI 0.2.49; ApplicationInspector 1.9.55");
            return 0;
        }
        Report report;
        try
        {
            Check(args.Length == 0, "only stdin scan requests or --version are supported");
            var upstream = VerifyDeployment();
            AssemblyLoadContext.Default.Resolving += (_, name) =>
            {
                var path = Path.Combine(upstream, name.Name + ".dll");
                return File.Exists(path) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path) : null;
            };
            using var input = Console.OpenStandardInput();
            var bytes = ReadBounded(input, 256 * 1024);
            using var document = JsonDocument.Parse(bytes);
            RejectDuplicateProperties(document.RootElement);
            var request = JsonSerializer.Deserialize<Request>(bytes, Json) ?? throw new InvalidDataException("request missing");
            report = Scan(request, upstream);
        }
        catch (Exception error)
        {
            report = new Report { Status = "error", Diagnostics = new[] { Limit(error.GetBaseException().Message, 1024) } };
        }
        var output = JsonSerializer.SerializeToUtf8Bytes(report, Json);
        if (output.Length > 1024 * 1024)
        {
            report = new Report { Status = "error", Diagnostics = new[] { "helper output limit exceeded" } };
            output = JsonSerializer.SerializeToUtf8Bytes(report, Json);
        }
        Console.OpenStandardOutput().Write(output);
        return report.Status == "error" ? 2 : 0;
    }

    internal static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }

    internal static byte[] ReadBounded(Stream stream, int limit)
    {
        using var target = new MemoryStream();
        var buffer = new byte[65536];
        while (true)
        {
            var read = stream.Read(buffer, 0, Math.Min(buffer.Length, limit + 1 - (int)target.Length));
            if (read == 0) break;
            target.Write(buffer, 0, read);
            Check(target.Length <= limit, "input byte limit exceeded");
        }
        return target.ToArray();
    }

    internal static string Digest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static string Limit(string value, int maximum) => value.Length > maximum ? value[..maximum] : value;

    static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                Check(seen.Add(property.Name), "duplicate JSON property");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var child in element.EnumerateArray()) RejectDuplicateProperties(child);
    }

    static string VerifyDeployment()
    {
        using var embedded = Assembly.GetExecutingAssembly().GetManifestResourceStream("UpstreamPins") ?? throw new InvalidDataException("embedded upstream pins missing");
        var pins = JsonSerializer.Deserialize<Deployment>(embedded, Json) ?? throw new InvalidDataException("upstream pins invalid");
        Check(pins.PackageVersion == "0.2.49" && pins.SourceRevision == "4063457b40211c25b41d56465d41783f2d42c5c1" && pins.PackageSha256 == Report.PackageDigest, "unexpected upstream deployment");
        var root = Path.Combine(AppContext.BaseDirectory, "upstream");
        Check(pins.Files.Count is > 0 and <= 512, "upstream deployment count invalid");
        foreach (var (name, digest) in pins.Files)
        {
            var path = LocalPath(root, name);
            using var file = File.OpenRead(path);
            var bytes = ReadBounded(file, 8 * 1024 * 1024);
            Check(Digest(bytes) == digest, "upstream deployment digest mismatch: " + name);
        }
        var actual = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Select(path => Path.GetRelativePath(root, path).Replace('\\', '/')).ToHashSet(StringComparer.Ordinal);
        Check(actual.SetEquals(pins.Files.Keys), "upstream deployment contains unexpected files");
        return root;
    }

    internal static string LocalPath(string root, string relative)
    {
        Check(Path.IsPathFullyQualified(root), "root must be absolute");
        Check(!string.IsNullOrEmpty(relative) && relative.Length <= 512 && !Path.IsPathRooted(relative) && !relative.Contains('\\') && !relative.Contains(':') && !relative.Contains('\0'), "invalid relative path");
        var parts = relative.Split('/');
        Check(parts.All(part => part.Length > 0 && part is not "." and not ".."), "unsafe relative path");
        var current = Path.GetFullPath(root);
        Check((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "root links are unsupported");
        foreach (var part in parts)
        {
            current = Path.Combine(current, part);
            Check((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "input links are unsupported");
        }
        Check(File.Exists(current), "input must name a regular file");
        return current;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static Report Scan(Request request, string upstream) => Engine.Scan(request, upstream);
}

sealed class Deployment
{
    public string PackageVersion { get; set; } = "";
    public string PackageSha256 { get; set; } = "";
    public string SourceRevision { get; set; } = "";
    public Dictionary<string, string> Files { get; set; } = new();
}

sealed class Request
{
    public int ProtocolVersion { get; set; }
    public string Mode { get; set; } = "";
    public string Root { get; set; } = "";
    public List<InputFile> Files { get; set; } = new();
    public string? RulesPath { get; set; }
    public string? RulesSha256 { get; set; }
}

sealed class InputFile
{
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
}

sealed class FileReport
{
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public int Size { get; set; }
    public string Status { get; set; } = "not_analyzed";
    public string? UpstreamStatus { get; set; }
    public string? Reason { get; set; }
}

sealed class Finding
{
    public string Path { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string? Description { get; set; }
    public string[] Tags { get; set; } = Array.Empty<string>();
    public string Severity { get; set; } = "";
    public string Confidence { get; set; } = "";
    public int SeverityValue { get; set; }
    public int ConfidenceValue { get; set; }
    public int StartLine { get; set; }
    public int StartColumn { get; set; }
    public int EndLine { get; set; }
    public int EndColumn { get; set; }
    public string? Language { get; set; }
}

sealed class Report
{
    public const string PackageDigest = "0f139a32ecf35538d44cf0be7781be6194a395bc331d4084240f77f1c5b8aded";
    public int ProtocolVersion { get; set; } = 1;
    public string HelperVersion { get; set; } = Program.HelperVersion;
    public string Engine { get; set; } = "Microsoft.ApplicationInspector 1.9.55 (from Microsoft.CST.OSSGadget.CLI 0.2.49)";
    public string PackageSha256 { get; set; } = PackageDigest;
    public string SourceRevision { get; set; } = "4063457b40211c25b41d56465d41783f2d42c5c1";
    public string Mode { get; set; } = "";
    public string Status { get; set; } = "partial";
    public bool Complete { get; set; }
    public bool ArchiveCrawling { get; set; }
    public string? RulesSha256 { get; set; }
    public int? EngineResultCode { get; set; }
    public string? EngineResultName { get; set; }
    public List<FileReport> Files { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();
    public object Totals => new { requested = Files.Count, analyzed = Files.Count(file => file.Status is "analyzed" or "affected"), skipped = Files.Count(file => file.Status == "skipped"), errored = Files.Count(file => file.Status == "error"), matches = Findings.Count };
    public string[] Diagnostics { get; set; } = Array.Empty<string>();
}

static class Engine
{
    static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static Report Scan(Request request, string upstream)
    {
        Program.Check(request.ProtocolVersion == 1 && request.Mode is "characteristic" or "backdoor" or "custom", "unsupported request protocol or mode");
        Program.Check(request.Files.Count is > 0 and <= 256, "request requires 1..256 explicit files");
        Program.Check(request.Mode == "custom" || request.RulesPath is null && request.RulesSha256 is null, "rules are supported only in custom mode");
        var report = new Report { Mode = request.Mode };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var snapshot = Directory.CreateTempSubdirectory("packweir-ossgadget-");
        try
        {
            long total = 0;
            var accepted = new Dictionary<string, FileReport>(StringComparer.Ordinal);
            foreach (var input in request.Files)
            {
                Program.Check(seen.Add(input.Path), "duplicate input path");
                var source = Program.LocalPath(request.Root, input.Path);
                using var stream = File.OpenRead(source);
                var bytes = Program.ReadBounded(stream, 4 * 1024 * 1024);
                total += bytes.Length;
                Program.Check(total <= 32 * 1024 * 1024, "combined input byte limit exceeded");
                Program.Check(Program.Digest(bytes) == input.Sha256, "input digest mismatch");
                var file = new FileReport { Path = input.Path, Sha256 = input.Sha256, Size = bytes.Length };
                report.Files.Add(file);
                var unsupported = Unsupported(input.Path, bytes);
                if (unsupported is not null)
                {
                    file.Status = "skipped";
                    file.Reason = unsupported;
                    continue;
                }
                var target = Path.Combine(snapshot.FullName, "inputs", input.Path.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.WriteAllBytes(target, bytes);
                File.SetAttributes(target, FileAttributes.ReadOnly);
                accepted.Add(Normalize(target), file);
            }

            string? rules = null;
            if (request.Mode == "backdoor") rules = Path.Combine(upstream, "Resources", "BackdoorRules");
            if (request.Mode == "custom")
            {
                Program.Check(request.RulesPath is not null && request.RulesSha256 is not null, "custom rules path and digest are required");
                var relative = Path.GetRelativePath(request.Root, request.RulesPath!).Replace('\\', '/');
                using var source = File.OpenRead(Program.LocalPath(request.Root, relative));
                var bytes = Program.ReadBounded(source, 1024 * 1024);
                Program.Check(Program.Digest(bytes) == request.RulesSha256, "custom rules digest mismatch");
                rules = Path.Combine(snapshot.FullName, ".packweir-rules.json");
                File.WriteAllBytes(rules, bytes);
                report.RulesSha256 = request.RulesSha256;
            }
            if (accepted.Count == 0) return report;

            var options = new AnalyzeOptions
            {
                SourcePath = accepted.Keys.Select(path => Path.DirectorySeparatorChar == '/' ? "/" + path : path).ToArray(),
                DisableCrawlArchives = true,
                IgnoreDefaultRules = request.Mode != "characteristic",
                CustomRulesPath = rules,
                SingleThread = true,
                NoShowProgress = true,
                NoFileMetadata = false,
                ScanUnknownTypes = true,
                AllowAllTagsInBuildFiles = true,
                EnableNonBacktrackingRegex = true,
                ContextLines = -1,
                ConfidenceFilters = new[] { Confidence.Unspecified | Confidence.Low | Confidence.Medium | Confidence.High },
                FilePathExclusions = Array.Empty<string>()
            };
            AnalyzeResult result;
            try { result = new AnalyzeCommand(options).GetResult(); }
            catch (Exception error)
            {
                report.Status = "error";
                report.Diagnostics = new[] { Program.Limit(error.GetBaseException().Message, 1024) };
                foreach (var file in accepted.Values) { file.Status = "error"; file.Reason = "analysis failed"; }
                return report;
            }
            report.EngineResultCode = (int)result.ResultCode;
            report.EngineResultName = result.ResultCode.ToString();
            Program.Check(result.Metadata is not null, "upstream metadata missing");
            var metadata = result.Metadata!;
            var observed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var file in metadata.Files)
            {
                var key = Normalize(file.FileName);
                Program.Check(accepted.TryGetValue(key, out var mapped) && observed.Add(key), "upstream returned an unexpected or duplicate file");
                mapped!.UpstreamStatus = file.Status.ToString();
                mapped.Status = file.Status switch { ScanState.Analyzed => "analyzed", ScanState.Affected => "affected", ScanState.Skipped => "skipped", _ => "error" };
                if (mapped.Status is "error" or "skipped") mapped.Reason = "upstream " + file.Status;
            }
            Program.Check(observed.Count == accepted.Count, "upstream did not attest every input file");
            Program.Check(metadata.Matches.Count <= 2000, "finding count limit exceeded");
            foreach (var match in metadata.Matches)
            {
                Program.Check(match.FileName is not null && accepted.TryGetValue(Normalize(match.FileName), out _), "upstream match is outside the explicit input list");
                var mapped = accepted[Normalize(match.FileName!)];
                report.Findings.Add(new Finding
                {
                    Path = mapped.Path, RuleId = Program.Limit(match.RuleId, 256), Description = match.RuleDescription is null ? null : Program.Limit(match.RuleDescription, 2048),
                    Tags = (match.Tags ?? Array.Empty<string>()).Take(64).Select(tag => Program.Limit(tag, 256)).ToArray(),
                    Severity = match.Severity.ToString(), Confidence = match.Confidence.ToString(), SeverityValue = (int)match.Severity, ConfidenceValue = (int)match.Confidence,
                    StartLine = match.StartLocationLine, StartColumn = match.StartLocationColumn, EndLine = match.EndLocationLine, EndColumn = match.EndLocationColumn, Language = match.Language
                });
            }
            report.Complete = !metadata.TimedOut && result.ResultCode is AnalyzeResult.ExitCode.Success or AnalyzeResult.ExitCode.NoMatches && report.Files.All(file => file.Status is "analyzed" or "affected");
            report.Status = report.Complete ? "complete" : "partial";
            return report;
        }
        finally
        {
            foreach (var file in snapshot.EnumerateFiles("*", SearchOption.AllDirectories)) file.Attributes = FileAttributes.Normal;
            snapshot.Delete(true);
        }
    }

    static string Normalize(string path) => path.Replace('\\', '/').TrimStart('/');

    static string? Unsupported(string path, byte[] bytes)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        if (new[] { ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".nupkg", ".whl", ".jar", ".war", ".crate", ".deb", ".rpm" }.Contains(extension)
            || bytes.AsSpan().StartsWith("PK"u8) || bytes.AsSpan().StartsWith(new byte[] { 0x1f, 0x8b })
            || bytes.AsSpan().StartsWith("BZh"u8) || bytes.AsSpan().StartsWith(new byte[] { 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0 })
            || bytes.AsSpan().StartsWith(new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c }) || bytes.AsSpan().StartsWith("Rar!"u8)
            || bytes.AsSpan().StartsWith(new byte[] { 0x28, 0xb5, 0x2f, 0xfd }) || bytes.Length > 262 && bytes.AsSpan(257, 5).SequenceEqual("ustar"u8))
            return "unsupported_archive";
        try { _ = StrictUtf8.GetString(bytes); }
        catch (DecoderFallbackException) { return "unsupported_binary_or_encoding"; }
        if (bytes.Contains((byte)0) || bytes.Count(value => char.IsControl((char)value) && !char.IsWhiteSpace((char)value)) > bytes.Length * 0.3)
            return "unsupported_binary_or_controls";
        return null;
    }
}
