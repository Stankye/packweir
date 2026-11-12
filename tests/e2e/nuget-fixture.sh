#!/bin/sh
# SDK-only local fixture: a real pack operation with every package source removed.
set -eu
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_HOME=/tmp/dotnet-home
export NUGET_PACKAGES=/tmp/nuget-packages
export NUGET_CERT_REVOCATION_MODE=offline
mkdir -p /tmp/nuget-fixture /fixtures/nuget
cd /tmp/nuget-fixture
cat > NuGet.Config <<'EOF'
<configuration><packageSources><clear/></packageSources></configuration>
EOF
cat > fixture.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><PackageId>Packweir.Private.Fixture</PackageId><Version>1.0.0</Version><Authors>Packweir</Authors><Description>Local hosted NuGet qualification fixture</Description><PackageLicenseExpression>MIT</PackageLicenseExpression><NuGetAudit>false</NuGetAudit><Deterministic>true</Deterministic></PropertyGroup></Project>
EOF
printf 'namespace Packweir.Private; public static class Fixture { public const string Marker = "packweir-ok"; }\n' > Fixture.cs
dotnet restore fixture.csproj --configfile NuGet.Config --verbosity minimal
dotnet pack fixture.csproj --no-restore --configuration Release --output /fixtures/nuget --verbosity minimal
test -s /fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg
mkdir -p /fixtures/nuget/unsigned
cp /fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg /fixtures/nuget/unsigned/
mkdir -p /tmp/nuget-versions
cd /tmp/nuget-versions
cp /tmp/nuget-fixture/NuGet.Config NuGet.Config
cat > versions.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><NuGetAudit>false</NuGetAudit></PropertyGroup><ItemGroup><Reference Include="NuGet.Versioning"><HintPath>$(MSBuildSDKsPath)/../NuGet.Versioning.dll</HintPath></Reference></ItemGroup></Project>
EOF
cat > Program.cs <<'EOF'
using NuGet.Versioning;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
// Ephemeral qualification-only key material stays in this run's fixture volume.
using var key = RSA.Create(2048);
var request = new CertificateRequest("CN=Packweir qualification fixture only", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, true));
request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
File.WriteAllBytes("/fixtures/nuget/qualification.pfx", certificate.Export(X509ContentType.Pfx, "fixture-only-password"));
File.WriteAllText("/fixtures/nuget/fingerprint.txt", certificate.GetCertHashString(HashAlgorithmName.SHA256));
var inputs = new[] { "1", "1.0", "01.0.0", "1.0.0.0", "1.2.3.4", "1.0.0+Build.007", "1.0.0-RC.1", "1.0.0-rc.1", "1.0.0-RC.01", "2147483647.0.0", "2147483648.0.0" };
var results = new Dictionary<string, string>();
foreach (var input in inputs)
    results[input] = NuGetVersion.TryParse(input, out var parsed) ? parsed.ToNormalizedString().ToLowerInvariant() : null;
File.WriteAllText("/fixtures/nuget/normalization.json", JsonSerializer.Serialize(results));
File.WriteAllText("/fixtures/nuget/versioning.txt", typeof(NuGetVersion).Assembly.FullName);
Console.WriteLine("PACKWEIR_NUGET_VERSIONING=" + typeof(NuGetVersion).Assembly.FullName);
Console.WriteLine("PACKWEIR_NUGET_NORMALIZATION=" + JsonSerializer.Serialize(results));
EOF
dotnet restore versions.csproj --configfile NuGet.Config --verbosity minimal
dotnet run --project versions.csproj --no-restore --verbosity minimal
fingerprint=$(cat /fixtures/nuget/fingerprint.txt)
cat > NuGet.Config <<EOF
<configuration><packageSources><clear/></packageSources><config><add key="signatureValidationMode" value="require"/></config><trustedSigners><author name="ephemeral-qualification-fixture"><certificate fingerprint="$fingerprint" hashAlgorithm="SHA256" allowUntrustedRoot="true"/></author></trustedSigners></configuration>
EOF
dotnet nuget sign /fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg \
  --certificate-path /fixtures/nuget/qualification.pfx --certificate-password fixture-only-password --overwrite --verbosity minimal
dotnet nuget verify /fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg --all --verbosity minimal
sha256sum /fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg > /fixtures/nuget/original.sha256
