#!/bin/sh
set -eu
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_HOME=/tmp/dotnet-hosted-home
export NUGET_PACKAGES=/tmp/nuget-hosted-packages
export NUGET_CERT_REVOCATION_MODE=offline
export DOTNET_NUGET_SIGNATURE_VERIFICATION=true
mkdir /tmp/nuget-hosted-project
cd /tmp/nuget-hosted-project
fingerprint=$(cat /fixtures/nuget/fingerprint.txt)
cat > NuGet.Config <<EOF
<configuration><packageSources><clear/><add key="production" value="http://gateway:8080/r/nuget-prod/index.json" allowInsecureConnections="true"/></packageSources><packageSourceCredentials><production><add key="Username" value="fixture"/><add key="ClearTextPassword" value="$PACKWEIR_READ_TOKEN"/></production></packageSourceCredentials><config><add key="signatureValidationMode" value="require"/></config><trustedSigners><author name="ephemeral-qualification-fixture"><certificate fingerprint="$fingerprint" hashAlgorithm="SHA256" allowUntrustedRoot="true"/></author></trustedSigners></configuration>
EOF
cat > fixture.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><NuGetAudit>false</NuGetAudit></PropertyGroup><ItemGroup><PackageReference Include="Packweir.Private.Fixture" Version="1.0.0"/></ItemGroup></Project>
EOF
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
dotnet --version
echo 'PACKWEIR_CLIENT_VERSION_END'
dotnet restore --configfile NuGet.Config --no-cache --force --verbosity minimal
cmp /fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg /tmp/nuget-hosted-packages/packweir.private.fixture/1.0.0/packweir.private.fixture.1.0.0.nupkg
