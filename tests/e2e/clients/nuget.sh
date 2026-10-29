#!/bin/sh
set -eu
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_HOME=/tmp/dotnet-home
export NUGET_PACKAGES=/tmp/nuget-packages
mkdir /tmp/project
cd /tmp/project
cat > NuGet.Config <<EOF
<configuration><packageSources><clear/><add key="packweir" value="http://gateway:8080/r/nuget/index.json" allowInsecureConnections="true"/></packageSources><packageSourceCredentials><packweir><add key="Username" value="fixture"/><add key="ClearTextPassword" value="$PACKWEIR_READ_TOKEN"/></packweir></packageSourceCredentials></configuration>
EOF
cat > fixture.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><NuGetAudit>false</NuGetAudit></PropertyGroup><ItemGroup><PackageReference Include="Packweir.Fixture" Version="1.0.0"/></ItemGroup></Project>
EOF
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
dotnet --version
echo 'PACKWEIR_CLIENT_VERSION_END'
dotnet restore --configfile NuGet.Config --no-cache --force --verbosity minimal
test -s /tmp/nuget-packages/packweir.fixture/1.0.0/packweir.fixture.1.0.0.nupkg
