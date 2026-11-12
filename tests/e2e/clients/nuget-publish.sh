#!/bin/sh
set -eu
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_HOME=/tmp/dotnet-home
export NUGET_PACKAGES=/tmp/nuget-packages
export NUGET_CERT_REVOCATION_MODE=offline
mkdir -p /tmp/nuget-publish
cd /tmp/nuget-publish
cat > NuGet.Config <<'EOF'
<configuration><packageSources><clear/></packageSources></configuration>
EOF
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
dotnet --version
echo 'PACKWEIR_CLIENT_VERSION_END'
# The explicit stage's V3 index advertises its PackagePublish/2.0.0 resource.
# dotnet sends multipart bytes with X-NuGet-ApiKey; no Basic/Bearer is configured.
dotnet nuget push /fixtures/nuget/Packweir.Private.Fixture.1.0.0.nupkg \
  --source "http://gateway:8080/api/v1/staging/$PACKWEIR_STAGE_ID/nuget/index.json" \
  --api-key "$PACKWEIR_PUBLISH_TOKEN" --no-symbols --timeout 60 --allow-insecure-connections
