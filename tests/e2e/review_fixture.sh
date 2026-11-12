#!/bin/sh
# Test-owned protocol fixture: exercises scoped evidence delivery, not a security review.
# Inputs are the deterministic qualification fixtures, serialized by Packweir.
set -eu
IFS= read -r request || test -n "$request"
case "$request" in *'"protocol_version":1'*) ;; *) exit 2 ;; esac
test ! -w resource-review_script
subject=$(printf '%s' "$request" | /bin/sed -n 's/.*"subject":"\([0-9a-f]\{64\}\)".*/\1/p')
configuration=$(printf '%s' "$request" | /bin/sed -n 's/.*"configuration":"\([0-9a-f]\{64\}\)".*/\1/p')
request_filename=$(printf '%s' "$request" | /bin/sed -n 's/.*"filename":"\([^"]*\)".*/\1/p')
bundle_digest=$(printf '%s' "$request" | /bin/sed -n 's/.*"evidence_digest":"\([0-9a-f]\{64\}\)".*/\1/p')
test ${#subject} -eq 64
test ${#configuration} -eq 64
test ${#bundle_digest} -eq 64
actual_subject=$(/usr/bin/sha256sum artifact)
actual_bundle=$(/usr/bin/sha256sum evidence.json)
test "${actual_subject%% *}" = "$subject"
test "${actual_bundle%% *}" = "$bundle_digest"
bundle=$(/bin/cat evidence.json)
# identities is the last top-level key in the deterministic serde_json bundle.
# Exact comparison below accepts one known scope, never a nested document match.
identities=${bundle##*'"identities":['}
outcome=inconclusive
for extension in jar pom; do
    filename="hosted-fixture-1.0.0.$extension"
    expected='{"filename":"'"$filename"'","origin":"http://gateway:8080/r/maven-prod/dev/packweir/private/hosted-fixture/1.0.0/'"$filename"'","package":{"basis":"hosted_coordinates_declared","ecosystem":"maven","name":"dev.packweir.private:hosted-fixture","namespace":"dev.packweir.private","purl":"pkg:maven/dev.packweir.private/hosted-fixture@1.0.0","version":"1.0.0"},"repository":"maven-prod"}]}'
    if test "$identities" = "$expected" && test "$request_filename" = "$filename"; then outcome=pass; fi
done
filename=packweir.private.fixture.1.0.0.nupkg
expected='{"filename":"'"$filename"'","origin":"http://gateway:8080/r/nuget-prod/flatcontainer/packweir.private.fixture/1.0.0/'"$filename"'","package":{"basis":"hosted_coordinates_declared","ecosystem":"nuget","name":"packweir.private.fixture","namespace":null,"purl":"pkg:nuget/packweir.private.fixture@1.0.0","version":"1.0.0"},"repository":"nuget-prod"}]}'
if test "$identities" = "$expected" && test "$request_filename" = "$filename"; then outcome=pass; fi
printf '{"outcome":"%s","details":{"fixture_only":true,"binding_subject":"%s","binding_configuration":"%s","binding_evidence_digest":"%s","production_scope_matched":%s},"references":[]}\n' "$outcome" "$subject" "$configuration" "$bundle_digest" "$(test "$outcome" = pass && printf true || printf false)"
