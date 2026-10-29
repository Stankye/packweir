#!/bin/sh
set -eu
mkdir /tmp/project
cd /tmp/project
printf '//gateway:8080/r/npm/:_authToken=%s\n' "$PACKWEIR_READ_TOKEN" > .npmrc
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
npm --version
echo 'PACKWEIR_CLIENT_VERSION_END'
npm install --registry=http://gateway:8080/r/npm/ --cache=/tmp/npm-cache --ignore-scripts --no-audit --no-fund packweir-fixture@1.0.0 @packweir/fixture@1.0.0
node -e "for (const name of ['packweir-fixture', '@packweir/fixture']) if (require(name) !== 'packweir-ok') process.exit(1)"
