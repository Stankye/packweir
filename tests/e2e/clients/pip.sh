#!/bin/sh
set -eu
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
python --version
python -m venv /tmp/venv
/tmp/venv/bin/pip --version
echo 'PACKWEIR_CLIENT_VERSION_END'
/tmp/venv/bin/pip install --index-url="http://fixture:$PACKWEIR_READ_TOKEN@gateway:8080/r/pypi/" --trusted-host=gateway --disable-pip-version-check --no-cache-dir --no-deps --require-hashes -r /fixtures/requirements.txt
/tmp/venv/bin/python -c "import packweir_fixture; assert packweir_fixture.MARKER == 'packweir-ok'"
