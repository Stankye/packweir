# Qualification image only. Runtime inputs are trusted local test fixtures.
FROM rust:1-bookworm AS tests
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    if ! cargo test --release --locked --test licenses --no-run --message-format=json > /tmp/test-build.jsonl; then \
      python3 -c 'import json; rows=[json.loads(line) for line in open("/tmp/test-build.jsonl")]; [print(r["message"].get("rendered","")) for r in rows if r.get("reason")=="compiler-message"]'; exit 1; fi \
    && python3 -c 'import json,shutil; rows=[json.loads(line) for line in open("/tmp/test-build.jsonl")]; paths=[r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="licenses" and r.get("executable")]; assert len(paths)==1,paths; shutil.copy2(paths[0],"/license-tests")'

FROM python:3.13-bookworm AS scancode
# The named context is supplied by run.py after downloading the official archive.
COPY --from=scancode_archive /scancode-toolkit-v32.5.0_py3.13-linux.tar.gz /tmp/scancode.tar.gz
RUN echo 'f9f83ffcf90577a74b61a30ebc4632a1fc89f026b438f597b18206babb964e28  /tmp/scancode.tar.gz' | sha256sum --check --strict \
    && mkdir /opt/scancode \
    && tar -xzf /tmp/scancode.tar.gz --strip-components=1 -C /opt/scancode \
    && rm /tmp/scancode.tar.gz \
    && useradd --create-home --uid 10001 packweir \
    && chown -R packweir:packweir /opt/scancode
USER packweir
WORKDIR /opt/scancode
# Configure exclusively from the release's bundled wheels and embedded bootstrap.
RUN --network=none PYTHON_EXECUTABLE=/usr/local/bin/python3.13 ./configure
# Warm the same detection/plugin path used by the driver without network access.
RUN --network=none mkdir /tmp/scancode-warmup \
    && printf 'SPDX-License-Identifier: MIT\n' > /tmp/scancode-warmup/LICENSE \
    && ./venv/bin/scancode --license --copyright --package --info --strip-root --quiet --processes 1 --json /tmp/scancode-warmup.json /tmp/scancode-warmup \
    && rm -r /tmp/scancode-warmup /tmp/scancode-warmup.json

FROM scancode AS runtime
LABEL io.packweir.scancode-version="32.5.0" \
      io.packweir.scancode-release-sha256="f9f83ffcf90577a74b61a30ebc4632a1fc89f026b438f597b18206babb964e28"
COPY --from=tests --chmod=0555 /license-tests /usr/local/bin/packweir-license-tests
ENV PACKWEIR_TEST_SCANCODE=/opt/scancode/venv/bin/scancode
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/packweir-license-tests"]
CMD ["--exact", "real_scancode_reports_complete_leaf_licenses_and_holds_unknowns", "--ignored", "--nocapture"]
