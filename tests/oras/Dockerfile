# Qualification only; upstream archive is provisioned and authenticated by run.py.
FROM rust:1-bookworm AS tests
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked cargo fetch --locked
RUN --network=none \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    if ! cargo test --release --locked --offline --test oras --no-run --message-format=json > /tmp/test-build.jsonl; then \
      python3 -c 'import json; rows=[json.loads(line) for line in open("/tmp/test-build.jsonl")]; [print(r["message"].get("rendered","")) for r in rows if r.get("reason")=="compiler-message"]'; exit 1; fi \
    && python3 -c 'import json,shutil; rows=[json.loads(line) for line in open("/tmp/test-build.jsonl")]; paths=[r["executable"] for r in rows if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="oras" and r.get("executable")]; assert len(paths)==1,paths; shutil.copy2(paths[0],"/oras-tests")' \
    && cp /build/target/release/packweir /packweir \
    && rustc --version > /rust-version.txt

FROM python:3.13-slim-bookworm AS runtime
ARG SOURCE_SHA256
ARG ORAS_EXECUTABLE_SHA256
LABEL io.packweir.oras-version="1.3.6" \
      io.packweir.oras-archive-sha256="66fb0ad7206f3f6fa77ed5b552049d364ccf4b50b1684554f731f76302b52ca0" \
      io.packweir.oras-source-sha256=$SOURCE_SHA256 \
      io.packweir.oras-executable-sha256=$ORAS_EXECUTABLE_SHA256
COPY --from=qualification_assets --chmod=0555 /extracted/oras /usr/local/bin/oras
COPY --from=qualification_assets /extracted/LICENSE /opt/oras/LICENSE.ORAS.txt
COPY --from=tests --chmod=0555 /oras-tests /usr/local/bin/packweir-oras-tests
COPY --from=tests --chmod=0555 /packweir /usr/local/bin/packweir
COPY --from=tests /rust-version.txt /opt/oras/rust-version.txt
COPY tests/oras/runtime.py /opt/oras/runtime.py
RUN mkdir -p /qualification && chown 10001:10001 /qualification
ENV PACKWEIR_TEST_ORAS=/usr/local/bin/oras PACKWEIR_TEST_CLI=/usr/local/bin/packweir
USER 10001:10001
WORKDIR /qualification
ENTRYPOINT ["python3", "/opt/oras/runtime.py"]
