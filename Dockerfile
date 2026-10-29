FROM rust:1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --locked && cp target/release/packweir /packweir

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 packweir && mkdir /data && chown packweir:packweir /data
COPY --from=build /packweir /usr/local/bin/packweir
WORKDIR /app
COPY packweir.container.toml /app/packweir.toml
COPY LICENSE-APACHE LICENSE-MIT /usr/share/licenses/packweir/
USER packweir
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 CMD ["packweir", "health"]
ENTRYPOINT ["packweir"]
CMD ["serve"]
