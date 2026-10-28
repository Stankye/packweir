FROM rust:1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 packweir && mkdir /data && chown packweir:packweir /data
COPY --from=build /build/target/release/packweir /usr/local/bin/packweir
WORKDIR /app
COPY packweir.toml /app/packweir.toml
USER packweir
EXPOSE 8080
ENTRYPOINT ["packweir"]
CMD ["serve"]
