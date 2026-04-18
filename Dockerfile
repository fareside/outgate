ARG RUST_VERSION=1.95
FROM rust:${RUST_VERSION}-trixie AS builder

WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo fetch --locked

RUN cargo build --release --locked -p outgate --bin outgate

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/outgate outgate \
    && mkdir -p /data /policies /usr/local/share/outgate/examples \
    && chown -R outgate:outgate /data /policies /home/outgate

COPY --from=builder /src/target/release/outgate /usr/local/bin/outgate
COPY examples /usr/local/share/outgate/examples

ENV HOST=0.0.0.0
ENV PORT=9191
ENV CERTIFICATE=/data/outgate-root-ca.pem
ENV RUST_LOG=info

EXPOSE 9191
VOLUME ["/data"]

USER outgate
WORKDIR /home/outgate

ENTRYPOINT ["outgate"]
