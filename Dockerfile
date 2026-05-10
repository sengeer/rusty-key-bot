# syntax=docker/dockerfile:1 — включает BuildKit-фичи (mount cache ниже).

# Стабильный Rust с поддержкой edition 2024 (при необходимости подними версию).
ARG RUST_VERSION=1.88

# builder: зависимости и бинарник
FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

# Кэш registry/git/target ускоряет повторные сборки; бинарь копируем в /tmp вне кэша target.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release \
 && install -m755 target/release/rusty-key-bot /tmp/rusty-key-bot

# runtime: минимальный образ, только libc + TLS корни для исходящих HTTPS (teloxide)
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /tmp/rusty-key-bot /usr/local/bin/rusty-key-bot
COPY migrations ./migrations

ENV RUST_LOG=info
ENV DATABASE_URL=sqlite://data/rusty_key.db

CMD ["rusty-key-bot"]
