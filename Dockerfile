FROM rust:1.92-alpine3.23 AS base

WORKDIR /app

EXPOSE 9000/udp

FROM base AS dev

RUN rustup component add rustfmt clippy \
    && cargo install cargo-audit --locked

CMD ["cargo", "run"]

FROM base AS builder

COPY Cargo.toml Cargo.lock ./
COPY . .
RUN cargo build --release

FROM alpine:3.23 AS runner

WORKDIR /app

COPY --from=builder /app/target/release/signalytics /app/signalytics

EXPOSE 9000/udp

CMD ["/app/signalytics"]
