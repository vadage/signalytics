FROM rust:1.94-alpine3.23 AS base

WORKDIR /app

EXPOSE 9000/udp

FROM base AS dev

ENV CARGO_TARGET_DIR=/target

RUN apk add --no-cache watchexec cargo-audit \
    && rustup component add rustfmt clippy

CMD ["watchexec", "--restart", "--exts", "rs,toml", "--", "cargo", "run"]

FROM base AS builder

COPY . .
RUN cargo build --release --locked

FROM scratch AS runner

COPY --from=builder /app/target/release/signalytics /signalytics

USER 65532:65532

EXPOSE 9000/udp

CMD ["/signalytics"]
