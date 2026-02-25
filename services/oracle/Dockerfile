FROM rust:1.77-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
COPY services/oracle/Cargo.toml services/oracle/Cargo.toml

RUN mkdir -p services/oracle/src \
  && echo "fn main(){}" > services/oracle/src/main.rs

RUN cargo build -p alpenguard-oracle --release \
  && rm -rf services/oracle/src

COPY services/oracle/src services/oracle/src

RUN cargo build -p alpenguard-oracle --release

FROM debian:bookworm-slim

RUN useradd -m -u 10001 app
USER app
WORKDIR /home/app

COPY --from=builder /app/target/release/alpenguard-oracle /usr/local/bin/alpenguard-oracle

ENV RUST_LOG=info
ENV PORT=8080

EXPOSE 8080

CMD ["/usr/local/bin/alpenguard-oracle"]
