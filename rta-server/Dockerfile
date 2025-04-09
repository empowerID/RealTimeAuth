# Stage 1: Build
FROM rust:latest AS builder

WORKDIR /usr/src/realtime-auth-idp

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Build application
COPY . .
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/realtime-auth-idp/target/release/realtime-auth-idp /usr/local/bin/realtime-auth-idp
COPY config/config.toml /app/config/config.toml

EXPOSE 4433

CMD ["/usr/local/bin/realtime-auth-idp"]
