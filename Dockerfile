# use the Rust official image
FROM rust:latest

WORKDIR /app

COPY ./ ./
RUN cargo build --release

# Run the binary
CMD ["./target/release/klerk"]