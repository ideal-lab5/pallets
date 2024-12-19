FROM paritytech/ci-linux:production as build

WORKDIR /code
COPY . .
# Install Rust 1.79.0
RUN rustup toolchain install 1.79.0
RUN rustup default 1.79.0

# Add the wasm32 target for Rust 1.79.0
RUN rustup target add wasm32-unknown-unknown --toolchain 1.79.0-x86_64-unknown-linux-gnu
RUN rustup component add rust-src --toolchain 1.79.0-x86_64-unknown-linux-gnu

# Build the project using Rust 1.79.0
RUN cargo +1.79.0 build --release

FROM ubuntu:22.04
WORKDIR /drand-example-node

# Copy the node binary.
COPY --from=build /code/target/release/drand-example-node .

# Install root certs, see: https://github.com/paritytech/substrate/issues/9984
RUN apt update && \
    apt install -y ca-certificates && \
    update-ca-certificates && \
    apt remove ca-certificates -y && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 9944
# Exposing unsafe RPC methods is needed for testing but should not be done in
# production.
ENTRYPOINT ["./drand-example-node"]