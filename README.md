# Drand Bridge Pallet

This is a [FRAME](https://docs.substrate.io/reference/frame-pallets/) pallet that allows Substrate-based chains to bridge to drand. It only supports bridging to drand's [Quicknet](https://drand.love/blog/quicknet-is-live-on-the-league-of-entropy-mainnet), which provides fresh randomness every 3 seconds. Adding this pallet to a runtime allows it to acquire verifiable on-chain randomness which can be used in runtime modules or ink! smart contracts. 

Read the [how it works](./docs/how_it_works.md) for a deep-dive into the pallet.

## Usage

Use this pallet in a Substrate runtime to acquire verifiable randomness from drand's quicknet.

### For Pallets
This pallet implements the [Randomness]() trait. FRAME pallets can use it by configuring their runtimes 

``` rust
impl pallet_with_randomness for Runtime {
    type Randomness = Drand;
}
```

Subsequently in your pallet, fetch the latest round randomness with:

``` rust
let latest_randomness = T::Randomness::random();
```

Follow the guide [here](../../../docs/integration.md) to get started with integrating this pallet into a runtime.

### For Smart Contracts

Add the [chain extension]() to your runtime and then follow the guide [here]().

## Building

``` shell
cargo build
```

## Testing

We maintain a minimum of 85% coverage on all new code. You can check coverage with tarpauling by running 

``` shell
cargo tarpaulin
```

### Unit Tests

``` shell
cargo test
```

### Benchmarks
``` shell
# build the node with benchmarks enables

# run the pallet benchmarks
cargo benchmarks
```

License: MIT-0
