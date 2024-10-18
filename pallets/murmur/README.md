# Murmur Pallet

The Murmur Pallet is a FRAME pallet designed to create and execute Murmur wallets. It provides functionalities to create time-based proxy accounts and proxy calls after verifying ciphertexts using Merkle proofs.

## Overview

The Murmur Pallet allows users to create proxy accounts with unique names and execute proxy calls securely. It leverages Merkle Mountain Range (MMR) for proof verification and integrates with the `pallet_proxy` for proxy call execution.

## Features

- **Create Proxy Accounts**: Create time-based proxy accounts with unique names.
- **Proxy Calls**: Proxy calls after verifying the ciphertext and Merkle proof.

## Usage

### Create a Proxy Account

To create a proxy account, use the `create` dispatchable function:

```rust
pub fn create(
    origin: OriginFor<T>,
    root: Vec<u8>,
    size: u64,
    name: BoundedVec<u8, ConstU32<32>>,
) -> DispatchResult
```

### Proxy a Call

To proxy a call, use the `proxy` dispatchable function:

```rust
pub fn proxy(
    _origin: OriginFor<T>,
    name: BoundedVec<u8, ConstU32<32>>,
    position: u64,
    hash: Vec<u8>,
    ciphertext: Vec<u8>,
    proof: Vec<Vec<u8>>,
    size: u64,
    call: sp_std::boxed::Box<<T as pallet_proxy::Config>::RuntimeCall>,
) -> DispatchResult
```

## Events

The pallet emits the following events:

- `OtpProxyCreated`: Emitted when a new proxy account is created.
- `OtpProxyExecuted`: Emitted when a proxy call is executed.

## Errors

The pallet can return the following errors:

- `BadCiphertext`: The provided ciphertext is invalid.
- `DuplicateName`: The provided name is already in use.
- `InvalidOTP`: The provided OTP is invalid.
- `InvalidMerkleProof`: The provided Merkle proof is invalid.
- `InvalidProxy`: The proxy account is invalid.
- `ProxyDNE`: The proxy account does not exist.

## Build

To build the project, use the following command:

```shell
cargo build
```

## Testing

To run the tests, use the following command:

```shell
cargo test
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the Apache-2.0. See the [LICENSE](../../LICENSE) file for details.

## Contact

For any inquiries, please contact [Ideal Labs](https://idealabs.network).
