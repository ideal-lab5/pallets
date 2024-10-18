# Proxy Pallet

This is a FRAME pallet that allows accounts to delegate permission to other accounts to dispatch specific types of calls from their signed origin. This delegation can include requirements for the delegate to announce their intended actions before execution, giving the original account the opportunity to veto the action.

## Overview

The Proxy Module provides a flexible mechanism for account delegation, enabling various use cases such as account recovery, multi-signature wallets, and more. It supports time-based announcements and vetoes, ensuring that the original account retains control over critical actions.

## Features

- **Account Delegation**: Delegate permission to other accounts to perform specific actions.
- **Announcement and Veto**: Require delegates to announce actions before execution, allowing the original account to veto if necessary.

## Events

The module emits the following events:

- `ProxyAdded`: Emitted when a new proxy is added.
- `Announced`: Emitted when a proxy call is announced.
- `ProxyExecuted`: Emitted when a proxy call is executed.
- `PureCreated`: Emitted when a new pure proxy is created.
- `ProxyRemoved`: Emitted when a proxy is removed.

## Errors

The module can return the following errors:

- `TooMany`: The account has too many proxies.
- `NotFound`: The proxy was not found.
- `NotProxy`: The account is not a proxy.
- `Unproxyable`: The call is not allowed to be proxied.
- `Duplicate`: The proxy is already in use.
- `NoPermission`: The account does not have permission to proxy the call.
- `Unannounced`: The call was not announced.
- `NoSelfProxy`: An account cannot proxy to itself.

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
