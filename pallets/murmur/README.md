# EtF Pallet

The EtF (Encryption to the Future) pallet enables EtF consensus when added to a runtime. It stores public parameters required for identity based encryption. In this initial version, parameters are set on genesis and only modifiable by the root node.

## Runtime Storage

- `IBEParams`: The publicly known generator required for the IBE block seals.

## Extrinsics

- `update_ibe_params`: Update the IBE public parameter. Only callable by the root node.

## License
GPLv3.0