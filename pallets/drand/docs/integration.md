# Drand Bridge Pallet Integration

This guide details how to integrate the drand bridge pallet into the runtime.

## Configure the Node Service

### Enable HTTP requests

Make sure the `enable_http_requests` is set to `true` in the `sc_offchain::OffchainWorkerOptions`.

### Add Arkworks Host Functions (recommnded for solochains only)

Arkworks is far more performant when run natively than in wasm, so we achieve a massive boost in speed when using host functions.
For optimal performance, the drand bridge pallet can utilize arkworks cryptographic functions that run directly on the host machine rather than in wasm. Here's what you need to know:
- For a Parachain:
  - The arkworks host functions must be available on all collator and validator machines
  - Since this availability cannot be guaranteed, and the relay chain may not support these functions, **it's recommended to run arkworks in wasm mode for parachains**
  - This ensures consistent behavior across the network

- For a Solochain:
  - You have more control over the environment and can enable the arkworks host functions
  - This will provide **significantly better performance** when verifiying drand pulses


#### Add support for the arkworks host functions. 

Near the top of `node/src/service.rs`, add change the `FullClient` to use the code below:

```rust
/// Host runctions required for Substrate and Arkworks
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions =
	(
		sp_io::SubstrateHostFunctions,
		sp_crypto_ec_utils::bls12_381::host_calls::HostFunctions
	);

/// Host runctions required for Substrate and Arkworks
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
	sp_io::SubstrateHostFunctions,
	sp_crypto_ec_utils::bls12_381::host_calls::HostFunctions,
	frame_benchmarking::benchmarking::HostFunctions,
);

/// A specialized `WasmExecutor`
pub type RuntimeExecutor = sc_executor::WasmExecutor::<HostFunctions>;

pub(crate) type FullClient = sc_service::TFullClient<
	Block,
	RuntimeApi,
	RuntimeExecutor,
>;
```

Once completed. you must also update the wasm_executor instantiated when calling `new_partial` (or equivalent if you use something else). Ensure that the wasm executor uses the expected set of `HostFunctions` and the type passed to `new_full_parts` expects the correct wasm executor.

```rust
let executor = sc_service::new_wasm_executor::<HostFunctions>(config);
let (client, backend, keystore_container, task_manager) =
    sc_service::new_full_parts::<Block, RuntimeApi, RuntimeExecutor>(
        config,
        telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        executor,
    )?;
```

#### Enable the `host-arkwork` feature

In your `Cargo.toml`, add the `host-arkworks` feature to the `pallet-drand` dependency.

```toml
pallet-drand = { ... features = ["host-arkworks"]}
```

## Configure the Runtime

To use this pallet, add it to a substrate runtime with

```rust
parameter_types! {
	pub const UnsignedPriority: u64 = 1 << 20;
	pub const ApiEndpoint: &'static str = "https://drand.cloudflare.com"; // See full list of endpoints at https://drand.love/docs/http-api-reference
	pub const HttpFetchTimeout: u64 = 1_000;
}

impl pallet_drand::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_drand::weights::SubstrateWeight<Runtime>;
	type AuthorityId = pallet_drand::crypto::TestAuthId;
	type UnsignedPriority = UnsignedPriority;
	type HttpFetchTimeout = HttpFetchTimeout;
	type Verifier = pallet_drand::verifier::QuicknetVerifier;
	type ApiEndpoint = ApiEndpoint;
}

#[frame_support::runtime]
mod runtime {
	...
	#[runtime::pallet_index(x)]
	pub type Drand = pallet_drand;
    ...
}
```

You will also need to configure the runtime to allow offchain workers to submit unsigned transactions. This can be done with:

```rust
impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
	RuntimeCall: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: RuntimeCall,
		public: <Signature as sp_runtime::traits::Verify>::Signer,
		account: AccountId,
		nonce: Nonce,
	) -> Option<(RuntimeCall, <UncheckedExtrinsic as sp_runtime::traits::Extrinsic>::SignaturePayload)> {
		let period = BlockHashCount::get() as u64;
		let current_block = System::block_number()
			.saturated_into::<u64>()
			.saturating_sub(1);
		let tip = 0;
		let extra: SignedExtra = (
			frame_system::CheckNonZeroSender::<Runtime>::new(),
			frame_system::CheckSpecVersion::<Runtime>::new(),
			frame_system::CheckTxVersion::<Runtime>::new(),
			frame_system::CheckGenesis::<Runtime>::new(),
			frame_system::CheckEra::<Runtime>::from(generic::Era::mortal(period, current_block)),
			frame_system::CheckNonce::<Runtime>::from(nonce),
			frame_system::CheckWeight::<Runtime>::new(),
			pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
		);

		let raw_payload = SignedPayload::new(call, extra)
			.map_err(|e| {
				log::warn!("Unable to create signed payload: {:?}", e);
			})
			.ok()?;
		let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
		let address = account;
		let (call, extra, _) = raw_payload.deconstruct();
		Some((call, (sp_runtime::MultiAddress::Id(address), signature.into(), extra)))
	}
}

impl frame_system::offchain::SigningTypes for Runtime {
	type Public = <Signature as sp_runtime::traits::Verify>::Signer;
	type Signature = Signature;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
RuntimeCall: From<C>,
{
	type OverarchingCall = RuntimeCall;
	type Extrinsic = UncheckedExtrinsic;
}
```

## Smart Contracts Config

This assumes that you have already integrated the contracts pallet in your time. To use the drand pallet's randomness within smart contracts, we first add a chain extension to the runtime and then tell the contracts pallet to use it.

### Add chain extension

This is just one possible way to write a chain extension. This can be customized on a per-chain basis.

At the bottom of `runtime/src/lib.rs`, add:

```rust
#[derive(Default)]
pub struct DrandExtension;

impl ChainExtension<Runtime> for DrandExtension {

    fn call<E: Ext>(
        &mut self,
        env: Environment<E, InitState>,
    ) -> Result<RetVal, DispatchError>
    where
        <E::T as SysConfig>::AccountId:
            UncheckedFrom<<E::T as SysConfig>::Hash> + AsRef<[u8]>,
    {
		let func_id = env.func_id();
		log::trace!(
			target: "runtime",
			"[ChainExtension]|call|func_id:{:}",
			func_id
		);
        match func_id {
            1101 => {
                let mut env = env.buf_in_buf_out();
				let rand = Drand::latest_random();
				env.write(&rand.encode(), false, None).map_err(|_| {
					DispatchError::Other("Failed to write output randomness")
				})?;

				Ok(RetVal::Converging(0))
            },
            _ => {
                log::error!("Called an unregistered `func_id`: {:}", func_id);
                Err(DispatchError::Other("Unimplemented func_id"))
            }
        }
    }

    fn enabled() -> bool {
        true
    }
}
```

### Configure Contracts Pallet

```rust
impl pallet_contracts::Config for Runtime {
	...
	type Randomness = Drand;
	...
	type ChainExtension = DrandExtension;
	...
}
```

## Add Authority Keys

Because of the limitations defined in [Assumptions and Limitations](./how_it_works.md#assumption-and-limitations), you must add the initial keys for the authorities' OCWs once your chain is running.
To add initial keys for an authority's OCW (e.g. Alice) you can do one of these:

### a. Via command line

```bash
# Parameters
NODE_URL="http://127.0.0.1:1234" # change this to your node's URL
KEY_TYPE="drnd"
SEED="//Alice" # change this to your authority's seed
PUBLIC_KEY="0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" # change this to your authority's public key

# Insert the key
curl -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"author_insertKey","params":["'"$KEY_TYPE"'","'"$SEED"'","'"$PUBLIC_KEY"'"],"id":1}' \
     $NODE_URL
```

### b. Via Polkadot.js Apps

1. Access the Polkadot.js Apps on your browser and connecto to your node.
2. Navigate to "Developer > RPC Calls" and select the `author_insertKey` call.
3. Fill in the parameters
   - **Key type**: `drnd`
   - **SURI**: The secret URI, usually a mnemonic seed phrase (for Alice it is `//Alice`)
   - **Public key**: The public key derived from the SURI (for Alice it is `0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d`)
