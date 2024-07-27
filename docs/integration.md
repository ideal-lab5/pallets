# Drand Bridge Pallet Integration

This guide details how to integrate the drand bridge pallet into the runtime.

## Configure the Node Service 

### Add Arkworks Host Functions

First you will need to add support for the arkworks host functions. Arkworks is far more performant when run natively than in wasm, so we achieve a massive boost in speed when using host functions.

Near the top of `node/src/service.rs`, add change the `FullClient` to use the code below:

``` rust
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

``` rust
let executor = sc_service::new_wasm_executor::<HostFunctions>(config);
let (client, backend, keystore_container, task_manager) =
    sc_service::new_full_parts::<Block, RuntimeApi, RuntimeExecutor>(
        config,
        telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
        executor,
    )?;
```

### (Optional) Add Authority Keys 

This is an optional step that should only be done in a testing environment. To add initial keys for an authority's OCW (e.g. Alice), add the following code inside of the if statement:

``` rust
if config.offchain_worker.enabled {
    sp_keystore::Keystore::sr25519_generate_new(
        &*keystore_container.keystore(),
        node_template_runtime::pallet_drand_bridge::KEY_TYPE,
        Some("//Alice"),
    ).expect("Creating key with account Alice should succeed.");
}
```

## Configure the Runtime

To use this pallet, add it to a substrate runtime with
``` rust
impl pallet_drand_bridge::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_drand_bridge::weights::SubstrateWeight<Runtime>;
	type AuthorityId = pallet_drand_bridge::crypto::TestAuthId;
	type MaxPulses = ConstU32<2048>;
	type Verifier = pallet_drand_bridge::QuicknetVerifier;
}

#[frame_support::runtime]
mod runtime {
	...
	#[runtime::pallet_index(x)]
	pub type Drand = pallet_drand_bridge;
    ...
}
```

You will also need to configure the runtime to allow offchain workers to submit unsigned transactions. This can be done with:
``` rust
impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
	RuntimeCall: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: RuntimeCall,
		public: <Signature as sp_runtime::traits::Verify>::Signer,
		account: AccountId,
		index: Index,
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
			frame_system::CheckNonce::<Runtime>::from(index),
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
