# Drand Bridge Pallet

This is a [FRAME](https://docs.substrate.io/reference/frame-pallets/) pallet that allows Substrate-based chains to bridge to drand. It only supports bridging to drand's [Quicknet](https://drand.love/blog/quicknet-is-live-on-the-league-of-entropy-mainnet), which provides fresh randomness every 3 seconds. Adding this pallet to a runtime allows it to acquire verifiable on-chain randomness which can be used in runtime modules or ink! smart contracts. 

## Usage

### For Pallets
This pallet implement the [Randomness]() trait. FRAME pallets can use it by configuring their runtimes 

``` rust
impl pallet_with_randomness for Runtime {
    type Randomness = Drand;
}
```

Subsequently in your pallet, fetch the latest round randomness with:

``` rust
let latest_randomness = T::Randomness::random();
```

### For Smart Contracts

Add the [chain extension]() to your runtime and then follow the guide [here]().

### Integration
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


Finally, make sure that your node supports the host functions for the optimized arkworks curves:
in node/src/ service.rs
``` rust
todo
```

### Chain Extension

To use the drand bridge pallet's randomness within smart contracts you must add the following chain extension.

``` rust
todo
```

### How it Works

* note: the offchain worker triggers on every block import,regardless of finality....

Drand's quicknet periodically outputs pulses of verifiable randomness every 3 seconds. There are various API's which provide access to the beacon, with this pallet simply using the main `api.drand.sh` URI.

#### Verification

To verify pulses from drand, we check the equality: $e(-sig, g2) == e(m, pk)$ where $m = H(message = Sha256(round))$

## Testing

### Unit Tests

### Benchmakrs

License: MIT-0
