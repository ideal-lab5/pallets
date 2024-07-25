# Drand Bridge Pallet

This is a [FRAME]() pallet that allows Substrate-based chains to bridge to drand. Currently, it only supports bridging to drand's [Quicknet](), which provides fresh randomness every 3 seconds.

## Usage

This pallet implement the [Randomness]() trait. FRAME pallets can use it by configuring their runtimes 

``` rust
impl pallet_with_randomness for Runtime {
    type Randomness = Drand;
}
```


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

```
### How it Works

#### Verification

To verify pulses from drand, we check the equality: $e(sig, g2) == e(msg_hash, pk)$ 

## Testing

### Unit Tests

### Benchmakrs

License: MIT-0
