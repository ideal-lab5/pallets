/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use super::*;
use std::vec;

use crate as pallet_murmur;
use codec::Encode;
use ark_serialize::CanonicalDeserialize;
use etf_crypto_primitives::encryption::tlock::{DecryptionResult, TLECiphertext};
use frame_support::{
	construct_runtime, derive_impl, parameter_types,
	traits::{ConstU128, ConstU32, ConstU64, InstanceFilter},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::Digest;
use sp_consensus_beefy_etf::{mmr::MmrLeafVersion, test_utils::etf_genesis};
use sp_core::Pair;
use sp_io::TestExternalities;
use sp_runtime::{
	impl_opaque_keys,
	testing::TestXt,
	traits::{BlakeTwo256, ConvertInto, Keccak256, OpaqueKeys},
	BuildStorage,
};
use sp_state_machine::BasicExternalities;
use w3f_bls::TinyBLS377;
use ark_transcript::{digest::Update, Transcript};

pub use sp_consensus_beefy_etf::bls_crypto::AuthorityId as BeefyId;

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Balances: pallet_balances,
		Proxy: pallet_proxy,
		Murmur: pallet_murmur,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountData = pallet_balances::AccountData<u128>;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Test
where
	RuntimeCall: From<C>,
{
	type OverarchingCall = RuntimeCall;
	type Extrinsic = TestXt<RuntimeCall, ()>;
}

impl pallet_balances::Config for Test {
	type MaxLocks = ();
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	type Balance = u128;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ConstU128<1>;
	type AccountStore = System;
	type WeightInfo = ();
	type RuntimeHoldReason = ();
	type RuntimeFreezeReason = ();
	type FreezeIdentifier = ();
	type MaxFreezes = ();
}

pub struct DummyTlockProvider;
impl TimelockEncryptionProvider<u64> for DummyTlockProvider {
	fn decrypt_at(
		bytes: &[u8],
		when: u64,
	) -> Result<DecryptionResult, pallet_randomness_beacon::TimelockError> {
		let seed = vec![1,2,3];

		let mut transcript = Transcript::new_labeled(murmur_core::murmur::MURMUR_PROTO_OTP);
		transcript.write_bytes(&seed);
		let nonce: u64 = 0;
		transcript.write_bytes(&nonce.to_be_bytes());
	
		let ephemeral_msk: Vec<u8> = vec![10, 124, 150, 208, 196, 211, 212, 13, 177, 116, 154, 11, 235, 242, 139, 2, 187, 80, 52, 58, 125, 72, 184, 194, 165, 119, 212, 134, 171, 185, 191, 101];

		let ciphertext: TLECiphertext<TinyBLS377> =
			TLECiphertext::deserialize_compressed(&mut &bytes[..]).unwrap();

		let otp = ciphertext
			.aes_decrypt(ephemeral_msk.as_slice().to_vec()).unwrap();

		Ok(DecryptionResult { message: otp.message, secret: [2; 32] })
	}

	fn latest() -> u64 {
		10
	}
}

impl pallet_murmur::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type TlockProvider = DummyTlockProvider;
}

#[derive(
	Copy,
	Clone,
	Eq,
	PartialEq,
	Ord,
	PartialOrd,
	Encode,
	Decode,
	RuntimeDebug,
	MaxEncodedLen,
	scale_info::TypeInfo,
)]
pub enum ProxyType {
	Any,
	JustTransfer,
}
impl Default for ProxyType {
	fn default() -> Self {
		Self::Any
	}
}
impl InstanceFilter<RuntimeCall> for ProxyType {
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::JustTransfer => {
				matches!(
					c,
					RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death { .. })
				)
			},
		}
	}
	fn is_superset(&self, o: &Self) -> bool {
		self == &ProxyType::Any || self == o
	}
}

impl pallet_proxy::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ProxyType = ProxyType;
	type ProxyDepositBase = ConstU128<1>;
	type ProxyDepositFactor = ConstU128<1>;
	type MaxProxies = ConstU32<4>;
	type WeightInfo = ();
	type CallHasher = BlakeTwo256;
	type MaxPending = ConstU32<2>;
	type AnnouncementDepositBase = ConstU128<1>;
	type AnnouncementDepositFactor = ConstU128<1>;
}

// Note, that we can't use `UintAuthorityId` here. Reason is that the implementation
// of `to_public_key()` assumes, that a public key is 32 bytes long. This is true for
// ed25519 and sr25519 but *not* for ecdsa. A compressed ecdsa public key is 33 bytes,
// with the first one containing information to reconstruct the uncompressed key.
pub fn mock_beefy_id(id: u8) -> BeefyId {
	// generate a new keypair and get the public key
	let kp = sp_core::bls::Pair::from_seed_slice(&[id; 32]).unwrap();
	BeefyId::from(kp.public())
}

pub fn mock_authorities(vec: Vec<u8>) -> Vec<(u64, BeefyId)> {
	vec.into_iter().map(|id| ((id as u64), mock_beefy_id(id))).collect()
}

pub fn new_test_ext(ids: Vec<u8>) -> TestExternalities {
	new_test_ext_raw_authorities(mock_authorities(ids))
}

pub fn new_test_ext_raw_authorities(authorities: Vec<(u64, BeefyId)>) -> TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

	let balances: Vec<_> = (0..authorities.len()).map(|i| (i as u64, 10_000_000)).collect();

	pallet_balances::GenesisConfig::<Test> { balances }
		.assimilate_storage(&mut t)
		.unwrap();

	t.into()
}
