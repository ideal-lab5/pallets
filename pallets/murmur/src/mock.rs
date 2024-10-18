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
use etf_crypto_primitives::encryption::tlock::DecryptionResult;
use frame_support::{
	construct_runtime, derive_impl, parameter_types,
	traits::{ConstU128, ConstU32, ConstU64, InstanceFilter},
};
use murmur_test_utils::BOTPGenerator;
use sha3::Digest;
use sp_consensus_beefy_etf::mmr::MmrLeafVersion;
use sp_core::Pair;
use sp_io::TestExternalities;
use sp_runtime::{
	impl_opaque_keys,
	testing::TestXt,
	traits::{BlakeTwo256, ConvertInto, Keccak256, OpaqueKeys},
	BuildStorage,
};
use sp_state_machine::BasicExternalities;

pub use sp_consensus_beefy_etf::bls_crypto::AuthorityId as BeefyId;

impl_opaque_keys! {
	pub struct MockSessionKeys {
		pub dummy: pallet_beefy_etf::Pallet<Test>,
	}
}

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Session: pallet_session,
		Mmr: pallet_mmr,
		RandomnessBeacon: pallet_randomness_beacon,
		Etf: pallet_etf,
		Beefy: pallet_beefy_etf,
		BeefyMmr: pallet_beefy_mmr_etf,
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

impl pallet_session::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = u64;
	type ValidatorIdOf = ConvertInto;
	type ShouldEndSession = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
	type NextSessionRotation = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
	type SessionManager = MockSessionManager;
	type SessionHandler = <MockSessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = MockSessionKeys;
	type WeightInfo = ();
}

impl pallet_mmr::Config for Test {
	const INDEXING_PREFIX: &'static [u8] = b"mmr";
	type Hashing = Keccak256;
	type LeafData = BeefyMmr;
	type OnNewRoot = pallet_beefy_mmr_etf::DepositBeefyDigest<Test>;
	type WeightInfo = ();
	type BlockHashProvider = pallet_mmr::DefaultBlockHashProvider<Test>;
}

impl pallet_etf::Config for Test {
	type BeefyId = BeefyId;
	type MaxAuthorities = ConstU32<100>;
}

impl pallet_beefy_etf::Config for Test {
	type BeefyId = BeefyId;
	type MaxAuthorities = ConstU32<100>;
	type MaxNominators = ConstU32<1000>;
	type MaxSetIdSessionEntries = ConstU64<100>;
	type OnNewValidatorSet = BeefyMmr;
	type WeightInfo = ();
	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
	type RoundCommitmentProvider = Etf;
}

parameter_types! {
	pub LeafVersion: MmrLeafVersion = MmrLeafVersion::new(1, 5);
}

impl pallet_beefy_mmr_etf::Config for Test {
	type LeafVersion = LeafVersion;

	type BeefyAuthorityToMerkleLeaf = pallet_beefy_mmr_etf::BeefyBlsToEthereum;

	type LeafExtra = Vec<u8>;

	type BeefyDataProvider = ();
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

impl pallet_randomness_beacon::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MaxPulses = ConstU32<256000>;
}

pub struct DummyTlockProvider;
impl TimelockEncryptionProvider<u64> for DummyTlockProvider {
	fn decrypt_at(
		_bytes: &[u8],
		when: u64,
	) -> Result<DecryptionResult, pallet_randomness_beacon::TimelockError> {
		let seed = b"seed".to_vec();
		let mut hasher = sha3::Sha3_256::default();
		hasher.update(seed);
		let hash = hasher.finalize();
		let generator = BOTPGenerator::new(hash.to_vec());
		let otp_code = generator.generate(when as u32);

		Ok(DecryptionResult { message: otp_code.as_bytes().to_vec(), secret: [0; 32] })
	}

	fn latest() -> u64 {
		1
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

pub struct MockSessionManager;
impl pallet_session::SessionManager<u64> for MockSessionManager {
	fn end_session(_: sp_staking::SessionIndex) {}
	fn start_session(_: sp_staking::SessionIndex) {}
	fn new_session(idx: sp_staking::SessionIndex) -> Option<Vec<u64>> {
		if idx == 0 || idx == 1 {
			Some(vec![1, 2])
		} else if idx == 2 {
			Some(vec![3, 4])
		} else {
			None
		}
	}
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

	let session_keys: Vec<_> = authorities
		.iter()
		.enumerate()
		.map(|(_, id)| (id.0 as u64, id.0 as u64, MockSessionKeys { dummy: id.1.clone() }))
		.collect();

	BasicExternalities::execute_with_storage(&mut t, || {
		for (ref id, ..) in &session_keys {
			frame_system::Pallet::<Test>::inc_providers(id);
		}
	});

	// mock the genesis config
	let genesis_resharing: Vec<(sp_consensus_beefy_etf::bls_crypto::Public, Vec<u8>)> =
		vec![(mock_beefy_id(123), [1u8; 32].into())];
	let round_pubkey = [
		144, 122, 123, 77, 192, 77, 117, 246, 132, 139, 163, 31, 26, 99, 75, 76, 23, 206, 24, 252,
		200, 112, 18, 199, 82, 203, 96, 23, 70, 76, 156, 253, 67, 126, 106, 164, 154, 25, 154, 95,
		155, 32, 173, 48, 126, 0, 123, 129, 86, 203, 71, 65, 207, 131, 55, 168, 72, 235, 88, 180,
		5, 20, 167, 118, 31, 36, 35, 125, 250, 33, 33, 224, 230, 106, 155, 79, 79, 137, 130, 57,
		146, 66, 236, 129, 17, 178, 199, 180, 48, 108, 247, 161, 0, 139, 7, 0, 180, 41, 114, 7, 69,
		134, 33, 178, 54, 23, 119, 67, 67, 173, 76, 36, 94, 29, 1, 134, 114, 228, 28, 69, 152, 14,
		57, 17, 38, 6, 83, 43, 155, 211, 188, 64, 91, 193, 205, 125, 222, 52, 19, 237, 173, 184,
		129, 128,
	]
	.into();

	pallet_etf::GenesisConfig::<Test> { genesis_resharing, round_pubkey }
		.assimilate_storage(&mut t)
		.unwrap();

	pallet_session::GenesisConfig::<Test> { keys: session_keys }
		.assimilate_storage(&mut t)
		.unwrap();

	t.into()
}
