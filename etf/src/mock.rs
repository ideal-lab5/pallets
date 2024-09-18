use std::vec;

use frame_support::{
	construct_runtime, derive_impl,
	traits::ConstU32,
};
use sp_io::TestExternalities;
use sp_runtime::{
	app_crypto::bls381::Public,
	traits::{OpaqueKeys},
	BuildStorage,
};
use sp_state_machine::BasicExternalities;

use crate as pallet_etf;

pub use sp_consensus_beefy_etf::{
	bls_crypto::AuthorityId as BeefyId,
};

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Etf: pallet_etf,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

impl pallet_etf::Config for Test {
	type BeefyId = BeefyId;
	type MaxAuthorities = ConstU32<100>;
}
// Note, that we can't use `UintAuthorityId` here. Reason is that the implementation
// of `to_public_key()` assumes, that a public key is 32 bytes long. This is true for
// ed25519 and sr25519 but *not* for aggregatable BLS. A compressed aggregated BLS public key is 144 bytes
pub fn mock_beefy_id(id: u8) -> BeefyId {
	let mut buf: [u8; 144] = [id; 144];
	// Set to something valid.
	buf[0] = 0x02;
	let pk = Public::from_raw(buf);
	BeefyId::from(pk)
}

pub fn mock_authorities(vec: Vec<u8>) -> Vec<(u64, BeefyId)> {
	vec.into_iter().map(|id| ((id as u64), mock_beefy_id(id))).collect()
}

pub fn new_test_ext(ids: Vec<u8>) -> TestExternalities {
	new_test_ext_raw_authorities(mock_authorities(ids))
}

pub fn new_test_ext_raw_authorities(authorities: Vec<(u64, BeefyId)>) -> TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

	let genesis_resharing = authorities
		.iter()
		.map(|(_idx, id)| (id.clone(), vec![2]))
		.collect();

	pallet_etf::GenesisConfig::<Test> { 
		genesis_resharing: genesis_resharing,
		round_pubkey: vec![1]
	}
		.assimilate_storage(&mut t)
		.unwrap();

	t.into()
}
