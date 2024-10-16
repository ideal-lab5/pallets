use crate::{self as murmur, mock::*, Error};
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, UniformRand};
use frame_support::{
	assert_noop, assert_ok, BoundedVec,
	traits::{
		ConstU32,
		OnInitialize,
	},
};
use frame_system::Call as SystemCall;

use sha3::Digest;

use murmur_core::types::{BlockNumber, Identity, IdentityBuilder, Leaf, MergeLeaves};

use murmur_test_utils::{
    BOTPGenerator, 
    MurmurStore
};
use sp_core::{bls377, Pair, ByteArray};
use ckb_merkle_mountain_range::{
	util::{MemMMR, MemStore},
	MerkleProof,
};

use codec::{Decode, Encode};
use sp_consensus_beefy_etf::{
	known_payloads, AuthorityIndex, BeefyAuthorityId, Commitment, ConsensusLog, EquivocationProof,
	OnNewValidatorSet, Payload, ValidatorSet, BEEFY_ENGINE_ID, GENESIS_AUTHORITY_SET_ID,
};
use ark_serialize::CanonicalDeserialize;
use w3f_bls::{
	DoublePublicKey, 
	DoubleSignature, 
	EngineBLS,
	SerializableToBytes, 
	TinyBLS377
};

#[derive(Debug)]
pub struct BasicIdBuilder;
impl IdentityBuilder<BlockNumber> for BasicIdBuilder {
	fn build_identity(at: BlockNumber) -> Identity {
		let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
		let commitment = Commitment {
			payload,
			block_number: at,
			validator_set_id: 0, /* TODO: how to ensure correct validator set ID is used? could
			                      * just always set to 1 for now, else set input param. */
		};
		Identity::new(&commitment.encode())
	}
}

#[test]
fn it_can_create_new_proxy_with_unique_name() {
	let seed = b"seed".to_vec();
	let unique_name = b"name".to_vec();
	let bounded_name = BoundedVec::<u8, ConstU32<32>>::truncate_from(unique_name);
	let block_schedule = vec![1, 2, 3];
	let ephem_msk = [3; 32];

	let size = 3;

	new_test_ext(vec![0]).execute_with(|| {
		let round_pubkey_bytes = Etf::round_pubkey().to_vec();
		let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();

		let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder>(
			seed.clone().into(),
			block_schedule.clone(),
			ephem_msk,
			round_pubkey,
		);
		let root = mmr_store.root.clone();
		assert_ok!(Murmur::create(
			RuntimeOrigin::signed(0),
			root.0.to_vec(),
			size,
			bounded_name.clone(),
		));

		// check storage
		let registered_proxy = murmur::Registry::<Test>::get(bounded_name.clone());
		assert!(registered_proxy.is_some());
	});
}

fn init_block(block: u64) {
	System::set_block_number(block);
	Session::on_initialize(block);
}

#[test]
fn it_can_proxy_valid_calls() {
	let seed = b"seed".to_vec();
	let unique_name = b"name".to_vec();
	let bounded_name = BoundedVec::<u8, ConstU32<32>>::truncate_from(unique_name);
	let when = 1;
	let block_schedule = vec![1, 2, 3];
	let ephem_msk = [3; 32];
	let size = 3;

	new_test_ext(vec![0]).execute_with(|| {
		let round_pubkey_bytes = Etf::round_pubkey().to_vec();
		let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();

		let mmr_store = MurmurStore::new::<TinyBLS377, BasicIdBuilder>(
			seed.clone().into(),
			block_schedule.clone(),
			ephem_msk,
			round_pubkey,
		);

		let root = mmr_store.root.clone();
		assert_ok!(Murmur::create(
			RuntimeOrigin::signed(0),
			root.0.to_vec(),
			size,
			bounded_name.clone(),
		));

		// the beacon would write a new pulse here, but we will mock it instead
		// but here, we can just generate the expected OTP code when we mock decryption
		
		// now we want to proxy a call 
		let call = call_remark(vec![1, 2, 3, 4, 5]);
		// We want to use the ciphertext for block = 1
		let (proof, commitment, ciphertext, pos) = mmr_store.execute(
			seed.clone(),
			when.clone() as u32,
			call.encode().to_vec(),
		).unwrap(); 

		let proof_items: Vec<Vec<u8>> = proof.proof_items().iter()
			.map(|leaf| leaf.0.to_vec())
			.collect::<Vec<_>>();

		assert_ok!(Murmur::proxy(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			pos,
			commitment,
			ciphertext,
			proof_items,
			size,
			Box::new(call),
		));

	});
}

fn calculate_signature(id: u8, serialized_resharing: &[u8], message: &[u8]) -> (bls377::Public, bls377::Signature) {
    let kp = sp_core::bls::Pair::from_seed_slice(&[id;32]).unwrap();
    let etf_kp = kp.acss_recover(serialized_resharing, 1).unwrap();
    (etf_kp.public(), etf_kp.sign(message))
}

fn call_remark(value: Vec<u8>) -> RuntimeCall {
	RuntimeCall::System(SystemCall::remark { remark: value })
}
