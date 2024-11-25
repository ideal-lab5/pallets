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

use crate::{self as murmur, mock::*, Error};
use codec::Encode;
use frame_support::{assert_ok, assert_noop, traits::ConstU32, BoundedVec};
use frame_system::Call as SystemCall;
use murmur_core::{murmur::EngineTinyBLS377, types::{BlockNumber, Identity, IdentityBuilder}};
use murmur_test_utils::{MurmurStore, get_dummy_beacon_pubkey};
use sp_consensus_beefy_etf::{known_payloads, Commitment, Payload};
use sp_core::{bls377, Pair};
use w3f_bls::{DoublePublicKey, SerializableToBytes, TinyBLS377};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use log::info;

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

/*
Test Contants
*/
pub const BLOCK_SCHEDULE: &[BlockNumber] = &[
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
];
pub const WHEN: u64 = 10;
pub const SEED: &[u8] = &[1, 2, 3];

fn calculate_signature(
	id: u8,
	serialized_resharing: &[u8],
	message: &[u8],
) -> (bls377::Public, bls377::Signature) {
	let kp = sp_core::bls::Pair::from_seed_slice(&[id; 32]).unwrap();
	let etf_kp = kp.acss_recover(serialized_resharing, 1).unwrap();
	(etf_kp.public(), etf_kp.sign(message))
}

#[test]
fn it_can_create_new_proxy_with_unique_name() {
	let seed = b"seed".to_vec();
	let unique_name = b"name".to_vec();
	let bounded_name = BoundedVec::<u8, ConstU32<32>>::truncate_from(unique_name);
	let block_schedule = vec![1, 2, 3];

	let size = 3;

	new_test_ext(vec![0]).execute_with(|| {
		let round_pubkey_bytes = get_dummy_beacon_pubkey();
				let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();

		let mut rng = ChaCha20Rng::seed_from_u64(0);

		let mmr_store = MurmurStore::<EngineTinyBLS377>::new::<BasicIdBuilder, ChaCha20Rng>(
			seed.clone().into(),
			block_schedule.clone(),
			0,
			round_pubkey,
			&mut rng,
		).unwrap();

		let root = mmr_store.root.clone();

		let bounded_root = BoundedVec::<u8, ConstU32<32>>::truncate_from(root.0);
		let bounded_pubkey = BoundedVec::<u8, ConstU32<48>>::truncate_from(mmr_store.public_key);
		let bounded_proof = BoundedVec::<u8, ConstU32<80>>::truncate_from(mmr_store.proof);

		assert_ok!(Murmur::create(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			bounded_root,
			size,
			bounded_proof.clone(),
			bounded_pubkey.clone(),
		));

		// check storage
		let registered_proxy = murmur::Registry::<Test>::get(bounded_name.clone());
		assert!(registered_proxy.is_some());
	});
}

#[test]
fn it_fails_to_create_new_proxy_with_duplicate_name() {
	let seed = b"seed".to_vec();
	let unique_name = b"name".to_vec();
	let bounded_name = BoundedVec::<u8, ConstU32<32>>::truncate_from(unique_name);
	let block_schedule = vec![1, 2, 3];

	let size = 3;

	new_test_ext(vec![0]).execute_with(|| {
		let round_pubkey_bytes = get_dummy_beacon_pubkey();
		let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();

		let mut rng = ChaCha20Rng::seed_from_u64(0);
		
		let mmr_store = MurmurStore::<EngineTinyBLS377>::new::<BasicIdBuilder, ChaCha20Rng>(
			seed.clone().into(),
			block_schedule.clone(),
			0,
			round_pubkey,
			&mut rng,
		).unwrap();

		let root = mmr_store.root.clone();
		let bounded_root = BoundedVec::<u8, ConstU32<32>>::truncate_from(root.0);
		let bounded_pubkey = BoundedVec::<u8, ConstU32<48>>::truncate_from(mmr_store.public_key);
		let bounded_proof = BoundedVec::<u8, ConstU32<80>>::truncate_from(mmr_store.proof);

		assert_ok!(Murmur::create(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			bounded_root.clone(),
			size,
			bounded_proof.clone(),
			bounded_pubkey.clone(),
		));

		// check storage
		let registered_proxy = murmur::Registry::<Test>::get(bounded_name.clone());
		assert!(registered_proxy.is_some());


		assert_noop!(Murmur::create(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			bounded_root,
			size,
			bounded_proof.clone(),
			bounded_pubkey.clone(),
		), Error::<Test>::DuplicateName);

		// verify that the proxy exists
	});
}

#[test]
fn it_can_update_proxy() {
	let _ = env_logger::try_init();
	let unique_name = b"name".to_vec();
	let bounded_name = BoundedVec::<u8, ConstU32<32>>::truncate_from(unique_name);

	new_test_ext(vec![0]).execute_with(|| {
		let round_pubkey_bytes = get_dummy_beacon_pubkey();

		let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();
		let same_round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();

		let mut rng = ChaCha20Rng::seed_from_u64(0);

		let mmr_store = MurmurStore::<EngineTinyBLS377>::new::<BasicIdBuilder, ChaCha20Rng>(
            SEED.to_vec(),
            BLOCK_SCHEDULE.to_vec(),
            0,
            round_pubkey,
            &mut rng,
        ).unwrap();

		let proof = mmr_store.proof.clone();
		let pk = mmr_store.public_key.clone();

		// use a new rng to ensure non-deterministic output
		let mut new_rng = ChaCha20Rng::seed_from_u64(1);
		let another_murmur_store = MurmurStore::<EngineTinyBLS377>::new::<BasicIdBuilder, ChaCha20Rng>(
            SEED.to_vec(),
            BLOCK_SCHEDULE.to_vec(),
            1,
            same_round_pubkey,
            &mut new_rng,
        ).unwrap();

		let another_proof = another_murmur_store.proof;

		// now we create a proxy and then update it
		/* CREATE THE PROXY */
		let root = mmr_store.root.clone();
		let bounded_root = BoundedVec::<u8, ConstU32<32>>::truncate_from(root.0);
		let bounded_pubkey = BoundedVec::<u8, ConstU32<48>>::truncate_from(pk.clone());
		let bounded_proof = BoundedVec::<u8, ConstU32<80>>::truncate_from(proof.clone());

		assert_ok!(Murmur::create(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			bounded_root,
			BLOCK_SCHEDULE.len() as u64,
			bounded_proof.clone(),
			bounded_pubkey.clone(),
		));

		// check storage
		let registered_proxy = murmur::Registry::<Test>::get(bounded_name.clone());
		assert!(registered_proxy.is_some());


		/* UPDATE THE PROXY */
		let second_root = another_murmur_store.root.clone();
		let second_bounded_root = BoundedVec::<u8, ConstU32<32>>::truncate_from(second_root.0);
		let second_bounded_proof = BoundedVec::<u8, ConstU32<80>>::truncate_from(another_proof.clone());
		
		assert_ok!(Murmur::update(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			second_bounded_root,
			BLOCK_SCHEDULE.len() as u64,
			second_bounded_proof.clone(),
		));
	});
}

#[test]
fn it_can_proxy_valid_calls() {
	let unique_name = b"name".to_vec();
	let bounded_name = BoundedVec::<u8, ConstU32<32>>::truncate_from(unique_name);
	let size = BLOCK_SCHEDULE.len() as u64;

	new_test_ext(vec![0]).execute_with(|| {
		let round_pubkey_bytes = get_dummy_beacon_pubkey();
		let round_pubkey = DoublePublicKey::<TinyBLS377>::from_bytes(&round_pubkey_bytes).unwrap();

		let mut rng = ChaCha20Rng::seed_from_u64(0);
		
		let mmr_store = MurmurStore::<EngineTinyBLS377>::new::<BasicIdBuilder, ChaCha20Rng>(
			SEED.to_vec(),
			BLOCK_SCHEDULE.to_vec().clone(),
			0,
			round_pubkey,
			&mut rng,
		).unwrap();

		let root = mmr_store.root.clone();
		let bounded_root = BoundedVec::<u8, ConstU32<32>>::truncate_from(root.0);
		let bounded_pubkey = BoundedVec::<u8, ConstU32<48>>::truncate_from(mmr_store.public_key.clone());
		let bounded_proof = BoundedVec::<u8, ConstU32<80>>::truncate_from(mmr_store.proof.clone());
	
		assert_ok!(Murmur::create(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			bounded_root.clone(),
			size,
			bounded_proof.clone(),
			bounded_pubkey.clone(),
		));

		// we must simulate the protocol here
		// in practice, the rng would be seeded from user input
		// along with some secure source of entropy
		let call = call_remark(vec![1, 2, 3, 4, 5]);
		let (merkle_proof, commitment, ciphertext, pos) = mmr_store
			.execute(
				SEED.to_vec().clone(), 
				10,
				call.encode().to_vec(),
			).unwrap();

		let proof_items: Vec<Vec<u8>> =
			merkle_proof.proof_items().iter().map(|leaf| leaf.0.to_vec()).collect::<Vec<_>>();

		assert_ok!(Murmur::proxy(
			RuntimeOrigin::signed(0),
			bounded_name.clone(),
			pos,
			commitment,
			ciphertext,
			proof_items,
			merkle_proof.mmr_size(),
			Box::new(call),
		));
	});
}

fn call_remark(value: Vec<u8>) -> RuntimeCall {
	RuntimeCall::System(SystemCall::remark { remark: value })
}
