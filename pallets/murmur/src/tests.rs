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

use crate::{self as murmur, mock::*};
use codec::Encode;
use frame_support::{assert_ok, traits::ConstU32, BoundedVec};
use frame_system::Call as SystemCall;
use murmur_core::types::{BlockNumber, Identity, IdentityBuilder};
use murmur_test_utils::MurmurStore;
use sp_consensus_beefy_etf::{known_payloads, Commitment, Payload};
use w3f_bls::{DoublePublicKey, SerializableToBytes, TinyBLS377};

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
		let (proof, commitment, ciphertext, pos) = mmr_store
			.execute(seed.clone(), when.clone() as u32, call.encode().to_vec())
			.unwrap();

		let proof_items: Vec<Vec<u8>> =
			proof.proof_items().iter().map(|leaf| leaf.0.to_vec()).collect::<Vec<_>>();

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

fn call_remark(value: Vec<u8>) -> RuntimeCall {
	RuntimeCall::System(SystemCall::remark { remark: value })
}
