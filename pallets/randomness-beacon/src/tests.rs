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

use crate::{self as beacon, mock::*, BlockNumberFor, Call, Config, Error, Weight};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use codec::Encode;
use frame_support::{assert_ok, traits::OnInitialize};
use sha2::Sha256;
use sp_consensus_beefy_etf::{known_payloads, Commitment, Payload, ValidatorSetId};
use sp_core::{bls377, ByteArray, Pair};
use std::vec;

use ark_ff::Zero;
use etf_crypto_primitives::{
	proofs::hashed_el_gamal_sigma::BatchPoK, utils::interpolate_threshold_bls,
};
use w3f_bls::{
	single_pop_aggregator::SignatureAggregatorAssumingPoP, DoublePublicKey, DoublePublicKeyScheme,
	DoubleSignature, EngineBLS, Keypair, Message, PublicKey, PublicKeyInSignatureGroup,
	SerializableToBytes, Signature, Signed, TinyBLS, TinyBLS377,
};

fn init_block(block: u64) {
	System::set_block_number(block);
	Session::on_initialize(block);
}

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
fn test_genesis() {
	// for simplicity of simulating a beacon, we use a single validator model
	new_test_ext(vec![1]).execute_with(|| {
		let pulses = beacon::Pulses::<Test>::get();
		assert!(pulses.is_empty());
	});
}

#[test]
fn test_can_write_single_pulse() {
	new_test_ext(vec![1, 2, 3]).execute_with(|| {
		let pulses = beacon::Pulses::<Test>::get();
		assert_eq!(pulses.len(), 0);

		let round_pk_bytes: Vec<u8> = <pallet_etf::Pallet<Test>>::round_pubkey().to_vec();
		let rk =
			DoublePublicKey::<TinyBLS377>::deserialize_compressed(&round_pk_bytes[..]).unwrap();
		// now we write a new pulse...
		let resharing_bytes_1 = &pallet_etf::Shares::<Test>::get()[0];
		let resharing_bytes_2 = &pallet_etf::Shares::<Test>::get()[1];
		let resharing_bytes_3 = &pallet_etf::Shares::<Test>::get()[2];

		// // convert to batchpok
		let etf_pk_1 = &pallet_etf::Commitments::<Test>::get()[0];
		let etf_pk_2 = &pallet_etf::Commitments::<Test>::get()[1];
		let etf_pk_3 = &pallet_etf::Commitments::<Test>::get()[2];

		let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
		let validator_set_id = <pallet_beefy::Pallet<Test>>::validator_set_id();
		let block_number: BlockNumberFor<Test> = 1;
		let commitment = Commitment { payload, block_number, validator_set_id };

		// let mut pub_keys_in_sig_grp: Vec<PublicKeyInSignatureGroup<TinyBLS377>> = Vec::new();

		let (_pk1, signature_1) = calculate_signature(1, resharing_bytes_1, &commitment.encode());

		let pk1_ref: &[u8] = etf_pk_1.as_ref();
		let pk1_bytes_pub = &pk1_ref[48..144];
		let pk1_bytes_sig = &pk1_ref[0..48];

		let pk1_pub =
			<TinyBLS377 as EngineBLS>::PublicKeyGroup::deserialize_compressed(pk1_bytes_pub)
				.unwrap();
		let pk1_sig =
			<TinyBLS377 as EngineBLS>::SignatureGroup::deserialize_compressed(pk1_bytes_sig)
				.unwrap();

		let sig_bytes_1: &[u8] = signature_1.as_ref();
		let sig_1 = DoubleSignature::<TinyBLS377>::from_bytes(sig_bytes_1).unwrap();

		let (_pk2, signature_2) = calculate_signature(2, resharing_bytes_2, &commitment.encode());
		let sig_bytes_2: &[u8] = signature_2.as_ref();

		let sig_2 = DoubleSignature::<TinyBLS377>::from_bytes(sig_bytes_2).unwrap();

		let mut pk2_bytes: &[u8] = etf_pk_2.as_ref();
		let pk2_bytes_pub = &pk2_bytes[48..144];
		let pk2_bytes_sig = &pk2_bytes[0..48];
		let pk2_pub =
			<TinyBLS377 as EngineBLS>::PublicKeyGroup::deserialize_compressed(pk2_bytes_pub)
				.unwrap();
		let pk2_sig =
			<TinyBLS377 as EngineBLS>::SignatureGroup::deserialize_compressed(pk2_bytes_sig)
				.unwrap();

		let (_pk3, signature_3) = calculate_signature(3, resharing_bytes_3, &commitment.encode());
		let sig_bytes_3: &[u8] = signature_3.as_ref();
		let sig_3 = DoubleSignature::<TinyBLS377>::from_bytes(sig_bytes_3).unwrap();

		let mut pk3_bytes: &[u8] = etf_pk_3.as_ref();
		let pk3_bytes_pub = &pk3_bytes[48..144];
		let pk3_bytes_sig = &pk3_bytes[0..48];
		let pk3_pub =
			<TinyBLS377 as EngineBLS>::PublicKeyGroup::deserialize_compressed(pk3_bytes_pub)
				.unwrap();
		let pk3_sig =
			<TinyBLS377 as EngineBLS>::SignatureGroup::deserialize_compressed(pk3_bytes_sig)
				.unwrap();

		let message = Message::new(b"", &commitment.encode());
		let mut prover_aggregator =
			SignatureAggregatorAssumingPoP::<TinyBLS377>::new(message.clone());

		let mut serialized_sig = Vec::new();
		let sig = &(&prover_aggregator).signature();
		sig.serialize_compressed(&mut serialized_sig).unwrap();

		assert_ok!(Beacon::write_pulse(
			RuntimeOrigin::none(),
			// serialized_sig.to_vec(),
			vec![sig_bytes_1.to_vec(), sig_bytes_2.to_vec(), sig_bytes_3.to_vec()],
			1,
		));
		// step to next block
		init_block(1);

		let pulses = beacon::Pulses::<Test>::get();
		assert_eq!(pulses.len(), 1);
	});
}

#[test]
fn test_can_write_many_pulses() {
	new_test_ext(vec![1]).execute_with(|| {
		let pulses = beacon::Pulses::<Test>::get();
		assert_eq!(pulses.len(), 0);

		let round_pk_bytes: Vec<u8> = <pallet_etf::Pallet<Test>>::round_pubkey().to_vec();
		let rk =
			DoublePublicKey::<TinyBLS377>::deserialize_compressed(&round_pk_bytes[..]).unwrap();
		// now we write a new pulse...
		let resharing_bytes_1 = &pallet_etf::Shares::<Test>::get()[0];

		// // convert to batchpok
		let etf_pk_1 = &pallet_etf::Commitments::<Test>::get()[0];

		let payload = Payload::from_single_entry(known_payloads::ETF_SIGNATURE, Vec::new());
		let validator_set_id = <pallet_beefy::Pallet<Test>>::validator_set_id();
		let block_number: BlockNumberFor<Test> = 1;
		let commitment = Commitment { payload, block_number, validator_set_id };

		let (_pk1, signature_1) = calculate_signature(1, resharing_bytes_1, &commitment.encode());
		let sig_bytes_1: &[u8] = signature_1.as_ref();
		assert_ok!(Beacon::write_pulse(RuntimeOrigin::none(), vec![sig_bytes_1.to_vec()], 1,));
		// step to next block
		init_block(1);

		let pulses = beacon::Pulses::<Test>::get();
		assert_eq!(pulses.len(), 1);

		let (_pk1, signature_1_next) =
			calculate_signature(1, resharing_bytes_1, &commitment.encode());
		let sig_bytes_1_next: &[u8] = signature_1_next.as_ref();
		assert_ok!(Beacon::write_pulse(RuntimeOrigin::none(), vec![sig_bytes_1_next.to_vec()], 2,));
		// step to next block
		init_block(2);

		let pulses = beacon::Pulses::<Test>::get();
		assert_eq!(pulses.len(), 2);
	});
}
