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

#![cfg_attr(not(feature = "std"), no_std)]
use codec::MaxEncodedLen;

use serde::{Serialize, Deserialize};

use frame_support::{
	pallet_prelude::*,
	traits::{Get, Randomness},
	BoundedVec,
	dispatch::{DispatchResultWithPostInfo, Pays},
};

use sp_std::prelude::*;
use frame_system::{
	pallet_prelude::*,
	offchain::SendTransactionTypes,
};

use sp_staking::{offence::OffenceReportSystem, SessionIndex};

use codec::{Decode, Encode};
use scale_info::TypeInfo;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use etf_crypto_primitives::utils::interpolate_threshold_bls;
use etf_crypto_primitives::{
	encryption::tlock::TLECiphertext,
};

use sp_session::{GetSessionNumber, GetValidatorCount};
use w3f_bls::{DoublePublicKey, DoubleSignature, EngineBLS, Message, SerializableToBytes, TinyBLS377};
use sp_consensus_beefy_etf::{
	Commitment, ValidatorSetId, Payload, known_payloads, BeefyAuthorityId,
};

use sp_runtime::{
	transaction_validity::{
		InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
		TransactionValidityError, ValidTransaction,
	},
	DispatchError, KeyTypeId, Perbill, RuntimeAppPublic,
	traits::Hash,
};
use sha3::{Digest, Sha3_512};
use log::{info, debug, error};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use pallet::*;

const LOG_TARGET: &str = "runtime::randomness-beacon";

pub type OpaqueSignature = BoundedVec<u8, ConstU32<48>>;

#[derive(
	Default, Clone, Eq, PartialEq, RuntimeDebugNoBound, 
	Encode, Decode, TypeInfo, MaxEncodedLen, Serialize, Deserialize)]
pub struct PulseHeader<BN: core::fmt::Debug> {
	pub block_number: BN,
	// pub hash_prev: BoundedVec<u8, ConstU32<64>>
}

#[derive(
	Default, Clone, Eq, PartialEq, RuntimeDebugNoBound, 
	Encode, Decode, TypeInfo, MaxEncodedLen, Serialize, Deserialize)]
pub struct PulseBody {
	pub signature: BoundedVec<u8, ConstU32<48>>,
	pub randomness: BoundedVec<u8, ConstU32<64>>,
}

#[derive(
	Default, Clone, Eq, PartialEq, RuntimeDebugNoBound, 
	Encode, Decode, TypeInfo, MaxEncodedLen, Serialize, Deserialize)]
pub struct Pulse<BN: core::fmt::Debug> {
	header: PulseHeader<BN>,
	body: PulseBody,	
}

impl<BN: core::fmt::Debug> Pulse<BN> {

	// builds the next pulse from a previous one
	pub fn build_next(
		signature: OpaqueSignature,
		block_number: BN,
		// prev: Pulse<BN>,
	) -> Self {
		let mut hasher = Sha3_512::new();
		hasher.update(signature.to_vec());
		let randomness = hasher.finalize();

		let bounded_rand = BoundedVec::<u8, ConstU32<64>>::try_from(randomness.to_vec())
			.expect("the hasher should work fix this later though");

		let header: PulseHeader<BN> = PulseHeader {
			block_number,
			// hash_prev: bounded_hash
		};

		let body = PulseBody {
			signature,
			randomness: bounded_rand,
		};

		Pulse {
			header,
			body,
		}
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::config]
	pub trait Config: frame_system::Config + SendTransactionTypes<Call<Self>> + pallet_etf::Config {
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// The maximum number of pulses to store in runtime storage
		#[pallet::constant]
		type MaxPulses: Get<u32>;
		
		// TODO
		// /// Weights for this pallet.
		// type WeightInfo: WeightInfo;
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			Self::validate_unsigned(source, call)
		}
	}
	
	/// the chain of randomness
	#[pallet::storage]
	pub type Pulses<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		BlockNumberFor<T>,
		Pulse<BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// the highest block number for which we have encoded a pulse
	#[pallet::storage]
	pub type Height<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub genesis_pulse: Pulse<BlockNumberFor<T>>,
	}

	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self { 
				genesis_pulse: Pulse::default(),
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize(
				&self.genesis_pulse
			).expect("The genesis pulse must be well formatted.");
		}
	}

	#[pallet::error]
	pub enum Error<T> {
		/// the origin should be unsigned
		InvalidOrigin,
		/// the signature could not be verified
		InvalidSignature,
		SignatureNotDeserializable,
		AlreadyInitialized,
		/// the bounded runtime storage has reached its limit
		PulseOverflow,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T> {
		PulseStored,
		InvalidSignatureNotStored,
	}

	/// Writes a new block from the randomness beacon into storage if it can be verified
	///
	/// * `signatures`: A set of threshold bls signatures (sigma, proof) output from the beacon protocol
	/// * `block_number`: The block number on which the pulse was generated (required for verification)
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(0)]
		pub fn write_pulse(
			origin: OriginFor<T>,
			signatures: Vec<Vec<u8>>,
			block_number: BlockNumberFor<T>,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
			let round_pk_bytes: Vec<u8> = <pallet_etf::Pallet<T>>::round_pubkey().to_vec();
			let rk = DoublePublicKey::<TinyBLS377>::deserialize_compressed(
				&round_pk_bytes[..]
			).unwrap();
			let validator_set_id = 0;//<pallet_beefy::Pallet<T>>::validator_set_id();
			let _ = Self::try_add_pulse(
				signatures, 
				block_number, 
				rk, 
				validator_set_id
			)?;

			Height::<T>::set(block_number);
			Self::deposit_event(Event::PulseStored);
			// Waive the fee since the pulse is valid and beneficial
			Ok(Pays::No.into())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// initialize the genesis state for this pallet
	fn initialize(
		genesis_pulse: &Pulse<BlockNumberFor<T>>,
	) -> Result<(), Error<T>> {
		let current_block = <frame_system::Pallet<T>>::block_number();
		<Pulses<T>>::insert(current_block, genesis_pulse);
		Ok(())
	}

	/// add a new pulse to the hash chain
	fn try_add_pulse(
		raw_signatures: Vec<Vec<u8>>,
		block_number: BlockNumberFor<T>,
		rk: DoublePublicKey<TinyBLS377>,
		validator_set_id: ValidatorSetId,
	) -> Result<(), Error<T>> {
		let payload = Payload::from_single_entry(
			known_payloads::ETF_SIGNATURE, 
			Vec::new()
		);
		let commitment = Commitment { 
			payload, 
			block_number, 
			validator_set_id,
		};

		// // TODO: error handling
		let mut good_sigs = Vec::new();
		raw_signatures.iter().enumerate().for_each(|(idx, rs)| {
			let etf_pk = <pallet_etf::Pallet<T>>::commitments()[idx].encode();
			let pk = DoublePublicKey::<TinyBLS377>::deserialize_compressed(
				&etf_pk[..]
			).unwrap();

			if let Ok(sig) = DoubleSignature::<TinyBLS377>::from_bytes(&rs) {	
				if sig.verify(&Message::new(b"", &commitment.encode()), &pk) {
					good_sigs.push((<TinyBLS377 as EngineBLS>::Scalar::from((idx as u8) + 1), sig.0));
				}
			}
		});

		let sig = interpolate_threshold_bls::<TinyBLS377>(good_sigs);
		let mut bytes = Vec::new();
		sig.serialize_compressed(&mut bytes).unwrap();
		let bounded_sig = 
			BoundedVec::<u8, ConstU32<48>>::try_from(bytes)
				.map_err(|_| Error::<T>::InvalidSignature)?;

		let pulse = Pulse::build_next(
			bounded_sig, 
			block_number, 
			// last_pulse
		);

		<Pulses<T>>::insert(block_number, pulse.clone());
		Ok(())
	}

	pub fn height() -> BlockNumberFor<T> {
		Height::<T>::get()
	}

	pub fn random_at(at: BlockNumberFor<T>) -> Option<Pulse<BlockNumberFor<T>>> {
		Pulses::<T>::get(at)
	}

	/// validate an unsigned transaction sent to this module
	pub fn validate_unsigned(source: TransactionSource, call: &Call<T>) -> TransactionValidity {
		if let Call::write_pulse { signatures, block_number } = call {
			// discard pulses not coming from the local node
			match source {
				TransactionSource::Local | TransactionSource::InBlock => { /* allowed */ },
				_ => {
					log::warn!(
						target: LOG_TARGET,
						"rejecting unsigned beacon pulse because it is not local/in-block."
					);
					return InvalidTransaction::Call.into()
				},
			}

			ValidTransaction::with_tag_prefix("RandomnessBeacon")
				// We assign the maximum priority for any equivocation report.
				.priority(TransactionPriority::MAX)
				.longevity(3) 
				// We don't propagate this. This can never be included on a remote node.
				.propagate(false)
				.build()
		} else {
			InvalidTransaction::Call.into()
		}
	}

	/// submit an unsigned transaction to write a new pulse into storage
	pub fn publish_pulse(
		signatures: Vec<Vec<u8>>, 
		block_number: BlockNumberFor<T>,
	) -> Option<()> {
		use frame_system::offchain::{Signer, SubmitTransaction};
		let call = Call::write_pulse {
			signatures,
			block_number,
		};
		let res = SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into());

		match res {
			Ok(_) => info!("submitted transaction succesfully"),
			Err(e) => error!("Failed to submit unsigned transaction: {:?}", e),
		}

		Some(())
	}
}

/// errors for timelock encryption
pub enum TimelockError {
	DecryptionFailed,
	MissingSecret,
	BoundCallFailure,
	DecodeFailure,
}

/// represents a timelock ciphertext
#[derive(Debug, Clone, PartialEq, Decode, Encode, MaxEncodedLen, TypeInfo)]
pub struct Ciphertext {
	/// the (AES) ciphertext
	pub ciphertext: BoundedVec<u8, ConstU32<512>>,
	/// the (AES) nonce
	pub nonce: BoundedVec<u8, ConstU32<96>>,
	/// the IBE ciphertext(s): for now we assume a single point in the future is used
	pub capsule: BoundedVec<u8, ConstU32<512>>,
}

/// provides timelock encryption using the current slot
pub trait TimelockEncryptionProvider<BN> {
	/// attempt to decrypt the ciphertext with the current slot secret
	fn decrypt_at(
		ciphertext: &[u8], 
		block_number: BN
	) -> Result<DecryptionResult, TimelockError>;

	/// get the latest block number for which randomness is known
	fn latest() -> BN;
}

// use ark_serialize::CanonicalDeserialize;
// use w3f_bls::{EngineBLS};
use etf_crypto_primitives::encryption::tlock::DecryptionResult;

impl<T:Config> TimelockEncryptionProvider<BlockNumberFor<T>> for Pallet<T> {
	fn decrypt_at(
		ciphertext_bytes: &[u8], 
		block_number: BlockNumberFor<T>
	) -> Result<DecryptionResult, TimelockError> {
		if let Some(secret) = Pulses::<T>::get(block_number) {
			let pk = <pallet_etf::Pallet<T>>::round_pubkey();
			// TODO: replace with optimized arkworks types?
			let ciphertext:TLECiphertext<TinyBLS377> = 
				TLECiphertext::deserialize_compressed(ciphertext_bytes)
					.map_err(|_| TimelockError::DecodeFailure)?;

			let sig: <TinyBLS377 as EngineBLS>::SignatureGroup = 
				<TinyBLS377 as EngineBLS>::SignatureGroup::deserialize_compressed(
					&secret.body.signature.to_vec()[..]
				).map_err(|_| TimelockError::DecodeFailure)?;

			let plaintext = ciphertext.tld(sig)
				.map_err(|_| TimelockError::DecryptionFailed)?;

			return Ok(plaintext);
		}
		Err(TimelockError::MissingSecret)
	}

	fn latest() -> BlockNumberFor<T> {
		return Height::<T>::get()
	}
}

// use frame_support::StorageHasher;


impl<T: Config> Randomness<T::Hash, BlockNumberFor<T>> for Pallet<T> {
	// this function hashes together the subject with the latest known randomness
	fn random(subject: &[u8]) -> (T::Hash, BlockNumberFor<T>) {
		let height = Height::<T>::get();

		let mut entropy = T::Hash::default();
		if let Some(pulse) = Pulses::<T>::get(height) {
			entropy = (subject, height, pulse.body.randomness.clone())
				.using_encoded(T::Hashing::hash);
		}

		(entropy, height)
	}
}