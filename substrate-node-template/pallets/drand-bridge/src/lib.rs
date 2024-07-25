//! # Drand Bridge Pallet
//!
//! A pallet to bridge to [drand](drand.love), injecting publicly verifiable randomness into the runtime
//!
//! ## Overview
//!
//! Normally, the quicknet chain runs in an 'unchained' mode, producing a fresh pulse of randomness every 3s
//! This pallet 'chains' the values fetched from drand when running against quicknet, effectively 'chaining' each pulse from drand
//! However it should be noted that we may miss some pulses, as our block times are slower than drand's pulses.
//!
//! Run `cargo doc --package pallet-drand-beacon --open` to view this pallet's documentation.

// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use codec::{Encode, Decode};
use serde::{Serialize, Deserialize};
use sp_runtime::{
	offchain::{
		http,
		storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
		Duration,
	},
	KeyTypeId,
	traits::Zero,
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	RuntimeDebug,
};
use frame_support::pallet_prelude::*;
use frame_system::offchain::{
	AppCrypto, 
	CreateSignedTransaction, 
	SendSignedTransaction, 
	Signer
};
use sha2::{Digest, Sha256};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec::{
	AffineRepr,
	hashing::HashToCurve,
};
use sp_ark_bls12_381::{
	Bls12_381 as Bls12_381Opt, Fr as FrOpt, G1Affine as G1AffineOpt,
	G1Projective as G1ProjectiveOpt, G2Affine as G2AffineOpt, G2Projective as G2ProjectiveOpt,
};

// use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
// use ark_ec::hashing::{
//     map_to_curve_hasher::{MapToCurve, MapToCurveBasedHasher},
//     HashToCurve,
// };
use ark_bls12_381::{G1Affine, G2Affine, G2Projective};
use w3f_bls::{EngineBLS, TinyBLS381, ZBLS};
//  use scale_info::prelude::format;

// FRAME pallets require their own "mock runtimes" to be able to run unit tests. This module
// contains a mock runtime specific for testing this pallet's functionality.
#[cfg(test)]
mod mock;

// This module contains the unit tests for this pallet.
// Learn about pallet unit testing here: https://docs.substrate.io/test/unit-testing/
#[cfg(test)]
mod tests;

// Every callable function or "dispatchable" a pallet exposes must have weight values that correctly
// estimate a dispatchable's execution time. The benchmarking module is used to calculate weights
// for each dispatchable and generates this pallet's weight.rs file. Learn more about benchmarking here: https://docs.substrate.io/test/benchmark/
#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;

pub mod bls12_381;
pub mod utils;
// pub mod hash_to_curve;


use ark_scale::hazmat::ArkScaleProjective;
const USAGE: ark_scale::Usage = ark_scale::WIRE;
type ArkScale<T> = ark_scale::ArkScale<T, USAGE>;

/// the main drand api endpoint 
pub const API_ENDPOINT: &str = "https://api.drand.sh";
/// the drand quicknet chain hash
pub const QUICKNET_CHAIN_HASH: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"drnd");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify, MultiSignature, MultiSigner
	};
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;

	// implemented for runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

// pub const PUBLIC_KEY_SERIALIZED_SIZE = 48;
pub type OpaquePublicKeyG2 = BoundedVec<u8, ConstU32<96>>;
/// an opauqe hash type
pub type Hash = BoundedVec<u8, ConstU32<32>>;
/// the round number to track rounds of the beacon 
pub type RoundNumber = u64;

#[derive(Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize, TypeInfo, Clone)]
pub struct BeaconInfoResponse {
	#[serde(with = "hex::serde")]
	pub public_key: Vec<u8>,
	pub period: u32,
	pub genesis_time: u32,
	#[serde(with = "hex::serde")]
	pub hash: Vec<u8>,
	#[serde(with = "hex::serde", rename = "groupHash")]
	pub group_hash: Vec<u8>,
	#[serde(rename = "schemeID")]
	pub scheme_id: String, 
	pub metadata: MetadataInfoResponse,
}

#[derive(Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize, TypeInfo, Clone)]
pub struct MetadataInfoResponse {
	#[serde(rename = "beaconID")]
	beacon_id: String,
}

impl BeaconInfoResponse {
	fn try_into_beacon_config(&self) -> Option<BeaconConfiguration> {
		let bounded_pubkey = OpaquePublicKeyG2::try_from(self.public_key.clone())
			.expect("a");
		let bounded_hash = Hash::try_from(self.hash.clone())
			.expect("a");
		let bounded_group_hash = Hash::try_from(self.group_hash.clone())
			.expect("a");
		let bounded_scheme_id = Hash::try_from(self.scheme_id.as_bytes().to_vec().clone())
			.expect("a");
		let bounded_beacon_id = Hash::try_from(self.metadata.beacon_id.as_bytes().to_vec().clone())
			.expect("a");
		
		Some(BeaconConfiguration {
			public_key: bounded_pubkey,
			period: self.period,
			genesis_time: self.genesis_time,
			hash: bounded_hash,
			group_hash: bounded_group_hash,
			scheme_id: bounded_scheme_id,
			metadata: Metadata {
				beacon_id: bounded_beacon_id,
			}
		})
	}
}

/// a pulse from the drand beacon
#[derive(Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize)]
pub struct DrandResponseBody {
	/// the randomness round number
	pub round: RoundNumber,
	/// the sha256 hash of the signature (todo: use Hash)
	#[serde(with = "hex::serde")]
	pub randomness: Vec<u8>,
	/// BLS sig for the current round (todo: use Signature)
	#[serde(with = "hex::serde")]
	pub signature: Vec<u8>,
	// /// BLS sig from the previous round
	// pub previous_signature: Option<Vec<u8>>,
}

impl DrandResponseBody {
	fn try_into_pulse(&self) -> Option<Pulse> {

		let bounded_randomness = BoundedVec::<u8, ConstU32<32>>::try_from(self.randomness.clone())
			.expect("a");
		let bounded_signature = BoundedVec::<u8, ConstU32<144>>::try_from(self.signature.clone())
			.expect("a");

		Some(Pulse {
			round: self.round,
			randomness: bounded_randomness,
			signature: bounded_signature,
		})
	}
}

/// a drand chain configuration
#[derive(Clone, Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize, MaxEncodedLen, TypeInfo)]
pub struct BeaconConfiguration {
	pub public_key: OpaquePublicKeyG2,
	pub period: u32,
	pub genesis_time: u32,
	pub hash: Hash,
	pub group_hash: Hash,
	pub scheme_id: Hash, 
	pub metadata: Metadata,
}

/// metadata for the drand beacon configuration
#[derive(Clone, Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize, MaxEncodedLen, TypeInfo)]
pub struct Metadata {
	beacon_id: Hash,
}


/// a pulse from the drand beacon
#[derive(Clone, Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize, MaxEncodedLen, TypeInfo)]
pub struct Pulse {
	/// the randomness round number
	pub round: RoundNumber,
	/// the sha256 hash of the signature (todo: use Hash)
	pub randomness: BoundedVec<u8, ConstU32<32>>,
	/// BLS sig for the current round (todo: use Signature)
	pub signature: BoundedVec<u8, ConstU32<144>>,
	// /// BLS sig from the previous round
	// pub previous_signature: Option<Vec<u8>>,
}

// All pallet logic is defined in its own module and must be annotated by the `pallet` attribute.
#[frame_support::pallet]
pub mod pallet {
	// Import various useful types required by all FRAME pallets.
	use super::*;
	use frame_system::pallet_prelude::*;

	// The `Pallet` struct serves as a placeholder to implement traits, methods and dispatchables
	// (`Call`s) in this pallet.
	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config {
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
		/// The overarching runtime event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// A type representing the weights required by the dispatchables of this pallet.
		type WeightInfo: WeightInfo;
		/// the maximum number of pulses before the chain should be archived
		type MaxPulses: Get<u32>;
		// / the curve used for the public key group
		// type PublicKeyGroup: ark_ec::bls12::Bls12Config;
		/// something that knows how to verify beacon pulses
		type Verifier: Verifier;
	}


	/// the drand beacon configuration
	#[pallet::storage]
	pub type BeaconConfig<T: Config> = StorageValue<_, BeaconConfiguration, OptionQuery>;

	/// pulses received from drand
	#[pallet::storage]
	pub type Pulses<T: Config> = StorageValue<_, BoundedVec<Pulse, T::MaxPulses>, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		BeaconConfigChanged,
		/// A user has successfully set a new value.
		NewPulse {
			/// The new value set.
			round: RoundNumber,
			/// The account who set the new value.
			who: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The value retrieved was `None` as no value was previously set.
		NoneValue,
		/// There was an attempt to increment the value in storage over `u32::MAX`.
		StorageOverflow,
		DrandConnectionFailure,
		UnverifiedPulse,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(_bn: BlockNumberFor<T>) {
			// if the beacon config isn't available, get it now
			if BeaconConfig::<T>::get().is_none() {
				if let Err(e) = Self::drand_config() {
					log::error!(
						"Failed to fetch chain info from drand, are you sure the chain hash is valid? {:?}",
						e
					);
				}
			} else {
				// otherwise query drand
				log::info!("fetching fresh randomness from drand");
				if let Err(e) = Self::fetch_drand_and_send_signed() {
					log::info!("ERROR FETCHING FROM DRAND {:?}", e);
				}
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn write_pulse(
			origin: OriginFor<T>, 
			pulse: Pulse,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			if let Some(config) = BeaconConfig::<T>::get() {
				if T::Verifier::verify(config, pulse.clone()) {
					let mut pulses = Pulses::<T>::get();
					if let Ok(_) = pulses.try_push(pulse.clone()) {
						Pulses::<T>::put(pulses);
					}
					Self::deposit_event(Event::NewPulse { round: pulse.round, who });
				}
			}

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn set_beacon_config(
			_origin: OriginFor<T>,
			config: BeaconConfiguration,
		) -> DispatchResult {
			log::info!("I am here!");
			// let who = ensure_root(origin)?;

			BeaconConfig::<T>::put(config);			

			Self::deposit_event(Event::BeaconConfigChanged { });

			Ok(())
		}
	}
} 

impl<T: Config> Pallet<T> {

	fn drand_config() -> Result<(), &'static str> {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)?
		}

		let config = Self::fetch_drand_chain_info().unwrap();
		let results = signer.send_signed_transaction(|_account| Call::set_beacon_config { config: config.clone() });
		log::info!("The result please??");
		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted new config: {:?}", acc.id, config),
				Err(e) => log::error!("[{:?}] Failed to submit transaction: {:?}", acc.id, e),
			}
		}

		Ok(())
	}

	/// fetch the latest public pulse from the configured drand beacon
	/// then send a signed transaction to include it on-chain
	fn fetch_drand_and_send_signed() -> Result<(),&'static str > {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)?
		}

		let pulse = Self::fetch_drand()
			.map_err(|_| Error::<T>::DrandConnectionFailure)?
			.try_into_pulse()
			.unwrap();
	
		let results = signer.send_signed_transaction(|_account| Call::write_pulse { pulse: pulse.clone() });

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted new pulse: {:?}", acc.id, pulse),
				Err(e) => log::info!("[{:?}] Failed to submit transaction: {:?}", acc.id, e),
			}
		}

		log::info!("done");

		Ok(())
	}
	
	/// Query the endpoint `{api}/{chainHash}/info` to receive information about the drand chain
	/// Valid response bodies are deserialized into `BeaconInfoResponse`
	fn fetch_drand_chain_info() -> Result<BeaconConfiguration, http::Error> {
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		let uri: &str = &format!("{}/{}/info", API_ENDPOINT, QUICKNET_CHAIN_HASH);
		let request = http::Request::get(uri);
		let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		
		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown)
		}
		let body = response.body().collect::<Vec<u8>>();
		let body_str = alloc::str::from_utf8(&body).map_err(|_| {
			log::warn!("No UTF8 body");
			http::Error::Unknown
		})?;

		let beacon_config: BeaconInfoResponse = serde_json::from_str(body_str).unwrap();
		let config = beacon_config.try_into_beacon_config().unwrap();
		Ok(config)
	}

	/// fetches the latest randomness from drand's API
	fn fetch_drand() -> Result<DrandResponseBody, http::Error> {
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		let uri: &str = &format!("{}/{}/public/latest", API_ENDPOINT, QUICKNET_CHAIN_HASH);
		let request = http::Request::get(uri);
		let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		
		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown)
		}
		let body = response.body().collect::<Vec<u8>>();
		let body_str = alloc::str::from_utf8(&body).map_err(|_| {
			log::warn!("No UTF8 body");
			http::Error::Unknown
		})?;

		let unbounded_pulse: DrandResponseBody = serde_json::from_str(body_str).unwrap();
		
		Ok(unbounded_pulse)
	}
}

/// construct a message (e.g. signed by drand)
pub fn message(current_round: RoundNumber, prev_sig: &[u8]) -> Vec<u8> {
	let mut hasher = Sha256::default();
	hasher.update(prev_sig);
	hasher.update(current_round.to_be_bytes());
	hasher.finalize().to_vec()
}

pub trait Verifier {

	fn verify(beacon_config: BeaconConfiguration, pulse: Pulse) -> bool;
}

/// A verifier to check values received from quicknet. It outputs true if valid, false otherwise
///
/// [Quicknet](https://drand.love/blog/quicknet-is-live-on-the-league-of-entropy-mainnet) operates in an unchained mode, so messages contain only the round number
/// in addition, public keys are in G2 and signatures are in G1
/// 
/// Values are valid if the pairing equality holds:
///			 $e(sig, g_2) == e(msg_on_curve, pk)$
/// where $sig \in \mathbb{G}_1$ is the signature 
///       $g_2 \in \mathbb{G}_2$ is a generator
///       $msg_on_curve \in \mathbb{G}_1$ is a hash of the message that drand signed (hash(round_number))
///       $pk \in \mathbb{G}_2$ is the public key, read from the input public parameters
///
///
pub struct QuicknetVerifier;

impl Verifier for QuicknetVerifier {
	fn verify(beacon_config: BeaconConfiguration, pulse: Pulse) -> bool {
		// let pk = G2AffineOpt::deserialize_compressed(
		// 	&mut beacon_config.public_key.into_inner().as_slice()
		// ).unwrap();

		// let signature = G1AffineOpt::deserialize_compressed(
		// 	&mut pulse.signature.into_inner().as_slice()
		// ).unwrap();

		// let message = message(pulse.round, &vec![]);
		
		// let hasher = <TinyBLS381 as EngineBLS>::hash_to_curve_map();
		// let message_hash = hasher.hash(&message)
		// 	.expect("handle this later");
		// let mut bytes = Vec::new();
		// message_hash.serialize_compressed(&mut bytes).unwrap();
		// let message_on_curve: G1AffineOpt = G1ProjectiveOpt::deserialize_compressed(&bytes[..]).unwrap().into();
		// let g2 = G2AffineOpt::generator();

		// // // check that the pairings are equal
		// let p1 = bls12_381::pairing_opt(-signature, g2);
		// let p2 = bls12_381::pairing_opt(message_on_curve, pk);
		// p1 == p2
		false
	}
}