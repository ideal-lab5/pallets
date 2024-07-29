//! # Drand Bridge Pallet
//!
//! A pallet to bridge to [drand](drand.love)'s Quicknet, injecting publicly verifiable randomness into the runtime
//!
//! ## Overview
//!
//! Quicknet chain runs in an 'unchained' mode, producing a fresh pulse of randomness every 3s
//! This pallet implements an offchain worker that consumes pulses from quicket and then sends a signed
//! transaction to encode them in the runtime. The runtime uses the optimized arkworks host functions
//! to efficiently verify the pulse.
//!
//! Run `cargo doc --package pallet-drand --open` to view this pallet's documentation.

// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

extern crate alloc;
use crate::alloc::string::ToString;

use alloc::{format, string::String, vec, vec::Vec};
use codec::{Encode, Decode};
use serde::{Serialize, Deserialize};
use sp_runtime::{
	offchain::{
		http,
		Duration,
	},
	traits::Hash,
	KeyTypeId,
};
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::BlockNumberFor;
use frame_support::traits::Randomness;
use frame_system::offchain::{
	AppCrypto, 
	CreateSignedTransaction, 
	SendSignedTransaction, 
	Signer
};
use sha2::{Digest, Sha256};
use ark_serialize::CanonicalSerialize;
use ark_ec::{
	AffineRepr,
	hashing::HashToCurve,
};
use sp_ark_bls12_381::{
	G1Affine as G1AffineOpt, 
	G2Affine as G2AffineOpt
};

use w3f_bls::{EngineBLS, TinyBLS381};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;

pub mod bls12_381;
pub mod utils;

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
pub type BoundedHash = BoundedVec<u8, ConstU32<32>>;
/// the round number to track rounds of the beacon 
pub type RoundNumber = u64;

/// the expected response body from the drand api endpoint `api.drand.sh/{chainId}/info`
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

/// metadata associated with the drand info response
#[derive(Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize, TypeInfo, Clone)]
pub struct MetadataInfoResponse {
	#[serde(rename = "beaconID")]
	beacon_id: String,
}

impl BeaconInfoResponse {
    fn try_into_beacon_config(&self) -> Result<BeaconConfiguration, String> {
        let bounded_pubkey = OpaquePublicKeyG2::try_from(self.public_key.clone())
            .map_err(|_| "Failed to convert public_key")?;
        let bounded_hash = BoundedHash::try_from(self.hash.clone())
            .map_err(|_| "Failed to convert hash")?;
        let bounded_group_hash = BoundedHash::try_from(self.group_hash.clone())
            .map_err(|_| "Failed to convert group_hash")?;
        let bounded_scheme_id = BoundedHash::try_from(self.scheme_id.as_bytes().to_vec().clone())
            .map_err(|_| "Failed to convert scheme_id")?;
        let bounded_beacon_id = BoundedHash::try_from(self.metadata.beacon_id.as_bytes().to_vec().clone())
            .map_err(|_| "Failed to convert beacon_id")?;

        Ok(BeaconConfiguration {
            public_key: bounded_pubkey,
            period: self.period,
            genesis_time: self.genesis_time,
            hash: bounded_hash,
            group_hash: bounded_group_hash,
            scheme_id: bounded_scheme_id,
            metadata: Metadata {
                beacon_id: bounded_beacon_id,
            },
        })
    }
}

/// a pulse from the drand beacon 
/// the expected response body from the drand api endpoint `api.drand.sh/{chainId}/pulse/latest`
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
    fn try_into_pulse(&self) -> Result<Pulse, String> {
        let bounded_randomness = BoundedVec::<u8, ConstU32<32>>::try_from(self.randomness.clone())
            .map_err(|_| "Failed to convert randomness")?;
        let bounded_signature = BoundedVec::<u8, ConstU32<144>>::try_from(self.signature.clone())
            .map_err(|_| "Failed to convert signature")?;

        Ok(Pulse {
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
	pub hash: BoundedHash,
	pub group_hash: BoundedHash,
	pub scheme_id: BoundedHash, 
	pub metadata: Metadata,
}

/// metadata for the drand beacon configuration
#[derive(Clone, Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize, MaxEncodedLen, TypeInfo)]
pub struct Metadata {
	beacon_id: BoundedHash,
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

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

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
		/// something that knows how to verify beacon pulses
		type Verifier: Verifier;
		/// The origin permissioned to update beacon configurations
		type UpdateOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	/// the drand beacon configuration
	#[pallet::storage]
	pub type BeaconConfig<T: Config> = StorageValue<_, BeaconConfiguration, OptionQuery>;

	/// pulses received from drand
	#[pallet::storage]
	pub type Pulses<T: Config> = StorageValue<_, BoundedVec<Pulse, T::MaxPulses>, ValueQuery>;

	/// map block number to index of pulse authored during that block
	#[pallet::storage]
	pub type PulseIndex<T: Config> = StorageMap<
		_, 
		Blake2_128Concat,
		BlockNumberFor<T>,
		u32,
		OptionQuery
	>;

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
		/// failed to connect to the
		DrandConnectionFailure,
		/// the pulse is invalid
		UnverifiedPulse,
		/// the round number did not increment
		InvalidRoundNumber,
		/// the pulse could not be verified
		PulseVerificationError,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(_bn: BlockNumberFor<T>) {
			// if the beacon config isn't available, get it now
			if BeaconConfig::<T>::get().is_none() {
				if let Err(e) = Self::fetch_drand_config() {
					log::error!(
						"Failed to fetch chain info from drand, are you sure the chain hash is valid? {:?}",
						e
					);
				}
			} else {
				// otherwise query drand
				if let Err(e) = Self::fetch_drand_and_send_signed() {
					log::error!(
						"Failed to fetch chain info from drand, are you sure the chain hash is valid? {:?}",
						e
					);
				}
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		
		/// Verify and write a pulse from the beacon into the runtime
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::write_pulse())]
		pub fn write_pulse(
			origin: OriginFor<T>, 
			pulse: Pulse,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			if let Some(config) = BeaconConfig::<T>::get() {
				let is_verified = T::Verifier::verify(config, pulse.clone())
					.map_err(|s| {
						log::error!("Could not verify the pulse due to: {}", s);
						return Error::<T>::PulseVerificationError;
					})?;
				if is_verified {
					let mut pulses = Pulses::<T>::get();

					if !pulses.is_empty() {
						// check that we have incremented the round number
						let last = &pulses[pulses.len() - 1];
						frame_support::ensure!(
							last.round < pulse.round, 
							Error::<T>::InvalidRoundNumber
						);
					}

					if let Ok(_) = pulses.try_push(pulse.clone()) {
						let current_block = frame_system::Pallet::<T>::block_number();
						PulseIndex::<T>::insert(current_block, pulses.len() as u32);
						Pulses::<T>::put(pulses);

					}
					Self::deposit_event(Event::NewPulse { round: pulse.round, who });
				}
			}

			Ok(())
		}

		/// allows the root user to set the beacon configuration
		/// generally this would be called from an offchain worker context.
		/// there is no verification of configurations, so be careful with this.
		///
		/// * `origin`: the root user
		/// * `config`: the beacon configuration
		///
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_beacon_config())]
		pub fn set_beacon_config(
			origin: OriginFor<T>,
			config: BeaconConfiguration,
		) -> DispatchResult {
			T::UpdateOrigin::ensure_origin(origin)?;
			BeaconConfig::<T>::put(config);			
			Self::deposit_event(Event::BeaconConfigChanged { });
			Ok(())
		}
	}
} 

impl<T: Config> Pallet<T> {

	/// query drand's /info endpoint for the quicknet chain
	/// then send a signed transaction to encode it on-chain
	fn fetch_drand_config() -> Result<(), &'static str> {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)?
		}

		let body_str = Self::fetch_drand_chain_info()
        	.map_err(|_| "Failed to fetch drand chain info")?;
		let beacon_config: BeaconInfoResponse = serde_json::from_str(&body_str)
			.map_err(|_| "Failed to convert response body to beacon configuration")?;
		let config = beacon_config.try_into_beacon_config()
        	.map_err(|_| "Failed to convert BeaconInfoResponse to BeaconConfiguration")?;

		let results = signer.send_signed_transaction(|_account| Call::set_beacon_config { config: config.clone() });
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
	fn fetch_drand_and_send_signed() -> Result<(), &'static str> {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)?
		}

		let pulse_body = Self::fetch_drand().map_err(|_| "Failed to query drand")?;
		let unbounded_pulse: DrandResponseBody = serde_json::from_str(&pulse_body)
			.map_err(|_| "Failed to serialize response body to pulse")?;
		let pulse = unbounded_pulse.try_into_pulse()
			.map_err(|_| "Received pulse contains invalid data")?;
	
		let results = signer.send_signed_transaction(|_account| Call::write_pulse { pulse: pulse.clone() });

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted new pulse: {:?}", acc.id, pulse.round),
				Err(e) => log::info!("[{:?}] Failed to submit transaction: {:?}", acc.id, e),
			}
		}

		Ok(())
	}
	
	/// Query the endpoint `{api}/{chainHash}/info` to receive information about the drand chain
	/// Valid response bodies are deserialized into `BeaconInfoResponse`
	fn fetch_drand_chain_info() -> Result<String, http::Error> {
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

		Ok(body_str.to_string())
	}

	/// fetches the latest randomness from drand's API
	fn fetch_drand() -> Result<String, http::Error> {
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

		Ok(body_str.to_string())
	}

	pub fn latest_random() -> [u8;32] {
		let pulses = Pulses::<T>::get();
		if !pulses.is_empty() {
			let rand = pulses[pulses.len() - 1].randomness.clone();
			let bounded_rand: [u8;32] = rand.into_inner()
				.try_into()
				.unwrap_or([0u8;32]);
			return bounded_rand;
		}

		[0u8;32]
	}

	// pub fn pulse_by_block_number(block_number: BlockNumberFor<T>) -> Option<Vec<u8>> {
	// 	if let Some(idx) = PulseIndex::<T>::get(block_number)  {
	// 		let pulses = Pulses::<T>::get();
	// 		// make sure the index is valid
	// 		if pulses.len() < idx as usize {
	// 			return None;
	// 		}

	// 		return Some(pulses[idx as usize].randomness.clone().into());
	// 	}

	// 	None
	// }
}

/// construct a message (e.g. signed by drand)
pub fn message(current_round: RoundNumber, prev_sig: &[u8]) -> Vec<u8> {
	let mut hasher = Sha256::default();
	hasher.update(prev_sig);
	hasher.update(current_round.to_be_bytes());
	hasher.finalize().to_vec()
}

/// something to verify beacon pulses
pub trait Verifier {
	/// verify the given pulse using beacon_config
	fn verify(beacon_config: BeaconConfiguration, pulse: Pulse) -> Result<bool, String>;
}

/// A verifier to check values received from quicknet. It outputs true if valid, false otherwise
///
/// [Quicknet](https://drand.love/blog/quicknet-is-live-on-the-league-of-entropy-mainnet) operates in an unchained mode, 
/// so messages contain only the round number. in addition, public keys are in G2 and signatures are in G1
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
	fn verify(beacon_config: BeaconConfiguration, pulse: Pulse) -> Result<bool, String> {
		// decode public key (pk)
		let pk = ArkScale::<G2AffineOpt>::decode(
			&mut beacon_config.public_key.into_inner().as_slice()
		).map_err(|e| format!("Failed to decode public key: {}", e))?;
	
		// decode signature (sigma)
		let signature = ArkScale::<G1AffineOpt>::decode(
			&mut pulse.signature.into_inner().as_slice()
		).map_err(|e| format!("Failed to decode signature: {}", e))?;
	
		// m = sha256({}{round})
		let message = message(pulse.round, &vec![]);
		let hasher = <TinyBLS381 as EngineBLS>::hash_to_curve_map();
		// H(m) \in G1
		let message_hash = hasher.hash(&message).map_err(|e| format!("Failed to hash message: {}", e))?;
		
		let mut bytes = Vec::new();
		message_hash.serialize_compressed(&mut bytes)
			.map_err(|e| format!("Failed to serialize message hash: {}", e))?;
		
		let message_on_curve = ArkScale::<G1AffineOpt>::decode(
			&mut &bytes[..]
		).map_err(|e| format!("Failed to decode message on curve: {}", e))?;
		
		let g2 = G2AffineOpt::generator();
		let mut g2_bytes = Vec::new();
		g2.serialize_compressed(&mut g2_bytes)
			.map_err(|e| format!("Failed to serialize G2 generator: {}", e))?;
		
		let g2_scale = ArkScale::<G2AffineOpt>::decode(&mut g2_bytes.as_slice())
			.map_err(|e| format!("Failed to decode G2 scale: {}", e))?;
	
		// check that the pairings are equal
		// e(-sigma, g2) == e(msg, pk)
		let p1 = bls12_381::pairing_opt(-signature.0, g2_scale.0);
		let p2 = bls12_381::pairing_opt(message_on_curve.0, pk.0);
		
		Ok(p1 == p2)
	}
}

impl<T: Config> Randomness<T::Hash, BlockNumberFor<T>> for Pallet<T> {
	// this function hashes together the subject with the latest known randomness from quicknet
	fn random(subject: &[u8]) -> (T::Hash, BlockNumberFor<T>) {
		let block_number = <frame_system::Pallet<T>>::block_number();
		let pulses = Pulses::<T>::get();
		// return hash of empty string if there is no onchain randomness
		if pulses.is_empty() {
			return (T::Hash::default(), block_number);
		}

		let latest = &pulses[pulses.len() - 1];

		let entropy = (subject, block_number, latest.randomness.clone())
			.using_encoded(T::Hashing::hash);

		(entropy, block_number)
	}
}