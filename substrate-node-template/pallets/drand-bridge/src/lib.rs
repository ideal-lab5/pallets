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

use alloc::{format, vec::Vec};
use codec::{Encode, Decode};
use serde::{Serialize, Deserialize};
use sp_runtime::{
	offchain::{
		http,
		storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
		Duration,
	},
	traits::Zero,
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	RuntimeDebug,
};
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

pub const API_ENDPOINT: &str = "https://api.drand.sh";
pub const QUICKNET_CHAIN_HASH: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// a pulse from the drand beacon
#[derive(Debug,  Decode, Default, PartialEq, Encode, Serialize, Deserialize)]
pub struct Pulse {
	/// the randomness round number
	pub round: u32,
	/// the sha256 hash of the signature (todo: use Hash)
	#[serde(with = "hex::serde")]
	pub randomness: Vec<u8>,
	/// BLS sig for the current round (todo: use Signature)
	#[serde(with = "hex::serde")]
	pub signature: Vec<u8>,
	// /// BLS sig from the previous round
	// pub previous_signature: Option<Vec<u8>>,
}

impl Pulse {
	fn verify(&self) -> bool {
		true
	}
}

// All pallet logic is defined in its own module and must be annotated by the `pallet` attribute.
#[frame_support::pallet]
pub mod pallet {
	// Import various useful types required by all FRAME pallets.
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	// The `Pallet` struct serves as a placeholder to implement traits, methods and dispatchables
	// (`Call`s) in this pallet.
	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching runtime event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// A type representing the weights required by the dispatchables of this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A user has successfully set a new value.
		SomethingStored {
			/// The new value set.
			something: u32,
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
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(_bn: BlockNumberFor<T>) {
			log::info!("fetching fresh randomness from drand");
			if let Err(e) = Self::fetch_drand() {
				log::info!("ERROR FETCHING FROM DRAND {:?}", e);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn submit_pulse_unsigned(
			origin: OriginFor<T>, 
			something: u32,
		) -> DispatchResult {
			// https://github.com/noislabs/drand-verify/blob/main/examples/drand_verify.rs
			// Check that the extrinsic was signed and get the signer.
			// let who = ensure_signed(origin)?;

			// // Update storage.
			// Something::<T>::put(something);

			// // Emit an event.
			// Self::deposit_event(Event::SomethingStored { something, who });

			// Return a successful `DispatchResult`
			Ok(())
		}
	}
} 

impl<T: Config> Pallet<T> {
	/// fetches the latest randomness from drand's API
	fn fetch_drand() -> Result<(), http::Error> {
		log::info!("calling fetch_drand function");
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		let uri: &str = &format!("{}/{}/public/latest", API_ENDPOINT, QUICKNET_CHAIN_HASH);
		// let uri = API_ENDPOINT + "/" + QUICKNET_CHAIN_HASH + "/public/latest"
		log::info!("URI: {}", uri.clone());
		let request = http::Request::get(uri);
		let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		// Let's check the status code before we proceed to reading the response.
		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown)
		}

		// Next we want to fully read the response body and collect it to a vector of bytes.
		// Note that the return object allows you to read the body in chunks as well
		// with a way to control the deadline.
		let body = response.body().collect::<Vec<u8>>();
		// panic!("{:?}", body);
		// Create a str slice from the body.
		let body_str = alloc::str::from_utf8(&body).map_err(|_| {
			log::warn!("No UTF8 body");
			http::Error::Unknown
		})?;

		let pulse: Pulse = serde_json::from_str(body_str).unwrap();
		log::info!("{:?}", pulse);

		if !pulse.verify() {
			// if the pulse is invalid, then we reject it
		}

		Ok(())
	}
}
