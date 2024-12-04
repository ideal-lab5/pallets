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

//! # Murmur Pallet
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use ckb_merkle_mountain_range::MerkleProof;
use codec::{Decode, Encode};
use frame_support::{
	dispatch::GetDispatchInfo,
	pallet_prelude::*,
	traits::{ConstU32, IsSubType},
};
use murmur_core::{
	murmur::verifier::{verify_execute, verify_update},
	types::{Leaf, MergeLeaves},
};
use pallet_randomness_beacon::TimelockEncryptionProvider;
use scale_info::TypeInfo;
use sp_runtime::traits::Dispatchable;
use sp_std::{vec, vec::Vec};
use w3f_bls::TinyBLS377;

/// A bounded name of a Murmur Proxy
pub type Name = BoundedVec<u8, ConstU32<32>>;
/// A root of an MMR
pub type Root = BoundedVec<u8, ConstU32<32>>;
/// A serialized public key (TinyBLS377 > SignatureGroup)
pub type SerializedPublicKey = BoundedVec<u8, ConstU32<48>>;
/// A serialized DLEQ proof
pub type Proof = BoundedVec<u8, ConstU32<80>>;

/// A struct to represent specific details of a murmur proxy account
#[derive(
	Debug,
	PartialEq,
	Eq,
	Hash,
	Clone,
	Encode,
	Decode,
	TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct MurmurProxyDetails<AccountId> {
	/// The proxy account address
	pub address: AccountId,
	/// The MMR root
	pub root: Vec<u8>,
	/// The MMR size
	pub size: u64,
	/// The serialized VRF pubkey
	pub pubkey: Vec<u8>,
	/// The nonce of the Murmur proxy
	pub nonce: u64,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::{traits::Zero, DispatchResult};

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_proxy::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// The overarching call type.
		type RuntimeCall: Parameter
			+ Dispatchable<RuntimeOrigin = Self::RuntimeOrigin>
			+ GetDispatchInfo
			+ From<frame_system::Call<Self>>
			+ IsSubType<Call<Self>>
			+ IsType<<Self as frame_system::Config>::RuntimeCall>;
		/// Something that can decrypt messages locked for the current slot
		type TlockProvider: TimelockEncryptionProvider<BlockNumberFor<Self>>;
	}

	/// A registry to track registered 'usernames' for OTP wallets
	// Q: what happens when this map becomes very large? in terms of query time?
	#[pallet::storage]
	pub(super) type Registry<T: Config> =
		StorageMap<_, Blake2_256, Name, MurmurProxyDetails<T::AccountId>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A murmur proxy was created
		MurmurProxyCreated,
		/// A murmur proxy was execute
		MurmurProxyExecuted,
		/// A murmur proxy was updated
		MurmurProxyUpdated,
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// The ciphertext could not be recovered
		BadCiphertext,
		/// The input name is already used
		DuplicateName,
		/// The OTP code is invalid
		InvalidOTP,
		/// The Merkle proof could not be verified
		InvalidMerkleProof,
		/// The Schnorr proof could not be verified
		SchnorrProofVerificationFailed,
		/// https://crypto.stanford.edu/cs355/19sp/lec5.pdf
		InvalidSchnorrProof,
		/// The proxy is not registered as a Murmur wallet or does not exist
		InvalidProxy,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Create a time-based proxy account
		/// * `name`: The name to assign to the murmur proxy
		/// * `root`: The MMR root
		/// * `size`: The size (number of leaves) of the MMR
		/// * `proof`: A (serialized) DLEQ proof
		/// * `public_key`: A (serialized) public key associated with the DLEQ
		#[pallet::weight(0)]
		#[pallet::call_index(0)]
		pub fn create(
			origin: OriginFor<T>,
			name: Name,
			root: Root,
			size: u64,
			proof: Proof,
			pubkey: SerializedPublicKey,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let nonce = 0;

			let validity = verify_update::<TinyBLS377>(proof.to_vec(), pubkey.to_vec(), nonce)
				.map_err(|_| Error::<T>::SchnorrProofVerificationFailed)?;

			ensure!(validity == true, Error::<T>::InvalidSchnorrProof);

			// ensure unique names
			ensure!(Registry::<T>::get(name.clone()).is_none(), Error::<T>::DuplicateName);

			// create a pure proxy with no delegate
			let signed_origin: T::RuntimeOrigin =
				frame_system::RawOrigin::Signed(who.clone()).into();
			pallet_proxy::Pallet::<T>::create_pure(
				signed_origin,
				T::ProxyType::default(),
				BlockNumberFor::<T>::zero(),
				0u16,
				true,
			)?;

			let address =
				pallet_proxy::Pallet::<T>::pure_account(&who, &T::ProxyType::default(), 0, None);

			Registry::<T>::insert(
				name,
				&MurmurProxyDetails {
					address,
					root: root.to_vec(),
					size,
					pubkey: pubkey.to_vec(),
					nonce,
				},
			);
			Self::deposit_event(Event::MurmurProxyCreated);

			Ok(())
		}

		/// Update the MMR associated with a Murmur proxy
		/// Does not require a signed origin
		///
		/// * `name`: The name to assign to the murmur proxy
		/// * `root`: The MMR root
		/// * `size`: The size (number of leaves) of the MMR
		/// * `proof`: A (serialized) DLEQ proof
		#[pallet::weight(0)]
		#[pallet::call_index(1)]
		pub fn update(
			_origin: OriginFor<T>,
			name: Name,
			new_root: Root,
			new_size: u64,
			proof: Proof,
		) -> DispatchResult {
			let proxy_details = Registry::<T>::get(name.clone()).ok_or(Error::<T>::InvalidProxy)?;
			// verify the proof
			let next_nonce = proxy_details.nonce + 1;
			let validity = verify_update::<TinyBLS377>(
				proof.to_vec(),
				proxy_details.pubkey.to_vec(),
				next_nonce,
			)
			.map_err(|_| Error::<T>::SchnorrProofVerificationFailed)?;

			ensure!(validity, Error::<T>::InvalidSchnorrProof);
			// update proxy details
			let mut new_proxy_details = proxy_details.clone();
			new_proxy_details.root = new_root.to_vec();
			new_proxy_details.size = new_size;
			new_proxy_details.nonce = next_nonce;

			Registry::<T>::insert(name, &new_proxy_details);
			Self::deposit_event(Event::MurmurProxyUpdated);

			Ok(())
		}

		/// Proxy a call after verifying the ciphertext
		/// this function first checks the validity of the merkle proof (using the ciphertext)
		/// if valid, it decrypts the ciphertext and uses it to verify the hash
		/// if valid, it proxies the call
		///
		/// * `name`: The uid of the murmur proxy
		/// * `position`: The position in the MMR of the encrypted OTP code
		/// * `hash`: A hash to commit to the OTP code and call data
		/// * `ciphertext`: The encrypted OTP code
		/// * `proof`: A merkle proof that the target leaf is in the expected MMR at the given
		///   position
		/// * `size`: The size of the Merkle proof
		/// * `call`: The call to be proxied
		#[pallet::weight(0)]
		#[pallet::call_index(2)]
		pub fn proxy(
			_origin: OriginFor<T>,
			name: BoundedVec<u8, ConstU32<32>>,
			position: u64,
			hash: Vec<u8>,
			ciphertext: Vec<u8>,
			proof: Vec<Vec<u8>>,
			size: u64,
			call: sp_std::boxed::Box<<T as pallet_proxy::Config>::RuntimeCall>,
		) -> DispatchResult {
			let when = T::TlockProvider::latest();

			let proxy_details = Registry::<T>::get(name.clone()).ok_or(Error::<T>::InvalidProxy)?;

			let result = T::TlockProvider::decrypt_at(&ciphertext, when)
				.map_err(|_| Error::<T>::BadCiphertext)?;

			let otp = result.message;
			let leaves: Vec<Leaf> = proof.clone().into_iter().map(|p| Leaf(p)).collect::<Vec<_>>();

			let merkle_proof = MerkleProof::<Leaf, MergeLeaves>::new(size, leaves.clone());

			let root = Leaf(proxy_details.root.to_vec());

			let validity = verify_execute(
				root,
				merkle_proof,
				hash,
				ciphertext,
				&otp,
				&call.encode(),
				position,
			);

			frame_support::ensure!(validity, Error::<T>::InvalidMerkleProof);

			let def = pallet_proxy::Pallet::<T>::find_proxy(
				&proxy_details.address,
				None,
				Some(T::ProxyType::default()),
			)
			.map_err(|_| Error::<T>::InvalidProxy)?;

			pallet_proxy::Pallet::<T>::do_proxy(def, proxy_details.address, *call);

			Self::deposit_event(Event::MurmurProxyExecuted);
			Ok(())
		}
	}
}
