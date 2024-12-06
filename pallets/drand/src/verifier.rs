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

//! A collection of verifiers
use crate::{
	bls12_381,
	types::{BeaconConfiguration, Pulse, RoundNumber},
};
use alloc::{format, string::String, vec::Vec};
use ark_ec::{hashing::HashToCurve, AffineRepr};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use timelock::{curves::drand::TinyBLS381, tlock::EngineBLS};

#[cfg(not(feature = "host-arkworks"))]
use ark_bls12_381::{G1Affine as G1AffineOpt, G2Affine as G2AffineOpt};
#[cfg(not(feature = "host-arkworks"))]
use ark_serialize::CanonicalDeserialize;

#[cfg(feature = "host-arkworks")]
use codec::Decode;
#[cfg(feature = "host-arkworks")]
use sp_ark_bls12_381::{G1Affine as G1AffineOpt, G2Affine as G2AffineOpt};

#[cfg(feature = "host-arkworks")]
const USAGE: ark_scale::Usage = ark_scale::WIRE;
#[cfg(feature = "host-arkworks")]
type ArkScale<T> = ark_scale::ArkScale<T, USAGE>;

/// Constructs a message (e.g. signed by drand)
fn message(current_round: RoundNumber, prev_sig: &[u8]) -> Vec<u8> {
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
/// so messages contain only the round number. in addition, public keys are in G2 and signatures are
/// in G1
///
/// Values are valid if the pairing equality holds: $e(sig, g_2) == e(msg_on_curve, pk)$
/// where $sig \in \mathbb{G}_1$ is the signature
///       $g_2 \in \mathbb{G}_2$ is a generator
///       $msg_on_curve \in \mathbb{G}_1$ is a hash of the message that drand signed
/// (hash(round_number))       $pk \in \mathbb{G}_2$ is the public key, read from the input public
/// parameters
pub struct QuicknetVerifier;

impl Verifier for QuicknetVerifier {
	/// Verify the given pulse using beacon_config
	/// Returns true if the pulse is valid, false otherwise.
	///
	/// If `host-arkworks` feature is enabled, it will look for the arkworks functions in the host,
	/// if they are not found it will cause a panic.
	/// Running the arkworks functions in the host is significantly faster than running them inside
	/// wasm, but this is not always possible if we don't control the validator nodes (i.e. when
	/// running a parachain).
	///
	/// See see docs/integration.md for more information on how to use the `host-arkworks` feature.
	fn verify(beacon_config: BeaconConfiguration, pulse: Pulse) -> Result<bool, String> {
		// decode public key (pk)
		#[cfg(feature = "host-arkworks")]
		let pk = ArkScale::<G2AffineOpt>::decode(&mut beacon_config.public_key.into_inner().as_slice())
			.map_err(|e| format!("Failed to decode public key: {}", e))?;
		#[cfg(not(feature = "host-arkworks"))]
		let pk = G2AffineOpt::deserialize_compressed(
			&mut beacon_config.public_key.into_inner().as_slice(),
		)
		.map_err(|e| format!("Failed to decode public key: {}", e))?;

		// decode signature (sigma)
		#[cfg(feature = "host-arkworks")]
		let signature = ArkScale::<G1AffineOpt>::decode(&mut pulse.signature.into_inner().as_slice())
			.map_err(|e| format!("Failed to decode signature: {}", e))?;
		#[cfg(not(feature = "host-arkworks"))]
		let signature = G1AffineOpt::deserialize_compressed(&mut pulse.signature.into_inner().as_slice())
			.map_err(|e| format!("Failed to decode signature: {}", e))?;

		// m = sha256({} || {round})
		let message = message(pulse.round, &[]);
		let hasher = <TinyBLS381 as EngineBLS>::hash_to_curve_map();
		// H(m) \in G1
		let message_hash =
			hasher.hash(&message).map_err(|e| format!("Failed to hash message: {}", e))?;

		let mut bytes = Vec::new();
		message_hash
			.serialize_compressed(&mut bytes)
			.map_err(|e| format!("Failed to serialize message hash: {}", e))?;

		#[cfg(feature = "host-arkworks")]
		let message_on_curve = ArkScale::<G1AffineOpt>::decode(&mut &bytes[..])
			.map_err(|e| format!("Failed to decode message on curve: {}", e))?;
		#[cfg(not(feature = "host-arkworks"))]
		let message_on_curve = G1AffineOpt::deserialize_compressed(&mut &bytes[..])
			.map_err(|e| format!("Failed to decode message on curve: {}", e))?;

		let g2 = G2AffineOpt::generator();

		#[cfg(feature = "host-arkworks")]
		let result = bls12_381::fast_pairing_opt(signature.0, g2, message_on_curve.0, pk.0);
		#[cfg(not(feature = "host-arkworks"))]
		let result = bls12_381::fast_pairing_opt(signature, g2, message_on_curve, pk);

		Ok(result)
	}
}

/// The unsafe skip verifier is just a pass-through verification, always returns true.
/// Skipping the verification process can be dangerous, as it allows for malicious actors to
/// inject false pulses into the system. But it speeds up the process significantly.
/// This is useful for testing purposes or when fully trusting the source of the pulses.
pub struct UnsafeSkipVerifier;
impl Verifier for UnsafeSkipVerifier {
	fn verify(_beacon_config: BeaconConfiguration, _pulse: Pulse) -> Result<bool, String> {
		Ok(true)
	}
}
