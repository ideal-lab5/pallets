//! Benchmarking setup for pallet-template
#![cfg(feature = "runtime-benchmarks")]
use super::*;

#[allow(unused)]
use crate::Pallet as Drand;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

pub const DRAND_RESPONSE: &str = "{\"round\":9683710,\"randomness\":\"87f03ef5f62885390defedf60d5b8132b4dc2115b1efc6e99d166a37ab2f3a02\",\"signature\":\"b0a8b04e009cf72534321aca0f50048da596a3feec1172a0244d9a4a623a3123d0402da79854d4c705e94bc73224c342\"}";
pub const QUICKNET_INFO_RESPONSE: &str = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":3,\"genesis_time\":1692803367,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\",\"metadata\":{\"beaconID\":\"quicknet\"}}";

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn set_beacon_config() {
		let info: BeaconInfoResponse = serde_json::from_str(QUICKNET_INFO_RESPONSE)
			.unwrap();
		let config = info.try_into_beacon_config().unwrap();
		// let value = 100u32.into();
		// let caller: T::AccountId = whitelisted_caller();
		#[extrinsic_call]
		set_beacon_config(RawOrigin::Root, config.clone());
		assert_eq!(BeaconConfig::<T>::get(), Some(config));
	}

	#[benchmark]
	fn update_beacon_pulses() {
		// let info: BeaconInfoResponse = serde_json::from_str(QUICKNET_INFO_RESPONSE)
		// 	.unwrap();
		// let config = info.try_into_beacon_config().unwrap();
		// let value = 100u32.into();
		let u_p: DrandResponseBody = serde_json::from_str(DRAND_RESPONSE).unwrap();
		let mut p: Pulse = u_p.try_into_pulse().unwrap();

		let caller: T::AccountId = whitelisted_caller();
		#[extrinsic_call]
		write_pulse(RawOrigin::Signed(caller), p.clone());
		assert_eq!(Pulses::<T>::get(), vec![]);
	}

	impl_benchmark_test_suite!(Drand, crate::mock::new_test_ext(), crate::mock::Test);
}
