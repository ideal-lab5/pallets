use crate::{mock::*, Error, Event, Pulse, Pulses, BeaconConfig, BeaconConfiguration, DrandResponseBody, BeaconInfoResponse};
use frame_support::{assert_noop, assert_ok};
use codec::Encode;
use sp_runtime::offchain::{
	OffchainWorkerExt,
	testing::{PendingRequest, TestOffchainExt},
};

pub const DRAND_RESPONSE: &str = "{\"round\":9683710,\"randomness\":\"87f03ef5f62885390defedf60d5b8132b4dc2115b1efc6e99d166a37ab2f3a02\",\"signature\":\"b0a8b04e009cf72534321aca0f50048da596a3feec1172a0244d9a4a623a3123d0402da79854d4c705e94bc73224c342\"}";
pub const QUICKNET_INFO_RESPONSE: &str = "{\"public_key\":\"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a\",\"period\":3,\"genesis_time\":1692803367,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\",\"metadata\":{\"beaconID\":\"quicknet\"}}";


#[test]
fn can_fail_submit_valid_pulse_when_beacon_config_missing() {
	new_test_ext().execute_with(|| {
		let u_p: DrandResponseBody = serde_json::from_str(DRAND_RESPONSE).unwrap();
		let p: Pulse = u_p.try_into_pulse().unwrap();

		let alice = sp_keyring::Sr25519Keyring::Alice.public();
		System::set_block_number(1);
		// Dispatch a signed extrinsic.
		assert_ok!(Drand::write_pulse(
			RuntimeOrigin::signed(alice.clone()), 
			p.clone())
		);
		// // Read pallet storage and assert an expected result.
		let pulses = Pulses::<Test>::get();
		assert_eq!(pulses.len(), 0);
		
	});
}


#[test]
fn can_submit_valid_pulse_when_beacon_config_exists() {
	new_test_ext().execute_with(|| {
		let u_p: DrandResponseBody = serde_json::from_str(DRAND_RESPONSE).unwrap();
		let p: Pulse = u_p.try_into_pulse().unwrap();

		let alice = sp_keyring::Sr25519Keyring::Alice.public();
		System::set_block_number(1);

		let info: BeaconInfoResponse = serde_json::from_str(QUICKNET_INFO_RESPONSE).unwrap();
		assert_ok!(Drand::set_beacon_config(RuntimeOrigin::root(), info.clone().try_into_beacon_config().unwrap()));
		
		// Dispatch a signed extrinsic.
		assert_ok!(Drand::write_pulse(
			RuntimeOrigin::signed(alice.clone()), 
			p.clone())
		);
		// // Read pallet storage and assert an expected result.
		let pulses = Pulses::<Test>::get();
		assert_eq!(pulses.len(), 1);
		assert_eq!(pulses[0], p);
		// // Assert that the correct event was deposited
		System::assert_last_event(Event::NewPulse {
			round: 9683710, 
			who: alice,
		}.into());
	});
}

// pulses rejected for:
// invalid size
// unverifiable
// invalid round number

#[test]
fn rejects_invalid_pulse() {
	new_test_ext().execute_with(|| {
		let http_response = "{\"round\":9683710,\"randomness\":\"87f03ef5f62885390defedf60d5b8132b4dc2115b1efc6e99d166a37ab2f3a02\",\"signature\":\"b0a8b04e009cf72534321aca0f50048da596a3feec1172a0244d9a4a623a3123d0402da79854d4c705e94bc73224c341\"}";
		let u_p: DrandResponseBody = serde_json::from_str(http_response).unwrap();
		let p: Pulse = u_p.try_into_pulse().unwrap();

		// let alice = sp_keyring::AccountKeyring::Alice.to_account_id().public();
		let alice = sp_keyring::Sr25519Keyring::Alice.public();
		// Go past genesis block so events get deposited
		System::set_block_number(1);
		// Dispatch a signed extrinsic.
		assert_ok!(Drand::write_pulse(
			RuntimeOrigin::signed(alice.clone()), 
			p.clone())
		);
		// // Read pallet storage and assert an expected result.
		let pulses = Pulses::<Test>::get();
		assert_eq!(pulses.len(), 0);
		// assert_eq!(pulses[0], []);
		// // Assert that the correct event was deposited
		// System::assert_last_event(Event::NewPulse {
		// 	round: 9683710, 
		// 	who: alice,
		// }.into());
	});
}

#[test]
fn root_can_submit_beacon_info() {
	new_test_ext().execute_with(|| {
		let info: BeaconInfoResponse = serde_json::from_str(QUICKNET_INFO_RESPONSE).unwrap();
		let alice = sp_keyring::Sr25519Keyring::Alice.public();
		assert!(BeaconConfig::<Test>::get().is_none());
		System::set_block_number(1);
		// Dispatch a signed extrinsic.
		assert_ok!(Drand::set_beacon_config(RuntimeOrigin::root(), info.clone().try_into_beacon_config().unwrap()));

		assert!(
			BeaconConfig::<Test>::get().unwrap()
				.eq(&info.try_into_beacon_config().unwrap()
		));
	});
}

#[test]
fn non_root_cannot_submit_beacon_info() {
	new_test_ext().execute_with(|| {
		let info: BeaconInfoResponse = serde_json::from_str(QUICKNET_INFO_RESPONSE).unwrap();
		let alice = sp_keyring::Sr25519Keyring::Alice.public();
		assert!(BeaconConfig::<Test>::get().is_none());
		System::set_block_number(1);
		// Dispatch a signed extrinsic.
		assert_noop!(
			Drand::set_beacon_config(
				RuntimeOrigin::signed(alice.clone()), 
				info.clone().try_into_beacon_config().unwrap()
			),
			sp_runtime::DispatchError::BadOrigin,
		);
	});
}

#[test]
fn knows_how_to_mock_http_calls() {
	let (offchain, state) = TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainWorkerExt::new(offchain));

	{
		let mut state = state.write();
		state.expect_request(PendingRequest {
			method: "GET".into(),
			uri: "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info".into(),
			response: Some(QUICKNET_INFO_RESPONSE.as_bytes().to_vec()),
			sent: true,
			..Default::default()
		});
		state.expect_request(PendingRequest {
			method: "GET".into(),
			uri: "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest".into(),
			response: Some(DRAND_RESPONSE.as_bytes().to_vec()),
			sent: true,
			..Default::default()
		});
	}

	let expected_config: BeaconInfoResponse = serde_json::from_str(QUICKNET_INFO_RESPONSE).unwrap();
	
	let expected_pulse: DrandResponseBody = serde_json::from_str(DRAND_RESPONSE).unwrap();

	t.execute_with(|| {
		let actual_config = Drand::fetch_drand_chain_info().unwrap();
		assert_eq!(actual_config, expected_config.try_into_beacon_config().unwrap());

		let actual_pulse = Drand::fetch_drand().unwrap();
		assert_eq!(actual_pulse, expected_pulse);
	});
}