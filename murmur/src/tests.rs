use crate::{mock::*, Error};
use ark_std::{test_rng, UniformRand};
use ark_serialize::CanonicalSerialize;
use frame_support::{assert_noop, assert_ok};

#[test]
fn it_can_create_wallet() {
    
	new_test_ext().execute_with(|| {
		
	});
}

// #[test]
// fn it_fails_to_update_generator_when_not_decodable() {
// 	let mut rng = test_rng();
	
// 	let g = ark_bls12_381::G1Affine::rand(&mut rng);
// 	let mut g_bytes = Vec::new();
// 	g.serialize_compressed(&mut g_bytes).unwrap();
// 	let hex = hex::encode(&g_bytes);

// 	let y = ark_bls12_381::G2Affine::rand(&mut rng);
// 	let mut y_bytes = Vec::new();
// 	y.serialize_compressed(&mut y_bytes).unwrap();
// 	let y_hex = hex::encode(&y_bytes);

// 	new_test_ext(&hex.clone(), &y_hex.clone()).execute_with(|| {
		
// 		let mut h_bytes = Vec::new();
// 		h_bytes.push(1);

// 		assert_noop!(
// 			Etf::update_ibe_params(
// 				RuntimeOrigin::root(),
// 				h_bytes.clone(),
// 				h_bytes.clone(),
// 				h_bytes.clone(),
// 			),
// 			Error::<Test>::G1DecodingFailure,
// 		);
// 	});
// }
