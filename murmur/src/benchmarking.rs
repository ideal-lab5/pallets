// //! Benchmarking setup for pallet-etf
// #![cfg(feature = "runtime-benchmarks")]
// use super::*;

// #[allow(unused)]
// use crate::Pallet as Etf;
// use frame_benchmarking::v2::*;
// use frame_system::RawOrigin;

// #[benchmarks]
// mod benchmarks {
// 	use super::*;

// 	#[benchmark]
// 	fn update_ibe_params() {
// 		let g1_bytes = array_bytes::hex2bytes_unchecked("a191b705ef18a6e4e5bd4cc56de0b8f94b1f3c908f3e3fcbd4d1dc12eb85059be7e7d801edc1856c8cfbe6d63a681c1f");
// 		let g2_bytes = array_bytes::hex2bytes_unchecked("878c5832d9519a9a22cee4d790be6bef6a0bc55e2c4c38185bf497061fb2712309f59e9eed0cdac8f8c97a61427bf35003065d0f83dca6defed8f50d715bb9430375153dff0b52bae38acf8d3aeb1612248856a8deae883f32dacaa04e3fba26");
// 		#[extrinsic_call]
// 		update_ibe_params(RawOrigin::Root, g1_bytes.clone(), g2_bytes.clone(), g2_bytes.clone());
// 		assert_eq!(IBEParams::<T>::get(), (g1_bytes.clone(), g2_bytes.clone(), g2_bytes.clone()));
// 	}

// 	impl_benchmark_test_suite!(
//         Etf, crate::mock::new_test_ext(
// 			&"a191b705ef18a6e4e5bd4cc56de0b8f94b1f3c908f3e3fcbd4d1dc12eb85059be7e7d801edc1856c8cfbe6d63a681c1f",
// 			&"878c5832d9519a9a22cee4d790be6bef6a0bc55e2c4c38185bf497061fb2712309f59e9eed0cdac8f8c97a61427bf35003065d0f83dca6defed8f50d715bb9430375153dff0b52bae38acf8d3aeb1612248856a8deae883f32dacaa04e3fba26",
// 		),
//         crate::mock::Test);
// }
