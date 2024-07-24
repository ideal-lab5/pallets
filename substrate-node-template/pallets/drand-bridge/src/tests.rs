use crate::{mock::*, Error, Event, Pulse};
use frame_support::{assert_noop, assert_ok};

#[test]
fn it_works_for_default_value() {
	// new_test_ext().execute_with(|| {
		let http_response = "{\"round\":9683710,\"randomness\":\"87f03ef5f62885390defedf60d5b8132b4dc2115b1efc6e99d166a37ab2f3a02\",\"signature\":\"b0a8b04e009cf72534321aca0f50048da596a3feec1172a0244d9a4a623a3123d0402da79854d4c705e94bc73224c342\"}";
		// let p: Pulse = serde_json::from_str(http_response).unwrap();
		// // Go past genesis block so events get deposited
		// System::set_block_number(1);
		// // Dispatch a signed extrinsic.
		// assert_ok!(TemplateModule::do_something(RuntimeOrigin::signed(1), 42));
		// // Read pallet storage and assert an expected result.
		// assert_eq!(Something::<Test>::get(), Some(42));
		// // Assert that the correct event was deposited
		// System::assert_last_event(Event::SomethingStored { something: 42, who: 1 }.into());
	// });

}
