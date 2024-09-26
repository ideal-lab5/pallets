// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use std::vec;
use crate::{self as etf, mock::*, Call, Config, Error, Weight};

#[test]
fn genesis_session_initializes_resharing_and_commitments_with_valid_values() {
	let genesis_resharing = vec![
			(1, vec![2]), 
			(2, vec![2]),
            (3, vec![2])
		];

	let want_resharing = genesis_resharing.clone();
	let genesis_roundkey = [1;96].to_vec();

	new_test_ext(vec![1, 2, 3]).execute_with(|| {
		// resharings are populated
		let resharings = etf::Shares::<Test>::get();
		assert_eq!(resharings.len(), 3);
		assert_eq!(resharings[0], want_resharing[0].1);
		assert_eq!(resharings[1], want_resharing[1].1);
        assert_eq!(resharings[2], want_resharing[2].1);
	});
}