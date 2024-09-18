use crate as pallet_etf;
use frame_support::traits::{ConstBool, ConstU64};
use sp_core::{ConstU32, H256};
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
};
use sp_runtime::BuildStorage;
use etf_crypto_primitives::encryption::tlock::DecryptionResult;
use sp_consensus_etf_aura::sr25519::AuthorityId as AuraId;

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
        Proxy: pallet_proxy,
        Otp: pallet_otp,
		// Balances: pallet_balances,
		// Aura: pallet_etf_aura,
		// Etf: pallet_etf,
	}
);

type AccountId = u64;

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU64<250>;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<3>;
}

// impl pallet_balances::Config for Test {
// 	type Balance = u64;
// 	type DustRemoval = ();
// 	type RuntimeEvent = RuntimeEvent;
// 	type ExistentialDeposit = ConstU64<1>;
// 	type AccountStore = System;
// 	type WeightInfo = ();
// 	type MaxLocks = ();
// 	type MaxReserves = ();
// 	type ReserveIdentifier = [u8; 8];
// 	type RuntimeHoldReason = RuntimeHoldReason;
// 	type RuntimeFreezeReason = RuntimeFreezeReason;
// 	type FreezeIdentifier = ();
// 	type MaxHolds = ConstU32<10>;
// 	type MaxFreezes = ();
// }


// impl pallet_timestamp::Config for Test {
// 	type Moment = u64;
// 	type OnTimestampSet = Aura;
// 	type MinimumPeriod = ConstU64<1>;
// 	type WeightInfo = ();
// }

// impl pallet_etf_aura::Config for Test {
// 	type AuthorityId = AuraId;
// 	type DisabledValidators = ();
// 	type MaxAuthorities = ConstU32<32>;
// 	type AllowMultipleBlocksPerSlot = ConstBool<false>;

// 	#[cfg(feature = "experimental")]
// 	type SlotDuration = pallet_etf_aura::MinimumPeriodTimesTwo<Test>;
// }

// impl pallet_etf::Config for Test {
// 	type RuntimeEvent = RuntimeEvent;
// 	type WeightInfo = pallet_etf::weights::SubstrateWeightInfo<Test>;
// }

impl pallet_proxy::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ProxyType = ();
	type ProxyDepositBase = ConstU64<1>;
	type ProxyDepositFactor = ConstU64<1>;
	type MaxProxies = ConstU32<32>;
	type WeightInfo = ();
	type MaxPending = ConstU32<32>;
	type CallHasher = BlakeTwo256;
	type AnnouncementDepositBase = ConstU64<1>;
	type AnnouncementDepositFactor = ConstU64<1>;
}

/// a passthrough dummy tlock provider
/// doesn't actually do anything, just passes the ciphertext as the plaintext
pub struct DummyTlock;
impl TlockProvider<u64> for DummyTlock {
    fn decrypt_at(
        passthrough: &[u8], 
        block_number: u64
    ) -> Result<DecryptionResult, pallet_randomness_beacon::TimelockError> {
        let result = DecryptionResult {
            message: passthrough.clone().to_vec(),
            secret: &[],
        };
        Ok(result)
    }
}

impl pallet_otp::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type TlockProvider = DummyTlock;
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

	config.assimilate_storage(&mut storage).unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
	// Clear thread local vars for https://github.com/paritytech/substrate/issues/10479.
	// ext.execute_with(|| take_hooks());
	ext.execute_with(|| System::set_block_number(1));
	ext
}
