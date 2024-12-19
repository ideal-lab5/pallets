//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use drand_example_runtime::{self, opaque::Block, RuntimeApi};
use frame_system::BlockHash;
use futures::{FutureExt, StreamExt};
use libp2p::{
	gossipsub,
	gossipsub::{
		Behaviour as GossipsubBehaviour, Config as GossipsubConfig,
		ConfigBuilder as GossipsubConfigBuilder, Event as GossipsubEvent, IdentTopic,
		Message as GossipsubMessage, MessageAuthenticity, MessageId, PublishError,
		SubscriptionError, Topic, TopicHash,
	},
	identity::Keypair,
	swarm::{NetworkBehaviour, Swarm, SwarmEvent},
	Transport,
};
use log;
use prost::bytes::{Buf, BufMut};
use prost::decode_length_delimiter;
use prost::DecodeError;
use sc_client_api::{Backend, BlockBackend};
use sc_consensus_aura::{ImportQueueParams, SlotProportion, StartAuraParams};
use sc_consensus_grandpa::SharedVoterState;
use sc_network::{
	config::notification_service, config::MultiaddrWithPeerId, multiaddr::Protocol,
	service::NetworkWorker, types::ProtocolName, Multiaddr, PeerId,
};
use sc_network_types::{
	multihash,
	multihash::{Code, Multihash},
};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager, WarpSyncConfig};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
use sp_runtime::traits::Block as BlockT;
use std::hash::DefaultHasher;
use std::net::ToSocketAddrs;
use std::sync::Mutex;
use std::{sync::Arc, time::Duration};

/// Host runctions required for Substrate and Arkworks
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions =
	(sp_io::SubstrateHostFunctions, sp_crypto_ec_utils::bls12_381::host_calls::HostFunctions);

/// Host runctions required for Substrate and Arkworks
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
	sp_io::SubstrateHostFunctions,
	sp_crypto_ec_utils::bls12_381::host_calls::HostFunctions,
	frame_benchmarking::benchmarking::HostFunctions,
);

/// A specialized `WasmExecutor`
pub type RuntimeExecutor = sc_executor::WasmExecutor<HostFunctions>;

pub(crate) type FullClient = sc_service::TFullClient<Block, RuntimeApi, RuntimeExecutor>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub const DRAND_SWARM_ADDR: &str = "/dnsaddr/api.drand.sh";
pub const DRAND_QUICKNET_PUBSUB_TOPIC: &str =
	"/drand/pubsub/v0.0.0/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// The minimum period of blocks on which justifications will be
/// imported and generated.
const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

pub type Service = sc_service::PartialComponents<
	FullClient,
	FullBackend,
	FullSelectChain,
	sc_consensus::DefaultImportQueue<Block>,
	sc_transaction_pool::FullPool<Block, FullClient>,
	(
		sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>,
		sc_consensus_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
		Option<Telemetry>,
	),
>;

pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = sc_service::new_wasm_executor::<HostFunctions>(&config.executor);
	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, RuntimeExecutor>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
		client.clone(),
		GRANDPA_JUSTIFICATION_PERIOD,
		&client,
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let cidp_client = client.clone();
	let import_queue =
		sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(ImportQueueParams {
			block_import: grandpa_block_import.clone(),
			justification_import: Some(Box::new(grandpa_block_import.clone())),
			client: client.clone(),
			create_inherent_data_providers: move |parent_hash, _| {
				let cidp_client = cidp_client.clone();
				async move {
					let slot_duration = sc_consensus_aura::standalone::slot_duration_at(
						&*cidp_client,
						parent_hash,
					)?;
					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

					let slot =
						sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
							*timestamp,
							slot_duration,
						);

					Ok((slot, timestamp))
				}
			},
			spawner: &task_manager.spawn_essential_handle(),
			registry: config.prometheus_registry(),
			check_for_equivocation: Default::default(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			compatibility_mode: Default::default(),
		})?;

	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (grandpa_block_import, grandpa_link, telemetry),
	})
}

/// Builds a new service for a full client.
pub fn new_full<
	N: sc_network::NetworkBackend<Block, <Block as sp_runtime::traits::Block>::Hash>,
>(
	config: Configuration,
) -> Result<TaskManager, ServiceError> {
	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (block_import, grandpa_link, mut telemetry),
	} = new_partial(&config)?;

	let mut net_config = sc_network::config::FullNetworkConfiguration::<
		Block,
		<Block as sp_runtime::traits::Block>::Hash,
		N,
	>::new(&config.network, config.prometheus_registry().cloned());

	let metrics = N::register_notification_metrics(config.prometheus_registry());

	let peer_store_handle = net_config.peer_store_handle();
	let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
		&client.block_hash(0).ok().flatten().expect("Genesis block exists; qed"),
		&config.chain_spec,
	);
	let (grandpa_protocol_config, grandpa_notification_service) =
		sc_consensus_grandpa::grandpa_peers_set_config::<_, N>(
			grandpa_protocol_name.clone(),
			metrics.clone(),
			peer_store_handle,
		);
	net_config.add_notification_protocol(grandpa_protocol_config);

	let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		grandpa_link.shared_authority_set().clone(),
		Vec::default(),
	));

	let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_config: Some(WarpSyncConfig::WithProvider(warp_sync)),
			block_relay: None,
			metrics,
		})?;

	if config.offchain_worker.enabled {
		// For testing purposes only: insert OCW key for Alice
		sp_keystore::Keystore::sr25519_generate_new(
			&*keystore_container.keystore(),
			drand_example_runtime::pallet_drand::KEY_TYPE,
			Some("//Alice"),
		)
		.expect("Creating key with account Alice should succeed.");

		task_manager.spawn_handle().spawn(
			"offchain-workers-runner",
			"offchain-worker",
			sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
				runtime_api_provider: client.clone(),
				is_validator: config.role.is_authority(),
				keystore: Some(keystore_container.keystore()),
				offchain_db: backend.offchain_storage(),
				transaction_pool: Some(OffchainTransactionPoolFactory::new(
					transaction_pool.clone(),
				)),
				network_provider: Arc::new(network.clone()),
				enable_http_requests: true,
				custom_extensions: |_| vec![],
			})
			.run(client.clone(), task_manager.spawn_handle())
			.boxed(),
		);

		// configure gossipsub for the libp2p network
		let local_identity: sc_network_types::ed25519::Keypair =
			config.network.node_key.clone().into_keypair()?;
		let local_public = local_identity.public().to_peer_id();
		let local_identity: libp2p::identity::ed25519::Keypair = local_identity.into();

		let local_identity: Keypair = local_identity.into();
		// TODO: handle error
		let mut gossipsub = GossipsubNetwork::new(&local_identity).unwrap();

		// Spawn the gossipsub network task
		task_manager.spawn_handle().spawn(
			"gossipsub-network",
			None,
			async move {
				if let Err(e) = gossipsub.subscribe(DRAND_QUICKNET_PUBSUB_TOPIC).await {
					log::error!("Failed to run gossipsub network: {:?}", e);
				}
			}
			.boxed(),
		);
	}

	let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks: Option<()> = None;
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa;
	let prometheus_registry = config.prometheus_registry().cloned();

	let rpc_extensions_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();

		Box::new(move |_| {
			let deps = crate::rpc::FullDeps { client: client.clone(), pool: pool.clone() };
			crate::rpc::create_full(deps).map_err(Into::into)
		})
	};

	let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		network: Arc::new(network.clone()),
		client: client.clone(),
		keystore: keystore_container.keystore(),
		task_manager: &mut task_manager,
		transaction_pool: transaction_pool.clone(),
		rpc_builder: rpc_extensions_builder,
		backend,
		system_rpc_tx,
		tx_handler_controller,
		sync_service: sync_service.clone(),
		config,
		telemetry: telemetry.as_mut(),
	})?;

	if role.is_authority() {
		let proposer_factory = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let slot_duration = sc_consensus_aura::slot_duration(&*client)?;

		let aura = sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _>(
			StartAuraParams {
				slot_duration,
				client,
				select_chain,
				block_import,
				proposer_factory,
				create_inherent_data_providers: move |_, ()| async move {
					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

					let slot =
						sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
							*timestamp,
							slot_duration,
						);

					Ok((slot, timestamp))
				},
				force_authoring,
				backoff_authoring_blocks,
				keystore: keystore_container.keystore(),
				sync_oracle: sync_service.clone(),
				justification_sync_link: sync_service.clone(),
				block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
				max_block_proposal_slot_portion: None,
				telemetry: telemetry.as_ref().map(|x| x.handle()),
				compatibility_mode: Default::default(),
			},
		)?;

		// the AURA authoring task is considered essential, i.e. if it
		// fails we take down the service with it.
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("aura", Some("block-authoring"), aura);
	}

	if enable_grandpa {
		// if the node isn't actively participating in consensus then it doesn't
		// need a keystore, regardless of which protocol we use below.
		let keystore = if role.is_authority() { Some(keystore_container.keystore()) } else { None };

		let grandpa_config = sc_consensus_grandpa::Config {
			// FIXME #1578 make this available through chainspec
			gossip_duration: Duration::from_millis(333),
			justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
			name: Some(name),
			observer_enabled: false,
			keystore,
			local_role: role,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			protocol_name: grandpa_protocol_name,
		};

		// start the full GRANDPA voter
		// NOTE: non-authorities could run the GRANDPA observer protocol, but at
		// this point the full voter should provide better guarantees of block
		// and vote data availability than the observer. The observer has not
		// been tested extensively yet and having most nodes in a network run it
		// could lead to finality stalls.
		let grandpa_config = sc_consensus_grandpa::GrandpaParams {
			config: grandpa_config,
			link: grandpa_link,
			network,
			sync: Arc::new(sync_service),
			notification_service: grandpa_notification_service,
			voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
			prometheus_registry,
			shared_voter_state: SharedVoterState::empty(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
		};

		// the GRANDPA voter task is considered infallible, i.e.
		// if it fails we take down the service with it.
		task_manager.spawn_essential_handle().spawn_blocking(
			"grandpa-voter",
			None,
			sc_consensus_grandpa::run_grandpa_voter(grandpa_config)?,
		);
	}

	network_starter.start_network();
	Ok(task_manager)
}

// DNS resolution helper function
fn multiaddress_resolve(address: &str) -> Result<Vec<Multiaddr>, Box<dyn std::error::Error>> {
	let mut resolved_addresses = Vec::new();

	// Extract hostname from the multiaddress
	let hostname = address
		.split('/')
		.filter(|s| !s.is_empty())
		.nth(1)
		.ok_or("Invalid multiaddress")?;

	// Resolve DNS
	let socket_addrs = format!("{}:44544", hostname).to_socket_addrs()?;

	for addr in socket_addrs {
		let ip_multiaddr = Multiaddr::from(addr.ip()).with(Protocol::Tcp(addr.port()));
		let random_peer_id = PeerId::random();
		let multihash =
			Multihash::wrap(multihash::Code::Sha2_256.into(), random_peer_id.as_ref().digest())
				.map_err(|_| "Failed to create multihash")?;

		let full_multiaddr = ip_multiaddr.with(Protocol::P2p(multihash));

		resolved_addresses.push(full_multiaddr);
	}

	Ok(resolved_addresses)
}

fn decode_raw_string(buf: &[u8]) -> Result<String, DecodeError> {
	let mut buffer = buf;

	// Decode the length delimiter (a varint indicating the length of the string)
	let length = prost::encoding::decode_length_delimiter(&mut buffer)?;

	// Extract the string bytes using the decoded length
	if buffer.remaining() < length {
		return Err(DecodeError::new("Buffer does not contain enough data"));
	}

	let string_bytes = buffer.copy_to_bytes(length);

	log::info!("************************************************************ {:?}", string_bytes);

	// Convert the string bytes to a UTF-8 string
	Ok(String::from_utf8(string_bytes.to_vec()).unwrap())
}
pub struct GossipsubNetwork {
	swarm: Swarm<GossipsubBehaviour>,
}

impl GossipsubNetwork {
	pub fn new(local_key: &Keypair) -> Result<Self, Box<dyn std::error::Error>> {
		// Set the message authenticity - How we expect to publish messages
		// Here we expect the publisher to sign the message with their key.
		let message_authenticity = MessageAuthenticity::Signed(local_key.clone());

		// Create the Swarm
		// Create the transport with TCP
		let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
			.upgrade(libp2p::core::upgrade::Version::V1)
			.authenticate(libp2p::noise::Config::new(local_key)?)
			.multiplex(libp2p::yamux::Config::default())
			.boxed();

		// set default parameters for gossipsub
		let gossipsub_config = libp2p::gossipsub::Config::default();
		// build a gossipsub network behaviour
		let mut gossipsub: libp2p::gossipsub::Behaviour =
			libp2p::gossipsub::Behaviour::new(message_authenticity, gossipsub_config).unwrap();

		let mut swarm = libp2p::swarm::SwarmBuilder::without_executor(
			transport,
			gossipsub,
			local_key.public().to_peer_id(),
		)
		.build();
		// dig TXT _dnsaddr.api.drand.sh
		let maddr1: libp2p::Multiaddr =
			"/ip4/184.72.27.233/tcp/44544/p2p/12D3KooWBhAkxEn3XE7QanogjGrhyKBMC5GeM3JUTqz54HqS6VHG"
				.parse()
				.unwrap();
		let maddr2: libp2p::Multiaddr = "/ip4/54.193.191.250/tcp/44544/p2p/12D3KooWQqDi3D3KLfDjWATQUUE4o5aSshwBFi9JM36wqEPMPD5y".parse().unwrap();
		swarm.dial(maddr1)?;
		swarm.dial(maddr2)?;
		Ok(Self { swarm })
	}

	pub async fn subscribe(&mut self, topic_str: &str) -> Result<(), Box<dyn std::error::Error>> {
		// Start listening on a random port
		self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

		log::info!("Subscribing to gossipsub topic: {:?}", topic_str);
		let topic = IdentTopic::new(topic_str);
		self.swarm.behaviour_mut().subscribe(&topic)?;

		loop {
			match self.swarm.next().await {
				Some(SwarmEvent::Behaviour(gossipsub::Event::Message {
					propagation_source,
					message_id,
					message,
				})) => {
					log::info!(
						"********************************************************** Got message: '{}' with id: {} from peer: {:?}",
						// &decode_raw_string(&message.data).unwrap(),
						String::from_utf8_lossy(&message.data),
						message_id,
						propagation_source
					);
				},
				Some(SwarmEvent::NewListenAddr { address, .. }) => {
					log::info!("********************************************************** Listening on {:?}", address);
				},
				Some(x) => {
					log::info!(
						"********************************************************** {:?}",
						x
					);
				},
				_ => {},
			}
		}
	}

	pub fn publish(
		&mut self,
		topic_str: &str,
		data: Vec<u8>,
	) -> Result<(), Box<dyn std::error::Error>> {
		let topic = IdentTopic::new(topic_str);
		self.swarm.behaviour_mut().publish(topic, data)?;
		Ok(())
	}
}

/*
Ok, some notes, because this is getting pretty confusing
I think I can add the gossipsub protocol by including it in the RequestResponse behaviours list,
protocol > request_responses.rs line 277
But, I'm not sure how to do that... or where that is even defined in the first place in this file, specifically.

*/
