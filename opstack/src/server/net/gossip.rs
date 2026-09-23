use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use eyre::Result;
use libp2p::{
    futures::StreamExt,
    gossipsub::{self, IdentTopic, Message, MessageId},
    multiaddr::Protocol,
    noise, ping,
    swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use libp2p_identity::Keypair;
use sha2::{Digest, Sha256};
use tokio::select;

use super::{block_handler::BlockHandler, discovery};

/// OP Stack gossip service
pub struct GossipService {
    /// The socket address that the service is listening on.
    addr: SocketAddr,
    /// The chain ID of the network
    chain_id: u64,
    /// A unique keypair to validate the node's identity
    keypair: Option<Keypair>,
    /// Handler for the block
    block_handler: BlockHandler,
}

impl GossipService {
    /// Creates a new [Service]
    pub fn new(addr: SocketAddr, chain_id: u64, handler: BlockHandler) -> Self {
        Self {
            addr,
            chain_id,
            keypair: None,
            block_handler: handler,
        }
    }

    /// Sets the keypair for [Service]
    pub fn set_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Starts the Discv5 peer discovery & libp2p services
    /// and continually listens for new peers and messages to handle
    pub fn start(self) -> Result<()> {
        let keypair = self.keypair.unwrap_or_else(Keypair::generate_secp256k1);

        let mut swarm = create_swarm(keypair, &self.block_handler)?;
        let mut peer_recv = discovery::start(self.addr, self.chain_id)?;
        let multiaddr = socket_to_multiaddr(self.addr);

        swarm
            .listen_on(multiaddr)
            .map_err(|_| eyre::eyre!("swarm listen failed"))?;

        let peers = std::env::var("OP_NODE_P2P_STATIC").unwrap_or_default();
        let static_peers = peers
            .split(',')
            .filter(|peer| !peer.is_empty())
            .map(str::parse::<Multiaddr>)
            .collect::<Result<Vec<_>, _>>()?;

        let idle_timeout = std::env::var("OP_NODE_P2P_STATIC_IDLE_TIMEOUT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map(Duration::from_secs);

        tokio::spawn(async move {
            let mut reconnect = tokio::time::interval(Duration::from_secs(5));
            let mut last_activity = tokio::time::Instant::now();
            let mut latest_block = self.block_handler.latest_block();
            loop {
                select! {
                    _ = reconnect.tick() => {
                        let current_block = self.block_handler.latest_block();
                        if current_block > latest_block {
                            latest_block = current_block;
                            last_activity = tokio::time::Instant::now();
                        }
                        for peer in &static_peers {
                            if let Some(Protocol::P2p(id)) = peer.iter().last() {
                                if let Ok(id) = PeerId::from_multihash(id) {
                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&id);
                                    if swarm.is_connected(&id) {
                                        if idle_timeout.is_some_and(|timeout| last_activity.elapsed() >= timeout) {
                                            tracing::warn!(%id, "static peer is idle; reconnecting");
                                            _ = swarm.disconnect_peer_id(id);
                                            last_activity = tokio::time::Instant::now();
                                        }
                                        continue;
                                    }
                                }
                            }
                            let _ = swarm.dial(peer.clone());
                        }
                    },
                    peer = peer_recv.recv() => {
                        if let Some(peer) = peer {
                            tracing::info!("adding peer");
                            let peer = socket_to_multiaddr(peer);
                            _ = swarm.dial(peer);
                        }
                    },
                    event = swarm.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(event) => event.handle(&mut swarm, &self.block_handler),
                            other => tracing::debug!("swarm event: {:?}", other),
                        }
                    },
                }
            }
        });

        Ok(())
    }
}

fn socket_to_multiaddr(socket: SocketAddr) -> Multiaddr {
    let mut multiaddr = Multiaddr::empty();
    match socket.ip() {
        IpAddr::V4(ip) => multiaddr.push(Protocol::Ip4(ip)),
        IpAddr::V6(ip) => multiaddr.push(Protocol::Ip6(ip)),
    }
    multiaddr.push(Protocol::Tcp(socket.port()));
    multiaddr
}

/// Computes the message ID of a `gossipsub` message
fn compute_message_id(msg: &Message) -> MessageId {
    let decoded = snap::raw::decompress_len(&msg.data)
        .ok()
        .filter(|len| *len <= 10 * 1024 * 1024)
        .and_then(|_| snap::raw::Decoder::new().decompress_vec(&msg.data).ok());
    let topic = msg.topic.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update([u8::from(decoded.is_some()), 0, 0, 0]);
    hasher.update((topic.len() as u64).to_le_bytes());
    hasher.update(topic);
    hasher.update(decoded.as_deref().unwrap_or(&msg.data));
    MessageId(hasher.finalize()[..20].to_vec())
}

/// Creates the libp2p [Swarm]
fn create_swarm(keypair: Keypair, handler: &BlockHandler) -> Result<Swarm<Behaviour>> {
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&keypair)?)
        .multiplex(yamux::Config::default())
        .boxed();

    let behaviour = Behaviour::new(handler)?;

    Ok(
        SwarmBuilder::with_tokio_executor(transport, behaviour, PeerId::from(keypair.public()))
            .build(),
    )
}

/// Specifies the [NetworkBehaviour] of the node
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
struct Behaviour {
    /// Adds [libp2p::ping] to respond to inbound pings, and send periodic outbound pings
    ping: ping::Behaviour,
    /// Adds [libp2p::gossipsub] to enable gossipsub as the routing layer
    gossipsub: gossipsub::Behaviour,
}

impl Behaviour {
    /// Configures the swarm behaviors, subscribes to the gossip topics, and returns a new [Behaviour]
    fn new(handler: &BlockHandler) -> Result<Self> {
        let ping = ping::Behaviour::default();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(10 * 1024 * 1024)
            .mesh_n(8)
            .mesh_n_low(6)
            .mesh_n_high(12)
            .gossip_lazy(6)
            .heartbeat_interval(Duration::from_millis(500))
            .fanout_ttl(Duration::from_secs(24))
            .history_length(12)
            .history_gossip(3)
            .duplicate_cache_time(Duration::from_secs(65))
            .validation_mode(gossipsub::ValidationMode::None)
            .validate_messages()
            .message_id_fn(compute_message_id)
            .build()
            .map_err(|_| eyre::eyre!("gossipsub config creation failed"))?;

        let mut gossipsub =
            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Anonymous, gossipsub_config)
                .map_err(|_| eyre::eyre!("gossipsub behaviour creation failed"))?;

        handler
            .topics()
            .iter()
            .map(|topic| {
                let topic = IdentTopic::new(topic.to_string());
                gossipsub
                    .subscribe(&topic)
                    .map_err(|_| eyre::eyre!("subscription failed"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { ping, gossipsub })
    }
}

/// The type of message received
#[derive(Debug)]
enum Event {
    /// Represents a [ping::Event]
    #[allow(dead_code)]
    Ping(ping::Event),
    /// Represents a [gossipsub::Event]
    Gossipsub(gossipsub::Event),
}

impl Event {
    /// Handles received gossipsub messages. Ping messages are ignored.
    /// Reports back to [libp2p::gossipsub] to apply peer scoring and forward the message to other peers if accepted.
    fn handle(self, swarm: &mut Swarm<Behaviour>, handler: &BlockHandler) {
        if let Self::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        }) = self
        {
            let status = handler.handle(message);

            _ = swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &propagation_source, status);
        }
    }
}

impl From<ping::Event> for Event {
    /// Converts [ping::Event] to [Event]
    fn from(value: ping::Event) -> Self {
        Event::Ping(value)
    }
}

impl From<gossipsub::Event> for Event {
    /// Converts [gossipsub::Event] to [Event]
    fn from(value: gossipsub::Event) -> Self {
        Event::Gossipsub(value)
    }
}
