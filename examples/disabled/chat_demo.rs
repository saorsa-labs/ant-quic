//! Chat demo example showing P2P messaging over QUIC
//!
//! This example demonstrates the chat protocol implementation
//! with NAT traversal support.

use ant_quic::{
    auth::AuthConfig,
    chat::{ChatMessage, PeerInfo},
    crypto::raw_public_keys::key_utils::{
        derive_peer_id_from_public_key, generate_ed25519_keypair,
    },
    nat_traversal_api::{EndpointRole, PeerId},
    quic_node::{QuicNodeConfig, QuicP2PNode},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::{error, info};

#[derive(Clone)]
struct ChatNode {
    node: Arc<QuicP2PNode>,
    peer_id: PeerId,
    nickname: String,
    peers: Arc<Mutex<HashMap<PeerId, PeerInfo>>>,
}

impl ChatNode {
    async fn new(
        role: EndpointRole,
        bootstrap_nodes: Vec<SocketAddr>,
        nickname: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Generate identity
        let (_private_key, public_key) = generate_ed25519_keypair();
        let peer_id = derive_peer_id_from_public_key(&public_key);

        // Create QUIC node
        let config = QuicNodeConfig {
            role,
            bootstrap_nodes,
            enable_coordinator: matches!(role, EndpointRole::Server { .. }),
            max_connections: 50,
            connection_timeout: Duration::from_secs(30),
            stats_interval: Duration::from_secs(60),
            auth_config: AuthConfig::default(),
            bind_addr: None,
        };

        let node = Arc::new(QuicP2PNode::new(config).await?);

        Ok(Self {
            node,
            peer_id,
            nickname,
            peers: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn connect_known_peer(
        &self,
        known_peer_addr: SocketAddr,
    ) -> Result<PeerId, Box<dyn std::error::Error + Send + Sync>> {
        info!("Connecting to known peer at {}", known_peer_addr);

        // Use the unified address-based outbound path
        let known_peer_id = self
            .node
            .connect_addr(known_peer_addr)
            .await
            .map_err(|e| format!("Failed to connect to known peer: {e}"))?;

        // Send join message to the connected peer
        let join_msg = ChatMessage::join(self.nickname.clone(), self.peer_id);
        let data = join_msg.serialize()?;
        self.node
            .send_to_peer(&known_peer_id, &data)
            .await
            .map_err(|e| format!("Failed to send join message to known peer: {e}"))?;

        Ok(known_peer_id)
    }

    async fn connect_peer(
        &self,
        peer_id: PeerId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Connecting to peer {:?}", peer_id);

        let addr = self.node.connect_peer(peer_id).await?;
        info!("Connected to peer at {}", addr);

        // Send join message
        let join_msg = ChatMessage::join(self.nickname.clone(), self.peer_id);
        let data = join_msg.serialize()?;
        self.node
            .send_to_peer(&peer_id, &data)
            .await
            .map_err(|e| format!("Failed to send join message: {e}"))?;

        Ok(())
    }

    async fn send_message(
        &self,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = ChatMessage::text(self.nickname.clone(), self.peer_id, text);
        let data = msg.serialize()?;

        // Send to all connected peers
        let peers = self.peers.lock().await;
        for (peer_id, _) in peers.iter() {
            if let Err(e) = self.node.send_to_peer(peer_id, &data).await {
                error!("Failed to send to peer {:?}: {}", peer_id, e);
            }
        }

        Ok(())
    }

    async fn handle_incoming_messages(&self) {
        loop {
            match self.node.receive().await {
                Ok((peer_id, data)) => match ChatMessage::deserialize(&data) {
                    Ok(msg) => {
                        self.handle_chat_message(peer_id, msg).await;
                    }
                    Err(e) => {
                        error!("Failed to deserialize message: {}", e);
                    }
                },
                Err(_) => {
                    // No messages available
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_chat_message(&self, peer_id: PeerId, msg: ChatMessage) {
        match msg {
            ChatMessage::Join {
                nickname,
                peer_id: sender_id,
                timestamp,
            } => {
                info!("[{}] joined the chat", nickname);
                let mut peers = self.peers.lock().await;
                peers.insert(
                    peer_id,
                    PeerInfo {
                        peer_id: sender_id,
                        nickname,
                        status: "Online".to_string(),
                        joined_at: timestamp,
                    },
                );
            }
            ChatMessage::Leave { nickname, .. } => {
                info!("[{}] left the chat", nickname);
                self.peers.lock().await.remove(&peer_id);
            }
            ChatMessage::Text { nickname, text, .. } => {
                println!("[{nickname}]: {text}");
            }
            ChatMessage::Status {
                nickname, status, ..
            } => {
                info!("[{}] status: {}", nickname, status);
                if let Some(peer_info) = self.peers.lock().await.get_mut(&peer_id) {
                    peer_info.status = status;
                }
            }
            ChatMessage::Direct {
                from_nickname,
                text,
                ..
            } => {
                println!("[DM from {from_nickname}]: {text}");
            }
            ChatMessage::Typing {
                nickname,
                is_typing,
                ..
            } => {
                if is_typing {
                    info!("[{}] is typing...", nickname);
                }
            }
            ChatMessage::PeerListRequest { .. } => {
                // Send peer list response
                let peers = self.peers.lock().await;
                let peer_list: Vec<PeerInfo> = peers.values().cloned().collect();
                let response = ChatMessage::PeerListResponse { peers: peer_list };
                if let Ok(data) = response.serialize() {
                    let _ = self.node.send_to_peer(&peer_id, &data).await;
                }
            }
            ChatMessage::PeerListResponse { peers } => {
                info!("Received peer list with {} peers", peers.len());
                for peer in peers {
                    info!("  - {}: {}", peer.nickname, peer.status);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("ant_quic=info,chat_demo=info")
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <coordinator|client> [known_peer_addrs...]",
            args[0]
        );
        eprintln!("       known_peer_addrs: comma-separated list of addresses");
        eprintln!(
            "Example: {} client 192.168.1.10:9000,192.168.1.11:9000",
            args[0]
        );
        std::process::exit(1);
    }

    let mode = &args[1];
    let known_peer_addrs: Vec<SocketAddr> = if args.len() > 2 {
        args[2]
            .split(',')
            .filter_map(|addr| {
                addr.trim().parse::<SocketAddr>().ok().or_else(|| {
                    eprintln!("Warning: Invalid known peer address: {}", addr.trim());
                    None
                })
            })
            .collect()
    } else {
        vec![
            "127.0.0.1:9000"
                .parse()
                .map_err(|e| format!("Failed to parse default known peer address: {}", e))?,
        ]
    };

    // Create chat node
    let (role, nickname) = match mode.as_str() {
        "coordinator" => (
            EndpointRole::Server {
                can_coordinate: true,
            },
            "Coordinator".to_string(),
        ),
        "client" => (
            EndpointRole::Client,
            format!("Client-{}", rand::random::<u16>()),
        ),
        _ => {
            eprintln!("Invalid mode: {mode}. Use 'coordinator' or 'client'");
            std::process::exit(1);
        }
    };

    let chat_node = ChatNode::new(role, known_peer_addrs.clone(), nickname.clone()).await?;
    info!("Started {} with peer ID: {:?}", nickname, chat_node.peer_id);

    // Connect to known peers if we're a client
    if matches!(role, EndpointRole::Client) && !known_peer_addrs.is_empty() {
        info!("Connecting to {} known peers", known_peer_addrs.len());
        for known_peer_addr in &known_peer_addrs {
            info!("Connecting to known peer at {}", known_peer_addr);
            match chat_node.connect_known_peer(*known_peer_addr).await {
                Ok(known_peer_id) => {
                    info!(
                        "Connected to known peer {} with peer ID: {:?}",
                        known_peer_addr, known_peer_id
                    );
                    // Add known peer to our peer list
                    chat_node.peers.lock().await.insert(
                        known_peer_id,
                        PeerInfo {
                            peer_id: known_peer_id.0, // Use the inner byte array
                            nickname: format!("KnownPeer-{known_peer_addr}"),
                            status: "connected".to_string(),
                            joined_at: std::time::SystemTime::now(),
                        },
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to connect to known peer {}: {}",
                        known_peer_addr, e
                    );
                }
            }
        }
    }

    // Start message handler
    let handler_node = chat_node.clone();
    tokio::spawn(async move {
        handler_node.handle_incoming_messages().await;
    });

    // Start stats reporting
    let _stats_handle = chat_node.node.start_stats_task();

    // Simple CLI interface
    println!("Chat node started. Commands:");
    println!("  /connect <peer_id_hex> - Connect to a peer by identity");
    println!("  /peers - List connected peers");
    println!("  /quit - Exit");
    println!("  <text> - Send message to all peers");

    let stdin = std::io::stdin();
    let mut line = String::new();

    loop {
        line.clear();
        if stdin.read_line(&mut line).is_err() {
            break;
        }

        let line = line.trim();

        if line.starts_with("/connect ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Parse peer ID
                if let Ok(peer_id_bytes) = hex::decode(parts[1]) {
                    if peer_id_bytes.len() == 32 {
                        let mut peer_id_array = [0u8; 32];
                        peer_id_array.copy_from_slice(&peer_id_bytes);
                        let peer_id = PeerId(peer_id_array);

                        if let Err(e) = chat_node.connect_peer(peer_id).await {
                            error!("Failed to connect: {}", e);
                        }
                    } else {
                        error!("Peer ID must be 32 bytes (64 hex chars)");
                    }
                } else {
                    error!("Invalid peer ID hex: {}", parts[1]);
                }
            } else {
                println!("Usage: /connect <peer_id_hex>");
            }
        } else if line == "/peers" {
            let peers = chat_node.peers.lock().await;
            println!("Connected peers: {}", peers.len());
            for (_, peer_info) in peers.iter() {
                println!(
                    "  - {} ({}): {}",
                    peer_info.nickname,
                    hex::encode(&peer_info.peer_id[..8]),
                    peer_info.status
                );
            }
        } else if line == "/quit" {
            break;
        } else if !line.is_empty() {
            if let Err(e) = chat_node.send_message(line.to_string()).await {
                error!("Failed to send message: {}", e);
            }
        }
    }

    info!("Chat node shutting down");
    Ok(())
}
