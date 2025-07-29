use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{info, error};

use crate::turn::{
    allocation::AllocationManager,
    auth::{NonceManager, UserDatabase},
};

#[derive(Clone)]
pub struct TurnServerConfig {
    pub listen_address: SocketAddr,
    pub realm: String,
    pub relay_address_start: SocketAddr,
    pub relay_address_count: u16,
}

impl Default for TurnServerConfig {
    fn default() -> Self {
        TurnServerConfig {
            listen_address: "0.0.0.0:3478".parse().unwrap(),
            realm: "turn.example.com".to_string(),
            relay_address_start: "0.0.0.0:49152".parse().unwrap(),
            relay_address_count: 100,
        }
    }
}

pub struct TurnServer {
    config: TurnServerConfig,
    socket: Arc<UdpSocket>,
    allocation_manager: Arc<AllocationManager>,
    nonce_manager: Arc<RwLock<NonceManager>>,
    user_database: Arc<UserDatabase>,
}

impl TurnServer {
    pub async fn new(config: TurnServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = Arc::new(UdpSocket::bind(&config.listen_address).await?);
        info!("TURN server listening on {}", config.listen_address);

        // Generate relay addresses
        let mut relay_addresses = Vec::new();
        let base_port = config.relay_address_start.port();
        for i in 0..config.relay_address_count {
            let mut addr = config.relay_address_start;
            addr.set_port(base_port + i);
            relay_addresses.push(addr);
        }

        let allocation_manager = Arc::new(AllocationManager::new(relay_addresses));
        let nonce_manager = Arc::new(RwLock::new(NonceManager::new(Duration::from_secs(300))));
        let user_database = Arc::new(UserDatabase::new());

        Ok(TurnServer {
            config,
            socket,
            allocation_manager,
            nonce_manager,
            user_database,
        })
    }

    pub fn add_user(&mut self, username: String, password: String) {
        Arc::get_mut(&mut self.user_database)
            .unwrap()
            .add_user(username, password);
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; 65535];
        
        // Spawn cleanup task
        let allocation_mgr = self.allocation_manager.clone();
        let nonce_mgr = self.nonce_manager.clone();
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60));
            loop {
                cleanup_interval.tick().await;
                allocation_mgr.cleanup_expired();
                nonce_mgr.write().await.cleanup_expired();
            }
        });

        // Main server loop
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    let data = buf[..len].to_vec();
                    
                    // Clone necessary components for the spawned task
                    let socket = self.socket.clone();
                    let allocation_manager = self.allocation_manager.clone();
                    let nonce_manager = self.nonce_manager.clone();
                    let user_database = self.user_database.clone();
                    let realm = self.config.realm.clone();
                    
                    // Handle message in a separate task
                    tokio::spawn(async move {
                        if let Err(e) = crate::server::message_handler::handle_message(
                            data,
                            src_addr,
                            socket,
                            allocation_manager,
                            nonce_manager,
                            user_database,
                            realm,
                        ).await {
                            error!("Error handling message from {}: {}", src_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error receiving data: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        let config = TurnServerConfig {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            realm: "test.realm".to_string(),
            relay_address_start: "127.0.0.1:50000".parse().unwrap(),
            relay_address_count: 10,
        };

        let server = TurnServer::new(config).await.unwrap();
        assert_eq!(server.config.realm, "test.realm");
    }

    #[tokio::test]
    async fn test_add_user() {
        let config = TurnServerConfig {
            listen_address: "127.0.0.1:0".parse().unwrap(),
            realm: "test.realm".to_string(),
            relay_address_start: "127.0.0.1:51000".parse().unwrap(),
            relay_address_count: 10,
        };
        let mut server = TurnServer::new(config).await.unwrap();
        
        server.add_user("alice".to_string(), "password123".to_string());
        
        let has_user = server.user_database.authenticate("alice", "password123");
        assert!(has_user);
    }
}