use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use crate::turn::error::TurnError;

pub const DEFAULT_ALLOCATION_LIFETIME: Duration = Duration::from_secs(600); // 10 minutes
pub const MAX_ALLOCATION_LIFETIME: Duration = Duration::from_secs(3600); // 1 hour

#[derive(Debug, Clone)]
pub struct Allocation {
    pub username: String,
    pub relayed_address: SocketAddr,
    pub client_address: SocketAddr,
    pub created_at: Instant,
    pub lifetime: Duration,
    pub relay_socket: Arc<UdpSocket>,
    pub permissions: HashMap<SocketAddr, Instant>,
    pub channel_bindings: HashMap<u16, SocketAddr>,
}

impl Allocation {
    pub fn new(
        username: String,
        relayed_address: SocketAddr,
        client_address: SocketAddr,
        relay_socket: Arc<UdpSocket>,
    ) -> Self {
        Allocation {
            username,
            relayed_address,
            client_address,
            created_at: Instant::now(),
            lifetime: DEFAULT_ALLOCATION_LIFETIME,
            relay_socket,
            permissions: HashMap::new(),
            channel_bindings: HashMap::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.lifetime
    }

    pub fn refresh(&mut self, lifetime: Duration) -> Result<(), TurnError> {
        if lifetime > MAX_ALLOCATION_LIFETIME {
            return Err(TurnError::BadRequest);
        }
        
        self.lifetime = lifetime;
        self.created_at = Instant::now();
        Ok(())
    }

    pub fn add_permission(&mut self, peer_address: SocketAddr) {
        self.permissions.insert(peer_address, Instant::now());
    }

    pub fn has_permission(&self, peer_address: &SocketAddr) -> bool {
        match self.permissions.get(peer_address) {
            Some(granted_at) => {
                // Permissions last for 5 minutes
                granted_at.elapsed() < Duration::from_secs(300)
            }
            None => false,
        }
    }

    pub fn add_channel_binding(&mut self, channel_number: u16, peer_address: SocketAddr) -> Result<(), TurnError> {
        if !(0x4000..=0x7FFF).contains(&channel_number) {
            return Err(TurnError::BadRequest);
        }
        
        self.channel_bindings.insert(channel_number, peer_address);
        self.add_permission(peer_address);
        Ok(())
    }

    pub fn get_peer_by_channel(&self, channel_number: u16) -> Option<&SocketAddr> {
        self.channel_bindings.get(&channel_number)
    }

    pub fn cleanup_expired_permissions(&mut self) {
        let now = Instant::now();
        self.permissions.retain(|_, granted_at| {
            now.duration_since(*granted_at) < Duration::from_secs(300)
        });
    }
}

#[derive(Debug, Clone)]
pub struct AllocationManager {
    allocations: Arc<Mutex<HashMap<SocketAddr, Allocation>>>,
    relay_address_pool: Arc<Mutex<Vec<SocketAddr>>>,
}

impl AllocationManager {
    pub fn new(relay_addresses: Vec<SocketAddr>) -> Self {
        AllocationManager {
            allocations: Arc::new(Mutex::new(HashMap::new())),
            relay_address_pool: Arc::new(Mutex::new(relay_addresses)),
        }
    }

    pub async fn create_allocation(
        &self,
        username: String,
        client_address: SocketAddr,
    ) -> Result<Allocation, TurnError> {
        let relayed_address = {
            let mut pool = self.relay_address_pool.lock().unwrap();
            
            if pool.is_empty() {
                return Err(TurnError::InsufficientCapacity);
            }
            
            pool.pop().unwrap()
        };
        
        // Create UDP socket for relay
        let relay_socket = match UdpSocket::bind(relayed_address).await {
            Ok(socket) => Arc::new(socket),
            Err(_) => {
                // Return address to pool on failure
                self.relay_address_pool.lock().unwrap().push(relayed_address);
                return Err(TurnError::InsufficientCapacity);
            }
        };
        
        let allocation = Allocation::new(
            username,
            relayed_address,
            client_address,
            relay_socket,
        );
        
        let mut allocations = self.allocations.lock().unwrap();
        allocations.insert(client_address, allocation.clone());
        
        Ok(allocation)
    }

    pub fn get_allocation(&self, client_address: &SocketAddr) -> Option<Allocation> {
        let allocations = self.allocations.lock().unwrap();
        allocations.get(client_address).cloned()
    }

    pub fn refresh_allocation(
        &self,
        client_address: &SocketAddr,
        lifetime: Duration,
    ) -> Result<(), TurnError> {
        let mut allocations = self.allocations.lock().unwrap();
        
        match allocations.get_mut(client_address) {
            Some(allocation) => allocation.refresh(lifetime),
            None => Err(TurnError::AllocationMismatch),
        }
    }

    pub fn remove_allocation(&self, client_address: &SocketAddr) -> Option<Allocation> {
        let mut allocations = self.allocations.lock().unwrap();
        
        if let Some(allocation) = allocations.remove(client_address) {
            // Return the relay address to the pool
            let mut pool = self.relay_address_pool.lock().unwrap();
            pool.push(allocation.relayed_address);
            Some(allocation)
        } else {
            None
        }
    }

    pub fn cleanup_expired(&self) {
        let mut allocations = self.allocations.lock().unwrap();
        let mut pool = self.relay_address_pool.lock().unwrap();
        
        allocations.retain(|_, allocation| {
            if allocation.is_expired() {
                pool.push(allocation.relayed_address);
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    async fn create_test_socket(addr: SocketAddr) -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind(addr).await.unwrap())
    }

    #[test]
    async fn test_allocation_creation() {
        let client_addr: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        let relayed_addr: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        let socket = create_test_socket(relayed_addr).await;
        
        let allocation = Allocation::new(
            "testuser".to_string(),
            relayed_addr,
            client_addr,
            socket,
        );
        
        assert_eq!(allocation.username, "testuser");
        assert_eq!(allocation.relayed_address, relayed_addr);
        assert_eq!(allocation.client_address, client_addr);
        assert!(!allocation.is_expired());
    }

    #[test]
    async fn test_allocation_permissions() {
        let client_addr: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        let relayed_addr: SocketAddr = "127.0.0.1:49153".parse().unwrap();
        let peer_addr: SocketAddr = "203.0.113.1:80".parse().unwrap();
        let socket = create_test_socket(relayed_addr).await;
        
        let mut allocation = Allocation::new(
            "testuser".to_string(),
            relayed_addr,
            client_addr,
            socket,
        );
        
        // Initially no permission
        assert!(!allocation.has_permission(&peer_addr));
        
        // Add permission
        allocation.add_permission(peer_addr);
        assert!(allocation.has_permission(&peer_addr));
    }

    #[test]
    async fn test_channel_binding() {
        let client_addr: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        let relayed_addr: SocketAddr = "127.0.0.1:49154".parse().unwrap();
        let peer_addr: SocketAddr = "203.0.113.1:80".parse().unwrap();
        let socket = create_test_socket(relayed_addr).await;
        
        let mut allocation = Allocation::new(
            "testuser".to_string(),
            relayed_addr,
            client_addr,
            socket,
        );
        
        // Add channel binding
        allocation.add_channel_binding(0x4000, peer_addr).unwrap();
        
        // Check channel mapping
        assert_eq!(allocation.get_peer_by_channel(0x4000), Some(&peer_addr));
        
        // Permission should be granted automatically
        assert!(allocation.has_permission(&peer_addr));
        
        // Invalid channel number should fail
        assert!(allocation.add_channel_binding(0x3FFF, peer_addr).is_err());
    }

    #[test]
    async fn test_allocation_manager() {
        let relay_addresses = vec![
            "127.0.0.1:49200".parse().unwrap(),
            "127.0.0.1:49201".parse().unwrap(),
        ];
        
        let manager = AllocationManager::new(relay_addresses);
        let client_addr: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        
        // Create allocation
        let allocation = manager.create_allocation(
            "testuser".to_string(),
            client_addr,
        ).await.unwrap();
        
        // Get allocation
        let retrieved = manager.get_allocation(&client_addr).unwrap();
        assert_eq!(retrieved.username, allocation.username);
        
        // Remove allocation
        let removed = manager.remove_allocation(&client_addr).unwrap();
        assert_eq!(removed.username, allocation.username);
        
        // Should be gone
        assert!(manager.get_allocation(&client_addr).is_none());
    }
}