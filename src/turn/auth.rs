use std::collections::HashMap;
use std::time::{Duration, Instant};
use rand::{thread_rng, Rng};
use crate::turn::error::TurnError;

#[derive(Debug, Clone)]
pub struct NonceManager {
    nonces: HashMap<String, Instant>,
    lifetime: Duration,
}

impl NonceManager {
    pub fn new(lifetime: Duration) -> Self {
        NonceManager {
            nonces: HashMap::new(),
            lifetime,
        }
    }

    pub fn generate_nonce(&mut self) -> String {
        let mut rng = thread_rng();
        let nonce: String = (0..16)
            .map(|_| format!("{:02x}", rng.r#gen::<u8>()))
            .collect();
        
        self.nonces.insert(nonce.clone(), Instant::now());
        nonce
    }

    pub fn validate_nonce(&mut self, nonce: &str) -> Result<(), TurnError> {
        match self.nonces.get(nonce) {
            Some(created_at) => {
                if created_at.elapsed() > self.lifetime {
                    self.nonces.remove(nonce);
                    Err(TurnError::StaleNonce)
                } else {
                    Ok(())
                }
            }
            None => Err(TurnError::StaleNonce),
        }
    }

    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.nonces.retain(|_, created_at| {
            now.duration_since(*created_at) <= self.lifetime
        });
    }
}

#[derive(Debug, Clone)]
pub struct UserDatabase {
    users: HashMap<String, String>, // username -> password
}

impl UserDatabase {
    pub fn new() -> Self {
        UserDatabase {
            users: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: String, password: String) {
        self.users.insert(username, password);
    }

    pub fn get_password(&self, username: &str) -> Option<&String> {
        self.users.get(username)
    }

    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        self.users.get(username)
            .map(|stored_password| stored_password == password)
            .unwrap_or(false)
    }
}

impl Default for UserDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let mut nonce_mgr = NonceManager::new(Duration::from_secs(300));
        
        let nonce1 = nonce_mgr.generate_nonce();
        let nonce2 = nonce_mgr.generate_nonce();
        
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 32); // 16 bytes * 2 hex chars
    }

    #[test]
    fn test_nonce_validation() {
        let mut nonce_mgr = NonceManager::new(Duration::from_secs(300));
        
        let nonce = nonce_mgr.generate_nonce();
        
        // Valid nonce should pass
        assert!(nonce_mgr.validate_nonce(&nonce).is_ok());
        
        // Unknown nonce should fail
        assert!(nonce_mgr.validate_nonce("unknown").is_err());
    }

    #[test]
    fn test_nonce_expiration() {
        let mut nonce_mgr = NonceManager::new(Duration::from_millis(100));
        
        let nonce = nonce_mgr.generate_nonce();
        
        // Valid nonce should pass immediately
        assert!(nonce_mgr.validate_nonce(&nonce).is_ok());
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));
        
        // Expired nonce should fail
        assert!(matches!(
            nonce_mgr.validate_nonce(&nonce),
            Err(TurnError::StaleNonce)
        ));
    }

    #[test]
    fn test_user_database() {
        let mut db = UserDatabase::new();
        
        db.add_user("alice".to_string(), "password123".to_string());
        db.add_user("bob".to_string(), "secret456".to_string());
        
        assert_eq!(db.get_password("alice"), Some(&"password123".to_string()));
        assert_eq!(db.get_password("charlie"), None);
        
        assert!(db.authenticate("alice", "password123"));
        assert!(!db.authenticate("alice", "wrongpassword"));
        assert!(!db.authenticate("charlie", "anypassword"));
    }
}