use hmac::{Hmac, Mac};
use sha1::Sha1;
use crate::stun::error::StunError;
use crate::stun::message::Message;
use crate::stun::attributes::{RawAttribute, AttributeType};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub realm: String,
}

impl Credentials {
    pub fn new(username: String, password: String, realm: String) -> Self {
        Credentials {
            username,
            password,
            realm,
        }
    }

    pub fn compute_key(&self) -> Vec<u8> {
        // Key = MD5(username:realm:password)
        // Note: In production, MD5 should be replaced with a more secure hash
        let key_string = format!("{}:{}:{}", self.username, self.realm, self.password);
        // For now, we'll use the string directly as the key
        // In a real implementation, this should be MD5 hashed
        key_string.into_bytes()
    }
}

pub fn calculate_message_integrity(message: &Message, key: &[u8]) -> Result<Vec<u8>, StunError> {
    // Create a copy of the message for integrity calculation
    let mut msg_bytes = message.serialize();
    
    // The message length must be adjusted to include MESSAGE-INTEGRITY
    let original_length = message.length;
    let new_length = original_length + 24; // MESSAGE-INTEGRITY attribute is 24 bytes (4 header + 20 HMAC)
    
    // Update the length field in the serialized message
    msg_bytes[2] = (new_length >> 8) as u8;
    msg_bytes[3] = new_length as u8;
    
    // Calculate HMAC-SHA1 over the message up to (but not including) the MESSAGE-INTEGRITY attribute
    let mut mac = HmacSha1::new_from_slice(key)
        .map_err(|_| StunError::ParseError("Invalid key length".to_string()))?;
    mac.update(&msg_bytes);
    
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_message_integrity(message: &Message, key: &[u8]) -> Result<bool, StunError> {
    // Find the MESSAGE-INTEGRITY attribute
    let mut offset = 0;
    let mut found_integrity = false;
    let mut integrity_value = Vec::new();
    let mut integrity_offset = 0;
    
    while offset < message.attributes.len() {
        let (attr, consumed) = RawAttribute::parse(&message.attributes[offset..])?;
        
        if AttributeType::from_u16(attr.attribute_type) == Some(AttributeType::MessageIntegrity) {
            found_integrity = true;
            integrity_value = attr.value;
            integrity_offset = offset;
            break;
        }
        
        offset += consumed;
    }
    
    if !found_integrity {
        return Ok(false);
    }
    
    // Create a message copy for verification
    let mut verify_msg = message.clone();
    verify_msg.attributes = message.attributes[..integrity_offset].to_vec();
    verify_msg.length = integrity_offset as u16;
    
    let calculated = calculate_message_integrity(&verify_msg, key)?;
    
    Ok(calculated == integrity_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::message::{MessageType, MessageMethod, MessageClass};

    #[test]
    fn test_credentials() {
        let creds = Credentials::new(
            "user".to_string(),
            "pass".to_string(),
            "realm".to_string(),
        );
        
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
        assert_eq!(creds.realm, "realm");
        
        let key = creds.compute_key();
        assert!(!key.is_empty());
    }

    #[test]
    fn test_calculate_message_integrity() {
        let mut message = Message::new(MessageType::new(
            MessageMethod::Binding,
            MessageClass::Request,
        ));
        message.transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        
        let key = b"test-key";
        let integrity = calculate_message_integrity(&message, key).unwrap();
        
        // HMAC-SHA1 produces 20 bytes
        assert_eq!(integrity.len(), 20);
    }

    #[test]
    fn test_message_integrity_round_trip() {
        let mut message = Message::new(MessageType::new(
            MessageMethod::Allocate,
            MessageClass::Request,
        ));
        
        // Add some attributes
        let username_attr = RawAttribute::new(
            AttributeType::Username as u16,
            b"testuser".to_vec(),
        );
        message.attributes.extend(username_attr.serialize());
        message.length = message.attributes.len() as u16;
        
        let key = b"secret-key";
        
        // Calculate integrity
        let integrity = calculate_message_integrity(&message, key).unwrap();
        
        // Add MESSAGE-INTEGRITY attribute to the message
        let integrity_attr = RawAttribute::new(
            AttributeType::MessageIntegrity as u16,
            integrity,
        );
        message.attributes.extend(integrity_attr.serialize());
        message.length = message.attributes.len() as u16;
        
        // Verify the integrity
        let valid = verify_message_integrity(&message, key).unwrap();
        assert!(valid);
        
        // Verify with wrong key should fail
        let wrong_key = b"wrong-key";
        let valid = verify_message_integrity(&message, wrong_key).unwrap();
        assert!(!valid);
    }
}