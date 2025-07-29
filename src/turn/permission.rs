use std::net::SocketAddr;
use crate::stun::{
    message::{Message, MessageClass, MessageMethod},
    attributes::{RawAttribute, AttributeType},
};
use crate::turn::error::TurnError;

#[derive(Debug, Clone)]
pub struct CreatePermissionRequest {
    pub transaction_id: [u8; 12],
    pub peer_addresses: Vec<SocketAddr>,
    pub username: Option<String>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl CreatePermissionRequest {
    pub fn from_message(message: &Message) -> Result<Self, TurnError> {
        if message.message_type.method() != MessageMethod::CreatePermission
            || message.message_type.class() != MessageClass::Request
        {
            return Err(TurnError::BadRequest);
        }

        let mut request = CreatePermissionRequest {
            transaction_id: message.transaction_id,
            peer_addresses: Vec::new(),
            username: None,
            realm: None,
            nonce: None,
        };

        // Parse attributes
        let mut offset = 0;
        while offset < message.attributes.len() {
            let (attr, consumed) = RawAttribute::parse(&message.attributes[offset..])?;
            offset += consumed;

            match AttributeType::from_u16(attr.attribute_type) {
                Some(AttributeType::XorPeerAddress) => {
                    if let Some(addr) = parse_xor_peer_address(&attr.value, &message.transaction_id) {
                        request.peer_addresses.push(addr);
                    }
                }
                Some(AttributeType::Username) => {
                    request.username = String::from_utf8(attr.value).ok();
                }
                Some(AttributeType::Realm) => {
                    request.realm = String::from_utf8(attr.value).ok();
                }
                Some(AttributeType::Nonce) => {
                    request.nonce = Some(attr.value);
                }
                _ => {} // Ignore unknown attributes for now
            }
        }

        if request.peer_addresses.is_empty() {
            return Err(TurnError::BadRequest);
        }

        Ok(request)
    }
}

#[derive(Debug, Clone)]
pub struct CreatePermissionResponse {
    pub transaction_id: [u8; 12],
    pub error_code: Option<(u16, String)>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl CreatePermissionResponse {
    pub fn success(transaction_id: [u8; 12]) -> Self {
        CreatePermissionResponse {
            transaction_id,
            error_code: None,
            realm: None,
            nonce: None,
        }
    }

    pub fn error(
        transaction_id: [u8; 12],
        error_code: u16,
        error_reason: String,
        realm: Option<String>,
        nonce: Option<Vec<u8>>,
    ) -> Self {
        CreatePermissionResponse {
            transaction_id,
            error_code: Some((error_code, error_reason)),
            realm,
            nonce,
        }
    }
}

fn parse_xor_peer_address(data: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    
    // XOR with magic cookie for port
    let port = xor_port ^ (crate::stun::message::MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => { // IPv4
            if data.len() < 8 {
                return None;
            }
            
            let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip = xor_ip ^ crate::stun::message::MAGIC_COOKIE;
            
            let ip_addr = std::net::Ipv4Addr::from(ip);
            Some(SocketAddr::from((ip_addr, port)))
        }
        0x02 => { // IPv6
            if data.len() < 20 {
                return None;
            }
            
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            
            // XOR with magic cookie and transaction ID
            for (i, byte) in ip_bytes.iter_mut().enumerate().take(4) {
                *byte ^= (crate::stun::message::MAGIC_COOKIE >> (24 - i * 8)) as u8;
            }
            for (i, byte) in ip_bytes.iter_mut().enumerate().skip(4).take(12) {
                *byte ^= transaction_id[i - 4];
            }
            
            let ip_addr = std::net::Ipv6Addr::from(ip_bytes);
            Some(SocketAddr::from((ip_addr, port)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::message::MessageType;

    fn create_permission_request_message(attributes: Vec<RawAttribute>) -> Message {
        let mut message = Message::new(MessageType::new(
            MessageMethod::CreatePermission,
            MessageClass::Request,
        ));
        
        // Serialize attributes
        let mut attr_bytes = Vec::new();
        for attr in attributes {
            attr_bytes.extend(attr.serialize());
        }
        
        message.attributes = attr_bytes;
        message.length = message.attributes.len() as u16;
        message
    }

    fn create_xor_peer_address_attr(addr: SocketAddr, _transaction_id: &[u8; 12]) -> RawAttribute {
        let mut data = Vec::new();
        
        // Padding
        data.push(0);
        
        match addr {
            SocketAddr::V4(v4) => {
                // Family
                data.push(0x01);
                
                // XOR Port
                let xor_port = addr.port() ^ (crate::stun::message::MAGIC_COOKIE >> 16) as u16;
                data.extend_from_slice(&xor_port.to_be_bytes());
                
                // XOR IP
                let ip_bytes = v4.ip().octets();
                let ip = u32::from_be_bytes(ip_bytes);
                let xor_ip = ip ^ crate::stun::message::MAGIC_COOKIE;
                data.extend_from_slice(&xor_ip.to_be_bytes());
            }
            SocketAddr::V6(_) => {
                // Not implemented for tests
                unimplemented!("IPv6 test not implemented");
            }
        }
        
        RawAttribute::new(AttributeType::XorPeerAddress as u16, data)
    }

    #[test]
    fn test_parse_create_permission_request() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let peer_addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        
        let peer_attr = create_xor_peer_address_attr(peer_addr, &transaction_id);
        let username_attr = RawAttribute::new(
            AttributeType::Username as u16,
            b"testuser".to_vec(),
        );

        let mut message = create_permission_request_message(vec![peer_attr, username_attr]);
        message.transaction_id = transaction_id;
        
        let request = CreatePermissionRequest::from_message(&message).unwrap();

        assert_eq!(request.username, Some("testuser".to_string()));
        assert_eq!(request.peer_addresses.len(), 1);
        assert_eq!(request.peer_addresses[0], peer_addr);
    }

    #[test]
    fn test_parse_create_permission_request_no_peer() {
        let username_attr = RawAttribute::new(
            AttributeType::Username as u16,
            b"testuser".to_vec(),
        );

        let message = create_permission_request_message(vec![username_attr]);
        let result = CreatePermissionRequest::from_message(&message);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TurnError::BadRequest));
    }

    #[test]
    fn test_create_permission_response_success() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let response = CreatePermissionResponse::success(transaction_id);

        assert_eq!(response.transaction_id, transaction_id);
        assert!(response.error_code.is_none());
    }

    #[test]
    fn test_create_permission_response_error() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let response = CreatePermissionResponse::error(
            transaction_id,
            403,
            "Forbidden".to_string(),
            None,
            None,
        );

        assert_eq!(response.transaction_id, transaction_id);
        assert_eq!(response.error_code, Some((403, "Forbidden".to_string())));
    }
}