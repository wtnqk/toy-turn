use std::net::SocketAddr;
use crate::stun::{
    message::{Message, MessageClass, MessageMethod},
    attributes::{RawAttribute, AttributeType},
};
use crate::turn::error::TurnError;

#[derive(Debug, Clone)]
pub struct AllocateRequest {
    pub transaction_id: [u8; 12],
    pub requested_transport: Option<u8>,
    pub dont_fragment: bool,
    pub reservation_token: Option<[u8; 8]>,
    pub even_port: bool,
    pub requested_address_family: Option<u8>,
    pub username: Option<String>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl AllocateRequest {
    pub fn from_message(message: &Message) -> Result<Self, TurnError> {
        if message.message_type.method() != MessageMethod::Allocate
            || message.message_type.class() != MessageClass::Request
        {
            return Err(TurnError::BadRequest);
        }

        let mut request = AllocateRequest {
            transaction_id: message.transaction_id,
            requested_transport: None,
            dont_fragment: false,
            reservation_token: None,
            even_port: false,
            requested_address_family: None,
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
                Some(AttributeType::RequestedTransport) => {
                    if attr.value.len() >= 4 {
                        request.requested_transport = Some(attr.value[0]);
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

        Ok(request)
    }
}

#[derive(Debug, Clone)]
pub struct AllocateResponse {
    pub transaction_id: [u8; 12],
    pub relayed_address: Option<SocketAddr>,
    pub mapped_address: Option<SocketAddr>,
    pub lifetime: Option<u32>,
    pub reservation_token: Option<[u8; 8]>,
    pub error_code: Option<(u16, String)>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl AllocateResponse {
    pub fn success(
        transaction_id: [u8; 12],
        relayed_address: SocketAddr,
        mapped_address: SocketAddr,
        lifetime: u32,
    ) -> Self {
        AllocateResponse {
            transaction_id,
            relayed_address: Some(relayed_address),
            mapped_address: Some(mapped_address),
            lifetime: Some(lifetime),
            reservation_token: None,
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
        AllocateResponse {
            transaction_id,
            relayed_address: None,
            mapped_address: None,
            lifetime: None,
            reservation_token: None,
            error_code: Some((error_code, error_reason)),
            realm,
            nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::message::MessageType;

    fn create_allocate_request_message(attributes: Vec<RawAttribute>) -> Message {
        let mut message = Message::new(MessageType::new(
            MessageMethod::Allocate,
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

    #[test]
    fn test_parse_allocate_request() {
        let username_attr = RawAttribute::new(
            AttributeType::Username as u16,
            b"testuser".to_vec(),
        );
        
        let transport_attr = RawAttribute::new(
            AttributeType::RequestedTransport as u16,
            vec![17, 0, 0, 0], // UDP transport
        );

        let message = create_allocate_request_message(vec![username_attr, transport_attr]);
        let request = AllocateRequest::from_message(&message).unwrap();

        assert_eq!(request.username, Some("testuser".to_string()));
        assert_eq!(request.requested_transport, Some(17)); // UDP
    }

    #[test]
    fn test_parse_allocate_request_wrong_method() {
        let message = Message::new(MessageType::new(
            MessageMethod::Binding,
            MessageClass::Request,
        ));
        
        let result = AllocateRequest::from_message(&message);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TurnError::BadRequest));
    }

    #[test]
    fn test_allocate_response_success() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let relayed_addr: SocketAddr = "192.0.2.1:49152".parse().unwrap();
        let mapped_addr: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        
        let response = AllocateResponse::success(
            transaction_id,
            relayed_addr,
            mapped_addr,
            600, // 10 minutes
        );

        assert_eq!(response.transaction_id, transaction_id);
        assert_eq!(response.relayed_address, Some(relayed_addr));
        assert_eq!(response.mapped_address, Some(mapped_addr));
        assert_eq!(response.lifetime, Some(600));
        assert!(response.error_code.is_none());
    }

    #[test]
    fn test_allocate_response_error() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        
        let response = AllocateResponse::error(
            transaction_id,
            401,
            "Unauthorized".to_string(),
            Some("example.com".to_string()),
            Some(b"nonce123".to_vec()),
        );

        assert_eq!(response.transaction_id, transaction_id);
        assert!(response.relayed_address.is_none());
        assert_eq!(response.error_code, Some((401, "Unauthorized".to_string())));
        assert_eq!(response.realm, Some("example.com".to_string()));
    }
}