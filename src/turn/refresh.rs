use crate::stun::{
    message::{Message, MessageClass, MessageMethod},
    attributes::{RawAttribute, AttributeType},
};
use crate::turn::error::TurnError;

#[derive(Debug, Clone)]
pub struct RefreshRequest {
    pub transaction_id: [u8; 12],
    pub lifetime: Option<u32>,
    pub username: Option<String>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl RefreshRequest {
    pub fn from_message(message: &Message) -> Result<Self, TurnError> {
        if message.message_type.method() != MessageMethod::Refresh
            || message.message_type.class() != MessageClass::Request
        {
            return Err(TurnError::BadRequest);
        }

        let mut request = RefreshRequest {
            transaction_id: message.transaction_id,
            lifetime: None,
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
                Some(AttributeType::Lifetime) => {
                    if attr.value.len() >= 4 {
                        let lifetime = u32::from_be_bytes([
                            attr.value[0],
                            attr.value[1],
                            attr.value[2],
                            attr.value[3],
                        ]);
                        request.lifetime = Some(lifetime);
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

    pub fn is_delete_request(&self) -> bool {
        matches!(self.lifetime, Some(0))
    }
}

#[derive(Debug, Clone)]
pub struct RefreshResponse {
    pub transaction_id: [u8; 12],
    pub lifetime: Option<u32>,
    pub error_code: Option<(u16, String)>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl RefreshResponse {
    pub fn success(transaction_id: [u8; 12], lifetime: u32) -> Self {
        RefreshResponse {
            transaction_id,
            lifetime: Some(lifetime),
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
        RefreshResponse {
            transaction_id,
            lifetime: None,
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

    fn create_refresh_request_message(attributes: Vec<RawAttribute>) -> Message {
        let mut message = Message::new(MessageType::new(
            MessageMethod::Refresh,
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
    fn test_parse_refresh_request() {
        let lifetime_attr = RawAttribute::new(
            AttributeType::Lifetime as u16,
            600u32.to_be_bytes().to_vec(),
        );
        
        let username_attr = RawAttribute::new(
            AttributeType::Username as u16,
            b"testuser".to_vec(),
        );

        let message = create_refresh_request_message(vec![lifetime_attr, username_attr]);
        let request = RefreshRequest::from_message(&message).unwrap();

        assert_eq!(request.lifetime, Some(600));
        assert_eq!(request.username, Some("testuser".to_string()));
        assert!(!request.is_delete_request());
    }

    #[test]
    fn test_parse_refresh_delete_request() {
        let lifetime_attr = RawAttribute::new(
            AttributeType::Lifetime as u16,
            0u32.to_be_bytes().to_vec(),
        );

        let message = create_refresh_request_message(vec![lifetime_attr]);
        let request = RefreshRequest::from_message(&message).unwrap();

        assert_eq!(request.lifetime, Some(0));
        assert!(request.is_delete_request());
    }

    #[test]
    fn test_parse_refresh_request_wrong_method() {
        let message = Message::new(MessageType::new(
            MessageMethod::Allocate,
            MessageClass::Request,
        ));
        
        let result = RefreshRequest::from_message(&message);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TurnError::BadRequest));
    }

    #[test]
    fn test_refresh_response_success() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let response = RefreshResponse::success(transaction_id, 300);

        assert_eq!(response.transaction_id, transaction_id);
        assert_eq!(response.lifetime, Some(300));
        assert!(response.error_code.is_none());
    }

    #[test]
    fn test_refresh_response_error() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let response = RefreshResponse::error(
            transaction_id,
            437,
            "Allocation Mismatch".to_string(),
            None,
            None,
        );

        assert_eq!(response.transaction_id, transaction_id);
        assert!(response.lifetime.is_none());
        assert_eq!(response.error_code, Some((437, "Allocation Mismatch".to_string())));
    }
}