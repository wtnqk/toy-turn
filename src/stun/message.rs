use bytes::{BufMut, BytesMut};
use crate::stun::error::StunError;

pub const MAGIC_COOKIE: u32 = 0x2112A442;
pub const STUN_HEADER_SIZE: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageMethod {
    Binding = 0x0001,
    Allocate = 0x0003,
    Refresh = 0x0004,
    Send = 0x0006,
    Data = 0x0007,
    CreatePermission = 0x0008,
    ChannelBind = 0x0009,
}

impl MessageMethod {
    fn from_u16(value: u16) -> Result<Self, StunError> {
        match value {
            0x0001 => Ok(MessageMethod::Binding),
            0x0003 => Ok(MessageMethod::Allocate),
            0x0004 => Ok(MessageMethod::Refresh),
            0x0006 => Ok(MessageMethod::Send),
            0x0007 => Ok(MessageMethod::Data),
            0x0008 => Ok(MessageMethod::CreatePermission),
            0x0009 => Ok(MessageMethod::ChannelBind),
            _ => Err(StunError::InvalidMessageType),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

#[derive(Debug, Clone, Copy)]
pub struct MessageType {
    method: MessageMethod,
    class: MessageClass,
}

impl MessageType {
    pub fn new(method: MessageMethod, class: MessageClass) -> Self {
        MessageType { method, class }
    }
    
    pub fn method(&self) -> MessageMethod {
        self.method
    }
    
    pub fn class(&self) -> MessageClass {
        self.class
    }
    
    pub fn as_u16(&self) -> u16 {
        let method = self.method as u16;
        let class_bits = match self.class {
            MessageClass::Request => 0b00,
            MessageClass::Indication => 0b01,
            MessageClass::SuccessResponse => 0b10,
            MessageClass::ErrorResponse => 0b11,
        };
        
        // STUN message type encoding:
        // M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
        let m = method & 0x0F;           // M3-M0
        let m1 = (method >> 4) & 0x07;   // M6-M4
        let m2 = (method >> 7) & 0x0F;   // M11-M8
        
        let c0 = class_bits & 0x01;
        let c1 = (class_bits >> 1) & 0x01;
        
        (m2 << 9) | (c1 << 8) | (m1 << 5) | (c0 << 4) | m
    }
    
    pub fn from_u16(value: u16) -> Result<Self, StunError> {
        // Extract method bits
        let m = value & 0x000F;           // M3-M0
        let m1 = (value >> 5) & 0x0007;  // M6-M4  
        let m2 = (value >> 9) & 0x000F;  // M11-M8
        
        let method_value = (m2 << 7) | (m1 << 4) | m;
        let method = MessageMethod::from_u16(method_value)?;
        
        // Extract class bits
        let c0 = (value >> 4) & 0x01;
        let c1 = (value >> 8) & 0x01;
        let class_bits = (c1 << 1) | c0;
        
        let class = match class_bits {
            0b00 => MessageClass::Request,
            0b01 => MessageClass::Indication,
            0b10 => MessageClass::SuccessResponse,
            0b11 => MessageClass::ErrorResponse,
            _ => return Err(StunError::InvalidMessageType),
        };
        
        Ok(MessageType { method, class })
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub message_type: MessageType,
    pub length: u16,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<u8>, // Will be replaced with proper attribute handling later
}

impl Message {
    pub fn new(message_type: MessageType) -> Self {
        let mut transaction_id = [0u8; 12];
        // Generate random transaction ID
        use rand::Rng;
        rand::thread_rng().fill(&mut transaction_id);
        
        Message {
            message_type,
            length: 0,
            transaction_id,
            attributes: Vec::new(),
        }
    }
    
    pub fn parse(data: &[u8]) -> Result<Self, StunError> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(StunError::MessageTooShort);
        }
        
        // Parse message type
        let msg_type_value = u16::from_be_bytes([data[0], data[1]]);
        let message_type = MessageType::from_u16(msg_type_value)?;
        
        // Parse length
        let length = u16::from_be_bytes([data[2], data[3]]);
        
        // Check magic cookie
        let magic_cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic_cookie != MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie);
        }
        
        // Parse transaction ID
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);
        
        // Check if we have enough data for the attributes
        if data.len() < STUN_HEADER_SIZE + length as usize {
            return Err(StunError::InvalidMessageLength);
        }
        
        // Parse attributes (for now, just store raw bytes)
        let attributes = data[STUN_HEADER_SIZE..STUN_HEADER_SIZE + length as usize].to_vec();
        
        Ok(Message {
            message_type,
            length,
            transaction_id,
            attributes,
        })
    }
    
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(STUN_HEADER_SIZE + self.attributes.len());
        
        // Message type
        buf.put_u16(self.message_type.as_u16());
        
        // Length
        buf.put_u16(self.attributes.len() as u16);
        
        // Magic cookie
        buf.put_u32(MAGIC_COOKIE);
        
        // Transaction ID
        buf.put_slice(&self.transaction_id);
        
        // Attributes
        buf.put_slice(&self.attributes);
        
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_parse_stun_message_header() {
        // STUNメッセージヘッダーのテストデータ
        // Binding Request の例
        let mut data = BytesMut::new();
        
        // Message Type (Binding Request: 0x0001)
        data.extend_from_slice(&[0x00, 0x01]);
        
        // Message Length (0 for header only)
        data.extend_from_slice(&[0x00, 0x00]);
        
        // Magic Cookie
        data.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        
        // Transaction ID (96 bits = 12 bytes)
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
        
        let message = Message::parse(&data).expect("Failed to parse STUN message");
        
        assert_eq!(message.message_type.method(), MessageMethod::Binding);
        assert_eq!(message.message_type.class(), MessageClass::Request);
        assert_eq!(message.length, 0);
        assert_eq!(message.transaction_id, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
    }

    #[test]
    fn test_parse_invalid_magic_cookie() {
        let mut data = BytesMut::new();
        
        // Message Type
        data.extend_from_slice(&[0x00, 0x01]);
        
        // Message Length
        data.extend_from_slice(&[0x00, 0x00]);
        
        // Invalid Magic Cookie
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        
        // Transaction ID
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
        
        let result = Message::parse(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StunError::InvalidMagicCookie));
    }

    #[test]
    fn test_message_type_encoding() {
        // Binding Request: Method=0x0001, Class=Request(00)
        let msg_type = MessageType::new(MessageMethod::Binding, MessageClass::Request);
        assert_eq!(msg_type.as_u16(), 0x0001);
        
        // Binding Success Response: Method=0x0001, Class=Success(01)
        let msg_type = MessageType::new(MessageMethod::Binding, MessageClass::SuccessResponse);
        assert_eq!(msg_type.as_u16(), 0x0101);
        
        // Binding Error Response: Method=0x0001, Class=Error(11)
        let msg_type = MessageType::new(MessageMethod::Binding, MessageClass::ErrorResponse);
        assert_eq!(msg_type.as_u16(), 0x0111);
        
        // Allocate Request: Method=0x0003, Class=Request(00)
        let msg_type = MessageType::new(MessageMethod::Allocate, MessageClass::Request);
        assert_eq!(msg_type.as_u16(), 0x0003);
    }

    #[test]
    fn test_serialize_stun_message() {
        let mut message = Message::new(MessageType::new(MessageMethod::Binding, MessageClass::Request));
        message.transaction_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        
        let serialized = message.serialize();
        
        // Verify header
        assert_eq!(&serialized[0..2], &[0x00, 0x01]); // Message Type
        assert_eq!(&serialized[2..4], &[0x00, 0x00]); // Length
        assert_eq!(&serialized[4..8], &MAGIC_COOKIE.to_be_bytes()); // Magic Cookie
        assert_eq!(&serialized[8..20], &message.transaction_id); // Transaction ID
    }

    #[test]
    fn test_message_too_short() {
        let data = vec![0u8; 10]; // Less than STUN_HEADER_SIZE
        let result = Message::parse(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StunError::MessageTooShort));
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = Message::new(MessageType::new(MessageMethod::Allocate, MessageClass::Request));
        let serialized = original.serialize();
        let parsed = Message::parse(&serialized).expect("Failed to parse serialized message");
        
        assert_eq!(parsed.message_type.method(), original.message_type.method());
        assert_eq!(parsed.message_type.class(), original.message_type.class());
        assert_eq!(parsed.transaction_id, original.transaction_id);
    }
}