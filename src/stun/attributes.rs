use crate::stun::error::StunError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorRelayedAddress = 0x0016,
    RequestedTransport = 0x0019,
    XorMappedAddress = 0x0020,
    Lifetime = 0x000D,
    XorPeerAddress = 0x0012,
    Data = 0x0013,
    ChannelNumber = 0x000C,
}

impl AttributeType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(AttributeType::MappedAddress),
            0x0006 => Some(AttributeType::Username),
            0x0008 => Some(AttributeType::MessageIntegrity),
            0x0009 => Some(AttributeType::ErrorCode),
            0x000A => Some(AttributeType::UnknownAttributes),
            0x0014 => Some(AttributeType::Realm),
            0x0015 => Some(AttributeType::Nonce),
            0x0016 => Some(AttributeType::XorRelayedAddress),
            0x0019 => Some(AttributeType::RequestedTransport),
            0x0020 => Some(AttributeType::XorMappedAddress),
            0x000D => Some(AttributeType::Lifetime),
            0x0012 => Some(AttributeType::XorPeerAddress),
            0x0013 => Some(AttributeType::Data),
            0x000C => Some(AttributeType::ChannelNumber),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawAttribute {
    pub attribute_type: u16,
    pub value: Vec<u8>,
}

impl RawAttribute {
    pub fn new(attribute_type: u16, value: Vec<u8>) -> Self {
        RawAttribute {
            attribute_type,
            value,
        }
    }
    
    pub fn parse(data: &[u8]) -> Result<(Self, usize), StunError> {
        if data.len() < 4 {
            return Err(StunError::InvalidAttribute);
        }
        
        let attribute_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]);
        
        if data.len() < 4 + length as usize {
            return Err(StunError::InvalidAttribute);
        }
        
        let value = data[4..4 + length as usize].to_vec();
        
        // Calculate padded length (4-byte alignment)
        let padded_length = ((length + 3) & !3) as usize;
        let total_length = 4 + padded_length;
        
        Ok((RawAttribute::new(attribute_type, value), total_length))
    }
    
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Type
        result.extend_from_slice(&self.attribute_type.to_be_bytes());
        
        // Length
        result.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        
        // Value
        result.extend_from_slice(&self.value);
        
        // Padding to 4-byte boundary
        let padding = (4 - (self.value.len() % 4)) % 4;
        result.extend_from_slice(&vec![0u8; padding]);
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_type_conversion() {
        assert_eq!(AttributeType::from_u16(0x0001), Some(AttributeType::MappedAddress));
        assert_eq!(AttributeType::from_u16(0x0006), Some(AttributeType::Username));
        assert_eq!(AttributeType::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_parse_attribute() {
        let data = vec![
            0x00, 0x06, // Type: USERNAME
            0x00, 0x04, // Length: 4
            b't', b'e', b's', b't', // Value: "test"
        ];
        
        let (attr, consumed) = RawAttribute::parse(&data).unwrap();
        assert_eq!(attr.attribute_type, 0x0006);
        assert_eq!(attr.value, b"test");
        assert_eq!(consumed, 8); // 4 header + 4 value (no padding needed)
    }

    #[test]
    fn test_parse_attribute_with_padding() {
        let data = vec![
            0x00, 0x06, // Type: USERNAME
            0x00, 0x05, // Length: 5
            b'h', b'e', b'l', b'l', b'o', // Value: "hello"
            0x00, 0x00, 0x00, // Padding
        ];
        
        let (attr, consumed) = RawAttribute::parse(&data).unwrap();
        assert_eq!(attr.attribute_type, 0x0006);
        assert_eq!(attr.value, b"hello");
        assert_eq!(consumed, 12); // 4 header + 5 value + 3 padding
    }

    #[test]
    fn test_serialize_attribute() {
        let attr = RawAttribute::new(0x0006, b"test".to_vec());
        let serialized = attr.serialize();
        
        assert_eq!(serialized.len(), 8);
        assert_eq!(&serialized[0..2], &[0x00, 0x06]);
        assert_eq!(&serialized[2..4], &[0x00, 0x04]);
        assert_eq!(&serialized[4..8], b"test");
    }

    #[test]
    fn test_serialize_attribute_with_padding() {
        let attr = RawAttribute::new(0x0006, b"hello".to_vec());
        let serialized = attr.serialize();
        
        assert_eq!(serialized.len(), 12);
        assert_eq!(&serialized[0..2], &[0x00, 0x06]);
        assert_eq!(&serialized[2..4], &[0x00, 0x05]);
        assert_eq!(&serialized[4..9], b"hello");
        assert_eq!(&serialized[9..12], &[0x00, 0x00, 0x00]);
    }
}