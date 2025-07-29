use std::net::SocketAddr;
use crate::stun::{
    message::{Message, MessageClass, MessageMethod},
    attributes::{RawAttribute, AttributeType},
};
use crate::turn::error::TurnError;

#[derive(Debug, Clone)]
pub struct ChannelBindRequest {
    pub transaction_id: [u8; 12],
    pub channel_number: u16,
    pub peer_address: SocketAddr,
    pub username: Option<String>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl ChannelBindRequest {
    pub fn from_message(message: &Message) -> Result<Self, TurnError> {
        if message.message_type.method() != MessageMethod::ChannelBind
            || message.message_type.class() != MessageClass::Request
        {
            return Err(TurnError::BadRequest);
        }

        let mut request = ChannelBindRequest {
            transaction_id: message.transaction_id,
            channel_number: 0,
            peer_address: "0.0.0.0:0".parse().unwrap(),
            username: None,
            realm: None,
            nonce: None,
        };

        let mut found_channel = false;
        let mut found_peer = false;

        // Parse attributes
        let mut offset = 0;
        while offset < message.attributes.len() {
            let (attr, consumed) = RawAttribute::parse(&message.attributes[offset..])?;
            offset += consumed;

            match AttributeType::from_u16(attr.attribute_type) {
                Some(AttributeType::ChannelNumber) => {
                    if attr.value.len() >= 4 {
                        request.channel_number = u16::from_be_bytes([attr.value[0], attr.value[1]]);
                        found_channel = true;
                    }
                }
                Some(AttributeType::XorPeerAddress) => {
                    if let Some(addr) = parse_xor_peer_address(&attr.value, &message.transaction_id) {
                        request.peer_address = addr;
                        found_peer = true;
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
                _ => {} // Ignore unknown attributes
            }
        }

        if !found_channel || !found_peer {
            return Err(TurnError::BadRequest);
        }

        // Validate channel number range
        if !(0x4000..=0x7FFF).contains(&request.channel_number) {
            return Err(TurnError::BadRequest);
        }

        Ok(request)
    }
}

#[derive(Debug, Clone)]
pub struct ChannelBindResponse {
    pub transaction_id: [u8; 12],
    pub error_code: Option<(u16, String)>,
    pub realm: Option<String>,
    pub nonce: Option<Vec<u8>>,
}

impl ChannelBindResponse {
    pub fn success(transaction_id: [u8; 12]) -> Self {
        ChannelBindResponse {
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
        ChannelBindResponse {
            transaction_id,
            error_code: Some((error_code, error_reason)),
            realm,
            nonce,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelData {
    pub channel_number: u16,
    pub data: Vec<u8>,
}

impl ChannelData {
    pub fn new(channel_number: u16, data: Vec<u8>) -> Result<Self, TurnError> {
        if !(0x4000..=0x7FFF).contains(&channel_number) {
            return Err(TurnError::BadRequest);
        }
        
        Ok(ChannelData {
            channel_number,
            data,
        })
    }

    pub fn parse(data: &[u8]) -> Result<Self, TurnError> {
        if data.len() < 4 {
            return Err(TurnError::BadRequest);
        }

        let channel_number = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Check channel number is in valid range
        if !(0x4000..=0x7FFF).contains(&channel_number) {
            return Err(TurnError::BadRequest);
        }

        if data.len() < 4 + length {
            return Err(TurnError::BadRequest);
        }

        let payload = data[4..4 + length].to_vec();

        Ok(ChannelData {
            channel_number,
            data: payload,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Channel number
        result.extend_from_slice(&self.channel_number.to_be_bytes());
        
        // Length
        result.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        
        // Data
        result.extend_from_slice(&self.data);
        
        // Padding to 4-byte boundary
        let padding = (4 - (self.data.len() % 4)) % 4;
        result.extend(vec![0u8; padding]);
        
        result
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

    fn create_channel_bind_request_message(channel: u16, peer: SocketAddr, transaction_id: [u8; 12]) -> Message {
        let mut message = Message::new(MessageType::new(
            MessageMethod::ChannelBind,
            MessageClass::Request,
        ));
        message.transaction_id = transaction_id;
        
        let mut attrs = Vec::new();
        
        // Add CHANNEL-NUMBER
        let mut channel_data = vec![0u8; 4];
        channel_data[0] = (channel >> 8) as u8;
        channel_data[1] = channel as u8;
        let channel_attr = RawAttribute::new(AttributeType::ChannelNumber as u16, channel_data);
        attrs.extend(channel_attr.serialize());
        
        // Add XOR-PEER-ADDRESS
        let peer_attr = create_xor_peer_address_attr(peer, &transaction_id);
        attrs.extend(peer_attr.serialize());
        
        message.attributes = attrs;
        message.length = message.attributes.len() as u16;
        message
    }

    fn create_xor_peer_address_attr(addr: SocketAddr, transaction_id: &[u8; 12]) -> RawAttribute {
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
            SocketAddr::V6(v6) => {
                // Family
                data.push(0x02);
                
                // XOR Port
                let xor_port = addr.port() ^ (crate::stun::message::MAGIC_COOKIE >> 16) as u16;
                data.extend_from_slice(&xor_port.to_be_bytes());
                
                // XOR IPv6
                let mut ip_bytes = v6.ip().octets();
                
                // XOR with magic cookie
                for (i, byte) in ip_bytes.iter_mut().enumerate().take(4) {
                    *byte ^= (crate::stun::message::MAGIC_COOKIE >> (24 - i * 8)) as u8;
                }
                // XOR with transaction ID
                for (i, byte) in ip_bytes.iter_mut().enumerate().skip(4).take(12) {
                    *byte ^= transaction_id[i - 4];
                }
                
                data.extend_from_slice(&ip_bytes);
            }
        }
        
        RawAttribute::new(AttributeType::XorPeerAddress as u16, data)
    }

    #[test]
    fn test_parse_channel_bind_request() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let channel_number = 0x4000;
        let peer_addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        
        let message = create_channel_bind_request_message(channel_number, peer_addr, transaction_id);
        let request = ChannelBindRequest::from_message(&message).unwrap();

        assert_eq!(request.channel_number, channel_number);
        assert_eq!(request.peer_address, peer_addr);
        assert_eq!(request.transaction_id, transaction_id);
    }

    #[test]
    fn test_invalid_channel_number() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let channel_number = 0x3FFF; // Invalid - too low
        let peer_addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        
        let message = create_channel_bind_request_message(channel_number, peer_addr, transaction_id);
        let result = ChannelBindRequest::from_message(&message);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TurnError::BadRequest));
    }

    #[test]
    fn test_channel_bind_response() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        
        let success_resp = ChannelBindResponse::success(transaction_id);
        assert!(success_resp.error_code.is_none());
        
        let error_resp = ChannelBindResponse::error(
            transaction_id,
            400,
            "Bad Request".to_string(),
            None,
            None,
        );
        assert_eq!(error_resp.error_code, Some((400, "Bad Request".to_string())));
    }

    #[test]
    fn test_channel_data() {
        let channel_number = 0x4001;
        let data = b"Hello, Channel!".to_vec();
        
        let channel_data = ChannelData::new(channel_number, data.clone()).unwrap();
        assert_eq!(channel_data.channel_number, channel_number);
        assert_eq!(channel_data.data, data);
    }

    #[test]
    fn test_channel_data_serialize_parse() {
        let channel_number = 0x4002;
        let data = b"Test data".to_vec();
        
        let channel_data = ChannelData::new(channel_number, data.clone()).unwrap();
        let serialized = channel_data.serialize();
        
        // Should have padding to 4-byte boundary
        assert_eq!(serialized.len(), 4 + 12); // 4 header + 9 data + 3 padding
        
        let parsed = ChannelData::parse(&serialized).unwrap();
        assert_eq!(parsed.channel_number, channel_number);
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn test_channel_data_invalid_number() {
        let result = ChannelData::new(0x8000, vec![1, 2, 3]); // Too high
        assert!(result.is_err());
        
        let result = ChannelData::new(0x3FFF, vec![1, 2, 3]); // Too low
        assert!(result.is_err());
    }
}