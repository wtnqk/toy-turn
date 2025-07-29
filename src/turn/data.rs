use std::net::SocketAddr;
use crate::stun::{
    message::{Message, MessageType, MessageClass, MessageMethod},
    attributes::{RawAttribute, AttributeType},
};
use crate::turn::error::TurnError;

#[derive(Debug, Clone)]
pub struct SendIndication {
    pub transaction_id: [u8; 12],
    pub peer_address: SocketAddr,
    pub data: Vec<u8>,
    pub dont_fragment: bool,
}

impl SendIndication {
    pub fn from_message(message: &Message) -> Result<Self, TurnError> {
        if message.message_type.method() != MessageMethod::Send
            || message.message_type.class() != MessageClass::Indication
        {
            return Err(TurnError::BadRequest);
        }

        let mut indication = SendIndication {
            transaction_id: message.transaction_id,
            peer_address: "0.0.0.0:0".parse().unwrap(),
            data: Vec::new(),
            dont_fragment: false,
        };

        let mut found_peer = false;
        let mut found_data = false;

        // Parse attributes
        let mut offset = 0;
        while offset < message.attributes.len() {
            let (attr, consumed) = RawAttribute::parse(&message.attributes[offset..])?;
            offset += consumed;

            match AttributeType::from_u16(attr.attribute_type) {
                Some(AttributeType::XorPeerAddress) => {
                    if let Some(addr) = parse_xor_peer_address(&attr.value, &message.transaction_id) {
                        indication.peer_address = addr;
                        found_peer = true;
                    }
                }
                Some(AttributeType::Data) => {
                    indication.data = attr.value;
                    found_data = true;
                }
                _ => {} // Ignore unknown attributes and DONT-FRAGMENT for now
            }
        }

        if !found_peer || !found_data {
            return Err(TurnError::BadRequest);
        }

        Ok(indication)
    }

    pub fn to_message(&self) -> Message {
        let mut message = Message::new(MessageType::new(
            MessageMethod::Send,
            MessageClass::Indication,
        ));
        message.transaction_id = self.transaction_id;

        let mut attrs = Vec::new();

        // Add XOR-PEER-ADDRESS
        let peer_attr = create_xor_peer_address_attr(self.peer_address, &self.transaction_id);
        attrs.extend(peer_attr.serialize());

        // Add DATA
        let data_attr = RawAttribute::new(AttributeType::Data as u16, self.data.clone());
        attrs.extend(data_attr.serialize());

        message.attributes = attrs;
        message.length = message.attributes.len() as u16;

        message
    }
}

#[derive(Debug, Clone)]
pub struct DataIndication {
    pub transaction_id: [u8; 12],
    pub peer_address: SocketAddr,
    pub data: Vec<u8>,
}

impl DataIndication {
    pub fn new(peer_address: SocketAddr, data: Vec<u8>) -> Self {
        let mut transaction_id = [0u8; 12];
        use rand::Rng;
        rand::thread_rng().fill(&mut transaction_id);

        DataIndication {
            transaction_id,
            peer_address,
            data,
        }
    }

    pub fn from_message(message: &Message) -> Result<Self, TurnError> {
        if message.message_type.method() != MessageMethod::Data
            || message.message_type.class() != MessageClass::Indication
        {
            return Err(TurnError::BadRequest);
        }

        let mut indication = DataIndication {
            transaction_id: message.transaction_id,
            peer_address: "0.0.0.0:0".parse().unwrap(),
            data: Vec::new(),
        };

        let mut found_peer = false;
        let mut found_data = false;

        // Parse attributes
        let mut offset = 0;
        while offset < message.attributes.len() {
            let (attr, consumed) = RawAttribute::parse(&message.attributes[offset..])?;
            offset += consumed;

            match AttributeType::from_u16(attr.attribute_type) {
                Some(AttributeType::XorPeerAddress) => {
                    if let Some(addr) = parse_xor_peer_address(&attr.value, &message.transaction_id) {
                        indication.peer_address = addr;
                        found_peer = true;
                    }
                }
                Some(AttributeType::Data) => {
                    indication.data = attr.value;
                    found_data = true;
                }
                _ => {} // Ignore unknown attributes
            }
        }

        if !found_peer || !found_data {
            return Err(TurnError::BadRequest);
        }

        Ok(indication)
    }

    pub fn to_message(&self) -> Message {
        let mut message = Message::new(MessageType::new(
            MessageMethod::Data,
            MessageClass::Indication,
        ));
        message.transaction_id = self.transaction_id;

        let mut attrs = Vec::new();

        // Add XOR-PEER-ADDRESS
        let peer_attr = create_xor_peer_address_attr(self.peer_address, &self.transaction_id);
        attrs.extend(peer_attr.serialize());

        // Add DATA
        let data_attr = RawAttribute::new(AttributeType::Data as u16, self.data.clone());
        attrs.extend(data_attr.serialize());

        message.attributes = attrs;
        message.length = message.attributes.len() as u16;

        message
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::message::MessageType;

    #[test]
    fn test_send_indication() {
        let peer_addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let data = b"Hello, World!".to_vec();
        
        let send_ind = SendIndication {
            transaction_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            peer_address: peer_addr,
            data: data.clone(),
            dont_fragment: false,
        };

        // Convert to message and back
        let message = send_ind.to_message();
        let parsed = SendIndication::from_message(&message).unwrap();

        assert_eq!(parsed.peer_address, peer_addr);
        assert_eq!(parsed.data, data);
        assert_eq!(parsed.transaction_id, send_ind.transaction_id);
    }

    #[test]
    fn test_data_indication() {
        let peer_addr: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let data = b"Response data".to_vec();
        
        let data_ind = DataIndication::new(peer_addr, data.clone());

        // Convert to message and back
        let message = data_ind.to_message();
        let parsed = DataIndication::from_message(&message).unwrap();

        assert_eq!(parsed.peer_address, peer_addr);
        assert_eq!(parsed.data, data);
        assert_eq!(parsed.transaction_id, data_ind.transaction_id);
    }

    #[test]
    fn test_send_indication_missing_data() {
        let mut message = Message::new(MessageType::new(
            MessageMethod::Send,
            MessageClass::Indication,
        ));

        // Add only peer address, no data
        let peer_attr = create_xor_peer_address_attr(
            "192.0.2.1:80".parse().unwrap(),
            &message.transaction_id,
        );
        message.attributes = peer_attr.serialize();
        message.length = message.attributes.len() as u16;

        let result = SendIndication::from_message(&message);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TurnError::BadRequest));
    }

    #[test]
    fn test_send_indication_wrong_class() {
        let message = Message::new(MessageType::new(
            MessageMethod::Send,
            MessageClass::Request, // Wrong class
        ));

        let result = SendIndication::from_message(&message);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TurnError::BadRequest));
    }

    #[test]
    fn test_ipv6_xor_address() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let peer_addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        
        let attr = create_xor_peer_address_attr(peer_addr, &transaction_id);
        let parsed = parse_xor_peer_address(&attr.value, &transaction_id).unwrap();
        
        assert_eq!(parsed, peer_addr);
    }
}