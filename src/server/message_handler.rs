use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::stun::{
    message::{Message, MessageClass},
    attributes::{RawAttribute, AttributeType},
};
use crate::turn::{
    allocation::AllocationManager,
    auth::{NonceManager, UserDatabase},
    allocate::{AllocateRequest, AllocateResponse},
    refresh::{RefreshRequest, RefreshResponse},
    permission::{CreatePermissionRequest, CreatePermissionResponse},
    data::SendIndication,
    channel::{ChannelBindRequest, ChannelBindResponse, ChannelData},
};

pub async fn handle_message(
    data: Vec<u8>,
    src_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    allocation_manager: Arc<AllocationManager>,
    nonce_manager: Arc<RwLock<NonceManager>>,
    user_database: Arc<UserDatabase>,
    realm: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Try to parse as STUN message
    if let Ok(message) = Message::parse(&data) {
        debug!("Received STUN message from {}: {:?}", src_addr, message.message_type);
        
        match message.message_type.class() {
            MessageClass::Request => {
                handle_request(
                    message,
                    src_addr,
                    socket,
                    allocation_manager,
                    nonce_manager,
                    user_database,
                    realm,
                ).await?;
            }
            MessageClass::Indication => {
                handle_indication(
                    message,
                    src_addr,
                    allocation_manager,
                ).await?;
            }
            _ => {
                warn!("Received unexpected message class from {}", src_addr);
            }
        }
    } else if data.len() >= 4 {
        // Try to parse as ChannelData
        let channel_number = u16::from_be_bytes([data[0], data[1]]);
        if (0x4000..=0x7FFF).contains(&channel_number) {
            if let Ok(channel_data) = ChannelData::parse(&data) {
                handle_channel_data(channel_data, src_addr, allocation_manager).await?;
            }
        }
    }
    
    Ok(())
}

async fn handle_request(
    message: Message,
    src_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    allocation_manager: Arc<AllocationManager>,
    nonce_manager: Arc<RwLock<NonceManager>>,
    _user_database: Arc<UserDatabase>,
    realm: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::stun::message::MessageMethod;
    
    match message.message_type.method() {
        MessageMethod::Allocate => {
            let request = AllocateRequest::from_message(&message)?;
            
            // Check authentication
            if request.username.is_none() || request.nonce.is_none() {
                // Send 401 Unauthorized with new nonce
                let nonce = nonce_manager.write().await.generate_nonce();
                let response = AllocateResponse::error(
                    request.transaction_id,
                    401,
                    "Unauthorized".to_string(),
                    Some(realm),
                    Some(nonce.into_bytes()),
                );
                
                send_error_response(response.transaction_id, 401, "Unauthorized", &socket, src_addr).await?;
                return Ok(());
            }
            
            // Create allocation
            let allocation = allocation_manager.create_allocation(
                request.username.unwrap_or_default(),
                src_addr,
            ).await?;
            
            let response = AllocateResponse::success(
                request.transaction_id,
                allocation.relayed_address,
                src_addr,
                600, // 10 minutes
            );
            
            send_success_response(response, &socket, src_addr).await?;
        }
        MessageMethod::Refresh => {
            let request = RefreshRequest::from_message(&message)?;
            
            if request.is_delete_request() {
                allocation_manager.remove_allocation(&src_addr);
            } else {
                let lifetime = request.lifetime.unwrap_or(600);
                allocation_manager.refresh_allocation(&src_addr, std::time::Duration::from_secs(lifetime as u64))?;
            }
            
            let response = RefreshResponse::success(request.transaction_id, request.lifetime.unwrap_or(0));
            send_success_response(response, &socket, src_addr).await?;
        }
        MessageMethod::CreatePermission => {
            let request = CreatePermissionRequest::from_message(&message)?;
            
            if let Some(mut allocation) = allocation_manager.get_allocation(&src_addr) {
                for peer_addr in request.peer_addresses {
                    allocation.add_permission(peer_addr);
                }
            }
            
            let response = CreatePermissionResponse::success(request.transaction_id);
            send_success_response(response, &socket, src_addr).await?;
        }
        MessageMethod::ChannelBind => {
            let request = ChannelBindRequest::from_message(&message)?;
            
            if let Some(mut allocation) = allocation_manager.get_allocation(&src_addr) {
                allocation.add_channel_binding(request.channel_number, request.peer_address)?;
            }
            
            let response = ChannelBindResponse::success(request.transaction_id);
            send_success_response(response, &socket, src_addr).await?;
        }
        _ => {
            warn!("Unhandled request method: {:?}", message.message_type.method());
        }
    }
    
    Ok(())
}

async fn handle_indication(
    message: Message,
    src_addr: SocketAddr,
    allocation_manager: Arc<AllocationManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::stun::message::MessageMethod;
    
    match message.message_type.method() {
        MessageMethod::Send => {
            let indication = SendIndication::from_message(&message)?;
            
            if let Some(allocation) = allocation_manager.get_allocation(&src_addr) {
                if allocation.has_permission(&indication.peer_address) {
                    // Send data to peer
                    allocation.relay_socket.send_to(&indication.data, indication.peer_address).await?;
                }
            }
        }
        _ => {
            warn!("Unhandled indication method: {:?}", message.message_type.method());
        }
    }
    
    Ok(())
}

async fn handle_channel_data(
    channel_data: ChannelData,
    src_addr: SocketAddr,
    allocation_manager: Arc<AllocationManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(allocation) = allocation_manager.get_allocation(&src_addr) {
        if let Some(peer_addr) = allocation.get_peer_by_channel(channel_data.channel_number) {
            // Send data to peer
            allocation.relay_socket.send_to(&channel_data.data, peer_addr).await?;
        }
    }
    
    Ok(())
}

async fn send_success_response<T>(
    _response: T,
    socket: &UdpSocket,
    dst_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Properly serialize response based on type
    // For now, send a minimal success response
    let response_data = vec![0u8; 20]; // Placeholder
    socket.send_to(&response_data, dst_addr).await?;
    Ok(())
}

async fn send_error_response(
    transaction_id: [u8; 12],
    error_code: u16,
    _error_text: &str,
    socket: &UdpSocket,
    dst_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::stun::message::{MessageType, MessageMethod};
    
    let mut response = Message::new(MessageType::new(
        MessageMethod::Allocate,
        MessageClass::ErrorResponse,
    ));
    response.transaction_id = transaction_id;
    
    // Add ERROR-CODE attribute
    let error_data = vec![(error_code / 100) as u8, (error_code % 100) as u8, 0, 0];
    let error_attr = RawAttribute::new(AttributeType::ErrorCode as u16, error_data);
    response.attributes = error_attr.serialize();
    response.length = response.attributes.len() as u16;
    
    let response_data = response.serialize();
    socket.send_to(&response_data, dst_addr).await?;
    Ok(())
}