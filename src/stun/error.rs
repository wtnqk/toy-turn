use thiserror::Error;

#[derive(Error, Debug)]
pub enum StunError {
    #[error("Invalid magic cookie")]
    InvalidMagicCookie,
    
    #[error("Invalid message length")]
    InvalidMessageLength,
    
    #[error("Message too short")]
    MessageTooShort,
    
    #[error("Invalid message type")]
    InvalidMessageType,
    
    #[error("Invalid attribute")]
    InvalidAttribute,
    
    #[error("Unknown attribute: {0}")]
    UnknownAttribute(u16),
    
    #[error("Invalid transaction ID")]
    InvalidTransactionId,
    
    #[error("Parse error: {0}")]
    ParseError(String),
}