use thiserror::Error;

#[derive(Error, Debug)]
pub enum TurnError {
    #[error("Bad Request")]
    BadRequest,
    
    #[error("Unauthorized")]
    Unauthorized,
    
    #[error("Unknown Attribute")]
    UnknownAttribute,
    
    #[error("Stale Nonce")]
    StaleNonce,
    
    #[error("Allocation Mismatch")]
    AllocationMismatch,
    
    #[error("Wrong Credentials")]
    WrongCredentials,
    
    #[error("Unsupported Transport Protocol")]
    UnsupportedTransportProtocol,
    
    #[error("Allocation Quota Reached")]
    AllocationQuotaReached,
    
    #[error("Insufficient Capacity")]
    InsufficientCapacity,
    
    #[error("STUN error: {0}")]
    StunError(#[from] crate::stun::error::StunError),
}

impl TurnError {
    pub fn error_code(&self) -> u16 {
        match self {
            TurnError::BadRequest => 400,
            TurnError::Unauthorized => 401,
            TurnError::UnknownAttribute => 420,
            TurnError::AllocationMismatch => 437,
            TurnError::StaleNonce => 438,
            TurnError::WrongCredentials => 441,
            TurnError::UnsupportedTransportProtocol => 442,
            TurnError::AllocationQuotaReached => 486,
            TurnError::InsufficientCapacity => 508,
            TurnError::StunError(_) => 400,
        }
    }
}