use toy_turn::server::turn_server::{TurnServer, TurnServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create server configuration
    let listen_addr = std::env::var("TURN_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3478".to_string());
    let relay_start = std::env::var("TURN_RELAY_START")
        .unwrap_or_else(|_| "0.0.0.0:49152".to_string());
    
    let config = TurnServerConfig {
        listen_address: listen_addr.parse()?,
        realm: "example.com".to_string(),
        relay_address_start: relay_start.parse()?,
        relay_address_count: 100,
    };

    // Create and configure server
    let mut server = TurnServer::new(config).await?;
    
    // Add some test users
    server.add_user("testuser".to_string(), "testpass".to_string());
    server.add_user("alice".to_string(), "password123".to_string());
    
    println!("TURN server starting on {listen_addr}");
    println!("Press Ctrl+C to stop the server");
    
    // Run the server
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                eprintln!("Server error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down TURN server...");
        }
    }
    
    Ok(())
}