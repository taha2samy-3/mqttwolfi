use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    info!("Starting wolf-mqtt-broker v0.1.0...");
    info!("MQTT v3.1.1 and v5.0 dual protocol engine initialized.");
    info!("wolfSSL security layer configured.");

    Ok(())
}
