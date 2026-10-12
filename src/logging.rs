use crate::config::LoggingConfig;
use std::str::FromStr;
use thiserror::Error;
use tracing::Level;
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*, registry::Registry};

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("Failed to parse log level '{0}'")]
    InvalidLevel(String),
    #[error("Failed to set global default tracing subscriber: {0}")]
    InitFailed(String),
}

/// Initializes the global tracing subscriber based on LoggingConfig.
pub fn init(config: &LoggingConfig) -> Result<(), LoggingError> {
    let default_level = Level::from_str(&config.level)
        .map_err(|_| LoggingError::InvalidLevel(config.level.clone()))?;

    // Allow RUST_LOG environment variable to override if set, otherwise fallback to config level
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level.as_str()));

    let registry = Registry::default().with(env_filter);

    match config.format.to_lowercase().as_str() {
        "json" => {
            let json_layer = fmt::layer()
                .json()
                .with_target(config.target)
                .with_thread_ids(config.thread_ids)
                .with_line_number(config.line_numbers);
            registry
                .with(json_layer)
                .try_init()
                .map_err(|e| LoggingError::InitFailed(e.to_string()))?;
        }
        "compact" => {
            let compact_layer = fmt::layer()
                .compact()
                .with_target(config.target)
                .with_thread_ids(config.thread_ids)
                .with_line_number(config.line_numbers);
            registry
                .with(compact_layer)
                .try_init()
                .map_err(|e| LoggingError::InitFailed(e.to_string()))?;
        }
        _ => {
            // "pretty" or default human-readable
            let pretty_layer = fmt::layer()
                .pretty()
                .with_target(config.target)
                .with_thread_ids(config.thread_ids)
                .with_line_number(config.line_numbers);
            registry
                .with(pretty_layer)
                .try_init()
                .map_err(|e| LoggingError::InitFailed(e.to_string()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_levels_parsing() {
        assert!(Level::from_str("trace").is_ok());
        assert!(Level::from_str("debug").is_ok());
        assert!(Level::from_str("info").is_ok());
        assert!(Level::from_str("warn").is_ok());
        assert!(Level::from_str("error").is_ok());
    }

    #[test]
    fn test_invalid_level_fails() {
        let bad_config = LoggingConfig {
            level: "super_verbose".into(),
            ..Default::default()
        };
        assert!(init(&bad_config).is_err());
    }
}
