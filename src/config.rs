use std::env;
use std::path::PathBuf;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory for exported files (default: current working directory)
    pub export_dir: PathBuf,
    /// Maximum number of IOCs to accept in a single session
    pub max_ioc_limit: usize,
}

impl Config {
    /// Load configuration from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        let export_dir = env::var("EXPORT_DIR")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        let max_ioc_limit = env::var("MAX_IOC_LIMIT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10_000);

        Config {
            export_dir,
            max_ioc_limit,
        }
    }
}
