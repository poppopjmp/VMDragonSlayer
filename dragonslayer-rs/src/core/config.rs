//! Configuration management for DragonSlayer-RS
//!
//! This module handles loading and managing configuration from various sources:
//! - Environment variables
//! - Configuration files (TOML/JSON)
//! - Default values

use serde::{Deserialize, Serialize};
// use std::time::Duration;  // Not used yet
use crate::core::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Default analysis type to use
    #[serde(default = "default_analysis_type")]
    pub default_analysis_type: String,
    
    /// Maximum analysis time in seconds
    #[serde(default = "default_max_analysis_time")]
    pub max_analysis_time: u64,
    
    /// Enable caching of analysis results
    #[serde(default = "default_true")]
    pub enable_caching: bool,
    
    /// Cache size limit
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    
    /// Enable parallel processing
    #[serde(default = "default_true")]
    pub enable_parallel_processing: bool,
    
    /// Maximum parallel jobs
    #[serde(default = "default_max_parallel_jobs")]
    pub max_parallel_jobs: usize,
    
    /// Memory limit in MB
    #[serde(default = "default_memory_limit")]
    pub memory_limit_mb: usize,
    
    /// Temporary directory path
    #[serde(default = "default_temp_dir")]
    pub temp_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    /// Model cache size
    #[serde(default = "default_model_cache_size")]
    pub model_cache_size: usize,
    
    /// Batch size for ML inference
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    
    /// Maximum sequence length
    #[serde(default = "default_max_sequence_length")]
    pub max_sequence_length: usize,
    
    /// Memory optimization enabled
    #[serde(default = "default_true")]
    pub memory_optimization: bool,
    
    /// Device preference (auto, cpu, cuda)
    #[serde(default = "default_device_preference")]
    pub device_preference: String,
    
    /// Pattern database path
    #[serde(default = "default_pattern_db_path")]
    pub pattern_database_path: String,
    
    /// Confidence threshold
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// API host
    #[serde(default = "default_api_host")]
    pub host: String,
    
    /// API port
    #[serde(default = "default_api_port")]
    pub port: u16,
    
    /// Number of workers
    #[serde(default = "default_api_workers")]
    pub workers: usize,
    
    /// Request timeout in seconds
    #[serde(default = "default_api_timeout")]
    pub timeout: u64,
    
    /// Maximum file size in MB
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: usize,
    
    /// Enable authentication
    #[serde(default = "default_true")]
    pub enable_auth: bool,
    
    /// Enable WebSocket support
    #[serde(default = "default_true")]
    pub enable_websockets: bool,
    
    /// CORS origins
    #[serde(default = "default_cors_origins")]
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Analysis configuration
    pub analysis: AnalysisConfig,
    
    /// Machine learning configuration
    pub ml: MlConfig,
    
    /// API configuration
    pub api: ApiConfig,
    
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    /// Data directory
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

// Default value functions
fn default_analysis_type() -> String { "hybrid".to_string() }
fn default_max_analysis_time() -> u64 { 600 }
fn default_true() -> bool { true }
fn default_cache_size() -> usize { 1000 }
fn default_max_parallel_jobs() -> usize { 4 }
fn default_memory_limit() -> usize { 2048 }
fn default_temp_dir() -> String { "temp".to_string() }
fn default_model_cache_size() -> usize { 3 }
fn default_batch_size() -> usize { 32 }
fn default_max_sequence_length() -> usize { 1024 }
fn default_device_preference() -> String { "auto".to_string() }
fn default_pattern_db_path() -> String { "data/pattern_database.json".to_string() }
fn default_confidence_threshold() -> f64 { 0.8 }
fn default_api_host() -> String { "127.0.0.1".to_string() }
fn default_api_port() -> u16 { 8000 }
fn default_api_workers() -> usize { 4 }
fn default_api_timeout() -> u64 { 300 }
fn default_max_file_size() -> usize { 100 }
fn default_cors_origins() -> Vec<String> { vec!["*".to_string()] }
fn default_log_level() -> String { "INFO".to_string() }
fn default_data_dir() -> String { "data".to_string() }

impl Config {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self {
            analysis: AnalysisConfig {
                default_analysis_type: default_analysis_type(),
                max_analysis_time: default_max_analysis_time(),
                enable_caching: default_true(),
                cache_size: default_cache_size(),
                enable_parallel_processing: default_true(),
                max_parallel_jobs: default_max_parallel_jobs(),
                memory_limit_mb: default_memory_limit(),
                temp_dir: default_temp_dir(),
            },
            ml: MlConfig {
                model_cache_size: default_model_cache_size(),
                batch_size: default_batch_size(),
                max_sequence_length: default_max_sequence_length(),
                memory_optimization: default_true(),
                device_preference: default_device_preference(),
                pattern_database_path: default_pattern_db_path(),
                confidence_threshold: default_confidence_threshold(),
            },
            api: ApiConfig {
                host: default_api_host(),
                port: default_api_port(),
                workers: default_api_workers(),
                timeout: default_api_timeout(),
                max_file_size_mb: default_max_file_size(),
                enable_auth: default_true(),
                enable_websockets: default_true(),
                cors_origins: default_cors_origins(),
            },
            log_level: default_log_level(),
            data_dir: default_data_dir(),
        }
    }
    
    /// Load configuration from a file
    pub fn load(path: &str) -> Result<Self> {
        // TODO: Implement TOML loading when TOML support is added back
        // For now, just return defaults
        log::warn!("Config file loading not yet implemented, using defaults");
        Ok(Self::new())
        
        // Future implementation:
        // let content = std::fs::read_to_string(path)
        //     .map_err(|e| DragonError::ConfigError(format!("Failed to read config file: {}", e)))?;
        // let config: Config = toml::from_str(&content)
        //     .map_err(|e| DragonError::ConfigError(format!("Failed to parse config: {}", e)))?;
        // Ok(config)
    }
    
    /// Load configuration with environment variable overrides
    pub fn load_with_env() -> Result<Self> {
        // For now, just return default
        // TODO: Implement environment variable loading
        Ok(Self::new())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid configuration: {0}")]
    Invalid(String),
    
    #[error("Configuration file not found: {0}")]
    NotFound(String),
    
    #[error("Failed to parse configuration: {0}")]
    Parse(String),
}

