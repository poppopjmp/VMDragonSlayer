//! Error types for DragonSlayer-RS
//!
//! This module defines the error hierarchy for the entire framework.

use std::fmt;

/// Main error type for DragonSlayer-RS
#[derive(Debug)]
pub enum DragonError {
    /// Configuration error
    ConfigError(String),
    
    /// VM detection failed
    VMDetection(String),
    
    /// Pattern analysis failed
    PatternAnalysis(String),
    
    /// Taint tracking failed
    TaintTracking(String),
    
    /// Symbolic execution failed
    SymbolicExecution(String),
    
    /// Solver error (Z3)
    SolverUnsat,
    
    /// Machine learning error
    MachineLearning(String),
    
    /// I/O error
    Io(std::io::Error),
    
    /// Serialization error
    Serialization(String),
    
    /// Generic error with context
    Other(String),
}

impl fmt::Display for DragonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DragonError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            DragonError::VMDetection(msg) => write!(f, "VM detection failed: {}", msg),
            DragonError::PatternAnalysis(msg) => write!(f, "Pattern analysis failed: {}", msg),
            DragonError::TaintTracking(msg) => write!(f, "Taint tracking failed: {}", msg),
            DragonError::SymbolicExecution(msg) => write!(f, "Symbolic execution failed: {}", msg),
            DragonError::MachineLearning(msg) => write!(f, "Machine learning error: {}", msg),
            DragonError::Io(e) => write!(f, "I/O error: {}", e),
            DragonError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            DragonError::Other(msg) => write!(f, "Error: {}", msg),
            DragonError::SolverUnsat => write!(f, "Solver unsatisfiable"),
        }
    }
}

impl std::error::Error for DragonError {}

// Type alias for convenience
pub type Result<T> = std::result::Result<T, DragonError>;

// Enable automatic conversions from common error types
impl From<std::io::Error> for DragonError {
    fn from(err: std::io::Error) -> Self {
        DragonError::Io(err)
    }
}

impl From<serde_json::Error> for DragonError {
    fn from(err: serde_json::Error) -> Self {
        DragonError::Serialization(err.to_string())
    }
}

// TODO: Re-enable when TOML support is added back
// impl From<toml::de::Error> for DragonError {
//     fn from(err: toml::de::Error) -> Self {
//         DragonError::ConfigError(format!("TOML parse error: {}", err))
//     }
// }

