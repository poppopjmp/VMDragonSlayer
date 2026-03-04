//! Core infrastructure for DragonSlayer-RS
//!
//! This module provides:
//! - Configuration management
//! - Orchestration of analysis workflows
//! - Error handling
//! - Result types

pub mod error;
pub mod config;
pub mod orchestrator;

// Re-export commonly used types
pub use error::{DragonError, Result};
pub use config::{Config, AnalysisConfig, MlConfig, ApiConfig};
pub use orchestrator::{Orchestrator, AnalysisRequest, AnalysisResult, AnalysisType};

