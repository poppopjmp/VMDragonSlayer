//! DragonSlayer-RS - Rust port of VMDragonSlayer
//!
//! An automated multi-engine framework for unpacking, analyzing, and devirtualizing binaries.
//!
//! # Overview
//!
//! VMDragonSlayer is a comprehensive framework for analyzing binaries protected by Virtual Machine
//! (VM) based protectors such as VMProtect 2.x/3.x, Themida, and custom malware VMs.
//!
//! # Architecture
//!
//! The framework consists of multiple analysis engines:
//! - **VM Discovery**: Detects VM structures and handlers
//! - **Pattern Analysis**: Pattern matching and classification
//! - **Taint Tracking**: Dynamic taint analysis via Intel Pin
//! - **Symbolic Execution**: Path exploration with Z3 solver
//! - **Machine Learning**: Classification and prediction (hybrid Python/Rust)
//!
//! # Example
//!
//! ```no_run
//! use dragonslayer_rs::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Load configuration
//!     let config = Config::load()?;
//!
//!     // Create orchestrator
//!     let orchestrator = Orchestrator::new(config)?;
//!
//!     // Analyze a binary
//!     let request = AnalysisRequest::new(b"binary_data");
//!     let result = orchestrator.analyze(request).await?;
//!
//!     println!("Analysis complete: {}", result.success);
//!
//!     Ok(())
//! }
//! ```

pub mod core;
pub mod analysis;
pub mod api;
pub mod workflows;
pub mod gpu;
pub mod ml;
pub mod enterprise;
pub mod utils;

// Re-export main types
pub use core::{
    Config, DragonError, Result, 
    Orchestrator, AnalysisRequest, AnalysisResult, AnalysisType,
};

#[doc(inline)]
pub use analysis::vm_discovery::{VMDetector, VMStructure, VMType};
#[doc(inline)]
pub use analysis::pattern_analysis::{PatternRecognizer, PatternMatch};

