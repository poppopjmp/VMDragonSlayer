//! Analysis engines for DragonSlayer-RS
//!
//! This module contains the various analysis engines:
//! - VM Discovery: Detects VM structures and handlers
//! - Pattern Analysis: Pattern matching and classification
//! - Taint Tracking: Dynamic taint analysis
//! - Symbolic Execution: Path exploration with constraint solving

pub mod vm_discovery;
pub mod pattern_analysis;
pub mod taint_tracking;
pub mod symbolic_execution;
