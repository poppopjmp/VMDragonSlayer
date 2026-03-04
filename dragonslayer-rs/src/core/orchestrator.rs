//! Orchestrator for coordinating multiple analysis engines

use crate::core::error::{DragonError, Result};
use crate::analysis::vm_discovery::{VMDetector, VMStructure};
use crate::analysis::pattern_analysis::{PatternRecognizer, PatternMatch};
use std::sync::Arc;

/// Analysis request
#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    /// Binary data to analyze
    pub binary_data: Vec<u8>,
    
    /// Analysis type
    pub analysis_type: AnalysisType,
    
    /// Additional options
    pub options: std::collections::HashMap<String, String>,
}

/// Analysis result
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Success status
    pub success: bool,
    
    /// VM detection results (if applicable)
    pub vm_structure: Option<VMStructure>,
    
    /// Pattern matches (if applicable)
    pub pattern_matches: Vec<PatternMatch>,
    
    /// Errors encountered
    pub errors: Vec<String>,
    
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

/// Types of analysis that can be performed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisType {
    /// VM discovery only
    VMDiscovery,
    
    /// Pattern analysis only
    PatternAnalysis,
    
    /// Both VM discovery and pattern analysis
    Hybrid,
}

/// Orchestrator coordinates multiple analysis engines
pub struct Orchestrator {
    vm_detector: VMDetector,
    pattern_recognizer: PatternRecognizer,
}

impl Orchestrator {
    /// Create a new orchestrator with default configuration
    pub fn new() -> Self {
        Self {
            vm_detector: VMDetector::new(),
            pattern_recognizer: PatternRecognizer::new(),
        }
    }
    
    /// Analyze binary data according to request
    pub fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResult> {
        let start = std::time::Instant::now();
        let mut errors = Vec::new();
        
        let (vm_structure, pattern_matches) = match request.analysis_type {
            AnalysisType::VMDiscovery => {
                match self.vm_detector.detect_vm(&request.binary_data) {
                    Ok(vm) => (Some(vm), vec![]),
                    Err(e) => {
                        errors.push(format!("VM detection failed: {}", e));
                        (None, vec![])
                    }
                }
            }
            AnalysisType::PatternAnalysis => {
                let matches = self.pattern_recognizer.recognize_patterns(&request.binary_data);
                (None, matches)
            }
            AnalysisType::Hybrid => {
                let vm_result = match self.vm_detector.detect_vm(&request.binary_data) {
                    Ok(vm) => Some(vm),
                    Err(e) => {
                        errors.push(format!("VM detection failed: {}", e));
                        None
                    }
                };
                
                let pattern_matches = self.pattern_recognizer.recognize_patterns(&request.binary_data);
                
                (vm_result, pattern_matches)
            }
        };
        
        let execution_time_ms = start.elapsed().as_millis() as u64;
        let success = errors.is_empty() || !vm_structure.is_none() || !pattern_matches.is_empty();
        
        Ok(AnalysisResult {
            success,
            vm_structure,
            pattern_matches,
            errors,
            execution_time_ms,
        })
    }
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new()
    }
}

