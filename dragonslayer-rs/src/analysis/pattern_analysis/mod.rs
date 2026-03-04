//! Pattern Analysis Engine
//!
//! This module provides pattern recognition and classification capabilities
//! for VM bytecode analysis.

use serde::{Deserialize, Serialize};

/// Pattern confidence levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum PatternConfidence {
    /// Very high confidence (>= 0.95)
    VeryHigh,
    
    /// High confidence (>= 0.80)
    High,
    
    /// Medium confidence (>= 0.65)
    Medium,
    
    /// Low confidence (>= 0.50)
    Low,
    
    /// Very low confidence (< 0.50)
    VeryLow,
}

impl PatternConfidence {
    /// Get the numeric value
    pub fn value(&self) -> f64 {
        match self {
            PatternConfidence::VeryHigh => 0.95,
            PatternConfidence::High => 0.80,
            PatternConfidence::Medium => 0.65,
            PatternConfidence::Low => 0.50,
            PatternConfidence::VeryLow => 0.35,
        }
    }
    
    /// Create from numeric value
    pub fn from_value(val: f64) -> Self {
        if val >= 0.95 {
            PatternConfidence::VeryHigh
        } else if val >= 0.80 {
            PatternConfidence::High
        } else if val >= 0.65 {
            PatternConfidence::Medium
        } else if val >= 0.50 {
            PatternConfidence::Low
        } else {
            PatternConfidence::VeryLow
        }
    }
}

/// Represents a pattern match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Pattern name
    pub name: String,
    
    /// Pattern type
    pub pattern_type: String,
    
    /// Match location in bytecode
    pub offset: usize,
    
    /// Match confidence (0.0 to 1.0)
    pub confidence: f64,
    
    /// Matched bytecode
    pub matched_bytes: Vec<u8>,
    
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl PatternMatch {
    /// Get the confidence level enum
    pub fn confidence_level(&self) -> PatternConfidence {
        PatternConfidence::from_value(self.confidence)
    }
}

/// Pattern recognizer - main entry point for pattern analysis
#[derive(Debug)]
pub struct PatternRecognizer {
    /// Recognition configuration
    pub(crate) config: PatternRecognizerConfig,
}

/// Configuration for pattern recognizer
#[derive(Debug, Clone)]
pub struct PatternRecognizerConfig {
    /// Minimum confidence threshold
    pub min_confidence: f64,
    
    /// Maximum matches per pattern
    pub max_matches_per_pattern: usize,
    
    /// Enable fuzzy matching
    pub enable_fuzzy_matching: bool,
}

impl Default for PatternRecognizerConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            max_matches_per_pattern: 10,
            enable_fuzzy_matching: true,
        }
    }
}

impl PatternRecognizer {
    /// Create a new pattern recognizer
    pub fn new() -> Self {
        Self {
            config: PatternRecognizerConfig::default(),
        }
    }
    
    /// Create a new pattern recognizer with custom configuration
    pub fn with_config(config: PatternRecognizerConfig) -> Self {
        Self { config }
    }
    
    /// Recognize patterns in bytecode
    ///
    /// # Arguments
    /// * `bytecode` - Bytecode sequence to analyze
    ///
    /// # Returns
    /// * List of pattern matches
    ///
    /// # Example
    /// ```no_run
    /// use dragonslayer_rs::analysis::pattern_analysis::*;
    ///
    /// let recognizer = PatternRecognizer::new();
    /// let bytecode = vec![0x48, 0x89, 0xC7, 0x90, 0x90];
    ///
    /// let matches = recognizer.recognize_patterns(&bytecode);
    /// println!("Found {} patterns", matches.len());
    /// ```
    pub fn recognize_patterns(&self, bytecode: &[u8]) -> Vec<PatternMatch> {
        if bytecode.is_empty() {
            return vec![];
        }
        
        let mut matches = Vec::new();
        
        // Define known patterns for VM detection
        let patterns = self.get_patterns();
        
        for (pattern_name, pattern_bytes) in patterns {
            // Find pattern occurrences
            for (offset, window) in bytecode.windows(pattern_bytes.len()).enumerate() {
                if window == pattern_bytes.as_slice() {
                    let confidence = self.calculate_confidence(window);
                    
                    if confidence >= self.config.min_confidence {
                        matches.push(PatternMatch {
                            name: pattern_name.clone(),
                            pattern_type: self.classify_pattern_type(&pattern_bytes),
                            offset,
                            confidence,
                            matched_bytes: Vec::from(window),
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        // Sort by confidence (highest first)
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        
        matches
    }
    
    /// Get known patterns for VM detection
    fn get_patterns(&self) -> Vec<(String, Vec<u8>)> {
        vec![
            ("vm_entry".to_string(), vec![0x0F, 0x01, 0x0D]),
            ("vm_call".to_string(), vec![0x50, 0x51, 0x52, 0x53]),
            ("push_all".to_string(), vec![0x9C, 0x60]),
            ("dispatcher_mov".to_string(), vec![0x8B, 0x45, 0x08]),
            ("dispatcher_jmp".to_string(), vec![0xFF, 0xE0]),
            ("handler_lodsb".to_string(), vec![0xAC]),
            ("stack_push".to_string(), vec![0x50, 0x51, 0x52]),
            ("indirect_jmp".to_string(), vec![0xFF, 0x24]),
        ]
    }
    
    /// Classify pattern type based on bytes
    fn classify_pattern_type(&self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "unknown".to_string();
        }
        
        // Simple heuristics
        match bytes[0] {
            0x50..=0x5F => "stack_operation".to_string(),
            0x8B => "data_movement".to_string(),
            0xFF => "control_flow".to_string(),
            0x0F => "extended_instruction".to_string(),
            0x90 => "nop".to_string(),
            0xAC => "byte_load".to_string(),
            _ => "generic".to_string(),
        }
    }
    
    /// Calculate confidence for a pattern match
    fn calculate_confidence(&self, matched_bytes: &[u8]) -> f64 {
        // Base confidence
        let base_confidence: f64 = 0.6;
        
        // Increase confidence based on pattern characteristics
        let has_stack_ops = matched_bytes.iter().any(|&b| b >= 0x50 && b <= 0x5F);
        let has_control_flow = matched_bytes.iter().any(|&b| b == 0xFF || b == 0xE8 || b == 0xE9);
        
        let mut confidence: f64 = base_confidence;
        if has_stack_ops {
            confidence += 0.15;
        }
        if has_control_flow {
            confidence += 0.10;
        }
        
        confidence.min(1.0)
    }
}

impl Default for PatternRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pattern_match_confidence() {
        let match_high = PatternMatch {
            name: "test".to_string(),
            pattern_type: "arithmetic".to_string(),
            offset: 0,
            confidence: 0.85,
            matched_bytes: vec![],
            metadata: std::collections::HashMap::new(),
        };
        
        assert_eq!(match_high.confidence_level(), PatternConfidence::High);
    }
    
    #[test]
    fn test_confidence_enum_values() {
        assert_eq!(PatternConfidence::VeryHigh.value(), 0.95);
        assert_eq!(PatternConfidence::Low.value(), 0.50);
    }
}

