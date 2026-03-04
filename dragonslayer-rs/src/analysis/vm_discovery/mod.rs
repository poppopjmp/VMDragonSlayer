//! VM Discovery Engine
//!
//! This module provides VM detection and structure analysis capabilities.
//! It detects VM-based protection schemes such as VMProtect, Themida, and custom malware VMs.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Type of VM architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VMType {
    /// Stack-based VM (like many VMs)
    StackBased,
    
    /// Register-based VM
    RegisterBased,
    
    /// Hybrid architecture
    Hybrid,
    
    /// Unknown type
    Unknown,
}

/// Type of VM handler
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerType {
    /// Arithmetic operations
    Arithmetic,
    
    /// Logical operations
    Logical,
    
    /// Control flow operations
    ControlFlow,
    
    /// Memory operations
    Memory,
    
    /// Stack operations
    Stack,
    
    /// Register operations
    Register,
    
    /// Unknown handler type
    Unknown,
}

/// Represents a VM handler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMHandler {
    /// Handler address
    pub address: u64,
    
    /// Handler name/identifier
    pub name: String,
    
    /// Type of handler
    pub handler_type: HandlerType,
    
    /// Bytecode sequence
    pub bytecode: Vec<u8>,
    
    /// Handler size
    pub size: usize,
    
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    
    /// Control flow targets
    pub control_flow_targets: HashSet<u64>,
}

/// Represents a detected VM structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMStructure {
    /// Type of VM
    pub vm_type: VMType,
    
    /// Dispatcher address
    pub dispatcher_address: u64,
    
    /// List of handlers
    pub handlers: Vec<VMHandler>,
    
    /// Bytecode table address
    pub bytecode_table: Option<u64>,
    
    /// Handler table address
    pub handler_table: Option<u64>,
    
    /// VM context size
    pub vm_context_size: usize,
    
    /// Instruction patterns
    pub instruction_patterns: Vec<Vec<u8>>,
    
    /// Overall confidence score
    pub confidence: f64,
}

/// VM Detector - main entry point for VM detection
#[derive(Debug)]
pub struct VMDetector {
    /// Configuration
    pub(crate) config: VMDetectorConfig,
}

/// Configuration for VM detector
#[derive(Debug, Clone)]
pub struct VMDetectorConfig {
    /// Minimum confidence threshold
    pub min_confidence: f64,
    
    /// Maximum handlers to analyze
    pub max_handlers: usize,
    
    /// Enable heuristic analysis
    pub enable_heuristics: bool,
}

impl Default for VMDetectorConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            max_handlers: 100,
            enable_heuristics: true,
        }
    }
}

impl VMDetector {
    /// Create a new VM detector with default configuration
    pub fn new() -> Self {
        Self {
            config: VMDetectorConfig::default(),
        }
    }
    
    /// Create a new VM detector with custom configuration
    pub fn with_config(config: VMDetectorConfig) -> Self {
        Self { config }
    }
    
    /// Detect VM structures in binary data
    ///
    /// # Arguments
    /// * `binary` - Binary data to analyze
    ///
    /// # Returns
    /// * `VMStructure` if VM is detected, otherwise returns error
    ///
    /// # Example
    /// ```no_run
    /// use dragonslayer_rs::analysis::vm_discovery::*;
    ///
    /// let detector = VMDetector::new();
    /// let binary = std::fs::read("sample.exe")?;
    ///
    /// match detector.detect_vm(&binary) {
    ///     Ok(structure) => println!("VM detected: {:?}", structure.vm_type),
    ///     Err(e) => println!("No VM detected: {:?}", e),
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn detect_vm(&self, binary: &[u8]) -> crate::core::error::Result<VMStructure> {
        if binary.is_empty() {
            return Err(crate::core::error::DragonError::VMDetection(
                "Empty binary data".to_string(),
            ));
        }
        
        // Step 1: Detect dispatcher loop
        let dispatcher = self.detect_dispatcher(binary)?;
        
        // Step 2: Find handler table
        let handlers = self.find_handlers(binary, dispatcher)?;
        
        // Step 3: Analyze VM type based on patterns
        let vm_type = self.classify_vm_type(&handlers);
        
        // Step 4: Calculate confidence
        let confidence = self.calculate_confidence(&handlers);
        
        if confidence < self.config.min_confidence {
            return Err(crate::core::error::DragonError::VMDetection(
                format!("Low confidence: {:.2}", confidence)
            ));
        }
        
        Ok(VMStructure {
            vm_type,
            dispatcher_address: dispatcher,
            handlers,
            bytecode_table: None,
            handler_table: None,
            vm_context_size: 0,
            instruction_patterns: vec![],
            confidence,
        })
    }
    
    /// Detect dispatcher loop in binary
    fn detect_dispatcher(&self, binary: &[u8]) -> crate::core::error::Result<u64> {
        // Look for common dispatcher patterns
        let dispatcher_patterns = vec![
            vec![0x8B, 0x45, 0x08],  // MOV EAX, [EBP+8]
            vec![0xFF, 0xE0],        // JMP EAX
            vec![0x8B, 0x0C, 0x8D],  // MOV ECX, [ECX*4+offset]
            vec![0xFF, 0xE1],        // JMP ECX
        ];
        
        // Try to find dispatcher pattern
        for pattern in &dispatcher_patterns {
            if let Some(offset) = binary.windows(pattern.len())
                .position(|window| window == pattern.as_slice()) {
                return Ok(offset as u64);
            }
        }
        
        // If no pattern found, look for indirect jump sequences
        for i in 0..binary.len().saturating_sub(32) {
            if self.is_probable_dispatcher(&binary[i..i + 32]) {
                return Ok(i as u64);
            }
        }
        
        Err(crate::core::error::DragonError::VMDetection(
            "No dispatcher found".to_string()
        ))
    }
    
    /// Check if a byte sequence resembles a dispatcher
    fn is_probable_dispatcher(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 8 {
            return false;
        }
        
        // Look for indirect jumps and register operations
        let indirect_jumps = bytes.windows(2)
            .filter(|w| *w == [0xFF, 0xE0] || *w == [0xFF, 0xE1] || *w == [0xFF, 0xE2])
            .count();
        
        let register_ops = bytes.windows(3)
            .filter(|w| {
                w[0] == 0x8B && w[1] == 0x45 ||  // MOV reg, [EBP+offset]
                w[0] == 0x8B && w[1] == 0x04    // MOV reg, [reg+reg*scale]
            })
            .count();
        
        // If we see multiple indirect jumps and register ops, likely a dispatcher
        indirect_jumps >= 2 && register_ops >= 1
    }
    
    /// Find VM handlers starting from dispatcher
    fn find_handlers(&self, binary: &[u8], dispatcher: u64) -> crate::core::error::Result<Vec<VMHandler>> {
        let mut handlers = Vec::new();
        let search_start = dispatcher as usize;
        let search_end = search_start.saturating_add(0x1000); // Search 4KB forward
        let search_end = search_end.min(binary.len());
        
        // Look for function prologues (potential handlers)
        let handler_patterns = vec![
            vec![0x55],           // PUSH EBP
            vec![0x51],           // PUSH ECX
            vec![0x52],           // PUSH EDX
            vec![0x50, 0x51],     // PUSH EAX, PUSH ECX
        ];
        
        for offset in search_start..search_end {
            for pattern in &handler_patterns {
                if offset + pattern.len() < search_end &&
                   binary[offset..offset + pattern.len()] == pattern[..] {
                    let handler = VMHandler {
                        address: offset as u64,
                        name: format!("handler_{:#x}", offset),
                        handler_type: HandlerType::Unknown,
                        bytecode: Vec::from(&binary[offset..(offset + 32).min(search_end)]),
                        size: 32,
                        confidence: 0.6,
                        control_flow_targets: HashSet::new(),
                    };
                    handlers.push(handler);
                    break;
                }
            }
        }
        
        if handlers.is_empty() {
            return Err(crate::core::error::DragonError::VMDetection(
                "No handlers found".to_string()
            ));
        }
        
        // Limit to configured max
        if handlers.len() > self.config.max_handlers {
            handlers.truncate(self.config.max_handlers);
        }
        
        Ok(handlers)
    }
    
    /// Classify VM type based on handler patterns
    fn classify_vm_type(&self, handlers: &[VMHandler]) -> VMType {
        // Analyze handler characteristics
        let has_stack_ops = handlers.iter().any(|h| {
            // Look for stack manipulation instructions
            h.bytecode.windows(1).any(|w| w[0] == 0x50 || w[0] == 0x58 || w[0] == 0x51 || w[0] == 0x59)
        });
        
        let has_register_ops = handlers.iter().any(|h| {
            h.bytecode.windows(1).any(|w| w[0] >= 0x89 && w[0] <= 0x8F) // MOV operations
        });
        
        match (has_stack_ops, has_register_ops) {
            (true, false) => VMType::StackBased,
            (false, true) => VMType::RegisterBased,
            (true, true) => VMType::Hybrid,
            _ => VMType::Unknown,
        }
    }
    
    /// Calculate overall confidence score
    fn calculate_confidence(&self, handlers: &[VMHandler]) -> f64 {
        if handlers.is_empty() {
            return 0.0;
        }
        
        let avg_handler_confidence: f64 = handlers.iter()
            .map(|h| h.confidence)
            .sum::<f64>() / handlers.len() as f64;
        
        let handler_count_factor = (handlers.len() as f64 / 10.0).min(1.0);
        
        // Combine factors
        (avg_handler_confidence * 0.7 + handler_count_factor * 0.3).min(1.0f64)
    }
    
    /// Detect VM structures with async support
    pub async fn detect_vm_async(&self, binary: &[u8]) -> crate::core::error::Result<VMStructure> {
        // For now, just call sync version
        // In the future, this will spawn async tasks for parallel analysis
        self.detect_vm(binary)
    }
}

impl Default for VMDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vm_detector_creation() {
        let detector = VMDetector::new();
        assert!(detector.config.enable_heuristics);
    }
    
    #[test]
    fn test_vm_structure_serialization() {
        let handler = VMHandler {
            address: 0x401000,
            name: "test_handler".to_string(),
            handler_type: HandlerType::Arithmetic,
            bytecode: vec![0x90, 0x90],
            size: 2,
            confidence: 0.8,
            control_flow_targets: HashSet::new(),
        };
        
        let structure = VMStructure {
            vm_type: VMType::StackBased,
            dispatcher_address: 0x400000,
            handlers: vec![handler],
            bytecode_table: Some(0x402000),
            handler_table: Some(0x403000),
            vm_context_size: 64,
            instruction_patterns: vec![],
            confidence: 0.85,
        };
        
        // Test that it can be serialized
        let json = serde_json::to_string(&structure).unwrap();
        assert!(json.contains("StackBased"));
    }
}

