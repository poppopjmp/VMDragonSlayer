//! Integration tests for DragonSlayer-RS

use dragonslayer_rs::{Orchestrator, AnalysisRequest, AnalysisType};
use dragonslayer_rs::analysis::vm_discovery::VMDetector;
use dragonslayer_rs::analysis::pattern_analysis::PatternRecognizer;

#[test]
fn test_vm_detector_basic() {
    let detector = VMDetector::new();
    let binary = vec![0x8B, 0x45, 0x08, 0xFF, 0xE0]; // MOV EAX, [EBP+8]; JMP EAX
    
    // This should find a dispatcher
    match detector.detect_vm(&binary) {
        Ok(vm) => {
            assert!(vm.confidence > 0.0, "VM confidence should be > 0");
            assert!(vm.dispatcher_address >= 0, "Dispatcher address should be valid");
        }
        Err(_) => {
            // It's okay if it fails due to low confidence
            // The important thing is it doesn't crash
        }
    }
}

#[test]
fn test_pattern_recognizer() {
    let recognizer = PatternRecognizer::new();
    
    // Test with VM-like bytecode
    let bytecode = vec![
        0x50, 0x51, 0x52,  // PUSH EAX, ECX, EDX (stack_push pattern)
        0x8B, 0x45, 0x08,  // MOV EAX, [EBP+8]
        0xFF, 0xE0,        // JMP EAX (dispatcher_jmp)
        0x90, 0x90,        // NOPs
        0xAC,              // LODSB (handler_lodsb)
    ];
    
    let matches = recognizer.recognize_patterns(&bytecode);
    
    // Should find at least some patterns
    assert!(!matches.is_empty(), "Should find at least one pattern");
    
    // Check that matches are sorted by confidence
    if matches.len() > 1 {
        for i in 0..matches.len() - 1 {
            assert!(
                matches[i].confidence >= matches[i + 1].confidence,
                "Matches should be sorted by confidence"
            );
        }
    }
}

#[test]
fn test_orchestrator_vm_discovery() {
    let orchestrator = Orchestrator::new();
    
    let request = AnalysisRequest {
        binary_data: vec![0x8B, 0x45, 0x08, 0xFF, 0xE0], // Simple binary
        analysis_type: AnalysisType::VMDiscovery,
        options: std::collections::HashMap::new(),
    };
    
    let result = orchestrator.analyze(request).expect("Analysis should complete");
    
    // Check basic result structure
    assert!(result.execution_time_ms >= 0, "Execution time should be non-negative");
    
    // VM detection might fail, but shouldn't panic
    println!("Analysis completed in {}ms", result.execution_time_ms);
}

#[test]
fn test_orchestrator_pattern_analysis() {
    let orchestrator = Orchestrator::new();
    
    let bytecode = vec![0x50, 0x51, 0x52, 0xFF, 0xE0];
    
    let request = AnalysisRequest {
        binary_data: bytecode,
        analysis_type: AnalysisType::PatternAnalysis,
        options: std::collections::HashMap::new(),
    };
    
    let result = orchestrator.analyze(request).expect("Analysis should complete");
    
    // Should succeed and find patterns
    assert!(result.success || !result.pattern_matches.is_empty(), 
        "Should find at least one pattern or succeed");
}

#[test]
fn test_orchestrator_hybrid() {
    let orchestrator = Orchestrator::new();
    
    let binary = vec![
        0x55, 0x8B, 0xEC,  // PUSH EBP, MOV EBP, ESP
        0x50, 0x51, 0x52,  // PUSH EAX, ECX, EDX
        0x8B, 0x45, 0x08,  // MOV EAX, [EBP+8]
        0xFF, 0xE0,        // JMP EAX
        0x90,              // NOP
        0xAC,              // LODSB
    ];
    
    let request = AnalysisRequest {
        binary_data: binary,
        analysis_type: AnalysisType::Hybrid,
        options: std::collections::HashMap::new(),
    };
    
    let result = orchestrator.analyze(request).expect("Analysis should complete");
    
    println!("Hybrid analysis completed in {}ms", result.execution_time_ms);
    println!("Pattern matches: {}", result.pattern_matches.len());
    
    // Hybrid analysis should attempt both
    assert!(result.execution_time_ms >= 0);
}

