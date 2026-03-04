//! Basic analysis example
//!
//! This example demonstrates how to use DragonSlayer-RS to analyze binary data

use dragonslayer_rs::{Orchestrator, AnalysisRequest, AnalysisType};

fn main() {
    println!("DragonSlayer-RS Basic Analysis Example");
    println!("=====================================\n");
    
    // Create sample binary data with VM-like patterns
    let sample_binary = vec![
        // Some VM entry sequences
        0x55, 0x8B, 0xEC,           // PUSH EBP, MOV EBP, ESP
        0x50, 0x51, 0x52,           // PUSH EAX, ECX, EDX
        // Dispatcher-like pattern
        0x8B, 0x45, 0x08,           // MOV EAX, [EBP+8]
        0xFF, 0xE0,                 // JMP EAX
        // More patterns
        0x90, 0x90, 0x90,           // NOPs
        0xAC,                       // LODSB
        0x50, 0x51,                 // PUSH EAX, ECX
        0x58, 0x59,                 // POP EAX, ECX
        0xFF, 0x24, 0x85,           // JMP [reg*4+offset]
    ];
    
    println!("Sample binary size: {} bytes", sample_binary.len());
    println!("\nAnalyzing binary...\n");
    
    // Create orchestrator
    let orchestrator = Orchestrator::new();
    
    // Run VM discovery
    println!("Running VM Discovery...");
    let request = AnalysisRequest {
        binary_data: sample_binary.clone(),
        analysis_type: AnalysisType::VMDiscovery,
        options: std::collections::HashMap::new(),
    };
    
    match orchestrator.analyze(request) {
        Ok(result) => {
            println!("Status: {}", if result.success { "Success" } else { "Failed" });
            println!("Execution time: {}ms", result.execution_time_ms);
            
            if let Some(vm) = result.vm_structure {
                println!("\nVM Structure Detected:");
                println!("  VM Type: {:?}", vm.vm_type);
                println!("  Dispatcher Address: 0x{:x}", vm.dispatcher_address);
                println!("  Number of Handlers: {}", vm.handlers.len());
                println!("  Confidence: {:.2}%", vm.confidence * 100.0);
                
                if !vm.handlers.is_empty() {
                    println!("\nSample Handler:");
                    let handler = &vm.handlers[0];
                    println!("  Address: 0x{:x}", handler.address);
                    println!("  Name: {}", handler.name);
                    println!("  Type: {:?}", handler.handler_type);
                    println!("  Size: {} bytes", handler.size);
                }
            }
            
            if !result.errors.is_empty() {
                println!("\nErrors:");
                for error in &result.errors {
                    println!("  - {}", error);
                }
            }
        }
        Err(e) => {
            println!("Analysis failed: {}", e);
        }
    }
    
    println!("{}", "=".repeat(50));
    
    // Run pattern analysis
    println!("\nRunning Pattern Analysis...");
    let request = AnalysisRequest {
        binary_data: sample_binary,
        analysis_type: AnalysisType::PatternAnalysis,
        options: std::collections::HashMap::new(),
    };
    
    match orchestrator.analyze(request) {
        Ok(result) => {
            println!("Status: {}", if result.success { "Success" } else { "Failed" });
            println!("Execution time: {}ms", result.execution_time_ms);
            println!("Pattern Matches: {}", result.pattern_matches.len());
            
            if !result.pattern_matches.is_empty() {
                println!("\nTop Pattern Matches:");
                for (i, pattern) in result.pattern_matches.iter().take(5).enumerate() {
                    println!("  {}. {} (type: {}, confidence: {:.2}%, offset: 0x{:x})",
                        i + 1,
                        pattern.name,
                        pattern.pattern_type,
                        pattern.confidence * 100.0,
                        pattern.offset
                    );
                }
            }
        }
        Err(e) => {
            println!("Analysis failed: {}", e);
        }
    }
    
    println!("\nExample completed!");
}

