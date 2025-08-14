/*
 * VMDragonSlayer - Advanced VM detection and analysis library
 * Copyright (C) 2025 van1sh
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package vmdragonslayer.integration;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import vmdragonslayer.api.AnalysisResult;
import vmdragonslayer.api.AIDecision;

/**
 * Ghidra Integration Utilities
 * 
 * Provides integration between VMDragonSlayer analysis results and Ghidra's
 * program analysis capabilities. Handles result highlighting, annotation,
 * navigation, and symbol management.
 */
@SuppressWarnings("removal")
public class GhidraIntegration {
    private final PluginTool tool;
    private final Program program;
    private final GoToService goToService;
    
    // Constants for annotations and bookmarks
    private static final String VM_DETECTION_CATEGORY = "VMDragonSlayer-VM";
    private static final String PATTERN_CATEGORY = "VMDragonSlayer-Patterns";
    private static final String AI_DECISION_CATEGORY = "VMDragonSlayer-AI";
    
    public GhidraIntegration(PluginTool tool, Program program) {
        this.tool = tool;
        this.program = program;
        this.goToService = tool.getService(GoToService.class);
    }
    
    /**
     * Integrates analysis results into Ghidra program
     */
    public boolean integrateAnalysisResults(AnalysisResult results, TaskMonitor monitor) {
        if (results == null || program == null) {
            return false;
        }
        
        try {
            monitor.setMessage("Integrating VM detection results...");
            integrateVMDetectionResults(results.getVmDetection(), monitor);
            
            monitor.setMessage("Integrating pattern discovery results...");
            integratePatternResults(results.getPatterns(), monitor);
            
            monitor.setMessage("Integrating AI decision results...");
            integrateAIDecisions(results.getAiDecisions(), monitor);
            
            monitor.setMessage("Creating summary annotations...");
            createSummaryAnnotations(results, monitor);
            
            return true;
        } catch (Exception e) {
            System.err.println("Error integrating analysis results: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Integrates VM detection results into Ghidra
     */
    private void integrateVMDetectionResults(List<AnalysisResult.VMDetectionResult> vmResults, 
            TaskMonitor monitor) {
        if (vmResults == null || vmResults.isEmpty()) {
            return;
        }
        
        for (AnalysisResult.VMDetectionResult vm : vmResults) {
            try {
                // Parse location if available
                Address address = parseLocationToAddress(vm.location);
                if (address != null) {
                    // Create bookmark for VM detection
                    String bookmarkComment = String.format(
                        "VM Detection: %s (Confidence: %.3f)\n" +
                        "Evidence: %s\n" +
                        "AI Reasoning: %s",
                        vm.vmType, vm.confidence, 
                        vm.evidence != null ? vm.evidence : "N/A",
                        vm.aiReasoning != null ? vm.aiReasoning : "N/A"
                    );
                    
                    createBookmark(address, VM_DETECTION_CATEGORY, 
                        "VM: " + vm.vmType, bookmarkComment);
                    
                    // Add plate comment if high confidence
                    if (vm.confidence >= 0.8) {
                        addPlateComment(address, "🖥️ VM DETECTED: " + vm.vmType + 
                            " (High Confidence: " + String.format("%.3f", vm.confidence) + ")");
                    }
                    
                    // Create symbol for easy navigation
                    createAnalysisSymbol(address, "VM_" + vm.vmType.replace(" ", "_"), 
                        "VMDragonSlayer VM Detection");
                }
            } catch (Exception e) {
                System.err.println("Error processing VM detection result: " + e.getMessage());
            }
        }
    }
    
    /**
     * Integrates pattern discovery results into Ghidra
     */
    private void integratePatternResults(List<AnalysisResult.PatternResult> patterns, 
            TaskMonitor monitor) {
        if (patterns == null || patterns.isEmpty()) {
            return;
        }
        
        for (AnalysisResult.PatternResult pattern : patterns) {
            try {
                // For patterns, we might need to handle ranges or multiple addresses
                Address address = parseLocationToAddress(pattern.location);
                if (address != null) {
                    String bookmarkComment = String.format(
                        "Pattern: %s (Confidence: %.3f)\n" +
                        "Frequency: %s\n" +
                        "Description: %s\n" +
                        "Impact: %s",
                        pattern.patternType, pattern.confidence,
                        pattern.frequency != null ? pattern.frequency.toString() : "N/A",
                        pattern.description != null ? pattern.description : "N/A",
                        pattern.impact != null ? pattern.impact : "N/A"
                    );
                    
                    createBookmark(address, PATTERN_CATEGORY, 
                        "Pattern: " + pattern.patternType, bookmarkComment);
                    
                    // Add EOL comment for patterns
                    if (pattern.confidence >= 0.7) {
                        addEOLComment(address, "🔍 PATTERN: " + pattern.patternType);
                    }
                    
                    // Create symbol for pattern
                    createAnalysisSymbol(address, "PATTERN_" + pattern.patternType.replace(" ", "_"), 
                        "VMDragonSlayer Pattern Detection");
                }
            } catch (Exception e) {
                System.err.println("Error processing pattern result: " + e.getMessage());
            }
        }
    }
    
    /**
     * Integrates AI decision results into Ghidra
     */
    private void integrateAIDecisions(List<AIDecision> decisions, 
            TaskMonitor monitor) {
        if (decisions == null || decisions.isEmpty()) {
            return;
        }
        
        for (AIDecision decision : decisions) {
            try {
                Address address = parseLocationToAddress(decision.getLocation());
                if (address != null) {
                    String bookmarkComment = String.format(
                        "AI Decision: %s (Confidence: %.3f)\n" +
                        "Engine: %s\n" +
                        "Reasoning: %s\n" +
                        "Timestamp: %s",
                        decision.getDecisionType(), decision.getConfidence(),
                        decision.getEngineUsed() != null ? decision.getEngineUsed() : "N/A",
                        decision.getReasoning() != null ? decision.getReasoning() : "N/A",
                        decision.getTimestamp() != null ? decision.getTimestamp() : "N/A"
                    );
                    
                    createBookmark(address, AI_DECISION_CATEGORY, 
                        "AI: " + decision.getDecisionType(), bookmarkComment);
                    
                    // Add pre-comment for AI decisions
                    addPreComment(address, "🤖 AI DECISION: " + decision.getDecisionType() + 
                        " (Confidence: " + String.format("%.3f", decision.getConfidence()) + ")");
                }
            } catch (Exception e) {
                System.err.println("Error processing AI decision: " + e.getMessage());
            }
        }
    }
    
    /**
     * Creates summary annotations for the analysis
     */
    private void createSummaryAnnotations(AnalysisResult results, TaskMonitor monitor) {
        try {
            // Find a good location for summary (entry point or first address)
            Address summaryAddress = findSummaryLocation();
            if (summaryAddress != null) {
                StringBuilder summary = new StringBuilder();
                summary.append("=== VMDragonSlayer Analysis Summary ===\n");
                summary.append("Engine Used: ").append(results.getEngineUsed() != null ? results.getEngineUsed() : "Unknown").append("\n");
                summary.append("Overall Confidence: ").append(results.getOverallConfidence() != null ? 
                    String.format("%.3f", results.getOverallConfidence()) : "N/A").append("\n");
                summary.append("Analysis Time: ").append(results.getAnalysisTime() != null ? 
                    results.getAnalysisTime() + "s" : "N/A").append("\n");
                
                if (results.getVmDetection() != null && !results.getVmDetection().isEmpty()) {
                    summary.append("VM Technologies: ").append(results.getVmDetection().size()).append(" detected\n");
                }
                
                if (results.getPatterns() != null && !results.getPatterns().isEmpty()) {
                    summary.append("Patterns: ").append(results.getPatterns().size()).append(" discovered\n");
                }
                
                summary.append("AI Reasoning: ").append(results.getAiReasoning() != null ? 
                    results.getAiReasoning() : "N/A").append("\n");
                
                createBookmark(summaryAddress, "VMDragonSlayer-Summary", 
                    "Analysis Summary", summary.toString());
                
                addPlateComment(summaryAddress, "📊 VMDragonSlayer Analysis Complete - " + 
                    "See bookmark for details");
            }
        } catch (Exception e) {
            System.err.println("Error creating summary annotations: " + e.getMessage());
        }
    }
    
    /**
     * Navigates to a specific analysis result
     */
    public boolean navigateToResult(Object resultObject) {
        try {
            Address address = null;
            
            if (resultObject instanceof AnalysisResult.VMDetectionResult) {
                AnalysisResult.VMDetectionResult vm = (AnalysisResult.VMDetectionResult) resultObject;
                address = parseLocationToAddress(vm.location);
            } else if (resultObject instanceof AnalysisResult.PatternResult) {
                AnalysisResult.PatternResult pattern = (AnalysisResult.PatternResult) resultObject;
                address = parseLocationToAddress(pattern.location);
            } else if (resultObject instanceof AIDecision) {
                AIDecision decision = (AIDecision) resultObject;
                address = parseLocationToAddress(decision.getLocation());
            }
            
            if (address != null && goToService != null) {
                ProgramLocation location = new ProgramLocation(program, address);
                return goToService.goTo(location);
            }
        } catch (Exception e) {
            System.err.println("Error navigating to result: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Highlights results in the current view
     */
    public void highlightResults(List<Object> results) {
        // Implementation would use Ghidra's highlighting service
        // This is a placeholder for the highlighting functionality
        for (Object result : results) {
            navigateToResult(result); // For now, just navigate to each result
        }
    }
    
    /**
     * Clears all VMDragonSlayer annotations and bookmarks
     */
    public void clearAnalysisResults() {
        try {
            // Clear bookmarks
            program.getBookmarkManager().removeBookmarks(VM_DETECTION_CATEGORY);
            program.getBookmarkManager().removeBookmarks(PATTERN_CATEGORY);
            program.getBookmarkManager().removeBookmarks(AI_DECISION_CATEGORY);
            program.getBookmarkManager().removeBookmarks("VMDragonSlayer-Summary");
            
            // Clear symbols created by analysis
            SymbolTable symbolTable = program.getSymbolTable();
            for (Symbol symbol : symbolTable.getAllSymbols(false)) {
                if (symbol.getName().startsWith("VM_") || 
                    symbol.getName().startsWith("PATTERN_") ||
                    symbol.getSource().toString().contains("VMDragonSlayer")) {
                    symbolTable.removeSymbolSpecial(symbol);
                }
            }
        } catch (Exception e) {
            System.err.println("Error clearing analysis results: " + e.getMessage());
        }
    }
    
    // Helper Methods
    
    private Address parseLocationToAddress(String location) {
        if (location == null || location.trim().isEmpty()) {
            return null;
        }
        
        try {
            AddressFactory addressFactory = program.getAddressFactory();
            
            // Try to parse as hex address
            if (location.startsWith("0x")) {
                return addressFactory.getAddress(location);
            }
            
            // Try to parse as decimal offset
            if (location.matches("\\d+")) {
                long offset = Long.parseLong(location);
                return program.getImageBase().add(offset);
            }
            
            // Try to parse as address string
            return addressFactory.getAddress(location);
            
        } catch (Exception e) {
            System.err.println("Could not parse location: " + location);
            return null;
        }
    }
    
    private void createBookmark(Address address, String category, String type, String comment) {
        try {
            program.getBookmarkManager().setBookmark(address, category, type, comment);
        } catch (Exception e) {
            System.err.println("Error creating bookmark at " + address + ": " + e.getMessage());
        }
    }
    
    private void addPlateComment(Address address, String comment) {
        try {
            Listing listing = program.getListing();
            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            if (codeUnit != null) {
                codeUnit.setComment(CodeUnit.PLATE_COMMENT, comment);
            }
        } catch (Exception e) {
            System.err.println("Error adding plate comment at " + address + ": " + e.getMessage());
        }
    }
    
    private void addEOLComment(Address address, String comment) {
        try {
            Listing listing = program.getListing();
            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            if (codeUnit != null) {
                codeUnit.setComment(CodeUnit.EOL_COMMENT, comment);
            }
        } catch (Exception e) {
            System.err.println("Error adding EOL comment at " + address + ": " + e.getMessage());
        }
    }
    
    private void addPreComment(Address address, String comment) {
        try {
            Listing listing = program.getListing();
            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            if (codeUnit != null) {
                codeUnit.setComment(CodeUnit.PRE_COMMENT, comment);
            }
        } catch (Exception e) {
            System.err.println("Error adding pre comment at " + address + ": " + e.getMessage());
        }
    }
    
    private void createAnalysisSymbol(Address address, String name, String source) {
        try {
            SymbolTable symbolTable = program.getSymbolTable();
            symbolTable.createLabel(address, name, ghidra.program.model.symbol.SourceType.ANALYSIS);
        } catch (InvalidInputException e) {
            System.err.println("Error creating symbol " + name + " at " + address + ": " + e.getMessage());
        }
    }
    
    private Address findSummaryLocation() {
        try {
            // Try to find entry point first
            Address entryPoint = program.getImageBase();
            if (program.getSymbolTable().getExternalSymbol("_start") != null) {
                entryPoint = program.getSymbolTable().getExternalSymbol("_start").getAddress();
            } else if (program.getSymbolTable().getExternalSymbol("main") != null) {
                entryPoint = program.getSymbolTable().getExternalSymbol("main").getAddress();
            }
            
            return entryPoint != null ? entryPoint : program.getImageBase();
        } catch (Exception e) {
            return program.getImageBase();
        }
    }
    
    /**
     * Gets statistics about integrated results
     */
    public Map<String, Integer> getIntegrationStats() {
        Map<String, Integer> stats = new HashMap<>();
        
        try {
            // Count bookmarks by iterating through them using proper Address parameter
            int vmDetectionCount = 0;
            int patternCount = 0;
            int aiDecisionCount = 0;
            
            // Get all bookmarks and filter by category
            var allBookmarks = program.getBookmarkManager().getBookmarksIterator();
            while (allBookmarks.hasNext()) {
                var bookmark = allBookmarks.next();
                String category = bookmark.getCategory();
                if (VM_DETECTION_CATEGORY.equals(category)) {
                    vmDetectionCount++;
                } else if (PATTERN_CATEGORY.equals(category)) {
                    patternCount++;
                } else if (AI_DECISION_CATEGORY.equals(category)) {
                    aiDecisionCount++;
                }
            }
            
            stats.put("VM Detection Bookmarks", vmDetectionCount);
            stats.put("Pattern Bookmarks", patternCount);
            stats.put("AI Decision Bookmarks", aiDecisionCount);
                
            // Count symbols created by analysis
            int analysisSymbols = 0;
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(false)) {
                if (symbol.getName().startsWith("VM_") || symbol.getName().startsWith("PATTERN_")) {
                    analysisSymbols++;
                }
            }
            stats.put("Analysis Symbols", analysisSymbols);
            
        } catch (Exception e) {
            System.err.println("Error getting integration stats: " + e.getMessage());
        }
        
        return stats;
    }
    
    /**
     * Validates that the integration is working properly
     */
    public boolean validateIntegration() {
        try {
            // Check that we have access to required services
            if (program == null) {
                System.err.println("No program available for integration");
                return false;
            }
            
            if (program.getBookmarkManager() == null) {
                System.err.println("Bookmark manager not available");
                return false;
            }
            
            if (program.getSymbolTable() == null) {
                System.err.println("Symbol table not available");
                return false;
            }
            
            return true;
        } catch (Exception e) {
            System.err.println("Integration validation failed: " + e.getMessage());
            return false;
        }
    }
}