package vmdragonslayer.api;

import java.util.List;

/**
 * Analysis Result with Enterprise Information
 */
public class AnalysisResult {
    private final String taskId;
    private final String status;
    private final double progress;
    
    // Analysis details
    private String analysisType;
    private double confidence;
    private double executionTime;
    private String agentReasoning;
    private List<String> recommendations;
    
    // Enterprise engine information
    private boolean enterpriseEngineUsed;
    private String engineType;
    private PerformanceMetrics performanceMetrics;
    
    // Additional fields needed by integration and UI
    private String engineUsed;
    private Double overallConfidence;
    private Double analysisTime;
    private String aiReasoning;
    private List<VMDetectionResult> vmDetection;
    private List<PatternResult> patterns;
    private List<AIDecision> aiDecisions;
    
    public AnalysisResult(String taskId, String status, double progress) {
        this.taskId = taskId;
        this.status = status;
        this.progress = progress;
    }
    
    // Getters and setters for all fields
    public String getTaskId() { return taskId; }
    public String getStatus() { return status; }
    public double getProgress() { return progress; }
    
    public String getAnalysisType() { return analysisType; }
    public void setAnalysisType(String analysisType) { this.analysisType = analysisType; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public double getExecutionTime() { return executionTime; }
    public void setExecutionTime(double executionTime) { this.executionTime = executionTime; }
    
    public String getAgentReasoning() { return agentReasoning; }
    public void setAgentReasoning(String agentReasoning) { this.agentReasoning = agentReasoning; }
    
    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
    
    public boolean isEnterpriseEngineUsed() { return enterpriseEngineUsed; }
    public void setEnterpriseEngineUsed(boolean enterpriseEngineUsed) { this.enterpriseEngineUsed = enterpriseEngineUsed; }
    
    public String getEngineType() { return engineType; }
    public void setEngineType(String engineType) { this.engineType = engineType; }
    
    public PerformanceMetrics getPerformanceMetrics() { return performanceMetrics; }
    public void setPerformanceMetrics(PerformanceMetrics performanceMetrics) { this.performanceMetrics = performanceMetrics; }
    
    // Additional field getters/setters
    public String getEngineUsed() { return engineUsed; }
    public void setEngineUsed(String engineUsed) { this.engineUsed = engineUsed; }
    
    public Double getOverallConfidence() { return overallConfidence; }
    public void setOverallConfidence(Double overallConfidence) { this.overallConfidence = overallConfidence; }
    
    public Double getAnalysisTime() { return analysisTime; }
    public void setAnalysisTime(Double analysisTime) { this.analysisTime = analysisTime; }
    
    public String getAiReasoning() { return aiReasoning; }
    public void setAiReasoning(String aiReasoning) { this.aiReasoning = aiReasoning; }
    
    public List<VMDetectionResult> getVmDetection() { return vmDetection; }
    public void setVmDetection(List<VMDetectionResult> vmDetection) { this.vmDetection = vmDetection; }
    
    public List<PatternResult> getPatterns() { return patterns; }
    public void setPatterns(List<PatternResult> patterns) { this.patterns = patterns; }
    
    public List<AIDecision> getAiDecisions() { return aiDecisions; }
    public void setAiDecisions(List<AIDecision> aiDecisions) { this.aiDecisions = aiDecisions; }
    
    // Static inner classes for data structures
    public static class VMDetectionResult {
        public String vmType;
        public double confidence;
        public String evidence;
        public String location;
        public String aiReasoning;
        
        public VMDetectionResult(String vmType, double confidence, String evidence, String location, String aiReasoning) {
            this.vmType = vmType;
            this.confidence = confidence;
            this.evidence = evidence;
            this.location = location;
            this.aiReasoning = aiReasoning;
        }
    }
    
    public static class PatternResult {
        public String patternType;
        public double confidence;
        public Integer frequency;
        public String description;
        public String impact;
        public String location;
        
        public PatternResult(String patternType, double confidence, String location) {
            this.patternType = patternType;
            this.confidence = confidence;
            this.location = location;
        }
    }
    
    public static class PerformanceData {
        public double overallScore;
        
        public PerformanceData(double overallScore) {
            this.overallScore = overallScore;
        }
    }
}