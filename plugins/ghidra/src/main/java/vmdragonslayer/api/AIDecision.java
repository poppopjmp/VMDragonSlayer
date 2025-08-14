package vmdragonslayer.api;

/**
 * AI Decision Information
 */
public class AIDecision {
    private final String decisionType;
    private final double confidence;
    private final String reasoning;
    private final String timestamp;
    
    // Additional fields needed by the UI
    private String location;
    private String engineUsed;
    private boolean successful = true;
    private String selectedEngine;
    
    public AIDecision(String decisionType, double confidence, String reasoning, String timestamp) {
        this.decisionType = decisionType;
        this.confidence = confidence;
        this.reasoning = reasoning;
        this.timestamp = timestamp;
    }
    
    // Getters for all fields
    public String getDecisionType() { return decisionType; }
    public double getConfidence() { return confidence; }
    public String getReasoning() { return reasoning; }
    public String getTimestamp() { return timestamp; }
    public String getLocation() { return location; }
    public String getEngineUsed() { return engineUsed; }
    public boolean isSuccessful() { return successful; }
    public String getSelectedEngine() { return selectedEngine; }
    
    // Setters for additional fields
    public void setLocation(String location) { this.location = location; }
    public void setEngineUsed(String engineUsed) { this.engineUsed = engineUsed; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    public void setSelectedEngine(String selectedEngine) { this.selectedEngine = selectedEngine; }
}