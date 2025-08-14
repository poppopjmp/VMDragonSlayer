package vmdragonslayer.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.List;
import java.util.Map;

/**
 * Analysis Request Configuration
 */
public class AnalysisRequest {
    @JsonProperty("sample_data")
    private String sampleData;
    
    @JsonProperty("analysis_type")
    private String analysisType;
    
    @JsonProperty("user_goals")
    private List<String> userGoals;
    
    @JsonProperty("time_constraints")
    private Integer timeConstraints;
    
    @JsonProperty("resource_limits")
    private Map<String, Object> resourceLimits;
    
    @JsonProperty("confidence_threshold")
    private double confidenceThreshold;
    
    @JsonProperty("enable_learning")
    private boolean enableLearning;
    
    @JsonProperty("webhook_url")
    private String webhookUrl;
    
    // This field is not part of the Python API, so we ignore it during serialization
    @JsonIgnore
    private boolean enterpriseMode;
    
    // Generic parameters field - not sent to API but used internally
    @JsonIgnore
    private Map<String, Object> parameters;
    
    public AnalysisRequest() {
        this.confidenceThreshold = 0.8;
        this.enableLearning = true;
        this.enterpriseMode = true;
    }
    
    // Getters and setters
    public String getSampleData() { return sampleData; }
    public void setSampleData(String sampleData) { this.sampleData = sampleData; }
    
    public String getAnalysisType() { return analysisType; }
    public void setAnalysisType(String analysisType) { this.analysisType = analysisType; }
    
    public List<String> getUserGoals() { return userGoals; }
    public void setUserGoals(List<String> userGoals) { this.userGoals = userGoals; }
    
    public double getConfidenceThreshold() { return confidenceThreshold; }
    public void setConfidenceThreshold(double confidenceThreshold) { this.confidenceThreshold = confidenceThreshold; }
    
    public Integer getTimeConstraints() { return timeConstraints; }
    public void setTimeConstraints(Integer timeConstraints) { this.timeConstraints = timeConstraints; }
    
    public Map<String, Object> getResourceLimits() { return resourceLimits; }
    public void setResourceLimits(Map<String, Object> resourceLimits) { this.resourceLimits = resourceLimits; }
    
    public String getWebhookUrl() { return webhookUrl; }
    public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
    
    public boolean isEnableLearning() { return enableLearning; }
    public void setEnableLearning(boolean enableLearning) { this.enableLearning = enableLearning; }
    
    public boolean isEnterpriseMode() { return enterpriseMode; }
    public void setEnterpriseMode(boolean enterpriseMode) { this.enterpriseMode = enterpriseMode; }
    
    public boolean isStandardMode() { return !enterpriseMode; }
    public void setStandardMode(boolean standardMode) { this.enterpriseMode = !standardMode; }
    
    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
}