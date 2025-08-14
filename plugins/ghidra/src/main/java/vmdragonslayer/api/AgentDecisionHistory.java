package vmdragonslayer.api;

import java.util.List;
import java.util.ArrayList;

/**
 * Agent Decision History for AI Dashboard
 */
public class AgentDecisionHistory {
    public List<AIDecision> decisions;
    public AgentStatistics statistics;
    
    public AgentDecisionHistory() {
        this.decisions = new ArrayList<>();
        this.statistics = new AgentStatistics();
    }
    
    public static class AgentStatistics {
        public int totalDecisions = 0;
        public double averageConfidence = 0.0;
        public String learningStatus = "Initializing";
        
        public AgentStatistics() {}
    }
}