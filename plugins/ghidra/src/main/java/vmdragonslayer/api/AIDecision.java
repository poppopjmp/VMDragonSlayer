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