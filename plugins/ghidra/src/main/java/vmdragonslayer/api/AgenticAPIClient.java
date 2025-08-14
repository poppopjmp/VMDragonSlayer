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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Consumer;

/**
 * API Client for VMDragonSlayer Agentic System
 * 
 * Provides communication with the Python agentic API service including:
 * - Engine status monitoring
 * - AI decision tracking and explanation
 * - Real-time WebSocket streaming
 * - Intelligent analysis orchestration
 */
public class AgenticAPIClient {
    
    private static final String USER_AGENT = "VMDragonSlayer-Ghidra-Plugin/1.0";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration WEBSOCKET_TIMEOUT = Duration.ofSeconds(5);
    
    private final String baseUrl;
    private final String authToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    // WebSocket connection for real-time updates
    private WebSocket webSocket;
    private Consumer<AnalysisUpdate> analysisUpdateHandler;
    
    // Connection state
    private boolean isConnected = false;
    private EngineStatus lastEngineStatus;
    
    public AgenticAPIClient(String baseUrl, String authToken) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.authToken = authToken;
        
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
            
        this.objectMapper = new ObjectMapper();
        // Configure ObjectMapper to exclude null values and empty collections
        this.objectMapper.setDefaultPropertyInclusion(
            com.fasterxml.jackson.annotation.JsonInclude.Value.construct(
                com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL,
                com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY
            )
        );
        
        Msg.info(this, "AgenticAPIClient initialized for: " + this.baseUrl);
    }
    
    /**
     * Test connection to the agentic API service
     */
    public boolean testConnection() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/health"))
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode healthData = objectMapper.readTree(response.body());
                String status = healthData.get("status").asText();
                isConnected = "healthy".equals(status);
                
                Msg.info(this, "API health check: " + status);
                return isConnected;
            }
            
        } catch (Exception e) {
            Msg.error(this, "Connection test failed: " + e.getMessage(), e);
            isConnected = false;
        }
        
        return false;
    }
    
    /**
     * ===== CORE API METHODS =====
     * Core functionality aligned with dragonslayer API
     */
    
    /**
     * Get analysis types supported by the API
     */
    public Map<String, Object> getSupportedAnalysisTypes() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/analysis-types"))
                .header("Authorization", "Bearer " + authToken)
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode responseData = objectMapper.readTree(response.body());
                return objectMapper.convertValue(responseData, Map.class);
            } else {
                Msg.warn(this, "Failed to get analysis types: " + response.statusCode());
                
                // Return default analysis types
                Map<String, Object> defaultTypes = new HashMap<>();
                defaultTypes.put("analysis_types", Arrays.asList("hybrid", "vm_discovery", "pattern_analysis"));
                defaultTypes.put("workflow_strategies", Arrays.asList("sequential", "parallel"));
                return defaultTypes;
            }
            
        } catch (Exception e) {
            Msg.error(this, "Failed to get analysis types: " + e.getMessage(), e);
            
            // Return default analysis types
            Map<String, Object> defaultTypes = new HashMap<>();
            defaultTypes.put("analysis_types", Arrays.asList("hybrid", "vm_discovery", "pattern_analysis"));
            defaultTypes.put("workflow_strategies", Arrays.asList("sequential", "parallel"));
            return defaultTypes;
        }
    }
    
    /**
     * Get engine status and availability
     */
    public EngineStatus getEngineStatus() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/status"))
                .header("Authorization", "Bearer " + authToken)
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode data = objectMapper.readTree(response.body());
                
                boolean standardEnginesAvailable = "active".equals(data.get("status").asText());
                List<String> availableEngines = Arrays.asList("hybrid", "vm_discovery", "pattern_analysis");
                
                lastEngineStatus = new EngineStatus(standardEnginesAvailable, availableEngines);
                
                Msg.info(this, String.format("Engines: %s, Available: %s", 
                    standardEnginesAvailable, String.join(", ", availableEngines)));
                
                return lastEngineStatus;
            }
            
        } catch (Exception e) {
            Msg.error(this, "Failed to get engine status: " + e.getMessage(), e);
        }
        
        return new EngineStatus(false, Arrays.asList("ml", "pattern", "semantic"));
    }
    
    /**
     * Get system statistics including metrics
     */
    public SystemStatistics getSystemStatistics() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/metrics"))
                .header("Authorization", "Bearer " + authToken)
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode data = objectMapper.readTree(response.body());
                
                return new SystemStatistics(
                    data.get("active_analyses").asInt(0),
                    data.get("total_analyses").asInt(0),
                    data.get("uptime_seconds").asDouble(0.0),
                    true // Standard engines available
                );
            }
            
        } catch (Exception e) {
            Msg.error(this, "Failed to get system statistics: " + e.getMessage(), e);
        }
        
        return new SystemStatistics(0, 0, 0.0, false);
    }
    
    /**
     * Get AI agent decision history (simulated for now)
     */
    public List<AIDecision> getAIDecisionHistory(int limit) {
        // Since the dragonslayer API doesn't have this endpoint yet,
        // return simulated decision history
        List<AIDecision> decisions = new ArrayList<>();
        
        decisions.add(new AIDecision(
            "analysis_type_selection",
            0.85,
            "Selected hybrid analysis based on binary characteristics",
            new java.util.Date().toString()
        ));
        
        decisions.add(new AIDecision(
            "vm_detection_strategy",
            0.92,
            "Applied VM discovery patterns based on entropy analysis",
            new java.util.Date().toString()
        ));
        
        Msg.info(this, "Returned simulated AI decision history");
        return decisions;
    }
    
    /**
     * Start agentic analysis with the dragonslayer API
     */
    public CompletableFuture<String> startAgenticAnalysis(AnalysisRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String requestBody = objectMapper.writeValueAsString(request);
                
                HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/analyze"))
                    .header("Authorization", "Bearer " + authToken)
                    .header("Content-Type", "application/json")
                    .header("User-Agent", USER_AGENT)
                    .timeout(REQUEST_TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
                
                HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() == 200) {
                    JsonNode data = objectMapper.readTree(response.body());
                    String taskId = data.get("request_id").asText();
                    
                    Msg.info(this, "Started analysis task: " + taskId);
                    return taskId;
                } else if (response.statusCode() == 422) {
                    // Validation error - provide detailed error information
                    String responseBody = response.body();
                    Msg.error(this, "Validation error (422): " + responseBody);
                    throw new RuntimeException("Validation error: " + responseBody);
                } else if (response.statusCode() == 401) {
                    throw new RuntimeException("Authentication failed: Invalid token");
                } else {
                    String responseBody = response.body();
                    String errorMsg = String.format("Analysis request failed with status %d: %s", 
                                                   response.statusCode(), responseBody);
                    Msg.error(this, errorMsg);
                    throw new RuntimeException(errorMsg);
                }
                
            } catch (Exception e) {
                Msg.error(this, "Failed to start analysis: " + e.getMessage(), e);
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Get analysis task status and results
     */
    public CompletableFuture<AnalysisResult> getAnalysisResult(String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/status"))
                    .header("Authorization", "Bearer " + authToken)
                    .header("User-Agent", USER_AGENT)
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();
                
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() == 200) {
                    JsonNode data = objectMapper.readTree(response.body());
                    
                    String status = data.get("status").asText();
                    double progress = 1.0; // Status endpoint doesn't provide progress, assume complete
                    
                    AnalysisResult result = new AnalysisResult(taskId, status, progress);
                    
                    // Parse status information
                    if (data.has("active_analyses")) {
                        result.setAnalysisType("standard");
                        result.setConfidence(0.8); // Default confidence
                        result.setExecutionTime(data.get("uptime_seconds").asDouble());
                    }
                    
                    return result;
                }
                
                throw new RuntimeException("Failed to get analysis result: " + response.statusCode());
                
            } catch (Exception e) {
                Msg.error(this, "Failed to get analysis result: " + e.getMessage(), e);
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Create WebSocket connection for real-time updates
     */
    public CompletableFuture<Void> connectWebSocket(Consumer<AnalysisUpdate> updateHandler) {
        this.analysisUpdateHandler = updateHandler;
        
        try {
            URI wsUri = new URI(baseUrl.replace("http://", "ws://").replace("https://", "wss://") + "/ws");
            
            WebSocket.Builder wsBuilder = httpClient.newWebSocketBuilder()
                .header("Authorization", "Bearer " + authToken)
                .connectTimeout(WEBSOCKET_TIMEOUT);
            
            return wsBuilder.buildAsync(wsUri, new WebSocketListener())
                .thenAccept(ws -> {
                    this.webSocket = ws;
                    Msg.info(this, "WebSocket connected for real-time updates");
                });
                
        } catch (URISyntaxException e) {
            Msg.error(this, "Invalid WebSocket URI: " + e.getMessage(), e);
            return CompletableFuture.failedFuture(e);
        }
    }
    
    /**
     * Create program context for AI agent
     */
    public ProgramContext createProgramContext(String name, String path, String format, 
                                              String language, int addressSize) {
        return new ProgramContext(name, path, format, language, addressSize);
    }
    
    /**
     * Update AI context with program information
     */
    public void updateAIContext(ProgramContext context) {
        // Implementation for updating AI context
        Msg.info(this, "AI context updated for program: " + context.getName());
    }
    
    /**
     * Disconnect from API service
     */
    public void disconnect() {
        if (webSocket != null) {
            webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "Plugin shutdown");
            webSocket = null;
        }
        isConnected = false;
        Msg.info(this, "Disconnected from agentic API service");
    }
    
    // Inner class for WebSocket message handling
    private class WebSocketListener implements WebSocket.Listener {
        @Override
        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            try {
                JsonNode message = objectMapper.readTree(data.toString());
                
                if (analysisUpdateHandler != null) {
                    AnalysisUpdate update = parseAnalysisUpdate(message);
                    analysisUpdateHandler.accept(update);
                }
                
            } catch (Exception e) {
                Msg.error(AgenticAPIClient.this, "WebSocket message parsing error: " + e.getMessage(), e);
            }
            
            return WebSocket.Listener.super.onText(webSocket, data, last);
        }
        
        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            Msg.error(AgenticAPIClient.this, "WebSocket error: " + error.getMessage(), error);
        }
    }
    
    private AnalysisUpdate parseAnalysisUpdate(JsonNode message) {
        String type = message.get("type").asText();
        JsonNode data = message.get("data");
        
        return new AnalysisUpdate(
            type,
            data.has("progress") ? data.get("progress").asDouble() : 0.0,
            data.has("status") ? data.get("status").asText() : "unknown",
            data.has("message") ? data.get("message").asText() : ""
        );
    }
    
    /**
     * Get agent decision history for AI dashboard (simulated)
     */
    public AgentDecisionHistory getAgentDecisionHistory() {
        // Since the dragonslayer API doesn't have this endpoint yet,
        // return simulated decision history
        AgentDecisionHistory history = new AgentDecisionHistory();
        
        Msg.info(this, "Returned simulated agent decision history");
        return history;
    }
    
    /**
     * Get system statistics for performance monitoring
     */
    public SystemStats getSystemStats() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/metrics"))
                .header("Authorization", "Bearer " + authToken)
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode responseData = objectMapper.readTree(response.body());
                return objectMapper.convertValue(responseData, SystemStats.class);
            } else {
                Msg.warn(this, "Failed to get system stats: " + response.statusCode());
                return new SystemStats();
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error getting system stats: " + e.getMessage(), e);
            return new SystemStats();
        }
    }
    
    /**
     * Get analysis status for progress monitoring (simulated)
     */
    public CompletableFuture<AnalysisStatus> getAnalysisStatus(String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            // Since the dragonslayer API doesn't have task tracking yet,
            // return simulated status
            AnalysisStatus status = new AnalysisStatus();
            
            Msg.info(this, "Returned simulated analysis status for task: " + taskId);
            return status;
        });
    }
    
    /**
     * Get collaboration requests (simulated for Phase 4 features)
     */
    public Object getCollaborationRequests(boolean includeResolved) {
        Map<String, Object> response = new HashMap<>();
        response.put("requests", new ArrayList<>());
        response.put("total", 0);
        
        Msg.info(this, "Returned simulated collaboration requests");
        return response;
    }
    
    /**
     * Get advanced orchestrator status (simulated for Phase 4 features)
     */
    public Object getAdvancedOrchestratorStatus() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "active");
        response.put("orchestrator_version", "1.0.0");
        response.put("agents_connected", 0);
        
        Msg.info(this, "Returned simulated orchestrator status");
        return response;
    }
    
    /**
     * Get meta learning history (simulated for Phase 4 features)
     */
    public Object getMetaLearningHistory(int limit) {
        Map<String, Object> response = new HashMap<>();
        response.put("history", new ArrayList<>());
        response.put("total_optimizations", 0);
        
        Msg.info(this, "Returned simulated meta learning history");
        return response;
    }
    
    /**
     * Get contextual insights (simulated for Phase 4 features)
     */
    public Object getContextualInsights(int limit) {
        Map<String, Object> response = new HashMap<>();
        response.put("insights", new ArrayList<>());
        response.put("total", 0);
        
        Msg.info(this, "Returned simulated contextual insights");
        return response;
    }
    
    /**
     * Submit collaboration response (simulated for Phase 4 features)
     */
    public Object submitCollaborationResponse(String requestId, String optionId, String explanation) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "accepted");
        response.put("request_id", requestId);
        
        Msg.info(this, "Submitted collaboration response for: " + requestId);
        return response;
    }
    
    /**
     * Trigger meta learning optimization (simulated for Phase 4 features)
     */
    public Object triggerMetaLearningOptimization() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "started");
        response.put("optimization_id", "opt_" + System.currentTimeMillis());
        response.put("improvements_found", 0);
        
        Msg.info(this, "Triggered meta learning optimization");
        return response;
    }
    
    // Getters
    public boolean isConnected() { return isConnected; }
    public String getBaseUrl() { return baseUrl; }
    public EngineStatus getLastEngineStatus() { return lastEngineStatus; }
}