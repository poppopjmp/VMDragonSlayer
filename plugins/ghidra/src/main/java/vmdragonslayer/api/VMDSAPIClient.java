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
public class VMDSAPIClient {
    
    private static final String USER_AGENT = "VMDragonSlayer-Ghidra-Plugin/1.0";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration WEBSOCKET_TIMEOUT = Duration.ofSeconds(5);
    
    private final String baseUrl;
    private final String authToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final boolean useSimulatedPhase4Features;
    
    // WebSocket connection for real-time updates
    private WebSocket webSocket;
    private Consumer<AnalysisUpdate> analysisUpdateHandler;
    
    // Connection state
    private boolean isConnected = false;
    private EngineStatus lastEngineStatus;
    
    public VMDSAPIClient(String baseUrl, String authToken) {
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
    // Be resilient to missing/extra properties
    this.objectMapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    // Default: do not use simulated Phase 4 features unless explicitly enabled via system property
    this.useSimulatedPhase4Features = Boolean.parseBoolean(System.getProperty("vmds.simulatePhase4", "false"));
        
        Msg.info(this, "VMDSAPIClient initialized for: " + this.baseUrl);
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
                String status = healthData.path("status").asText("unknown");
                isConnected = "healthy".equalsIgnoreCase(status) || "active".equalsIgnoreCase(status);
                
                Msg.info(this, "API health check: " + status);
                return isConnected;
            }
            Msg.warn(this, "Health check non-200: " + response.statusCode() + ", body: " + safeBody(response.body()));
            
        } catch (Exception e) {
            Msg.error(this, "Connection test failed: " + e.getMessage(), e);
            isConnected = false;
        }
        
        return isConnected;
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
                .header("Authorization", bearer())
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode responseData = objectMapper.readTree(response.body());
                return objectMapper.convertValue(responseData, Map.class);
            } else {
                Msg.warn(this, "Failed to get analysis types: " + response.statusCode() + ", body: " + safeBody(response.body()));
                
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
                .header("Authorization", bearer())
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode data = objectMapper.readTree(response.body());
                
                boolean standardEnginesAvailable = "active".equalsIgnoreCase(data.path("status").asText("unknown"));
                List<String> availableEngines = Arrays.asList("hybrid", "vm_discovery", "pattern_analysis", "taint_tracking", "symbolic_execution");
                
                lastEngineStatus = new EngineStatus(standardEnginesAvailable, availableEngines);
                
                Msg.info(this, String.format("Engines: %s, Available: %s", 
                    standardEnginesAvailable, String.join(", ", availableEngines)));
                
                return lastEngineStatus;
            } else {
                Msg.warn(this, "Status fetch failed: " + response.statusCode() + ", body: " + safeBody(response.body()));
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
                .header("Authorization", bearer())
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode data = objectMapper.readTree(response.body());
                
                return new SystemStatistics(
                    data.path("api_active_analyses").asInt(data.path("active_analyses").asInt(0)),
                    data.path("api_total_analyses").asInt(data.path("total_analyses").asInt(0)),
                    data.path("api_uptime_seconds").asDouble(data.path("uptime_seconds").asDouble(0.0)),
                    true // Standard engines available
                );
            } else {
                Msg.warn(this, "Metrics fetch failed: " + response.statusCode() + ", body: " + safeBody(response.body()));
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
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "AI decision history endpoint not available; simulation disabled");
            return Collections.emptyList();
        }
        // Simulated fallback (feature-flagged)
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
        
    Msg.info(this, "Returned simulated AI decision history (feature-flag)");
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
                    .header("Authorization", bearer())
                    .header("Content-Type", "application/json")
                    .header("User-Agent", USER_AGENT)
                    .timeout(REQUEST_TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
                
                HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() == 200) {
                    JsonNode data = objectMapper.readTree(response.body());
                    String taskId = data.path("request_id").asText(null);
                    if (taskId == null || taskId.isEmpty()) {
                        String msg = "Missing request_id in response: " + safeBody(response.body());
                        Msg.error(this, msg);
                        throw new RuntimeException(msg);
                    }
                    
                    Msg.info(this, "Started analysis task: " + taskId);
                    return taskId;
                } else if (response.statusCode() == 422) {
                    // Validation error - provide detailed error information
                    String responseBody = response.body();
                    Msg.error(this, "Validation error (422): " + responseBody);
                    throw new RuntimeException("Validation error: " + responseBody);
                } else if (response.statusCode() == 401 || response.statusCode() == 403) {
                    throw new RuntimeException("Authentication/Authorization failed (" + response.statusCode() + "): " + safeBody(response.body()));
                } else if (response.statusCode() == 404) {
                    throw new RuntimeException("Endpoint not found: /analyze");
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
                String url = baseUrl + "/status" + (taskId != null && !taskId.isEmpty() ? ("?task_id=" + encode(taskId)) : "");
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", bearer())
                    .header("User-Agent", USER_AGENT)
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();
                
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                
                if (response.statusCode() == 200) {
                    JsonNode data = objectMapper.readTree(response.body());
                    
                    String status = data.path("status").asText("unknown");
                    double progress = data.path("progress").asDouble("active".equalsIgnoreCase(status) ? 0.5 : ("complete".equalsIgnoreCase(status) ? 1.0 : 0.0));
                    
                    AnalysisResult result = new AnalysisResult(taskId, status, progress);
                    
                    // Parse status information
                    if (data.has("active_analyses") || data.has("api_active_analyses")) {
                        result.setAnalysisType("standard");
                        result.setConfidence(0.8); // Default confidence
                        result.setExecutionTime(data.path("uptime_seconds").asDouble(0.0));
                    }
                    
                    return result;
                } else {
                    Msg.warn(this, "Get result failed: " + response.statusCode() + ", body: " + safeBody(response.body()));
                    throw new RuntimeException("Failed to get analysis result: " + response.statusCode());
                }
                
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
            URI wsUri = new URI(
                baseUrl.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
            );
            
            WebSocket.Builder wsBuilder = httpClient.newWebSocketBuilder()
                .header("Authorization", bearer())
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
        // No-op unless backend exposes /context; keep lightweight debounce via hash
        try {
            String payload = objectMapper.writeValueAsString(Map.of(
                "name", context.getName(),
                "path", context.getPath(),
                "format", context.getFormat(),
                "language", context.getLanguage(),
                "address_size", context.getAddressSize()
            ));

            // Attempt POST to /context when available
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/context"))
                .header("Authorization", bearer())
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenAccept(resp -> {
                    if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                        Msg.info(this, "AI context updated for program: " + context.getName());
                    } else if (resp.statusCode() == 404) {
                        Msg.info(this, "/context not supported by backend; ignoring");
                    } else {
                        Msg.warn(this, "AI context update non-2xx: " + resp.statusCode());
                    }
                });
        } catch (Exception e) {
            Msg.debug(this, "AI context update skipped: " + e.getMessage());
        }
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
                Msg.error(VMDSAPIClient.this, "WebSocket message parsing error: " + e.getMessage(), e);
            }
            
            return WebSocket.Listener.super.onText(webSocket, data, last);
        }
        
        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            Msg.error(VMDSAPIClient.this, "WebSocket error: " + error.getMessage(), error);
        }
    }
    
    private AnalysisUpdate parseAnalysisUpdate(JsonNode message) {
        String type = message.path("type").asText("unknown");
        JsonNode data = message.path("data");
        
        return new AnalysisUpdate(
            type,
            data.path("progress").asDouble(0.0),
            data.path("status").asText("unknown"),
            data.path("message").asText("")
        );
    }
    
    /**
     * Get agent decision history for AI dashboard (simulated)
     */
    public AgentDecisionHistory getAgentDecisionHistory() {
        // Feature-flagged simulation
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "Agent decision history not supported; simulation disabled");
            return new AgentDecisionHistory();
        }
        Msg.info(this, "Returned simulated agent decision history (feature-flag)");
        return new AgentDecisionHistory();
    }
    
    /**
     * Get system statistics for performance monitoring
     */
    public SystemStats getSystemStats() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/metrics"))
                .header("Authorization", bearer())
                .header("User-Agent", USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode responseData = objectMapper.readTree(response.body());
                return objectMapper.convertValue(responseData, SystemStats.class);
            } else {
                Msg.warn(this, "Failed to get system stats: " + response.statusCode() + ", body: " + safeBody(response.body()));
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
            if (!useSimulatedPhase4Features) {
                // Attempt to query status with optional taskId
                try {
                    String url = baseUrl + "/status" + (taskId != null && !taskId.isEmpty() ? ("?task_id=" + encode(taskId)) : "");
                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Authorization", bearer())
                        .header("User-Agent", USER_AGENT)
                        .timeout(REQUEST_TIMEOUT)
                        .GET()
                        .build();

                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    if (response.statusCode() == 200) {
                        JsonNode data = objectMapper.readTree(response.body());
                        String s = data.path("status").asText("unknown");
                        double p = data.path("progress").asDouble("active".equalsIgnoreCase(s) ? 0.5 : 1.0);
                        return new AnalysisStatus(s, p);
                    } else {
                        Msg.warn(this, "Analysis status non-200: " + response.statusCode());
                        return new AnalysisStatus("unknown", 0.0);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Analysis status fetch error: " + e.getMessage(), e);
                    return new AnalysisStatus("error", 0.0);
                }
            }
            Msg.info(this, "Returned simulated analysis status (feature-flag) for task: " + taskId);
            return new AnalysisStatus("running", 0.5);
        });
    }
    
    /**
     * Get collaboration requests (simulated for Phase 4 features)
     */
    public Object getCollaborationRequests(boolean includeResolved) {
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "Collaboration requests not supported; simulation disabled");
            return Map.of("requests", Collections.emptyList(), "total", 0);
        }
        Map<String, Object> response = new HashMap<>();
        response.put("requests", new ArrayList<>());
        response.put("total", 0);
        
        Msg.info(this, "Returned simulated collaboration requests (feature-flag)");
        return response;
    }
    
    /**
     * Get advanced orchestrator status (simulated for Phase 4 features)
     */
    public Object getAdvancedOrchestratorStatus() {
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "Advanced orchestrator status not supported; simulation disabled");
            return Map.of("status", "inactive");
        }
        Map<String, Object> response = new HashMap<>();
        response.put("status", "active");
        response.put("orchestrator_version", "1.0.0");
        response.put("agents_connected", 0);
        
        Msg.info(this, "Returned simulated orchestrator status (feature-flag)");
        return response;
    }
    
    /**
     * Get meta learning history (simulated for Phase 4 features)
     */
    public Object getMetaLearningHistory(int limit) {
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "Meta learning history not supported; simulation disabled");
            return Map.of("history", Collections.emptyList(), "total_optimizations", 0);
        }
        Map<String, Object> response = new HashMap<>();
        response.put("history", new ArrayList<>());
        response.put("total_optimizations", 0);
        
        Msg.info(this, "Returned simulated meta learning history (feature-flag)");
        return response;
    }
    
    /**
     * Get contextual insights (simulated for Phase 4 features)
     */
    public Object getContextualInsights(int limit) {
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "Contextual insights not supported; simulation disabled");
            return Map.of("insights", Collections.emptyList(), "total", 0);
        }
        Map<String, Object> response = new HashMap<>();
        response.put("insights", new ArrayList<>());
        response.put("total", 0);
        
        Msg.info(this, "Returned simulated contextual insights (feature-flag)");
        return response;
    }
    
    /**
     * Submit collaboration response (simulated for Phase 4 features)
     */
    public Object submitCollaborationResponse(String requestId, String optionId, String explanation) {
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "Submit collaboration response not supported; simulation disabled");
            return Map.of("status", "unsupported");
        }
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
        if (!useSimulatedPhase4Features) {
            Msg.info(this, "Trigger meta learning optimization not supported; simulation disabled");
            return Map.of("status", "unsupported");
        }
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

    // Helpers
    private String bearer() {
        return (authToken == null || authToken.isEmpty()) ? "" : ("Bearer " + authToken);
    }

    private String safeBody(String body) {
        if (body == null) return "";
        // Do not log tokens; scrub if accidentally present
        return body.replace(authToken != null ? authToken : "", "***");
    }

    private String encode(String s) {
        try {
            return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }
}