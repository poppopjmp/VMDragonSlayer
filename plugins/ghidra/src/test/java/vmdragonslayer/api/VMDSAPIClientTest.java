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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Unit tests for VMDSAPIClient - demonstrates testing patterns for the refactored client.
 * These tests would run in a proper Java/Ghidra environment with JUnit and Mockito.
 */
public class VMDSAPIClientTest {
    
    private VMDSAPIClient client;
    private HttpClient mockHttpClient;
    
    @BeforeEach
    void setUp() {
        client = new VMDSAPIClient("http://localhost:8000", "test-token");
        mockHttpClient = mock(HttpClient.class);
    }
    
    @Test
    void testConnection_healthy_returns_true() throws Exception {
        // Given: healthy response from /health endpoint
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("{\"status\":\"healthy\"}");
        
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);
        
        // When: testing connection
        boolean connected = client.testConnection();
        
        // Then: should return true and set isConnected
        assertTrue(connected);
        assertTrue(client.isConnected());
    }
    
    @Test
    void getSupportedAnalysisTypes_parses_json_map() throws Exception {
        // Given: mock response from /analysis-types
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(
            "{\"analysis_types\":[\"hybrid\",\"vm_discovery\"],\"workflow_strategies\":[\"sequential\"]}"
        );
        
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);
        
        // When: getting analysis types
        Map<String, Object> result = client.getSupportedAnalysisTypes();
        
        // Then: should parse JSON correctly
        assertNotNull(result);
        assertTrue(result.containsKey("analysis_types"));
        assertTrue(result.containsKey("workflow_strategies"));
    }
    
    @Test
    void startAgenticAnalysis_200_returns_request_id() throws Exception {
        // Given: successful analysis start
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("{\"request_id\":\"req-12345\",\"success\":true}");
        
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);
        
        AnalysisRequest request = new AnalysisRequest("dGVzdCBkYXRh", "hybrid"); // "test data" in base64
        
        // When: starting analysis
        CompletableFuture<String> future = client.startAgenticAnalysis(request);
        String requestId = future.get();
        
        // Then: should return request ID
        assertEquals("req-12345", requestId);
    }
    
    @Test
    void startAgenticAnalysis_422_throws_validation_error() throws Exception {
        // Given: validation error response
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(422);
        when(mockResponse.body()).thenReturn("{\"error\":\"Invalid base64 data\"}");
        
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);
        
        AnalysisRequest request = new AnalysisRequest("invalid-data", "hybrid");
        
        // When/Then: should throw RuntimeException with error details
        CompletableFuture<String> future = client.startAgenticAnalysis(request);
        RuntimeException exception = assertThrows(RuntimeException.class, future::get);
        assertTrue(exception.getMessage().contains("Validation error"));
    }
    
    @Test
    void getAnalysisResult_uses_task_id_in_query() throws Exception {
        // Given: mock response with progress
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(
            "{\"status\":\"running\",\"progress\":0.75,\"uptime_seconds\":120}"
        );
        
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);
        
        // When: getting analysis result
        CompletableFuture<AnalysisResult> future = client.getAnalysisResult("task-123");
        AnalysisResult result = future.get();
        
        // Then: should parse progress and status
        assertEquals("task-123", result.getTaskId());
        assertEquals("running", result.getStatus());
        assertEquals(0.75, result.getProgress(), 0.01);
    }
    
    @Test
    void websocket_tolerates_malformed_frames() {
        // Given: WebSocket listener
        VMDSAPIClient.WebSocketListener listener = client.new WebSocketListener();
        
        // When: receiving malformed JSON
        assertDoesNotThrow(() -> {
            listener.onText(null, "not valid json", true);
            listener.onText(null, "{\"incomplete\":", true);
            listener.onText(null, "", true);
        });
        
        // Then: should not throw exceptions
        // Listener should log errors but continue processing
    }
    
    @Test
    void phase4_features_disabled_by_default() {
        // Given: default client (no system property set)
        VMDSAPIClient defaultClient = new VMDSAPIClient("http://localhost:8000", "token");
        
        // When: calling Phase 4 methods
        var decisions = defaultClient.getAIDecisionHistory(10);
        var history = defaultClient.getAgentDecisionHistory();
        var requests = defaultClient.getCollaborationRequests(false);
        
        // Then: should return empty results
        assertTrue(decisions.isEmpty());
        assertNotNull(history);
        assertNotNull(requests);
        
        // And: should log that simulation is disabled
        // (In real test, we'd capture and verify log messages)
    }
    
    @Test
    void phase4_features_enabled_with_system_property() {
        // Given: system property enabling Phase 4 simulation
        try (MockedStatic<System> systemMock = Mockito.mockStatic(System.class)) {
            systemMock.when(() -> System.getProperty("vmds.simulatePhase4", "false"))
                     .thenReturn("true");
            
            VMDSAPIClient simulationClient = new VMDSAPIClient("http://localhost:8000", "token");
            
            // When: calling Phase 4 methods
            var decisions = simulationClient.getAIDecisionHistory(10);
            
            // Then: should return simulated data
            assertFalse(decisions.isEmpty());
        }
    }
}
