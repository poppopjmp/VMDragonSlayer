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

package vmdragonslayer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import vmdragonslayer.api.AgenticAPIClient;
import vmdragonslayer.ui.VMDragonSlayerProvider;
import vmdragonslayer.ui.EngineStatusPanel;
import vmdragonslayer.ui.AIDecisionDashboard;

import javax.swing.*;
import java.awt.BorderLayout;
import java.util.concurrent.CompletableFuture;

/**
 * VMDragonSlayer Ghidra Plugin with Agentic AI Integration
 * 
 * This plugin provides VM analysis capabilities through:
 * - 5 analysis engines (Hybrid, Parallel, DTT, Symbolic, ML)
 * - AI-driven intelligent decision making
 * - Real-time monitoring and streaming
 * - Confidence-based analysis with explanations
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "VMDragonSlayer",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "VM Analysis with Agentic AI",
    description = "VMDragonSlayer provides intelligent VM protection analysis using " +
                 "analysis engines and AI-driven decision making. Features include " +
                 "real-time analysis streaming, confidence scoring, and adaptive learning.",
    servicesRequired = { ProgramManager.class }
)
public class VMDragonSlayerPlugin extends ProgramPlugin {
    
    private static final String PLUGIN_NAME = "VMDragonSlayer";
    private static final String API_BASE_URL = "http://127.0.0.1:8000";
    private static final String AUTH_TOKEN = "vmdragonslayer-demo-token";
    
    // Core components
    private AgenticAPIClient apiClient;
    private VMDragonSlayerProvider mainProvider;
    private EngineStatusPanel engineStatusPanel;
    private AIDecisionDashboard aiDashboard;
    
    // Plugin state
    private boolean isConnected = false;
    private Program currentProgram;
    
    /**
     * Plugin initialization
     */
    public VMDragonSlayerPlugin(PluginTool tool) {
        super(tool);
        
        Msg.info(this, "Initializing VMDragonSlayer Plugin with Agentic AI...");
        
        // Initialize API client
        this.apiClient = new AgenticAPIClient(API_BASE_URL, AUTH_TOKEN);
        
        // Create main UI provider
        this.mainProvider = new VMDragonSlayerProvider(this, apiClient);
        
        // Initialize monitoring components
        this.engineStatusPanel = new EngineStatusPanel(apiClient);
        this.aiDashboard = new AIDecisionDashboard(apiClient);
        
        Msg.info(this, "VMDragonSlayer Plugin initialized successfully");
    }
    
    @Override
    protected void init() {
        super.init();
        
        // Connect to agentic API service
        connectToAPI();
        
        // Register providers
        tool.addComponentProvider(mainProvider, true);
        
        // Add monitoring panels to main provider
        mainProvider.addComponents(engineStatusPanel, aiDashboard);
        
        Msg.info(this, "VMDragonSlayer Plugin components registered");
    }
    
    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        this.currentProgram = program;
        
        if (mainProvider != null) {
            mainProvider.programActivated(program);
        }
        
        // Update AI context with new program
        if (isConnected && program != null) {
            updateAIContext(program);
        }
        
        Msg.info(this, "Program activated: " + (program != null ? program.getName() : "none"));
    }
    
    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        
        if (mainProvider != null) {
            mainProvider.programDeactivated(program);
        }
        
        this.currentProgram = null;
        Msg.info(this, "Program deactivated: " + (program != null ? program.getName() : "none"));
    }
    
    @Override
    protected void dispose() {
        // Cleanup API connections
        if (apiClient != null) {
            apiClient.disconnect();
        }
        
        // Dispose UI components
        if (mainProvider != null) {
            tool.removeComponentProvider(mainProvider);
        }
        
        super.dispose();
        Msg.info(this, "VMDragonSlayer Plugin disposed");
    }
    
    /**
     * Connect to the agentic API service and verify engines
     */
    private void connectToAPI() {
        CompletableFuture.runAsync(() -> {
            try {
                // Test connection
                boolean connected = apiClient.testConnection();
                
                if (connected) {
                    isConnected = true;
                    
                    // Check engine status
                    var engineStatus = apiClient.getEngineStatus();
                    
                    SwingUtilities.invokeLater(() -> {
                        String statusMessage = String.format(
                            "Connected to VMDragonSlayer API\n" +
                            "Engines: %s\n" +
                            "Available Engines: %s",
                            engineStatus.isAvailable() ? "Available" : "Fallback Mode",
                            String.join(", ", engineStatus.getAvailableEngines())
                        );
                        
                        JOptionPane.showMessageDialog(
                            tool.getToolFrame(),
                            statusMessage,
                            "VMDragonSlayer Connected",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                        
                        // Update status panel
                        engineStatusPanel.updateStatus(engineStatus);
                        
                        Msg.info(this, "Successfully connected to agentic API with engines");
                    });
                    
                } else {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(
                            tool.getToolFrame(),
                            "Could not connect to VMDragonSlayer API service.\n" +
                            "Please ensure the server is running on " + API_BASE_URL,
                            "Connection Failed",
                            JOptionPane.WARNING_MESSAGE
                        );
                    });
                    
                    Msg.warn(this, "Failed to connect to agentic API service");
                }
                
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(
                        tool.getToolFrame(),
                        "Error connecting to VMDragonSlayer API:\n" + e.getMessage(),
                        "Connection Error",
                        JOptionPane.ERROR_MESSAGE
                    );
                });
                
                Msg.error(this, "API connection error: " + e.getMessage(), e);
            }
        });
    }
    
    /**
     * Update AI context with current program information
     */
    private void updateAIContext(Program program) {
        CompletableFuture.runAsync(() -> {
            try {
                // Prepare program context for AI agent
                var programInfo = apiClient.createProgramContext(
                    program.getName(),
                    program.getExecutablePath(),
                    program.getExecutableFormat(),
                    program.getLanguage().getLanguageDescription().getLanguageID().getIdAsString(),
                    program.getAddressFactory().getDefaultAddressSpace().getSize()
                );
                
                // Send context to AI agent for better decision making
                apiClient.updateAIContext(programInfo);
                
                Msg.info(this, "Updated AI context for program: " + program.getName());
                
            } catch (Exception e) {
                Msg.error(this, "Failed to update AI context: " + e.getMessage(), e);
            }
        });
    }
    
    // Getters for UI components
    public AgenticAPIClient getAPIClient() {
        return apiClient;
    }
    
    public Program getCurrentProgram() {
        return currentProgram;
    }
    
    public boolean isConnected() {
        return isConnected;
    }
    
    public EngineStatusPanel getEngineStatusPanel() {
        return engineStatusPanel;
    }
    
    public AIDecisionDashboard getAIDashboard() {
        return aiDashboard;
    }
}
