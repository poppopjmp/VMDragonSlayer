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

package vmdragonslayer.ui;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import vmdragonslayer.VMDragonSlayerPlugin;
import vmdragonslayer.api.VMDSAPIClient;
import vmdragonslayer.integration.GhidraIntegration;
import vmdragonslayer.api.AnalysisRequest;
import vmdragonslayer.api.AnalysisResult;
import vmdragonslayer.api.AnalysisUpdate;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;

/**
 * Main UI Provider for VMDragonSlayer Plugin
 * 
 * Provides the primary interface for agentic VM analysis including:
 * - Analysis control panel with engine selection
 * - Real-time results viewer with AI decision explanations
 * - Engine monitoring dashboard
 * - Performance metrics and confidence visualization
 */
public class VMDragonSlayerProvider extends ComponentProviderAdapter {
    
    private final VMDragonSlayerPlugin plugin;
    private final VMDSAPIClient apiClient;
    
    // UI Components
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    
    // Analysis Control Tab
    private AnalysisControlPanel analysisControlPanel;
    
    // Results Tab
    private ResultsViewer resultsViewer;
    
    // Engine Monitoring Tab
    private EngineStatusPanel engineStatusPanel;
    
    // AI Dashboard Tab
    private AIDecisionDashboard aiDashboard;
    
    // Features Tab
    private FeaturesPanel featuresPanel;
    
    // Status and current program
    private Program currentProgram;
    private JLabel statusLabel;
    private JProgressBar analysisProgressBar;
    
    public VMDragonSlayerProvider(VMDragonSlayerPlugin plugin, VMDSAPIClient apiClient) {
        super(plugin.getTool(), "VMDragonSlayer", plugin.getName());
        
        this.plugin = plugin;
        this.apiClient = apiClient;
        
        setTitle("VMDragonSlayer - Agentic Analysis");
        setWindowMenuGroup("VMDragonSlayer");
        
        buildUI();
        
        // Setup WebSocket for real-time updates
        setupRealtimeUpdates();
        
        Msg.info(this, "VMDragonSlayer UI Provider initialized");
    }
    
    private void buildUI() {
        mainPanel = new JPanel(new BorderLayout());
        
        // Create tabbed interface
        tabbedPane = new JTabbedPane();
        
        // Analysis Control Panel
        analysisControlPanel = new AnalysisControlPanel(this, apiClient);
        tabbedPane.addTab("🔍 Analysis", createAnalysisTab());
        
        // Results Viewer
        resultsViewer = new ResultsViewer(apiClient);
        tabbedPane.addTab("📊 Results", resultsViewer);
        
        // Engine Status
        engineStatusPanel = new EngineStatusPanel(apiClient);
        tabbedPane.addTab("🏭 Engines", engineStatusPanel);
        
        // AI Decision Dashboard
        aiDashboard = new AIDecisionDashboard(apiClient);
        tabbedPane.addTab("🤖 AI Dashboard", aiDashboard);
        
        // Features
        featuresPanel = new FeaturesPanel(apiClient);
        tabbedPane.addTab("🚀 Features", featuresPanel);
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Status panel at bottom
        mainPanel.add(createStatusPanel(), BorderLayout.SOUTH);
    }
    
    private JPanel createAnalysisTab() {
        JPanel analysisTab = new JPanel(new BorderLayout());
        
        // Analysis control at top
        analysisTab.add(analysisControlPanel, BorderLayout.NORTH);
        
        // Progress and status in center
        JPanel progressPanel = createProgressPanel();
        analysisTab.add(progressPanel, BorderLayout.CENTER);
        
        return analysisTab;
    }
    
    private JPanel createProgressPanel() {
        JPanel progressPanel = new JPanel(new BorderLayout());
        progressPanel.setBorder(new TitledBorder("Analysis Progress"));
        
        // Progress bar
        analysisProgressBar = new JProgressBar(0, 100);
        analysisProgressBar.setStringPainted(true);
        analysisProgressBar.setString("Ready for analysis");
        
        progressPanel.add(analysisProgressBar, BorderLayout.NORTH);
        
        // Progress details area
        JTextArea progressDetails = new JTextArea(10, 50);
        progressDetails.setEditable(false);
        progressDetails.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(progressDetails);
        scrollPane.setBorder(new TitledBorder("Real-time Analysis Log"));
        
        progressPanel.add(scrollPane, BorderLayout.CENTER);
        
        return progressPanel;
    }
    
    private JPanel createStatusPanel() {
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.setBorder(BorderFactory.createLoweredBevelBorder());
        
        statusLabel = new JLabel("Ready - No program loaded");
        statusPanel.add(statusLabel);
        
        // Connection status
        JLabel connectionLabel = new JLabel();
        updateConnectionStatus(connectionLabel);
        statusPanel.add(Box.createHorizontalStrut(20));
        statusPanel.add(connectionLabel);
        
        return statusPanel;
    }
    
    private void updateConnectionStatus(JLabel label) {
        if (apiClient.isConnected()) {
            label.setText("🟢 Connected to VMDragonSlayer API");
            label.setForeground(Color.GREEN.darker());
        } else {
            label.setText("🔴 Disconnected from API");
            label.setForeground(Color.RED.darker());
        }
    }
    
    public void addComponents(EngineStatusPanel enginePanel, AIDecisionDashboard aiPanel) {
        this.engineStatusPanel = enginePanel;
        this.aiDashboard = aiPanel;
        
        // Replace placeholder tabs
        tabbedPane.setComponentAt(2, enginePanel);
        tabbedPane.setComponentAt(3, aiPanel);
        
        // Update tab titles with current status
        updateTabTitles();
    }
    
    private void updateTabTitles() {
        if (engineStatusPanel != null) {
            var engineStatus = apiClient.getLastEngineStatus();
            if (engineStatus != null) {
                String title = String.format("🏭 Engines (%d active)", 
                    engineStatus.getAvailableEngines().size());
                tabbedPane.setTitleAt(2, title);
            }
        }
    }
    
    private void setupRealtimeUpdates() {
        apiClient.connectWebSocket(this::handleAnalysisUpdate)
            .exceptionally(throwable -> {
                Msg.error(this, "Failed to setup WebSocket: " + throwable.getMessage(), throwable);
                return null;
            });
    }
    
    private void handleAnalysisUpdate(AnalysisUpdate update) {
        SwingUtilities.invokeLater(() -> {
            // Update progress bar
            int progress = (int) (update.getProgress() * 100);
            analysisProgressBar.setValue(progress);
            analysisProgressBar.setString(String.format("%.1f%% - %s", 
                update.getProgress() * 100, update.getStatus()));
            
            // Update results viewer if applicable
            if (resultsViewer != null) {
                resultsViewer.addProgressUpdate(update);
            }
            
            // Update AI dashboard
            if (aiDashboard != null && "agent_decision".equals(update.getType())) {
                aiDashboard.addDecisionUpdate(update);
            }
            
            // Update features panel
            if (featuresPanel != null && update.getType().startsWith("features_")) {
                featuresPanel.handleFeaturesUpdate(update);
            }
        });
    }
    
    public void programActivated(Program program) {
        this.currentProgram = program;
        
        SwingUtilities.invokeLater(() -> {
            if (program != null) {
                statusLabel.setText("Program: " + program.getName());
                analysisControlPanel.setProgramContext(program);
            } else {
                statusLabel.setText("Ready - No program loaded");
                analysisControlPanel.setProgramContext(null);
            }
        });
        
        Msg.info(this, "Program activated in UI: " + (program != null ? program.getName() : "none"));
    }
    
    public void programDeactivated(Program program) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Ready - No program loaded");
            analysisControlPanel.setProgramContext(null);
        });
        
        this.currentProgram = null;
        Msg.info(this, "Program deactivated in UI");
    }
    
    /**
     * Start agentic analysis
     */
    public void startAnalysis(AnalysisRequest request) {
        // Reset progress
        analysisProgressBar.setValue(0);
        analysisProgressBar.setString("Starting analysis...");
        
        // Start analysis
        CompletableFuture<String> analysisTask = apiClient.startAgenticAnalysis(request);
        
        analysisTask.thenAccept(taskId -> {
            Msg.info(this, "Analysis started with task ID: " + taskId);
            
            // Monitor progress
            monitorAnalysisProgress(taskId);
            
        }).exceptionally(throwable -> {
            SwingUtilities.invokeLater(() -> {
                analysisProgressBar.setString("Analysis failed: " + throwable.getMessage());
                JOptionPane.showMessageDialog(mainPanel, 
                    "Failed to start analysis: " + throwable.getMessage(),
                    "Analysis Error", JOptionPane.ERROR_MESSAGE);
            });
            
            Msg.error(this, "Analysis failed: " + throwable.getMessage(), throwable);
            return null;
        });
    }
    
    private void monitorAnalysisProgress(String taskId) {
        Timer progressTimer = new Timer(1000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                apiClient.getAnalysisStatus(taskId).thenAccept(status -> {
                    SwingUtilities.invokeLater(() -> {
                        // Update progress
                        if (status != null) {
                            analysisProgressBar.setValue((int)(status.progress * 100));
                            analysisProgressBar.setString(String.format("%.1f%% - %s", 
                                status.progress * 100, status.status));
                        }
                        
                        // Check if completed
                        if (status != null && "completed".equals(status.status)) {
                            ((Timer) e.getSource()).stop();
                            
                            // Get full results
                            apiClient.getAnalysisResult(taskId).thenAccept(result -> {
                                SwingUtilities.invokeLater(() -> {
                                    if (result != null) {
                                        // Update results viewer
                                        resultsViewer.updateResults(result);
                                        
                                        // Switch to results tab
                                        tabbedPane.setSelectedIndex(1);
                                        
                                        // Update AI dashboard with any new decisions
                                        if (aiDashboard != null) {
                                            aiDashboard.refreshAllData();
                                        }
                                        
                                        // Update features panel with advanced insights
                                        if (featuresPanel != null) {
                                            featuresPanel.refreshAllData();
                                        }
                                        
                                        analysisProgressBar.setString("Analysis completed successfully");
                                        
                                        // Optional: Integrate results into Ghidra
                                        integrateResultsIntoGhidra(result);
                                    }
                                });
                            }).exceptionally(ex -> {
                                SwingUtilities.invokeLater(() -> {
                                    Msg.error(this, "Failed to retrieve analysis results: " + ex.getMessage());
                                    analysisProgressBar.setString("Failed to retrieve results");
                                });
                                return null;
                            });
                            
                        } else if (status != null && "failed".equals(status.status)) {
                            ((Timer) e.getSource()).stop();
                            analysisProgressBar.setString("Analysis failed");
                            
                            JOptionPane.showMessageDialog(mainPanel,
                                "Analysis failed: " + (status.error != null ? status.error : "Unknown error"),
                                "Analysis Failed", JOptionPane.ERROR_MESSAGE);
                        }
                    });
                }).exceptionally(ex -> {
                    SwingUtilities.invokeLater(() -> {
                        ((Timer) e.getSource()).stop();
                        Msg.error(this, "Failed to monitor analysis progress: " + ex.getMessage());
                        analysisProgressBar.setString("Progress monitoring failed");
                    });
                    return null;
                });
            }
        });
        progressTimer.start();
    }
    
    /**
     * Integrates analysis results into Ghidra program
     */
    private void integrateResultsIntoGhidra(AnalysisResult result) {
        if (currentProgram == null) {
            return;
        }
        
        // Ask user if they want to integrate results
        int option = JOptionPane.showConfirmDialog(mainPanel,
            "Would you like to integrate the analysis results into Ghidra?\n" +
            "This will add bookmarks, comments, and symbols based on the findings.",
            "Integrate Results",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE);
            
        if (option == JOptionPane.YES_OPTION) {
            // Run integration in background
            new Thread(() -> {
                try {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Integrating results into Ghidra...");
                    });
                    
                    GhidraIntegration integration = new GhidraIntegration(plugin.getTool(), currentProgram);
                    
                    // Validate integration capability
                    if (integration.validateIntegration()) {
                        // Perform integration
                        boolean success = integration.integrateAnalysisResults(result, TaskMonitor.DUMMY);
                        
                        SwingUtilities.invokeLater(() -> {
                            if (success) {
                                statusLabel.setText("Results integrated successfully");
                                JOptionPane.showMessageDialog(mainPanel,
                                    "Analysis results have been integrated into Ghidra.\n" +
                                    "Check bookmarks and symbols for detailed findings.",
                                    "Integration Complete",
                                    JOptionPane.INFORMATION_MESSAGE);
                            } else {
                                statusLabel.setText("Integration failed");
                                JOptionPane.showMessageDialog(mainPanel,
                                    "Failed to integrate results into Ghidra.\n" +
                                    "Check the console for error details.",
                                    "Integration Failed",
                                    JOptionPane.WARNING_MESSAGE);
                            }
                        });
                    } else {
                        SwingUtilities.invokeLater(() -> {
                            statusLabel.setText("Integration not available");
                            JOptionPane.showMessageDialog(mainPanel,
                                "Cannot integrate results: Ghidra integration not available.\n" +
                                "Make sure a program is loaded and accessible.",
                                "Integration Not Available",
                                JOptionPane.WARNING_MESSAGE);
                        });
                    }
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Integration error");
                        Msg.error(this, "Error during Ghidra integration: " + ex.getMessage());
                        JOptionPane.showMessageDialog(mainPanel,
                            "Error during integration: " + ex.getMessage(),
                            "Integration Error",
                            JOptionPane.ERROR_MESSAGE);
                    });
                }
            }).start();
        }
    }
    
    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
    
    // Getters
    public Program getCurrentProgram() { return currentProgram; }
    public VMDragonSlayerPlugin getPlugin() { return plugin; }
    public VMDSAPIClient getAPIClient() { return apiClient; }
}