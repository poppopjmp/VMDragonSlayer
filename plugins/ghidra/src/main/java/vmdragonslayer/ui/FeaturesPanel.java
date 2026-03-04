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

import ghidra.util.Msg;
import vmdragonslayer.api.AgenticAPIClient;
import vmdragonslayer.api.AnalysisUpdate;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Advanced Agentic Features Panel
 * 
 * Provides UI for advanced capabilities:
 * - Human-AI collaboration interface
 * - Meta-learning optimization controls
 * - Deep contextual insights display
 * - Advanced orchestrator monitoring
 */
public class FeaturesPanel extends JPanel {
    
    private static final long serialVersionUID = 1L;
    
    private final AgenticAPIClient apiClient;
    
    // Collaboration Components
    private JList<CollaborationRequest> collaborationRequestsList;
    private DefaultListModel<CollaborationRequest> collaborationModel;
    private JTextArea collaborationDetailsArea;
    private JComboBox<String> responseOptionsCombo;
    private JTextArea humanResponseArea;
    private JButton submitResponseButton;
    
    // Meta-learning Components
    private JTextArea metaLearningStatusArea;
    private JButton triggerOptimizationButton;
    private JList<MetaLearningResult> optimizationHistoryList;
    private DefaultListModel<MetaLearningResult> optimizationModel;
    private JProgressBar optimizationProgressBar;
    
    // Contextual Insights Components
    private JList<ContextualInsight> insightsList;
    private DefaultListModel<ContextualInsight> insightsModel;
    private JTextArea insightDetailsArea;
    private JComboBox<String> insightTypeFilter;
    
    // Advanced Orchestrator Status
    private JTextArea orchestratorStatusArea;
    private JLabel capabilitiesLabel;
    private JLabel statisticsLabel;
    
    // Auto-refresh components
    private Timer refreshTimer;
    private JCheckBox autoRefreshCheckbox;
    
    public FeaturesPanel(AgenticAPIClient apiClient) {
        this.apiClient = apiClient;
        initializeComponents();
        layoutComponents();
        setupEventHandlers();
        startAutoRefresh();
    }
    
    private void initializeComponents() {
        // Collaboration components
        collaborationModel = new DefaultListModel<>();
        collaborationRequestsList = new JList<>(collaborationModel);
        collaborationRequestsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        collaborationRequestsList.setCellRenderer(new CollaborationRequestRenderer());
        
        collaborationDetailsArea = new JTextArea(6, 30);
        collaborationDetailsArea.setEditable(false);
        collaborationDetailsArea.setBackground(getBackground());
        collaborationDetailsArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        responseOptionsCombo = new JComboBox<>();
        humanResponseArea = new JTextArea(3, 30);
        humanResponseArea.setBorder(BorderFactory.createLoweredBevelBorder());
        submitResponseButton = new JButton("Submit Response");
        submitResponseButton.setEnabled(false);
        
        // Meta-learning components
        metaLearningStatusArea = new JTextArea(4, 30);
        metaLearningStatusArea.setEditable(false);
        metaLearningStatusArea.setBackground(getBackground());
        metaLearningStatusArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        triggerOptimizationButton = new JButton("Trigger Optimization");
        optimizationProgressBar = new JProgressBar();
        optimizationProgressBar.setStringPainted(true);
        optimizationProgressBar.setString("Ready");
        
        optimizationModel = new DefaultListModel<>();
        optimizationHistoryList = new JList<>(optimizationModel);
        optimizationHistoryList.setCellRenderer(new MetaLearningResultRenderer());
        
        // Contextual insights components
        insightsModel = new DefaultListModel<>();
        insightsList = new JList<>(insightsModel);
        insightsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        insightsList.setCellRenderer(new ContextualInsightRenderer());
        
        insightDetailsArea = new JTextArea(5, 30);
        insightDetailsArea.setEditable(false);
        insightDetailsArea.setBackground(getBackground());
        insightDetailsArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        insightTypeFilter = new JComboBox<>(new String[]{
            "All Types", "Binary Structure", "Behavioral Pattern", 
            "Resource Usage", "Historical Performance"
        });
        
        // Orchestrator status components
        orchestratorStatusArea = new JTextArea(4, 30);
        orchestratorStatusArea.setEditable(false);
        orchestratorStatusArea.setBackground(getBackground());
        orchestratorStatusArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        capabilitiesLabel = new JLabel("Capabilities: Loading...");
        statisticsLabel = new JLabel("Statistics: Loading...");
        
        // Auto-refresh components
        autoRefreshCheckbox = new JCheckBox("Auto-refresh (10s)", true);
        refreshTimer = new Timer(10000, e -> refreshAllData()); // 10 seconds
    }
    
    private void layoutComponents() {
        setLayout(new BorderLayout());
        
        // Create tabbed pane for different features
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Collaboration tab
        JPanel collaborationPanel = createCollaborationPanel();
        tabbedPane.addTab("Human-AI Collaboration", collaborationPanel);
        
        // Meta-learning tab
        JPanel metaLearningPanel = createMetaLearningPanel();
        tabbedPane.addTab("Meta-Learning", metaLearningPanel);
        
        // Insights tab
        JPanel insightsPanel = createInsightsPanel();
        tabbedPane.addTab("Contextual Insights", insightsPanel);
        
        // Orchestrator status tab
        JPanel orchestratorPanel = createOrchestratorPanel();
        tabbedPane.addTab("Advanced Orchestrator", orchestratorPanel);
        
        add(tabbedPane, BorderLayout.CENTER);
        
        // Control panel at bottom
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.add(autoRefreshCheckbox);
        JButton refreshButton = new JButton("Refresh Now");
        refreshButton.addActionListener(e -> refreshAllData());
        controlPanel.add(refreshButton);
        
        add(controlPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createCollaborationPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Left side - requests list
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(new TitledBorder("Collaboration Requests"));
        
        JScrollPane requestsScrollPane = new JScrollPane(collaborationRequestsList);
        requestsScrollPane.setPreferredSize(new Dimension(300, 200));
        leftPanel.add(requestsScrollPane, BorderLayout.CENTER);
        
        JPanel requestsButtonPanel = new JPanel(new FlowLayout());
        JButton refreshRequestsButton = new JButton("Refresh");
        refreshRequestsButton.addActionListener(e -> refreshCollaborationRequests());
        requestsButtonPanel.add(refreshRequestsButton);
        leftPanel.add(requestsButtonPanel, BorderLayout.SOUTH);
        
        panel.add(leftPanel, BorderLayout.WEST);
        
        // Right side - response interface
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(new TitledBorder("Response Interface"));
        
        // Details area
        JScrollPane detailsScrollPane = new JScrollPane(collaborationDetailsArea);
        detailsScrollPane.setBorder(new TitledBorder("Request Details"));
        rightPanel.add(detailsScrollPane, BorderLayout.NORTH);
        
        // Response panel
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(new TitledBorder("Your Response"));
        
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        optionsPanel.add(new JLabel("Select Option:"));
        optionsPanel.add(responseOptionsCombo);
        responsePanel.add(optionsPanel, BorderLayout.NORTH);
        
        JScrollPane responseScrollPane = new JScrollPane(humanResponseArea);
        responseScrollPane.setBorder(new TitledBorder("Additional Comments"));
        responsePanel.add(responseScrollPane, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(submitResponseButton);
        responsePanel.add(buttonPanel, BorderLayout.SOUTH);
        
        rightPanel.add(responsePanel, BorderLayout.CENTER);
        panel.add(rightPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createMetaLearningPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Top - status and controls
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(new TitledBorder("Meta-Learning Status"));
        
        JScrollPane statusScrollPane = new JScrollPane(metaLearningStatusArea);
        topPanel.add(statusScrollPane, BorderLayout.CENTER);
        
        JPanel controlPanel = new JPanel(new FlowLayout());
        controlPanel.add(triggerOptimizationButton);
        controlPanel.add(optimizationProgressBar);
        topPanel.add(controlPanel, BorderLayout.SOUTH);
        
        panel.add(topPanel, BorderLayout.NORTH);
        
        // Bottom - optimization history
        JPanel historyPanel = new JPanel(new BorderLayout());
        historyPanel.setBorder(new TitledBorder("Optimization History"));
        
        JScrollPane historyScrollPane = new JScrollPane(optimizationHistoryList);
        historyScrollPane.setPreferredSize(new Dimension(400, 200));
        historyPanel.add(historyScrollPane, BorderLayout.CENTER);
        
        panel.add(historyPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createInsightsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Top - filter
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterPanel.add(new JLabel("Filter by type:"));
        filterPanel.add(insightTypeFilter);
        JButton refreshInsightsButton = new JButton("Refresh");
        refreshInsightsButton.addActionListener(e -> refreshContextualInsights());
        filterPanel.add(refreshInsightsButton);
        panel.add(filterPanel, BorderLayout.NORTH);
        
        // Center - split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // Left - insights list
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(new TitledBorder("Contextual Insights"));
        JScrollPane insightsScrollPane = new JScrollPane(insightsList);
        insightsScrollPane.setPreferredSize(new Dimension(300, 300));
        leftPanel.add(insightsScrollPane, BorderLayout.CENTER);
        
        splitPane.setLeftComponent(leftPanel);
        
        // Right - insight details
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(new TitledBorder("Insight Details"));
        JScrollPane detailsScrollPane = new JScrollPane(insightDetailsArea);
        rightPanel.add(detailsScrollPane, BorderLayout.CENTER);
        
        splitPane.setRightComponent(rightPanel);
        splitPane.setDividerLocation(300);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createOrchestratorPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Status area
        JScrollPane statusScrollPane = new JScrollPane(orchestratorStatusArea);
        statusScrollPane.setBorder(new TitledBorder("Orchestrator Status"));
        panel.add(statusScrollPane, BorderLayout.CENTER);
        
        // Info panel
        JPanel infoPanel = new JPanel(new GridLayout(2, 1));
        infoPanel.add(capabilitiesLabel);
        infoPanel.add(statisticsLabel);
        panel.add(infoPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private void setupEventHandlers() {
        // Collaboration request selection
        collaborationRequestsList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateCollaborationDetails();
            }
        });
        
        // Submit response button
        submitResponseButton.addActionListener(e -> submitCollaborationResponse());
        
        // Trigger optimization button
        triggerOptimizationButton.addActionListener(e -> triggerMetaLearningOptimization());
        
        // Insight selection
        insightsList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateInsightDetails();
            }
        });
        
        // Insight type filter
        insightTypeFilter.addActionListener(e -> filterInsights());
        
        // Auto-refresh checkbox
        autoRefreshCheckbox.addActionListener(e -> {
            if (autoRefreshCheckbox.isSelected()) {
                refreshTimer.start();
            } else {
                refreshTimer.stop();
            }
        });
    }
    
    private void startAutoRefresh() {
        if (autoRefreshCheckbox.isSelected()) {
            refreshTimer.start();
        }
        // Initial data load
        refreshAllData();
    }
    
    public void refreshAllData() {
        SwingUtilities.invokeLater(() -> {
            refreshCollaborationRequests();
            refreshMetaLearningStatus();
            refreshMetaLearningHistory();
            refreshContextualInsights();
            refreshOrchestratorStatus();
        });
    }
    
    private void refreshCollaborationRequests() {
        CompletableFuture.supplyAsync(() -> {
            try {
                return apiClient.getCollaborationRequests(true);
            } catch (Exception e) {
                Msg.error(this, "Failed to fetch collaboration requests: " + e.getMessage());
                return null;
            }
        }).thenAccept(response -> {
            if (response != null) {
                @SuppressWarnings("unchecked")
                Map<String,Object> responseMap = (Map<String,Object>) response;
                SwingUtilities.invokeLater(() -> updateCollaborationRequestsList(responseMap));
            }
        });
    }
    
    private void refreshMetaLearningStatus() {
        CompletableFuture.supplyAsync(() -> {
            try {
                return apiClient.getAdvancedOrchestratorStatus();
            } catch (Exception e) {
                Msg.error(this, "Failed to fetch meta-learning status: " + e.getMessage());
                return null;
            }
        }).thenAccept(response -> {
            if (response != null) {
                @SuppressWarnings("unchecked")
                Map<String,Object> responseMap = (Map<String,Object>) response;
                SwingUtilities.invokeLater(() -> updateMetaLearningStatus(responseMap));
            }
        });
    }
    
    private void refreshMetaLearningHistory() {
        CompletableFuture.supplyAsync(() -> {
            try {
                return apiClient.getMetaLearningHistory(20);
            } catch (Exception e) {
                Msg.error(this, "Failed to fetch meta-learning history: " + e.getMessage());
                return null;
            }
        }).thenAccept(response -> {
            if (response != null) {
                @SuppressWarnings("unchecked")
                Map<String,Object> responseMap = (Map<String,Object>) response;
                SwingUtilities.invokeLater(() -> updateMetaLearningHistory(responseMap));
            }
        });
    }
    
    private void refreshContextualInsights() {
        CompletableFuture.supplyAsync(() -> {
            try {
                return apiClient.getContextualInsights(50);
            } catch (Exception e) {
                Msg.error(this, "Failed to fetch contextual insights: " + e.getMessage());
                return null;
            }
        }).thenAccept(response -> {
            if (response != null) {
                @SuppressWarnings("unchecked")
                Map<String,Object> responseMap = (Map<String,Object>) response;
                SwingUtilities.invokeLater(() -> updateContextualInsights(responseMap));
            }
        });
    }
    
    private void refreshOrchestratorStatus() {
        CompletableFuture.supplyAsync(() -> {
            try {
                return apiClient.getAdvancedOrchestratorStatus();
            } catch (Exception e) {
                Msg.error(this, "Failed to fetch orchestrator status: " + e.getMessage());
                return null;
            }
        }).thenAccept(response -> {
            if (response != null) {
                @SuppressWarnings("unchecked")
                Map<String,Object> responseMap = (Map<String,Object>) response;
                SwingUtilities.invokeLater(() -> updateOrchestratorStatus(responseMap));
            }
        });
    }
    
    private void updateCollaborationRequestsList(Map<String, Object> response) {
        collaborationModel.clear();
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> requests = (List<Map<String, Object>>) response.get("requests");
        
        if (requests != null) {
            for (Map<String, Object> requestData : requests) {
                CollaborationRequest request = new CollaborationRequest(requestData);
                collaborationModel.addElement(request);
            }
        }
        
        // Update submit button state
        submitResponseButton.setEnabled(!collaborationModel.isEmpty());
    }
    
    private void updateCollaborationDetails() {
        CollaborationRequest selected = collaborationRequestsList.getSelectedValue();
        if (selected == null) {
            collaborationDetailsArea.setText("No request selected");
            responseOptionsCombo.removeAllItems();
            return;
        }
        
        // Update details area
        StringBuilder details = new StringBuilder();
        details.append("Trigger: ").append(selected.getTrigger()).append("\n");
        details.append("Question: ").append(selected.getQuestion()).append("\n");
        details.append("Urgency: ").append(selected.getUrgency()).append("\n");
        details.append("Timeout: ").append(selected.getTimeoutMinutes()).append(" minutes\n");
        details.append("Created: ").append(selected.getCreatedAt()).append("\n\n");
        details.append("Background Info:\n");
        details.append(selected.getBackgroundInfo());
        
        collaborationDetailsArea.setText(details.toString());
        collaborationDetailsArea.setCaretPosition(0);
        
        // Update options combo
        responseOptionsCombo.removeAllItems();
        for (Map<String, Object> option : selected.getOptions()) {
            String label = (String) option.get("label");
            responseOptionsCombo.addItem(label);
        }
    }
    
    private void submitCollaborationResponse() {
        CollaborationRequest selected = collaborationRequestsList.getSelectedValue();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Please select a collaboration request first.", 
                "No Request Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String selectedOption = (String) responseOptionsCombo.getSelectedItem();
        if (selectedOption == null) {
            JOptionPane.showMessageDialog(this, "Please select a response option.", 
                "No Option Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Find option ID
        String optionId = null;
        for (Map<String, Object> option : selected.getOptions()) {
            if (selectedOption.equals(option.get("label"))) {
                optionId = (String) option.get("id");
                break;
            }
        }
        
        if (optionId == null) {
            JOptionPane.showMessageDialog(this, "Selected option not found.", 
                "Invalid Option", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String explanation = humanResponseArea.getText().trim();
        
        // Make variables final for lambda expression
        final String finalOptionId = optionId;
        final String finalExplanation = explanation;
        
        CompletableFuture.supplyAsync(() -> {
            try {
                return apiClient.submitCollaborationResponse(selected.getRequestId(), finalOptionId, finalExplanation);
            } catch (Exception e) {
                Msg.error(this, "Failed to submit response: " + e.getMessage());
                return null;
            }
        }).thenAccept(response -> {
            if (response != null) {
                SwingUtilities.invokeLater(() -> {
                    Msg.showInfo(this, this, "Response Submitted", "Your response has been submitted successfully.");
                    humanResponseArea.setText("");
                    refreshCollaborationRequests(); // Refresh to remove responded request
                });
            }
        });
    }
    
    private void triggerMetaLearningOptimization() {
        triggerOptimizationButton.setEnabled(false);
        optimizationProgressBar.setIndeterminate(true);
        optimizationProgressBar.setString("Optimizing...");
        
        CompletableFuture.supplyAsync(() -> {
            try {
                return apiClient.triggerMetaLearningOptimization();
            } catch (Exception e) {
                Msg.error(this, "Failed to trigger optimization: " + e.getMessage());
                return null;
            }
        }).thenAccept(response -> {
            SwingUtilities.invokeLater(() -> {
                triggerOptimizationButton.setEnabled(true);
                optimizationProgressBar.setIndeterminate(false);
                optimizationProgressBar.setString("Ready");
                
                if (response != null) {
                    @SuppressWarnings("unchecked")
                    Map<String,Object> responseMap = (Map<String,Object>) response;
                    Integer improvements = (Integer) responseMap.get("improvements_found");
                    Msg.showInfo(this, this, "Optimization Complete", 
                        "Meta-learning optimization completed with " + improvements + " improvements found.");
                    refreshMetaLearningHistory(); // Refresh history
                }
            });
        });
    }
    
    private void updateMetaLearningStatus(Map<String, Object> response) {
        StringBuilder status = new StringBuilder();
        
        Boolean initialized = (Boolean) response.get("initialized");
        status.append("Initialized: ").append(initialized != null && initialized ? "Yes" : "No").append("\n");
        
        if (initialized != null && initialized) {
            // Handle statistics - could be Map or List
            Object statsObj = response.get("statistics");
            if (statsObj != null) {
                if (statsObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> stats = (Map<String, Object>) statsObj;
                    status.append("Total Insights: ").append(stats.get("total_insights")).append("\n");
                    status.append("Meta-learning Results: ").append(stats.get("meta_learning_results")).append("\n");
                    status.append("Collaboration Sessions: ").append(stats.get("collaboration_sessions")).append("\n");
                } else if (statsObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> stats = (List<Object>) statsObj;
                    status.append("Statistics available: ").append(stats.size()).append(" items\n");
                    for (int i = 0; i < Math.min(stats.size(), 3); i++) {
                        status.append("• Stat ").append(i + 1).append(": ").append(stats.get(i)).append("\n");
                    }
                } else {
                    status.append("Statistics: ").append(statsObj.toString()).append("\n");
                }
            }
        }
        
        metaLearningStatusArea.setText(status.toString());
    }
    
    private void updateMetaLearningHistory(Map<String, Object> response) {
        optimizationModel.clear();
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> history = (List<Map<String, Object>>) response.get("history");
        
        if (history != null) {
            for (Map<String, Object> resultData : history) {
                MetaLearningResult result = new MetaLearningResult(resultData);
                optimizationModel.addElement(result);
            }
        }
    }
    
    private void updateContextualInsights(Map<String, Object> response) {
        insightsModel.clear();
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> insights = (List<Map<String, Object>>) response.get("recent_insights");
        
        if (insights != null) {
            for (Map<String, Object> insightData : insights) {
                ContextualInsight insight = new ContextualInsight(insightData);
                insightsModel.addElement(insight);
            }
        }
        
        filterInsights(); // Apply current filter
    }
    
    private void updateInsightDetails() {
        ContextualInsight selected = insightsList.getSelectedValue();
        if (selected == null) {
            insightDetailsArea.setText("No insight selected");
            return;
        }
        
        StringBuilder details = new StringBuilder();
        details.append("Type: ").append(selected.getContextType()).append("\n");
        details.append("Confidence: ").append(String.format("%.2f", selected.getConfidence())).append("\n");
        details.append("Description: ").append(selected.getDescription()).append("\n\n");
        
        details.append("Supporting Evidence:\n");
        for (String evidence : selected.getSupportingEvidence()) {
            details.append("• ").append(evidence).append("\n");
        }
        
        details.append("\nImplications:\n");
        for (String implication : selected.getImplications()) {
            details.append("• ").append(implication).append("\n");
        }
        
        details.append("\nRecommended Actions:\n");
        for (String action : selected.getRecommendedActions()) {
            details.append("• ").append(action).append("\n");
        }
        
        if (!selected.getUncertaintyFactors().isEmpty()) {
            details.append("\nUncertainty Factors:\n");
            for (String factor : selected.getUncertaintyFactors()) {
                details.append("• ").append(factor).append("\n");
            }
        }
        
        insightDetailsArea.setText(details.toString());
        insightDetailsArea.setCaretPosition(0);
    }
    
    private void filterInsights() {
        // This would implement filtering logic based on insight type
        // For now, we'll just refresh the display
        String selectedType = (String) insightTypeFilter.getSelectedItem();
        
        // In a full implementation, you'd filter the model here
        // For demo purposes, we'll just update the display
    }
    
    private void updateOrchestratorStatus(Map<String, Object> response) {
        StringBuilder status = new StringBuilder();
        
        Boolean advancedFeaturesAvailable = (Boolean) response.get("advanced_features_available");
        status.append("Advanced Features Available: ").append(advancedFeaturesAvailable != null && advancedFeaturesAvailable ? "Yes" : "No").append("\n");
        
        if (advancedFeaturesAvailable != null && advancedFeaturesAvailable) {
            Boolean initialized = (Boolean) response.get("initialized");
            status.append("Advanced Orchestrator: ").append(initialized != null && initialized ? "Initialized" : "Not Initialized").append("\n");
            
            // Handle capabilities - could be Map or List
            Object capabilitiesObj = response.get("capabilities");
            if (capabilitiesObj != null) {
                status.append("\nCapabilities:\n");
                if (capabilitiesObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> capabilities = (Map<String, Object>) capabilitiesObj;
                    capabilities.forEach((key, value) -> 
                        status.append("• ").append(key).append(": ").append(value).append("\n"));
                } else if (capabilitiesObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> capabilities = (List<Object>) capabilitiesObj;
                    for (int i = 0; i < capabilities.size(); i++) {
                        status.append("• Capability ").append(i + 1).append(": ").append(capabilities.get(i)).append("\n");
                    }
                } else {
                    status.append("• ").append(capabilitiesObj.toString()).append("\n");
                }
            }
            
            // Handle statistics - could be Map or List
            Object statsObj = response.get("statistics");
            if (statsObj != null) {
                status.append("\nStatistics:\n");
                if (statsObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> stats = (Map<String, Object>) statsObj;
                    stats.forEach((key, value) -> 
                        status.append("• ").append(key).append(": ").append(value).append("\n"));
                } else if (statsObj instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> stats = (List<Object>) statsObj;
                    for (int i = 0; i < stats.size(); i++) {
                        status.append("• Stat ").append(i + 1).append(": ").append(stats.get(i)).append("\n");
                    }
                } else {
                    status.append("• ").append(statsObj.toString()).append("\n");
                }
            }
        }
        
        orchestratorStatusArea.setText(status.toString());
        
        // Update labels
        capabilitiesLabel.setText("Capabilities: " + (advancedFeaturesAvailable != null && advancedFeaturesAvailable ? "Full Advanced" : "Basic"));
        
        // Handle statistics for labels - with safe type checking
        Object statsObj = response.get("statistics");
        if (statsObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> stats = (Map<String, Object>) statsObj;
            Integer totalInsights = (Integer) stats.get("total_insights");
            Integer activeCollabs = (Integer) stats.get("active_collaborations");
            statisticsLabel.setText(String.format("Statistics: %d insights, %d active collaborations", 
                totalInsights != null ? totalInsights : 0, 
                activeCollabs != null ? activeCollabs : 0));
        } else {
            statisticsLabel.setText("Statistics: Data format not supported");
        }
    }
    
    // Data model classes for advanced features
    
    public static class CollaborationRequest {
        private final Map<String, Object> data;
        
        public CollaborationRequest(Map<String, Object> data) {
            this.data = data;
        }
        
        public String getRequestId() { return (String) data.get("request_id"); }
        public String getTrigger() { return (String) data.get("trigger"); }
        public String getQuestion() { return (String) data.get("question"); }
        public String getUrgency() { return (String) data.get("urgency"); }
        public Integer getTimeoutMinutes() { return (Integer) data.get("timeout_minutes"); }
        public String getCreatedAt() { return (String) data.get("created_at"); }
        
        @SuppressWarnings("unchecked")
        public List<Map<String, Object>> getOptions() { 
            return (List<Map<String, Object>>) data.get("options"); 
        }
        
        public String getBackgroundInfo() {
            @SuppressWarnings("unchecked")
            Map<String, Object> bgInfo = (Map<String, Object>) data.get("background_info");
            if (bgInfo == null) return "No background information available";
            
            StringBuilder sb = new StringBuilder();
            bgInfo.forEach((key, value) -> sb.append(key).append(": ").append(value).append("\n"));
            return sb.toString();
        }
        
        @Override
        public String toString() {
            return String.format("[%s] %s (%s)", getUrgency().toUpperCase(), getTrigger(), getCreatedAt());
        }
    }
    
    public static class MetaLearningResult {
        private final Map<String, Object> data;
        
        public MetaLearningResult(Map<String, Object> data) {
            this.data = data;
        }
        
        public String getStrategy() { return (String) data.get("strategy"); }
        public String getOptimizationId() { return (String) data.get("optimization_id"); }
        public Double getPreviousPerformance() { return (Double) data.get("previous_performance"); }
        public Double getNewPerformance() { return (Double) data.get("new_performance"); }
        public Double getImprovement() { return (Double) data.get("improvement"); }
        public Double getConfidence() { return (Double) data.get("confidence"); }
        public String getTimestamp() { return (String) data.get("timestamp"); }
        
        @Override
        public String toString() {
            return String.format("%s: +%.3f improvement (%.2f confidence)", 
                getStrategy(), getImprovement(), getConfidence());
        }
    }
    
    public static class ContextualInsight {
        private final Map<String, Object> data;
        
        public ContextualInsight(Map<String, Object> data) {
            this.data = data;
        }
        
        public String getInsightId() { return (String) data.get("insight_id"); }
        public String getContextType() { return (String) data.get("context_type"); }
        public Double getConfidence() { return (Double) data.get("confidence"); }
        public String getDescription() { return (String) data.get("description"); }
        public String getTimestamp() { return (String) data.get("timestamp"); }
        
        @SuppressWarnings("unchecked")
        public List<String> getSupportingEvidence() { 
            return (List<String>) data.getOrDefault("supporting_evidence", List.of()); 
        }
        
        @SuppressWarnings("unchecked")
        public List<String> getImplications() { 
            return (List<String>) data.getOrDefault("implications", List.of()); 
        }
        
        @SuppressWarnings("unchecked")
        public List<String> getRecommendedActions() { 
            return (List<String>) data.getOrDefault("recommended_actions", List.of()); 
        }
        
        @SuppressWarnings("unchecked")
        public List<String> getUncertaintyFactors() { 
            return (List<String>) data.getOrDefault("uncertainty_factors", List.of()); 
        }
        
        @Override
        public String toString() {
            return String.format("[%.2f] %s: %s", getConfidence(), getContextType(), getDescription());
        }
    }
    
    // Custom renderers
    
    private static class CollaborationRequestRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof CollaborationRequest) {
                CollaborationRequest request = (CollaborationRequest) value;
                setText(request.toString());
                
                // Color coding by urgency
                String urgency = request.getUrgency();
                if (!isSelected) {
                    switch (urgency.toLowerCase()) {
                        case "critical":
                            setBackground(new Color(255, 230, 230)); // Light red
                            break;
                        case "high":
                            setBackground(new Color(255, 245, 230)); // Light orange
                            break;
                        case "medium":
                            setBackground(new Color(255, 255, 230)); // Light yellow
                            break;
                        default:
                            setBackground(Color.WHITE);
                    }
                }
            }
            
            return this;
        }
    }
    
    private static class MetaLearningResultRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof MetaLearningResult) {
                MetaLearningResult result = (MetaLearningResult) value;
                setText(result.toString());
                
                // Color coding by improvement
                if (!isSelected) {
                    Double improvement = result.getImprovement();
                    if (improvement > 0.05) {
                        setBackground(new Color(230, 255, 230)); // Light green
                    } else if (improvement > 0.02) {
                        setBackground(new Color(245, 255, 230)); // Very light green
                    } else {
                        setBackground(Color.WHITE);
                    }
                }
            }
            
            return this;
        }
    }
    
    private static class ContextualInsightRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof ContextualInsight) {
                ContextualInsight insight = (ContextualInsight) value;
                setText(insight.toString());
                
                // Color coding by confidence
                if (!isSelected) {
                    Double confidence = insight.getConfidence();
                    if (confidence > 0.8) {
                        setBackground(new Color(230, 255, 230)); // Light green
                    } else if (confidence > 0.6) {
                        setBackground(new Color(255, 255, 230)); // Light yellow
                    } else {
                        setBackground(new Color(255, 240, 240)); // Light pink
                    }
                }
            }
            
            return this;
        }
    }
    
    /**
     * Handle features specific updates from WebSocket
     */
    public void handleFeaturesUpdate(AnalysisUpdate update) {
        SwingUtilities.invokeLater(() -> {
            String updateType = update.getType();
            String message = update.getMessage();
            
            if ("features_collaboration_request".equals(updateType)) {
                // New collaboration request received
                appendToCollaborationLog("🔔 New collaboration request: " + message);
                refreshCollaborationRequests();
            } else if ("features_meta_learning".equals(updateType)) {
                // Meta-learning optimization completed
                appendToMetaLearningLog("🧠 Meta-learning update: " + message);
                refreshMetaLearningStatus();
            } else if ("features_context_insight".equals(updateType)) {
                // New contextual insight available
                appendToInsightsLog("💡 New insight: " + message);
                refreshContextualInsights();
            } else if ("features_orchestrator_status".equals(updateType)) {
                // Orchestrator status change
                appendToOrchestratorLog("⚙️ Orchestrator: " + message);
                refreshOrchestratorStatus();
            }
        });
    }
    
    /**
     * Append message to collaboration log
     */
    private void appendToCollaborationLog(String message) {
        SwingUtilities.invokeLater(() -> {
            String currentText = collaborationDetailsArea.getText();
            String timestamp = java.time.LocalTime.now().toString();
            collaborationDetailsArea.setText(currentText + "\n[" + timestamp + "] " + message);
        });
    }
    
    /**
     * Append message to meta-learning log
     */
    private void appendToMetaLearningLog(String message) {
        SwingUtilities.invokeLater(() -> {
            String currentText = metaLearningStatusArea.getText();
            String timestamp = java.time.LocalTime.now().toString();
            metaLearningStatusArea.setText(currentText + "\n[" + timestamp + "] " + message);
        });
    }
    
    /**
     * Append message to insights log
     */
    private void appendToInsightsLog(String message) {
        SwingUtilities.invokeLater(() -> {
            String currentText = insightDetailsArea.getText();
            String timestamp = java.time.LocalTime.now().toString();
            insightDetailsArea.setText(currentText + "\n[" + timestamp + "] " + message);
        });
    }
    
    /**
     * Append message to orchestrator log
     */
    private void appendToOrchestratorLog(String message) {
        SwingUtilities.invokeLater(() -> {
            String currentText = orchestratorStatusArea.getText();
            String timestamp = java.time.LocalTime.now().toString();
            orchestratorStatusArea.setText(currentText + "\n[" + timestamp + "] " + message);
        });
    }
}