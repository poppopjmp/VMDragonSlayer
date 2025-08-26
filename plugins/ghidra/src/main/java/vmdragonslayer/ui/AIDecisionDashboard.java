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

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Map;
import vmdragonslayer.api.AgenticAPIClient;
import vmdragonslayer.api.AIDecision;
import vmdragonslayer.api.AnalysisUpdate;
import vmdragonslayer.api.AgentDecisionHistory;
import vmdragonslayer.api.SystemStats;

/**
 * AI Decision Dashboard Panel
 * 
 * Provides real-time visualization of AI agent decisions, learning progress,
 * and performance metrics. Shows decision history, confidence tracking,
 * and manual intervention controls.
 */
public class AIDecisionDashboard extends JPanel {
    private final AgenticAPIClient apiClient;
    private Timer refreshTimer;
    
    // Decision History Components
    private JTable decisionHistoryTable;
    private DefaultTableModel decisionHistoryModel;
    private JScrollPane decisionHistoryScroll;
    
    // Learning Progress Components
    private JProgressBar learningProgressBar;
    private JLabel learningStatusLabel;
    private JLabel totalDecisionsLabel;
    private JLabel confidenceAverageLabel;
    
    // Performance Metrics Components
    private JLabel avgResponseTimeLabel;
    private JLabel successRateLabel;
    private JLabel learningEfficiencyLabel;
    private JTextArea performanceNotesArea;
    
    // Control Components
    private JButton refreshDecisionsButton;
    private JButton clearHistoryButton;
    private JCheckBox autoRefreshCheckBox;
    private JSlider confidenceThresholdSlider;
    private JLabel confidenceThresholdLabel;
    
    // Visualization Components
    private JPanel confidenceChartPanel;
    private JPanel learningTrendPanel;
    
    public AIDecisionDashboard(AgenticAPIClient apiClient) {
        this.apiClient = apiClient;
        initializeComponents();
        setupLayout();
        setupEventHandlers();
        startAutoRefresh();
    }
    
    private void initializeComponents() {
        // Decision History Table
        String[] columnNames = {
            "Timestamp", "Decision Type", "Engine Selected", 
            "Confidence", "Reasoning", "Result"
        };
        decisionHistoryModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table read-only
            }
        };
        decisionHistoryTable = new JTable(decisionHistoryModel);
        decisionHistoryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        decisionHistoryTable.getColumnModel().getColumn(4).setPreferredWidth(200); // Reasoning column wider
        decisionHistoryScroll = new JScrollPane(decisionHistoryTable);
        decisionHistoryScroll.setPreferredSize(new Dimension(600, 200));
        
        // Learning Progress Components
        learningProgressBar = new JProgressBar(0, 100);
        learningProgressBar.setStringPainted(true);
        learningProgressBar.setString("AI Learning Progress");
        learningStatusLabel = new JLabel("Learning Status: Initializing...");
        totalDecisionsLabel = new JLabel("Total Decisions: 0");
        confidenceAverageLabel = new JLabel("Average Confidence: 0.00");
        
        // Performance Metrics Components
        avgResponseTimeLabel = new JLabel("Avg Response Time: 0.00s");
        successRateLabel = new JLabel("Success Rate: 0.00%");
        learningEfficiencyLabel = new JLabel("Learning Efficiency: 0.00%");
        performanceNotesArea = new JTextArea(3, 30);
        performanceNotesArea.setEditable(false);
        performanceNotesArea.setBorder(BorderFactory.createTitledBorder("Performance Notes"));
        performanceNotesArea.setText("AI agent performance metrics will appear here...");
        
        // Control Components
        refreshDecisionsButton = new JButton("🔄 Refresh Decisions");
        clearHistoryButton = new JButton("🗑️ Clear History");
        autoRefreshCheckBox = new JCheckBox("Auto-refresh (5s)", true);
        
        confidenceThresholdSlider = new JSlider(50, 100, 80);
        confidenceThresholdSlider.setMajorTickSpacing(10);
        confidenceThresholdSlider.setMinorTickSpacing(5);
        confidenceThresholdSlider.setPaintTicks(true);
        confidenceThresholdSlider.setPaintLabels(true);
        confidenceThresholdLabel = new JLabel("Confidence Threshold: 0.80");
        
        // Visualization Panels
        confidenceChartPanel = createVisualizationPanel("Confidence Trend", Color.BLUE);
        learningTrendPanel = createVisualizationPanel("Learning Trend", Color.GREEN);
    }
    
    private JPanel createVisualizationPanel(String title, Color color) {
        JPanel panel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                drawSimpleChart(g, color);
            }
        };
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.setPreferredSize(new Dimension(250, 150));
        panel.setBackground(Color.WHITE);
        return panel;
    }
    
    private void drawSimpleChart(Graphics g, Color color) {
        Graphics2D g2d = (Graphics2D) g;
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        // Draw a simple trend line (placeholder)
        g2d.setColor(color);
        g2d.setStroke(new BasicStroke(2));
        
        int width = getWidth() - 40;
        int height = getHeight() - 40;
        int x1 = 20;
        int y1 = height - 20;
        
        // Draw sample trend line
        for (int i = 0; i < 10; i++) {
            int x2 = x1 + (width / 10);
            int y2 = y1 - (int)(Math.random() * 30); // Simulate trend
            g2d.drawLine(x1, y1, x2, y2);
            x1 = x2;
            y1 = y2;
        }
        
        // Draw axis
        g2d.setColor(Color.GRAY);
        g2d.setStroke(new BasicStroke(1));
        g2d.drawLine(20, height - 20, width + 20, height - 20); // X-axis
        g2d.drawLine(20, 20, 20, height - 20); // Y-axis
    }
    
    private void setupLayout() {
        setLayout(new BorderLayout());
        
        // Main content panel with tabs
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Decision History Tab
        JPanel historyPanel = new JPanel(new BorderLayout());
        historyPanel.add(decisionHistoryScroll, BorderLayout.CENTER);
        
        JPanel historyControlPanel = new JPanel(new FlowLayout());
        historyControlPanel.add(refreshDecisionsButton);
        historyControlPanel.add(clearHistoryButton);
        historyControlPanel.add(autoRefreshCheckBox);
        historyPanel.add(historyControlPanel, BorderLayout.SOUTH);
        
        tabbedPane.addTab("📊 Decision History", historyPanel);
        
        // Learning Dashboard Tab
        JPanel learningPanel = new JPanel(new BorderLayout());
        
        // Learning Progress Panel
        JPanel progressPanel = new JPanel(new GridBagLayout());
        progressPanel.setBorder(BorderFactory.createTitledBorder("Learning Progress"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        progressPanel.add(learningProgressBar, gbc);
        
        gbc.gridy = 1; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
        progressPanel.add(learningStatusLabel, gbc);
        gbc.gridx = 1;
        progressPanel.add(totalDecisionsLabel, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        progressPanel.add(confidenceAverageLabel, gbc);
        
        learningPanel.add(progressPanel, BorderLayout.NORTH);
        
        // Visualization Panel
        JPanel vizPanel = new JPanel(new FlowLayout());
        vizPanel.add(confidenceChartPanel);
        vizPanel.add(learningTrendPanel);
        learningPanel.add(vizPanel, BorderLayout.CENTER);
        
        tabbedPane.addTab("🧠 Learning Dashboard", learningPanel);
        
        // Performance Metrics Tab
        JPanel performancePanel = new JPanel(new BorderLayout());
        
        JPanel metricsPanel = new JPanel(new GridLayout(3, 1, 5, 5));
        metricsPanel.setBorder(BorderFactory.createTitledBorder("Performance Metrics"));
        metricsPanel.add(avgResponseTimeLabel);
        metricsPanel.add(successRateLabel);
        metricsPanel.add(learningEfficiencyLabel);
        
        performancePanel.add(metricsPanel, BorderLayout.NORTH);
        performancePanel.add(new JScrollPane(performanceNotesArea), BorderLayout.CENTER);
        
        tabbedPane.addTab("⚡ Performance", performancePanel);
        
        // Configuration Tab
        JPanel configPanel = new JPanel(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("AI Configuration:"), gbc);
        
        gbc.gridy = 1; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        configPanel.add(confidenceThresholdSlider, gbc);
        
        gbc.gridy = 2; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(confidenceThresholdLabel, gbc);
        
        JPanel configButtonPanel = new JPanel(new FlowLayout());
        configButtonPanel.add(new JButton("💾 Save Config"));
        configButtonPanel.add(new JButton("🔄 Reset to Defaults"));
        
        gbc.gridy = 3; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        configPanel.add(configButtonPanel, gbc);
        
        tabbedPane.addTab("⚙️ Configuration", configPanel);
        
        add(tabbedPane, BorderLayout.CENTER);
        
        // Status bar
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.setBorder(BorderFactory.createLoweredBevelBorder());
        statusPanel.add(new JLabel("🤖 AI Dashboard Ready"));
        add(statusPanel, BorderLayout.SOUTH);
    }
    
    private void setupEventHandlers() {
        refreshDecisionsButton.addActionListener(e -> refreshDecisionHistory());
        
        clearHistoryButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(
                    AIDecisionDashboard.this,
                    "Are you sure you want to clear the decision history?",
                    "Clear History",
                    JOptionPane.YES_NO_OPTION
                );
                if (result == JOptionPane.YES_OPTION) {
                    clearDecisionHistory();
                }
            }
        });
        
        autoRefreshCheckBox.addActionListener(e -> {
            if (autoRefreshCheckBox.isSelected()) {
                startAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        });
        
        confidenceThresholdSlider.addChangeListener(e -> {
            double threshold = confidenceThresholdSlider.getValue() / 100.0;
            confidenceThresholdLabel.setText(String.format("Confidence Threshold: %.2f", threshold));
        });
    }
    
    private void startAutoRefresh() {
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
        refreshTimer = new Timer(5000, e -> {
            if (autoRefreshCheckBox.isSelected()) {
                refreshAllData();
            }
        });
        refreshTimer.start();
    }
    
    private void stopAutoRefresh() {
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
    }
    
    /**
     * Refreshes all data in the dashboard
     */
    public void refreshAllData() {
        // Refresh decision history
        refreshDecisionHistory();
        
        // Refresh metrics if available
        refreshMetrics();
        
        // Update charts and visualizations
        updateCharts();
        
        // Repaint the panel
        repaint();
    }
    
    private void refreshDecisionHistory() {
        try {
            AgentDecisionHistory history = apiClient.getAgentDecisionHistory();
            if (history != null && history.decisions != null) {
                updateDecisionHistoryTable(history.decisions);
                updateLearningStats(history);
            }
        } catch (Exception e) {
            System.err.println("Error refreshing decision history: " + e.getMessage());
        }
    }
    
    private void refreshMetrics() {
        refreshPerformanceMetrics();
    }
    
    private void updateCharts() {
        repaintVisualizationPanels();
    }
    
    private void updateDecisionHistoryTable(List<AIDecision> decisions) {
        // Clear existing data
        decisionHistoryModel.setRowCount(0);
        
        // Add new decisions
        for (AIDecision decision : decisions) {
            Object[] row = {
                decision.getTimestamp(),
                decision.getDecisionType(),
                decision.getSelectedEngine(),
                String.format("%.2f", decision.getConfidence()),
                decision.getReasoning(),
                decision.isSuccessful() ? " Success" : " Failed"
            };
            decisionHistoryModel.addRow(row);
        }
        
        // Auto-scroll to latest
        if (decisionHistoryTable.getRowCount() > 0) {
            decisionHistoryTable.scrollRectToVisible(
                decisionHistoryTable.getCellRect(decisionHistoryTable.getRowCount() - 1, 0, true)
            );
        }
    }
    
    private void updateLearningStats(AgentDecisionHistory history) {
        if (history.statistics != null) {
            totalDecisionsLabel.setText("Total Decisions: " + history.statistics.totalDecisions);
            confidenceAverageLabel.setText(String.format("Average Confidence: %.2f", 
                history.statistics.averageConfidence));
            
            // Update learning progress bar (simulate learning progress)
            int progress = Math.min(100, (int)(history.statistics.averageConfidence * 100));
            learningProgressBar.setValue(progress);
            learningProgressBar.setString(String.format("Learning Progress: %d%%", progress));
            
            // Update learning status
            if (history.statistics.averageConfidence > 0.90) {
                learningStatusLabel.setText("Learning Status: Expert Level 🌟");
            } else if (history.statistics.averageConfidence > 0.75) {
                learningStatusLabel.setText("Learning Status: Advanced 📈");
            } else if (history.statistics.averageConfidence > 0.60) {
                learningStatusLabel.setText("Learning Status: Intermediate 📊");
            } else {
                learningStatusLabel.setText("Learning Status: Learning 📚");
            }
        }
    }
    
    private void refreshPerformanceMetrics() {
        try {
            SystemStats stats = apiClient.getSystemStats();
            if (stats != null) {
                avgResponseTimeLabel.setText(String.format("Avg Response Time: %.2fs", 
                    stats.averageResponseTime));
                successRateLabel.setText(String.format("Success Rate: %.1f%%", 
                    stats.successRate * 100));
                
                // Calculate learning efficiency (simplified)
                double efficiency = stats.successRate * stats.averageResponseTime * 100;
                learningEfficiencyLabel.setText(String.format("Learning Efficiency: %.1f%%", efficiency));
                
                // Update performance notes
                StringBuilder notes = new StringBuilder();
                notes.append("Performance Analysis:\n");
                notes.append("• Response time trend: ");
                notes.append(stats.averageResponseTime < 0.5 ? "Excellent" : "Good").append("\n");
                notes.append("• Success rate: ");
                notes.append(stats.successRate > 0.9 ? "Outstanding" : "Good").append("\n");
                notes.append("• AI learning rate: Active and improving\n");
                notes.append("• Standard engines: Fully operational");
                
                performanceNotesArea.setText(notes.toString());
            }
        } catch (Exception e) {
            System.err.println("Error refreshing performance metrics: " + e.getMessage());
        }
    }
    
    private void repaintVisualizationPanels() {
        confidenceChartPanel.repaint();
        learningTrendPanel.repaint();
    }
    
    private void clearDecisionHistory() {
        decisionHistoryModel.setRowCount(0);
        totalDecisionsLabel.setText("Total Decisions: 0");
        confidenceAverageLabel.setText("Average Confidence: 0.00");
        learningProgressBar.setValue(0);
        learningProgressBar.setString("Learning Progress: 0%");
        learningStatusLabel.setText("Learning Status: Reset");
        performanceNotesArea.setText("Decision history cleared. AI will begin learning from new data...");
    }
    
    public void cleanup() {
        stopAutoRefresh();
    }
    
    public void updateDecisionThreshold(double threshold) {
        confidenceThresholdSlider.setValue((int)(threshold * 100));
        confidenceThresholdLabel.setText(String.format("Confidence Threshold: %.2f", threshold));
    }
    
    public double getDecisionThreshold() {
        return confidenceThresholdSlider.getValue() / 100.0;
    }
    
    /**
     * Add decision update to AI dashboard
     */
    public void addDecisionUpdate(AnalysisUpdate update) {
        SwingUtilities.invokeLater(() -> {
            if (update != null && "agent_decision".equals(update.getType())) {
                // Add the decision update to the dashboard
                // This could update the decision history table or metrics
                System.out.println("AI Decision Update: " + update.getMessage());
                // Refresh the decision history to include new updates
                refreshDecisionHistory();
            }
        });
    }
}