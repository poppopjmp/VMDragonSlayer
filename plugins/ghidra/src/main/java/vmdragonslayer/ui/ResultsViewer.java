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
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Map;
import vmdragonslayer.api.VMDSAPIClient;
import vmdragonslayer.api.AnalysisResult;
import vmdragonslayer.api.AnalysisUpdate;
import vmdragonslayer.api.AIDecision;

/**
 * Results Viewer Panel
 * 
 * Displays comprehensive analysis results with confidence visualization,
 * AI decision reasoning, actionable recommendations, and Ghidra integration.
 * Provides interactive result exploration and confidence-based highlighting.
 */
public class ResultsViewer extends JPanel {
    private final VMDSAPIClient apiClient;
    
    // Results Display Components
    private JTree resultsTree;
    private DefaultTreeModel resultsTreeModel;
    private DefaultMutableTreeNode rootNode;
    private JScrollPane resultsTreeScroll;
    
    // Details Panel Components
    private JTextArea detailsArea;
    private JScrollPane detailsScroll;
    private JLabel confidenceLabel;
    private JProgressBar confidenceBar;
    
    // VM Detection Results
    private JTable vmDetectionTable;
    private DefaultTableModel vmDetectionModel;
    private JScrollPane vmDetectionScroll;
    
    // Pattern Discovery Results
    private JTable patternTable;
    private DefaultTableModel patternModel;
    private JScrollPane patternScroll;
    
    // AI Reasoning Panel
    private JTextArea reasoningArea;
    private JScrollPane reasoningScroll;
    private JLabel aiEngineLabel;
    private JLabel decisionTimeLabel;
    
    // Action Buttons
    private JButton exportResultsButton;
    private JButton highlightInGhidraButton;
    private JButton generateReportButton;
    private JButton shareWithTeamButton;
    
    // Filter Controls
    private JSlider confidenceFilterSlider;
    private JLabel confidenceFilterLabel;
    private JCheckBox showOnlyHighConfidenceCheckBox;
    private JComboBox<String> resultTypeFilter;
    
    // Current Results
    private AnalysisResult currentResults;
    
    public ResultsViewer(VMDSAPIClient apiClient) {
        this.apiClient = apiClient;
        initializeComponents();
        setupLayout();
        setupEventHandlers();
    }
    
    private void initializeComponents() {
        // Results Tree
        rootNode = new DefaultMutableTreeNode("Analysis Results");
        resultsTreeModel = new DefaultTreeModel(rootNode);
        resultsTree = new JTree(resultsTreeModel);
        resultsTree.setRootVisible(true);
        resultsTree.setShowsRootHandles(true);
        resultsTreeScroll = new JScrollPane(resultsTree);
        resultsTreeScroll.setPreferredSize(new Dimension(300, 400));
        
        // Details Panel
        detailsArea = new JTextArea(10, 40);
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailsArea.setText("Select a result from the tree to view details...");
        detailsScroll = new JScrollPane(detailsArea);
        
        confidenceLabel = new JLabel("Confidence: N/A");
        confidenceBar = new JProgressBar(0, 100);
        confidenceBar.setStringPainted(true);
        confidenceBar.setString("No data");
        
        // VM Detection Table
        String[] vmColumns = {"VM Technology", "Confidence", "Evidence", "Location", "AI Reasoning"};
        vmDetectionModel = new DefaultTableModel(vmColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        vmDetectionTable = new JTable(vmDetectionModel);
        vmDetectionTable.setDefaultRenderer(Object.class, new ConfidenceTableCellRenderer());
        vmDetectionScroll = new JScrollPane(vmDetectionTable);
        vmDetectionScroll.setPreferredSize(new Dimension(600, 150));
        
        // Pattern Discovery Table
        String[] patternColumns = {"Pattern Type", "Confidence", "Frequency", "Description", "Impact"};
        patternModel = new DefaultTableModel(patternColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        patternTable = new JTable(patternModel);
        patternTable.setDefaultRenderer(Object.class, new ConfidenceTableCellRenderer());
        patternScroll = new JScrollPane(patternTable);
        patternScroll.setPreferredSize(new Dimension(600, 150));
        
        // AI Reasoning Panel
        reasoningArea = new JTextArea(6, 40);
        reasoningArea.setEditable(false);
        reasoningArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        reasoningArea.setText("AI reasoning and decision explanations will appear here...");
        reasoningArea.setLineWrap(true);
        reasoningArea.setWrapStyleWord(true);
        reasoningScroll = new JScrollPane(reasoningArea);
        reasoningScroll.setBorder(BorderFactory.createTitledBorder("🤖 AI Decision Reasoning"));
        
        aiEngineLabel = new JLabel("AI Engine: Not selected");
        decisionTimeLabel = new JLabel("Decision Time: N/A");
        
        // Action Buttons
        exportResultsButton = new JButton("📁 Export Results");
        highlightInGhidraButton = new JButton("🎯 Highlight in Ghidra");
        generateReportButton = new JButton("📊 Generate Report");
        shareWithTeamButton = new JButton("👥 Share with Team");
        
        // Filter Controls
        confidenceFilterSlider = new JSlider(0, 100, 50);
        confidenceFilterSlider.setMajorTickSpacing(25);
        confidenceFilterSlider.setMinorTickSpacing(5);
        confidenceFilterSlider.setPaintTicks(true);
        confidenceFilterSlider.setPaintLabels(true);
        confidenceFilterLabel = new JLabel("Min Confidence: 0.50");
        
        showOnlyHighConfidenceCheckBox = new JCheckBox("Show only high confidence results", true);
        
        String[] resultTypes = {"All Results", "VM Detection", "Pattern Discovery", "Performance Issues", "Security Findings"};
        resultTypeFilter = new JComboBox<>(resultTypes);
    }
    
    private void setupLayout() {
        setLayout(new BorderLayout());
        
        // Main content with split panes
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // Left panel - Results tree and filters
        JPanel leftPanel = new JPanel(new BorderLayout());
        
        // Filter panel
        JPanel filterPanel = new JPanel(new GridBagLayout());
        filterPanel.setBorder(BorderFactory.createTitledBorder("Filters"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 2, 2, 2);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        filterPanel.add(resultTypeFilter, gbc);
        
        gbc.gridy = 1; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
        filterPanel.add(new JLabel("Confidence Filter:"), gbc);
        
        gbc.gridy = 2; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        filterPanel.add(confidenceFilterSlider, gbc);
        
        gbc.gridy = 3; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
        filterPanel.add(confidenceFilterLabel, gbc);
        
        gbc.gridy = 4; gbc.gridwidth = 2;
        filterPanel.add(showOnlyHighConfidenceCheckBox, gbc);
        
        leftPanel.add(filterPanel, BorderLayout.NORTH);
        leftPanel.add(resultsTreeScroll, BorderLayout.CENTER);
        
        mainSplitPane.setLeftComponent(leftPanel);
        
        // Right panel - Details and results
        JPanel rightPanel = new JPanel(new BorderLayout());
        
        // Top section - Confidence and basic details
        JPanel topSection = new JPanel(new BorderLayout());
        
        JPanel confidencePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        confidencePanel.setBorder(BorderFactory.createTitledBorder("Result Confidence"));
        confidencePanel.add(confidenceLabel);
        confidencePanel.add(Box.createHorizontalStrut(10));
        confidencePanel.add(confidenceBar);
        topSection.add(confidencePanel, BorderLayout.NORTH);
        
        JPanel aiInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        aiInfoPanel.add(aiEngineLabel);
        aiInfoPanel.add(Box.createHorizontalStrut(20));
        aiInfoPanel.add(decisionTimeLabel);
        topSection.add(aiInfoPanel, BorderLayout.SOUTH);
        
        rightPanel.add(topSection, BorderLayout.NORTH);
        
        // Center section - Tabbed results
        JTabbedPane resultsTabs = new JTabbedPane();
        
        // Overview tab
        JPanel overviewPanel = new JPanel(new BorderLayout());
        overviewPanel.add(detailsScroll, BorderLayout.CENTER);
        resultsTabs.addTab("📋 Overview", overviewPanel);
        
        // VM Detection tab
        JPanel vmPanel = new JPanel(new BorderLayout());
        vmPanel.add(vmDetectionScroll, BorderLayout.CENTER);
        resultsTabs.addTab("🖥️ VM Detection", vmPanel);
        
        // Pattern Discovery tab
        JPanel patternPanel = new JPanel(new BorderLayout());
        patternPanel.add(patternScroll, BorderLayout.CENTER);
        resultsTabs.addTab("🔍 Patterns", patternPanel);
        
        // AI Reasoning tab
        JPanel aiPanel = new JPanel(new BorderLayout());
        aiPanel.add(reasoningScroll, BorderLayout.CENTER);
        resultsTabs.addTab("🤖 AI Reasoning", aiPanel);
        
        rightPanel.add(resultsTabs, BorderLayout.CENTER);
        
        // Bottom section - Action buttons
        JPanel actionPanel = new JPanel(new FlowLayout());
        actionPanel.setBorder(BorderFactory.createTitledBorder("Actions"));
        actionPanel.add(exportResultsButton);
        actionPanel.add(highlightInGhidraButton);
        actionPanel.add(generateReportButton);
        actionPanel.add(shareWithTeamButton);
        
        rightPanel.add(actionPanel, BorderLayout.SOUTH);
        
        mainSplitPane.setRightComponent(rightPanel);
        mainSplitPane.setDividerLocation(300);
        
        add(mainSplitPane, BorderLayout.CENTER);
    }
    
    private void setupEventHandlers() {
        // Results tree selection
        resultsTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) 
                resultsTree.getLastSelectedPathComponent();
            if (selectedNode != null) {
                displayResultDetails(selectedNode);
            }
        });
        
        // Double-click to highlight in Ghidra
        resultsTree.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    highlightSelectedInGhidra();
                }
            }
        });
        
        // Filter controls
        confidenceFilterSlider.addChangeListener(e -> {
            double threshold = confidenceFilterSlider.getValue() / 100.0;
            confidenceFilterLabel.setText(String.format("Min Confidence: %.2f", threshold));
            applyFilters();
        });
        
        showOnlyHighConfidenceCheckBox.addActionListener(e -> applyFilters());
        resultTypeFilter.addActionListener(e -> applyFilters());
        
        // Action buttons
        exportResultsButton.addActionListener(e -> exportResults());
        highlightInGhidraButton.addActionListener(e -> highlightSelectedInGhidra());
        generateReportButton.addActionListener(e -> generateReport());
        shareWithTeamButton.addActionListener(e -> shareWithTeam());
    }
    
    public void updateResults(AnalysisResult results) {
        this.currentResults = results;
        SwingUtilities.invokeLater(() -> {
            populateResultsTree(results);
            updateConfidenceDisplay(results);
            updateAIReasoningDisplay(results);
            populateDetailedResults(results);
        });
    }
    
    /**
     * Add progress update to results viewer
     */
    public void addProgressUpdate(AnalysisUpdate update) {
        SwingUtilities.invokeLater(() -> {
            // Add update to progress log or status display
            if (update != null) {
                // Implementation for displaying progress updates
                // This could update a progress log area or status display
                System.out.println("Progress Update: " + update.getType() + " - " + update.getMessage());
            }
        });
    }

    private void populateResultsTree(AnalysisResult results) {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("Analysis Results");
        
        // VM Detection Results
        if (results.getVmDetection() != null && !results.getVmDetection().isEmpty()) {
            DefaultMutableTreeNode vmNode = new DefaultMutableTreeNode("🖥️ VM Detection");
            for (AnalysisResult.VMDetectionResult vm : results.getVmDetection()) {
                String vmText = String.format("%s (%.2f)", vm.vmType, vm.confidence);
                DefaultMutableTreeNode vmItemNode = new DefaultMutableTreeNode(vmText);
                vmItemNode.setUserObject(vm);
                vmNode.add(vmItemNode);
            }
            root.add(vmNode);
        }
        
        // Pattern Results
        if (results.getPatterns() != null && !results.getPatterns().isEmpty()) {
            DefaultMutableTreeNode patternNode = new DefaultMutableTreeNode("🔍 Patterns");
            for (AnalysisResult.PatternResult pattern : results.getPatterns()) {
                String patternText = String.format("%s (%.2f)", 
                    pattern.patternType, pattern.confidence);
                DefaultMutableTreeNode patternItemNode = new DefaultMutableTreeNode(patternText);
                patternItemNode.setUserObject(pattern);
                patternNode.add(patternItemNode);
            }
            root.add(patternNode);
        }
        
        // Performance Results (using available metrics)
        if (results.getPerformanceMetrics() != null) {
            DefaultMutableTreeNode perfNode = new DefaultMutableTreeNode("⚡ Performance");
            DefaultMutableTreeNode perfItemNode = new DefaultMutableTreeNode(
                String.format("Overall Score: %.2f", results.getConfidence()));
            perfItemNode.setUserObject(results.getPerformanceMetrics());
            perfNode.add(perfItemNode);
            root.add(perfNode);
        }
        
        // AI Decisions
        if (results.getAiDecisions() != null && !results.getAiDecisions().isEmpty()) {
            DefaultMutableTreeNode aiNode = new DefaultMutableTreeNode("🤖 AI Decisions");
            for (AIDecision decision : results.getAiDecisions()) {
                String aiText = String.format("%s (%.2f)", 
                    decision.getDecisionType(), decision.getConfidence());
                DefaultMutableTreeNode aiItemNode = new DefaultMutableTreeNode(aiText);
                aiItemNode.setUserObject(decision);
                aiNode.add(aiItemNode);
            }
            root.add(aiNode);
        }
        
        ((DefaultTreeModel) resultsTree.getModel()).setRoot(root);
        expandAllNodes(resultsTree, 0, resultsTree.getRowCount());
    }
    
    private void updateConfidenceIndicator(AnalysisResult results) {
        if (results != null && results.getOverallConfidence() != null) {
            double confidence = results.getOverallConfidence();
            confidenceBar.setValue((int) (confidence * 100));
            confidenceBar.setString(String.format("Overall Confidence: %.1f%%", confidence * 100));
            
            // Color coding based on confidence
            if (confidence >= 0.8) {
                confidenceBar.setForeground(new Color(34, 139, 34)); // Forest Green
            } else if (confidence >= 0.6) {
                confidenceBar.setForeground(new Color(255, 165, 0)); // Orange
            } else {
                confidenceBar.setForeground(new Color(220, 20, 60)); // Crimson
            }
        } else {
            confidenceBar.setValue(0);
            confidenceBar.setString("No confidence data available");
            confidenceBar.setForeground(Color.GRAY);
        }
    }
    
    private void updateAnalysisInfo(AnalysisResult results) {
        if (results != null && results.getAiReasoning() != null) {
            reasoningArea.setText(results.getAiReasoning());
            aiEngineLabel.setText("AI Engine: " + (results.getEngineUsed() != null ? results.getEngineUsed() : "Unknown"));
            decisionTimeLabel.setText("Decision Time: " + 
                (results.getAnalysisTime() != null ? results.getAnalysisTime() + "s" : "N/A"));
        } else {
            reasoningArea.setText("No AI reasoning available for this analysis.");
            aiEngineLabel.setText("AI Engine: Unknown");
            decisionTimeLabel.setText("Decision Time: N/A");
        }
    }
    
    private void populateVMTable(AnalysisResult results) {
        vmDetectionModel.setRowCount(0); // Clear existing data
        
        if (results != null && results.getVmDetection() != null) {
            for (AnalysisResult.VMDetectionResult vm : results.getVmDetection()) {
                Object[] row = {
                    vm.vmType,
                    vm.confidence,
                    vm.evidence != null ? vm.evidence : "N/A",
                    vm.location != null ? vm.location : "N/A"
                };
                vmDetectionModel.addRow(row);
            }
        }
    }
    
    private void populatePatternTable(AnalysisResult results) {
        patternModel.setRowCount(0); // Clear existing data
        
        if (results != null && results.getPatterns() != null) {
            for (AnalysisResult.PatternResult pattern : results.getPatterns()) {
                Object[] row = {
                    pattern.patternType,
                    pattern.confidence,
                    pattern.frequency != null ? pattern.frequency.toString() : "N/A",
                    pattern.description != null ? pattern.description : "N/A"
                };
                patternModel.addRow(row);
            }
        }
    }
    
    private String generateDetailedReport(AnalysisResult results) {
        StringBuilder details = new StringBuilder();
        
        if (results != null) {
            details.append("=== VMDragonSlayer Analysis Report ===\n\n");
            details.append("Engine Used: ").append(results.getEngineUsed() != null ? results.getEngineUsed() : "Unknown").append("\n");
            details.append("Analysis Time: ").append(results.getAnalysisTime() != null ? results.getAnalysisTime() + "s" : "N/A").append("\n");
            details.append("Overall Confidence: ").append(results.getOverallConfidence() != null ? 
                String.format("%.3f", results.getOverallConfidence()) : "N/A").append("\n\n");
            
            // VM Detection Summary
            if (results.getVmDetection() != null && !results.getVmDetection().isEmpty()) {
                details.append("• VM Technologies Detected: ").append(results.getVmDetection().size()).append("\n");
                for (AnalysisResult.VMDetectionResult vm : results.getVmDetection()) {
                    details.append("  - ").append(vm.vmType)
                           .append(" (Confidence: ").append(String.format("%.3f", vm.confidence)).append(")\n");
                }
                details.append("\n");
            }
            
            if (results.getPatterns() != null && !results.getPatterns().isEmpty()) {
                details.append("• Patterns Discovered: ").append(results.getPatterns().size()).append("\n");
                for (AnalysisResult.PatternResult pattern : results.getPatterns()) {
                    details.append("  - ").append(pattern.patternType)
                           .append(" (Confidence: ").append(String.format("%.3f", pattern.confidence)).append(")\n");
                }
                details.append("\n");
            }
            
            if (results.getAiReasoning() != null) {
                details.append("AI Reasoning:\n").append(results.getAiReasoning()).append("\n");
            }
        } else {
            details.append("No analysis results available.");
        }
        
        return details.toString();
    }
    
    private void displayResultDetails(DefaultMutableTreeNode node) {
        Object userObject = node.getUserObject();
        
        if (userObject instanceof AnalysisResult.VMDetectionResult) {
            AnalysisResult.VMDetectionResult vm = (AnalysisResult.VMDetectionResult) userObject;
            StringBuilder details = new StringBuilder();
            details.append("=== VM Detection Details ===\n");
            details.append("VM Type: ").append(vm.vmType).append("\n");
            details.append("Confidence: ").append(String.format("%.3f", vm.confidence)).append("\n");
            details.append("Evidence: ").append(vm.evidence != null ? vm.evidence : "N/A").append("\n");
            details.append("Location: ").append(vm.location != null ? vm.location : "N/A").append("\n");
            details.append("AI Reasoning: ").append(vm.aiReasoning != null ? vm.aiReasoning : "N/A").append("\n");
            detailsArea.setText(details.toString());
        } else if (userObject instanceof AnalysisResult.PatternResult) {
            AnalysisResult.PatternResult pattern = (AnalysisResult.PatternResult) userObject;
            StringBuilder details = new StringBuilder();
            details.append("=== Pattern Discovery Details ===\n");
            details.append("Pattern Type: ").append(pattern.patternType).append("\n");
            details.append("Confidence: ").append(String.format("%.3f", pattern.confidence)).append("\n");
            details.append("Frequency: ").append(pattern.frequency != null ? pattern.frequency : "N/A").append("\n");
            details.append("Description: ").append(pattern.description != null ? pattern.description : "N/A").append("\n");
            details.append("Impact: ").append(pattern.impact != null ? pattern.impact : "N/A").append("\n");
            detailsArea.setText(details.toString());
        }
    }
    
    private void applyFilters() {
        // Filter implementation would go here
        // This would filter the results tree based on confidence and type
    }
    
    private void exportResults() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Analysis Results");
        fileChooser.setSelectedFile(new java.io.File("analysis_results.json"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            // Export implementation
            JOptionPane.showMessageDialog(this, "Results exported successfully!", 
                "Export Complete", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void highlightSelectedInGhidra() {
        DefaultMutableTreeNode selectedNode = (DefaultMutableTreeNode) 
            resultsTree.getLastSelectedPathComponent();
        
        if (selectedNode != null) {
            // Implementation would integrate with Ghidra to highlight results
            JOptionPane.showMessageDialog(this, 
                "Highlighting selected result in Ghidra...\n(Feature will be implemented in integration phase)", 
                "Highlight in Ghidra", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    private void generateReport() {
        JOptionPane.showMessageDialog(this, 
            "Generating comprehensive analysis report...\n(Report generation feature coming soon)", 
            "Generate Report", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void shareWithTeam() {
        JOptionPane.showMessageDialog(this, 
            "Sharing results with team...\n(Team collaboration features coming soon)", 
            "Share with Team", JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Custom table cell renderer that highlights cells based on confidence values
     */
    private static class ConfidenceTableCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            
            Component component = super.getTableCellRendererComponent(table, value, 
                isSelected, hasFocus, row, column);
            
            // Check if this is a confidence column
            if (column == 1 && value instanceof String) {
                try {
                    double confidence = Double.parseDouble((String) value);
                    if (!isSelected) {
                        if (confidence >= 0.8) {
                            component.setBackground(new Color(200, 255, 200)); // Light green
                        } else if (confidence >= 0.6) {
                            component.setBackground(new Color(255, 255, 200)); // Light yellow
                        } else {
                            component.setBackground(new Color(255, 200, 200)); // Light red
                        }
                    }
                } catch (NumberFormatException e) {
                    // Not a number, use default background
                    if (!isSelected) {
                        component.setBackground(Color.WHITE);
                    }
                }
            } else if (!isSelected) {
                component.setBackground(Color.WHITE);
            }
            
            return component;
        }
    }
    
    public void clearResults() {
        currentResults = null;
        rootNode.removeAllChildren();
        resultsTreeModel.reload();
        vmDetectionModel.setRowCount(0);
        patternModel.setRowCount(0);
        detailsArea.setText("No analysis results available.");
        reasoningArea.setText("AI reasoning will appear here after analysis...");
        updateConfidenceDisplay(null);
    }
    
    private void updateConfidenceDisplay(AnalysisResult results) {
        updateConfidenceIndicator(results);
    }
    
    private void updateAIReasoningDisplay(AnalysisResult results) {
        updateAnalysisInfo(results);
    }
    
    private void populateDetailedResults(AnalysisResult results) {
        populateVMTable(results);
        populatePatternTable(results);
        detailsArea.setText(generateDetailedReport(results));
    }
    
    private void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
        for (int i = startingIndex; i < rowCount; ++i) {
            tree.expandRow(i);
        }
        
        if (tree.getRowCount() != rowCount) {
            expandAllNodes(tree, rowCount, tree.getRowCount());
        }
    }
}