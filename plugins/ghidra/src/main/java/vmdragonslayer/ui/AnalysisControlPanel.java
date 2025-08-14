package vmdragonslayer.ui;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import vmdragonslayer.api.AgenticAPIClient;
import vmdragonslayer.api.AnalysisRequest;
import vmdragonslayer.api.EngineStatus;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

/**
 * Analysis Control Panel with Engine Selection
 * 
 * Provides comprehensive control over agentic analysis including:
 * - Engine selection and configuration
 * - AI-driven analysis type selection
 * - User goal specification for intelligent decision making
 * - Confidence threshold and learning settings
 */
public class AnalysisControlPanel extends JPanel {
    
    private final VMDragonSlayerProvider provider;
    private final AgenticAPIClient apiClient;
    
    // UI Components
    private JComboBox<String> analysisTypeCombo;
    private JList<String> userGoalsList;
    private JSlider confidenceSlider;
    private JCheckBox enableLearningCheckbox;
    private JCheckBox standardModeCheckbox;
    private JButton startAnalysisButton;
    private JButton refreshEnginesButton;
    
    // Engine selection
    private JPanel engineSelectionPanel;
    private ButtonGroup engineButtonGroup;
    private JLabel engineStatusLabel;
    
    // Program context
    private Program currentProgram;
    private JLabel programInfoLabel;
    
    public AnalysisControlPanel(VMDragonSlayerProvider provider, AgenticAPIClient apiClient) {
        this.provider = provider;
        this.apiClient = apiClient;
        
        setLayout(new BorderLayout());
        setBorder(new TitledBorder("Agentic Analysis Control"));
        
        buildUI();
        refreshEngineStatus();
        
        Msg.info(this, "Analysis Control Panel initialized");
    }
    
    private void buildUI() {
        // Main control panel
        JPanel controlPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Program information
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        programInfoLabel = new JLabel("No program loaded");
        programInfoLabel.setFont(programInfoLabel.getFont().deriveFont(Font.BOLD));
        controlPanel.add(programInfoLabel, gbc);
        
        // Analysis type selection
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        controlPanel.add(new JLabel("Analysis Type:"), gbc);
        
        gbc.gridx = 1;
        analysisTypeCombo = new JComboBox<>(new String[]{
            "auto - AI Agent Selection",
            "hybrid - Multi-Engine Analysis", 
            "parallel - Distributed Processing",
            "dtt - Dynamic Taint Tracking",
            "symbolic - Symbolic Execution",
            "ml - Machine Learning",
            "pattern - Pattern Matching"
        });
        analysisTypeCombo.setSelectedIndex(0); // Default to auto
        controlPanel.add(analysisTypeCombo, gbc);
        
        // User goals selection
        gbc.gridx = 0; gbc.gridy = 2;
        controlPanel.add(new JLabel("Analysis Goals:"), gbc);
        
        gbc.gridx = 1;
        String[] availableGoals = {
            "vm_detection",
            "pattern_discovery", 
            "performance_optimization",
            "comprehensive_analysis",
            "handler_classification",
            "multi_stage_analysis",
            "batch_processing",
            "scalability",
            "detailed_analysis",
            "quick_scan"
        };
        
        userGoalsList = new JList<>(availableGoals);
        userGoalsList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        userGoalsList.setSelectedIndices(new int[]{0, 1}); // Default selection
        userGoalsList.setVisibleRowCount(4);
        
        JScrollPane goalsScrollPane = new JScrollPane(userGoalsList);
        goalsScrollPane.setPreferredSize(new Dimension(250, 80));
        controlPanel.add(goalsScrollPane, gbc);
        
        // Confidence threshold
        gbc.gridx = 0; gbc.gridy = 3;
        controlPanel.add(new JLabel("Confidence Threshold:"), gbc);
        
        gbc.gridx = 1;
        JPanel confidencePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        confidenceSlider = new JSlider(50, 100, 80);
        confidenceSlider.setMajorTickSpacing(10);
        confidenceSlider.setMinorTickSpacing(5);
        confidenceSlider.setPaintTicks(true);
        confidenceSlider.setPaintLabels(true);
        
        JLabel confidenceValue = new JLabel("0.80");
        confidenceSlider.addChangeListener(e -> {
            double value = confidenceSlider.getValue() / 100.0;
            confidenceValue.setText(String.format("%.2f", value));
        });
        
        confidencePanel.add(confidenceSlider);
        confidencePanel.add(Box.createHorizontalStrut(10));
        confidencePanel.add(confidenceValue);
        controlPanel.add(confidencePanel, gbc);
        
        // Options
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        enableLearningCheckbox = new JCheckBox("Enable AI Learning", true);
        enableLearningCheckbox.setToolTipText("Allow the AI agent to learn from analysis results");
        optionsPanel.add(enableLearningCheckbox);
        
        standardModeCheckbox = new JCheckBox("Standard Mode", true);
        standardModeCheckbox.setToolTipText("Use standard engines when available");
        optionsPanel.add(standardModeCheckbox);
        
        controlPanel.add(optionsPanel, gbc);
        
        add(controlPanel, BorderLayout.NORTH);
        
        // Engine selection panel
        add(createEngineSelectionPanel(), BorderLayout.CENTER);
        
        // Control buttons
        add(createButtonPanel(), BorderLayout.SOUTH);
    }
    
    private JPanel createEngineSelectionPanel() {
        engineSelectionPanel = new JPanel(new BorderLayout());
        engineSelectionPanel.setBorder(new TitledBorder("Engine Selection"));
        
        // Engine status
        engineStatusLabel = new JLabel("Checking engine status...");
        engineStatusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        engineSelectionPanel.add(engineStatusLabel, BorderLayout.NORTH);
        
        // Engine selection will be added dynamically
        JPanel engineButtonPanel = new JPanel(new FlowLayout());
        engineButtonGroup = new ButtonGroup();
        
        // Default radio button for auto-selection
        JRadioButton autoSelectButton = new JRadioButton("Auto-Select (AI Agent Choice)", true);
        autoSelectButton.setActionCommand("auto");
        engineButtonGroup.add(autoSelectButton);
        engineButtonPanel.add(autoSelectButton);
        
        engineSelectionPanel.add(engineButtonPanel, BorderLayout.CENTER);
        
        return engineSelectionPanel;
    }
    
    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        // Refresh engines button
        refreshEnginesButton = new JButton("🔄 Refresh Engines");
        refreshEnginesButton.addActionListener(e -> refreshEngineStatus());
        buttonPanel.add(refreshEnginesButton);
        
        buttonPanel.add(Box.createHorizontalStrut(20));
        
        // Start analysis button
        startAnalysisButton = new JButton("🚀 Start Analysis");
        startAnalysisButton.setFont(startAnalysisButton.getFont().deriveFont(Font.BOLD));
        startAnalysisButton.addActionListener(e -> startAnalysis());
        buttonPanel.add(startAnalysisButton);
        
        return buttonPanel;
    }
    
    private void refreshEngineStatus() {
        refreshEnginesButton.setEnabled(false);
        engineStatusLabel.setText("Refreshing engine status...");
        
        SwingUtilities.invokeLater(() -> {
            try {
                EngineStatus status = apiClient.getEngineStatus();
                updateEngineDisplay(status);
                
            } catch (Exception e) {
                engineStatusLabel.setText("⚠️ Failed to get engine status: " + e.getMessage());
                Msg.error(this, "Failed to refresh engine status: " + e.getMessage(), e);
            } finally {
                refreshEnginesButton.setEnabled(true);
            }
        });
    }
    
    private void updateEngineDisplay(EngineStatus status) {
        if (status.isAvailable()) {
            engineStatusLabel.setText(String.format(
                "✅ Engines Available (%d active)", 
                status.getAvailableEngines().size()
            ));
            engineStatusLabel.setForeground(Color.GREEN.darker());
            
            // Add engine-specific radio buttons
            updateEngineButtons(status.getAvailableEngines());
            
        } else {
            engineStatusLabel.setText("⚠️ Engines in Fallback Mode");
            engineStatusLabel.setForeground(Color.ORANGE.darker());
            
            // Show fallback engines
            updateEngineButtons(status.getAvailableEngines());
        }
    }
    
    private void updateEngineButtons(List<String> availableEngines) {
        // Clear existing engine buttons (except auto-select)
        Component[] components = ((JPanel) engineSelectionPanel.getComponent(1)).getComponents();
        JPanel buttonPanel = (JPanel) engineSelectionPanel.getComponent(1);
        
        // Keep only the first button (auto-select)
        for (int i = buttonPanel.getComponentCount() - 1; i > 0; i--) {
            Component comp = buttonPanel.getComponent(i);
            if (comp instanceof JRadioButton) {
                engineButtonGroup.remove((JRadioButton) comp);
                buttonPanel.remove(comp);
            }
        }
        
        // Add buttons for available engines
        for (String engine : availableEngines) {
            String displayName = getEngineDisplayName(engine);
            JRadioButton engineButton = new JRadioButton(displayName);
            engineButton.setActionCommand(engine);
            engineButtonGroup.add(engineButton);
            buttonPanel.add(engineButton);
        }
        
        buttonPanel.revalidate();
        buttonPanel.repaint();
    }
    
    private String getEngineDisplayName(String engine) {
        switch (engine.toLowerCase()) {
            case "hybrid": return "🔄 Hybrid Multi-Engine";
            case "parallel": return "⚡ Parallel Processing"; 
            case "dtt": return "🔍 Dynamic Taint Tracking";
            case "symbolic": return "🧠 Symbolic Execution";
            case "ml": return "🤖 Machine Learning";
            case "gpu": return "💻 GPU Acceleration";
            case "memory_opt": return "🚀 Memory Optimization";
            case "pattern": return "🔎 Pattern Matching";
            case "semantic": return "📚 Semantic Analysis";
            default: return "🔧 " + engine.toUpperCase();
        }
    }
    
    private void startAnalysis() {
        if (currentProgram == null) {
            JOptionPane.showMessageDialog(this,
                "No program is currently loaded. Please open a program in Ghidra first.",
                "No Program", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        try {
            // Create analysis request
            AnalysisRequest request = createAnalysisRequest();
            
            // Start analysis through provider
            provider.startAnalysis(request);
            
            Msg.info(this, "Started agentic analysis");
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "Failed to start analysis: " + e.getMessage(),
                "Analysis Error", JOptionPane.ERROR_MESSAGE);
            
            Msg.error(this, "Failed to start analysis: " + e.getMessage(), e);
        }
    }
    
    private AnalysisRequest createAnalysisRequest() {
        AnalysisRequest request = new AnalysisRequest();
        
        // Set sample data (simplified for demo)
        request.setSampleData(createSampleData());
        
        // Analysis type
        String selectedAnalysis = (String) analysisTypeCombo.getSelectedItem();
        String analysisType = selectedAnalysis.split(" ")[0]; // Extract type from display string
        
        // Override with specific engine selection if not auto
        String selectedEngine = engineButtonGroup.getSelection().getActionCommand();
        if (!"auto".equals(selectedEngine)) {
            analysisType = selectedEngine;
        }
        
        request.setAnalysisType(analysisType);
        
        // User goals
        List<String> selectedGoals = userGoalsList.getSelectedValuesList();
        request.setUserGoals(selectedGoals);
        
        // Configuration
        request.setConfidenceThreshold(confidenceSlider.getValue() / 100.0);
        request.setEnableLearning(enableLearningCheckbox.isSelected());
        request.setStandardMode(standardModeCheckbox.isSelected());
        
        return request;
    }
    
    private String createSampleData() {
        if (currentProgram == null) return "";
        
        // Create a simplified binary representation for analysis
        // In a real implementation, this would extract relevant binary data
        return java.util.Base64.getEncoder().encodeToString(
            ("Program: " + currentProgram.getName() + "\\n" +
             "Format: " + currentProgram.getExecutableFormat() + "\\n" +
             "Language: " + currentProgram.getLanguage().getLanguageDescription().getLanguageID())
             .getBytes()
        );
    }
    
    public void setProgramContext(Program program) {
        this.currentProgram = program;
        
        if (program != null) {
            programInfoLabel.setText(String.format(
                "📁 %s (%s, %s)", 
                program.getName(),
                program.getExecutableFormat(),
                program.getLanguage().getLanguageDescription().getLanguageID()
            ));
            programInfoLabel.setForeground(Color.BLUE.darker());
            startAnalysisButton.setEnabled(true);
            
        } else {
            programInfoLabel.setText("No program loaded");
            programInfoLabel.setForeground(Color.GRAY);
            startAnalysisButton.setEnabled(false);
        }
    }
}
