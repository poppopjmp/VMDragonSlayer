# VMDragonSlayer IDA Pro Plugin

A sophisticated IDA Pro plugin for analyzing VM-based protectors and automated handler detection.

## Overview

The VMDragonSlayer IDA Pro plugin provides comprehensive VM protection analysis capabilities including:

- **VM Handler Detection**: Automated identification of VM bytecode handlers
- **Dynamic Taint Tracking**: Integration with Pin-based DTT tools
- **Symbolic Execution**: angr-based symbolic execution for handler analysis
- **Pattern Matching**: ML-enhanced pattern recognition for VM structures
- **Interactive Analysis**: GUI components for manual analysis workflow

## Installation

### Prerequisites

- IDA Pro 7.0 or higher
- Python 3.8+ (IDA Python environment)
- Required Python packages (see requirements.txt in root)

### Plugin Installation

1. **Copy Plugin File**
   ```bash
   cp vmdragonslayer_ida.py $IDA_DIR/plugins/
   ```

2. **Install Dependencies**
   ```bash
   # Navigate to project root
   cd ../../
   pip install -r requirements.txt
   ```

3. **Configure Plugin**
   - Launch IDA Pro
   - Go to Edit → Plugins → VMDragonSlayer
   - Configure analysis parameters in the settings dialog

## Usage

### Quick Start

1. **Load Target Binary**
   - Open a VM-protected binary in IDA Pro
   - Wait for initial auto-analysis to complete

2. **Launch VMDragonSlayer**
   - Go to Edit → Plugins → VMDragonSlayer
   - Or use Ctrl+Alt+V shortcut

3. **Configure Analysis**
   - Set VM type (VMProtect, Themida, etc.)
   - Configure analysis depth and timeout
   - Enable desired analysis modules

4. **Run Analysis**
   - Click "Start Analysis" button
   - Monitor progress in the output window
   - Review results in the VMDragonSlayer panel

### Analysis Workflow

#### 1. VM Structure Discovery
```
Analysis → Discover VM Structure
```
- Identifies VM entry points and dispatch tables
- Maps VM register allocation
- Detects handler table structure

#### 2. Handler Classification
```
Analysis → Classify Handlers
```
- Uses ML models to classify handler types
- Provides confidence scores for predictions
- Generates semantic annotations

#### 3. Dynamic Analysis Integration
```
Tools → Dynamic Taint Tracking
Tools → Symbolic Execution
```
- Integrates with external DTT and SE tools
- Correlates static and dynamic analysis results
- Provides unified analysis reporting

### Advanced Features

#### Custom Pattern Database
- Load custom VM pattern definitions
- Export discovered patterns for reuse
- Community pattern sharing capabilities

#### Scripting Interface
```python
import vmdragonslayer

# Programmatic API usage
vmd = vmdragonslayer.VMDragonSlayer()
vmd.analyze_function(ea=here())
results = vmd.get_analysis_results()
```

#### Export/Import
- Export analysis results to JSON
- Import results from other tools
- Integration with Ghidra and Binary Ninja plugins

## Configuration

### Settings File
Located at: `%APPDATA%/VMDragonSlayer/ida_config.json`

### Key Settings

```json
{
  "analysis": {
    "vm_types": ["vmprotect", "themida", "enigma"],
    "max_analysis_time": 300,
    "enable_ml_classification": true,
    "confidence_threshold": 0.7
  },
  "integration": {
    "pin_tool_path": "../../lib/dtt_tool/pin/",
    "angr_timeout": 60,
    "enable_dynamic_analysis": true
  },
  "ui": {
    "auto_highlight": true,
    "color_scheme": "default",
    "show_confidence_scores": true
  }
}
```

## Output and Results

### Analysis Reports
- **Handler Classification**: Detailed breakdown of identified handlers
- **VM Structure Map**: Visual representation of VM architecture
- **Performance Metrics**: Analysis timing and coverage statistics
- **Confidence Scores**: ML prediction reliability indicators

### Export Formats
- **JSON**: Machine-readable analysis results
- **IDB Comments**: Persistent annotations in IDA database
- **CSV**: Tabular data for further analysis
- **HTML**: Interactive analysis reports

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**
   - Check IDA Python version compatibility
   - Verify plugin file permissions
   - Check IDA Pro plugin directory path

2. **Analysis Failures**
   - Increase analysis timeout in settings
   - Check target binary architecture support
   - Verify required dependencies are installed

3. **Performance Issues**
   - Reduce analysis scope in configuration
   - Disable ML classification for faster analysis
   - Use incremental analysis mode

### Debug Mode
Enable debug logging by setting:
```python
vmdragonslayer.set_debug_mode(True)
```

## Development

### Building from Source
See main project README for build instructions.

### Contributing
- Follow IDA Pro plugin development guidelines
- Maintain compatibility with IDA Pro 7.0+
- Add unit tests for new features
- Update documentation for API changes

### API Documentation
The plugin provides a comprehensive API for:
- Custom handler detection algorithms
- Integration with external analysis tools
- UI component extension
- Results processing and export

## Support

- **Issue Tracker**: GitHub repository issues
- **Documentation**: Full API docs in /docs directory
- **Community**: Join our Discord/Matrix channel
- **Commercial Support**: Available through project maintainers

## License

MIT License - see LICENSE file in project root.

## Acknowledgments

- IDA Pro SDK and community
- angr symbolic execution framework
- Intel Pin dynamic analysis platform
- ML model contributors and researchers
