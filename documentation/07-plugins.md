# Plugins

VMDragonSlayer integrates with common reverse engineering tools via optional plugins. This page summarizes supported backends, API integration patterns, and how to build/install each plugin.

Supported backends:

- Ghidra (Java/Kotlin extension)
- IDA Pro (Python plugin)  
- Binary Ninja (Python plugin)

Source locations: `plugins/ghidra`, `plugins/idapro`, `plugins/binaryninja`.

See also: `BUILD_PLUGINS.md` for a full step-by-step build/release guide.

## API Client Usage Examples

All plugins now support API client integration for seamless analysis workflows.

### Basic API Client Setup

```python
from dragonslayer.api.client import APIClient
from dragonslayer.api.transfer import BinaryTransfer

# Initialize API client
api_client = APIClient(
    base_url="http://localhost:8080",
    api_key="your_api_key_here"  # Optional
)

# Initialize binary transfer utility  
binary_transfer = BinaryTransfer(
    chunk_size=2*1024*1024,  # 2MB chunks
    enable_compression=True
)

# Test connection
if api_client.get("/health").get("status") == "ok":
    print("✓ Connected to VMDragonSlayer API")
else:
    print("✗ API connection failed")
```

### Binary Transfer Protocol

The binary transfer protocol optimizes large file handling:

```python
# Prepare binary data for transfer
def prepare_binary_transfer(binary_data: bytes) -> dict:
    """Prepare binary data with compression and chunking"""
    transfer_data = binary_transfer.prepare_transfer(binary_data)
    
    return {
        "binary_data": transfer_data,
        "metadata": {
            "original_size": len(binary_data),
            "compressed": binary_transfer.enable_compression,
            "chunk_size": binary_transfer.chunk_size
        }
    }

# Submit for analysis
def submit_analysis(binary_data: bytes, metadata: dict) -> str:
    """Submit binary for VM detection analysis"""
    payload = prepare_binary_transfer(binary_data)
    payload["metadata"].update(metadata)
    payload["analysis_type"] = "vm_detection"
    
    response = api_client.post("/api/v1/analysis/submit", json=payload)
    return response.get("analysis_id")

# Poll for results
def get_analysis_results(analysis_id: str, timeout: int = 300) -> dict:
    """Poll for analysis results with timeout"""
    import time
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        response = api_client.get(f"/api/v1/analysis/{analysis_id}")
        
        if response.get("status") == "completed":
            return response.get("results")
        elif response.get("status") == "failed":
            raise Exception(f"Analysis failed: {response.get('error')}")
        
        time.sleep(5)  # Wait 5 seconds before next poll
    
    raise TimeoutError("Analysis timeout reached")
```

### Event Handling and Callbacks

Plugins support event-driven analysis workflows:

```python
class AnalysisEventHandler:
    def __init__(self, tool_interface):
        self.tool = tool_interface  # IDA, Binary Ninja, etc.
        
    def on_analysis_started(self, analysis_id: str):
        """Called when analysis begins"""
        self.tool.log_info(f"VM analysis started: {analysis_id}")
        
    def on_analysis_progress(self, analysis_id: str, progress: int):
        """Called during analysis progress updates"""
        self.tool.update_progress_bar(progress)
        
    def on_analysis_completed(self, analysis_id: str, results: dict):
        """Called when analysis completes successfully"""
        self.display_results(results)
        
    def on_analysis_failed(self, analysis_id: str, error: str):
        """Called when analysis fails"""
        self.tool.log_error(f"Analysis failed: {error}")
        
    def display_results(self, results: dict):
        """Display analysis results in tool interface"""
        vm_handlers = results.get("vm_handlers", [])
        
        for handler in vm_handlers:
            address = handler.get("address")
            handler_type = handler.get("type")
            confidence = handler.get("confidence", 0.0)
            
            # Add comment/bookmark at handler location
            self.tool.set_comment(
                address, 
                f"VM Handler ({handler_type}) - Confidence: {confidence:.2f}"
            )
            
            # Add to analysis results view
            self.tool.add_analysis_result({
                "address": address,
                "type": handler_type,
                "confidence": confidence
            })

# Usage in plugin
event_handler = AnalysisEventHandler(tool_interface)
```

## Ghidra plugin

Prerequisites:
- JDK 17+
- Gradle 7.0+
- Environment variable `GHIDRA_INSTALL_DIR` set to Ghidra install folder

Build (PowerShell):

```pwsh
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.4.1_PUBLIC"
cd plugins/ghidra
gradle clean
gradle buildExtension
```

Output: `plugins/ghidra/dist/vmdragonslayer_ghidra_*.zip`.

### Ghidra API Integration

The Ghidra plugin provides seamless integration with the analysis pipeline:

```java
// Ghidra script example (Java)
import ghidra.app.script.GhidraScript;
import vmdragonslayer.GhidraDragonSlayerClient;

public class VMAnalysisScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Initialize client
        GhidraDragonSlayerClient client = new GhidraDragonSlayerClient(
            "http://localhost:8080", 
            null  // API key
        );
        
        // Extract binary data from current program
        byte[] binaryData = client.extractBinaryFromProgram(currentProgram);
        
        // Submit for analysis
        String analysisId = client.submitForAnalysis(binaryData, getMetadata());
        
        // Poll for results and display
        AnalysisResults results = client.pollForResults(analysisId);
        displayResults(results);
    }
    
    private Map<String, Object> getMetadata() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("filename", currentProgram.getName());
        metadata.put("architecture", currentProgram.getLanguage().getProcessor().toString());
        metadata.put("imageBase", currentProgram.getImageBase().toString());
        return metadata;
    }
    
    private void displayResults(AnalysisResults results) {
        for (VMHandler handler : results.getVmHandlers()) {
            Address address = toAddr(handler.getAddress());
            setEOLComment(address, 
                String.format("VM Handler: %s (%.2f)", 
                    handler.getType(), handler.getConfidence()));
        }
    }
}
```

Install:
- Via Ghidra GUI: File > Install Extensions > select the ZIP > Restart
- Manual: copy ZIP to `$env:GHIDRA_INSTALL_DIR/Extensions/Ghidra/`

## IDA Pro plugin

The IDA plugin is pure Python with full API integration.

### IDA Pro API Integration Example

```python
# IDA Pro plugin integration
import idaapi
import idautils
from vmdragonslayer_ida import IDADragonSlayerClient

class VMAnalysisAction(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()
        self.client = IDADragonSlayerClient()
        
    def activate(self, ctx):
        """Triggered when user selects VM analysis"""
        if not self.client.is_connected():
            print(" Not connected to VMDragonSlayer API")
            return 1
            
        # Analyze current binary
        results = self.client.analyze_current_binary()
        if results:
            self.display_results(results)
        else:
            print(" Analysis failed")
            
        return 1
        
    def display_results(self, results):
        """Display results in IDA interface"""
        vm_handlers = results.get("vm_handlers", [])
        
        print(f"🔍 Found {len(vm_handlers)} VM handlers:")
        
        for handler in vm_handlers:
            addr = handler.get("address")
            handler_type = handler.get("type")
            confidence = handler.get("confidence", 0.0)
            
            # Convert address and add comment
            ea = int(addr, 16)
            comment = f"VM Handler: {handler_type} (confidence: {confidence:.2f})"
            idaapi.set_cmt(ea, comment, 0)
            
            print(f"  📍 {addr}: {handler_type} ({confidence:.2f})")

# Register action
action_desc = idaapi.action_desc_t(
    'vmdragonslayer:analyze',
    'Analyze with VMDragonSlayer',
    VMAnalysisAction(),
    'Ctrl+Shift+V',
    'Run VM detection analysis',
    199
)

idaapi.register_action(action_desc)
idaapi.attach_action_to_menu(
    'Edit/Plugins/',
    'vmdragonslayer:analyze',
    idaapi.SETMENU_APP
)
```

Quick verify and package:

```pwsh
cd plugins/idapro
python -m py_compile vmdragonslayer_ida.py
Compress-Archive -Path vmdragonslayer_ida.py, README.md -DestinationPath vmdragonslayer_ida_plugin.zip -Force
```

Install:
- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- Linux: `~/.idapro/plugins/`
- macOS: `~/.idapro/plugins/`

Copy the file (or unzipped plugin) into the plugins directory and restart IDA.

## Binary Ninja plugin

The Binary Ninja plugin provides comprehensive UI integration and background analysis.

### Binary Ninja API Integration Example

```python
# Binary Ninja plugin integration
import binaryninja as bn
from binaryninja import PluginCommand
from vmdragonslayer_bn import BinaryNinjaDragonSlayerClient

def analyze_with_vmdragonslayer(bv):
    """Main analysis command for Binary Ninja"""
    client = BinaryNinjaDragonSlayerClient()
    
    if not client.is_connected():
        bn.log_error(" Not connected to VMDragonSlayer API")
        return
        
    # Start background analysis
    analysis_id = client.analyze_binary_view(bv, background=True)
    
    if analysis_id:
        bn.log_info(f"🚀 VM analysis started: {analysis_id}")
        
        # Show active tasks
        active_tasks = client.get_active_tasks()
        bn.log_info(f"📊 Active analyses: {len(active_tasks)}")
    else:
        bn.log_error(" Failed to start analysis")

def show_vmdragonslayer_dashboard(bv):
    """Show VMDragonSlayer dashboard"""
    from vmdragonslayer_bn import VMDragonSlayerUIManager
    
    ui_manager = VMDragonSlayerUIManager()
    ui_manager.show_dashboard(bv)

def show_analysis_results(bv):
    """Show detailed analysis results"""
    from vmdragonslayer_bn import VMAnalysisResultsViewer
    
    results_viewer = VMAnalysisResultsViewer()
    results_viewer.show_results(bv)

# Register plugin commands
PluginCommand.register(
    "VMDragonSlayer\\Analyze Binary",
    "Run VM detection analysis on current binary",
    analyze_with_vmdragonslayer
)

PluginCommand.register(
    "VMDragonSlayer\\Show Dashboard", 
    "Open VMDragonSlayer analysis dashboard",
    show_vmdragonslayer_dashboard
)

PluginCommand.register(
    "VMDragonSlayer\\View Results",
    "View detailed analysis results",
    show_analysis_results
)
```

### UI Component Customization

Binary Ninja plugins support extensive UI customization:

```python
from binaryninja.dockwidgets import DockHandler
from PySide2.QtWidgets import QWidget, QVBoxLayout, QLabel
from vmdragonslayer_bn import BinaryNinjaDragonSlayerClient

class VMAnalysisDockWidget(QWidget, DockHandler):
    def __init__(self, parent, name, bv):
        QWidget.__init__(self, parent)
        DockHandler.__init__(self, parent, name)
        
        self.bv = bv
        self.client = BinaryNinjaDragonSlayerClient()
        
        # Setup UI
        layout = QVBoxLayout()
        
        # Status display
        self.status_label = QLabel("Ready for analysis")
        layout.addWidget(self.status_label)
        
        # Results area
        self.results_area = self.create_results_area()
        layout.addWidget(self.results_area)
        
        self.setLayout(layout)
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def create_results_area(self):
        """Create results display area"""
        from PySide2.QtWidgets import QTreeWidget, QTreeWidgetItem
        
        tree = QTreeWidget()
        tree.setHeaderLabels(["Address", "Type", "Confidence"])
        return tree
        
    def update_status(self):
        """Update analysis status"""
        if not self.client.is_connected():
            self.status_label.setText(" Disconnected from API")
            return
            
        active_tasks = self.client.get_active_tasks()
        if active_tasks:
            self.status_label.setText(f"🔄 Running {len(active_tasks)} analyses")
        else:
            self.status_label.setText(" Ready for analysis")

# Register dock widget
def create_dock_widget(parent, name, bv):
    return VMAnalysisDockWidget(parent, name, bv)

bn.DockHandler.register_dock_widget_type(
    "VMDragonSlayer Analysis", 
    create_dock_widget
)
```

Quick verify and package:

```pwsh
cd plugins/binaryninja
python -m py_compile vmdragonslayer_bn.py, ui/__init__.py
Compress-Archive -Path * -DestinationPath vmdragonslayer_bn_plugin.zip -Force
```

Install:
- Windows: `%APPDATA%\Binary Ninja\plugins\`
- Linux: `~/.binaryninja/plugins/`
- macOS: `~/Library/Application Support/Binary Ninja/plugins/`

Copy the plugin folder or ZIP contents into the user plugins directory and restart Binary Ninja.

## Advanced Integration Patterns

### Multi-Tool Workflow

Coordinate analysis across multiple tools:

```python
class MultiToolWorkflow:
    def __init__(self):
        self.ida_client = IDADragonSlayerClient() if ida_available else None
        self.bn_client = BinaryNinjaDragonSlayerClient() if bn_available else None
        
    def run_comprehensive_analysis(self, binary_path):
        """Run analysis across available tools"""
        results = {}
        
        # IDA Pro static analysis
        if self.ida_client and self.ida_client.is_connected():
            results["ida_analysis"] = self.run_ida_analysis(binary_path)
            
        # Binary Ninja control flow analysis  
        if self.bn_client and self.bn_client.is_connected():
            results["bn_analysis"] = self.run_bn_analysis(binary_path)
            
        # Combine and correlate results
        combined_results = self.correlate_results(results)
        
        return combined_results
        
    def correlate_results(self, tool_results):
        """Correlate findings from different tools"""
        handlers = []
        confidence_weights = {"ida_analysis": 0.6, "bn_analysis": 0.4}
        
        for tool, results in tool_results.items():
            weight = confidence_weights.get(tool, 0.5)
            
            for handler in results.get("vm_handlers", []):
                handler["weighted_confidence"] = handler["confidence"] * weight
                handler["source_tool"] = tool
                handlers.append(handler)
        
        # Remove duplicates and merge similar findings
        merged_handlers = self.merge_duplicate_handlers(handlers)
        
        return {"vm_handlers": merged_handlers}
```

### Performance Optimization

Optimize API calls for large-scale analysis:

```python
class OptimizedAnalysisClient:
    def __init__(self, max_concurrent=5):
        self.max_concurrent = max_concurrent
        self.semaphore = threading.Semaphore(max_concurrent)
        
    def analyze_batch(self, binary_paths, progress_callback=None):
        """Analyze multiple binaries concurrently"""
        import concurrent.futures
        
        results = {}
        completed = 0
        total = len(binary_paths)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            # Submit all analysis tasks
            future_to_path = {
                executor.submit(self.analyze_single, path): path 
                for path in binary_paths
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                
                try:
                    result = future.result()
                    results[path] = result
                except Exception as e:
                    results[path] = {"error": str(e)}
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
        
        return results
        
    def analyze_single(self, binary_path):
        """Analyze single binary with rate limiting"""
        with self.semaphore:
            # Implementation here
            pass
```

## Tips and troubleshooting

### Common Issues

1. **API Connection Problems**
   ```python
   # Test API connectivity
   def test_api_connection():
       try:
           client = APIClient("http://localhost:8080")
           response = client.get("/health", timeout=5)
           
           if response.get("status") == "ok":
               print(" API connection successful")
               return True
           else:
               print(f" API returned unexpected status: {response}")
               return False
               
       except Exception as e:
           print(f" API connection failed: {e}")
           return False
   ```

2. **Large Binary Handling**
   ```python
   # Configure for large binaries
   binary_transfer = BinaryTransfer(
       chunk_size=10*1024*1024,  # 10MB chunks
       enable_compression=True,
       max_file_size=1024*1024*1024  # 1GB limit
   )
   ```

3. **Memory Management**
   ```python
   # Process large datasets efficiently
   def process_large_dataset(file_paths, batch_size=10):
       for i in range(0, len(file_paths), batch_size):
           batch = file_paths[i:i+batch_size]
           
           # Process batch
           results = analyze_batch(batch)
           
           # Save results immediately
           save_results(results)
           
           # Clear memory
           del results
           gc.collect()
   ```

### Plugin Development Best Practices

1. **Error Handling**: Always wrap API calls in try-catch blocks
2. **Progress Feedback**: Provide progress updates for long-running operations
3. **Configuration**: Allow users to configure API endpoint and settings
4. **Logging**: Use appropriate logging levels (info, warning, error)
5. **Performance**: Cache results when appropriate to avoid redundant API calls

- Match tool versions (e.g., Ghidra 11.x) with your environment; rebuild after upgrades.
- For Ghidra, verify `java -version` (17+) and `gradle --version` (7.0+).
- If packaging for distribution, include a short README and version in filenames.
- Keep the core Python package and plugin versions aligned in your release process.
- Test API connectivity before performing analysis operations.
- Use background processing for long-running analyses to avoid blocking the UI.
