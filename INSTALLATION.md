# VMDragonSlayer Installation Guide

## Quick Start

### Basic Installation (CPU-only)
```bash
# Install from PyPI (recommended)
pip install vmdragonslayer

# Or install from source
git clone https://github.com/poppopjmp/VMDragonSlayer.git
cd VMDragonSlayer
pip install -e .
```

### Full Installation with GPU Support
```bash
# Install VMDragonSlayer with ML dependencies
pip install vmdragonslayer[ml]

# Install PyTorch with CUDA support (RTX 30xx/40xx series)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Or for older GPUs (GTX 10xx/RTX 20xx)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

## Manual Dependency Installation

If automatic installation fails, install dependencies manually:

### Core Dependencies
```bash
# Essential symbolic execution dependency (CRITICAL)
pip install z3-solver

# Machine learning
pip install scikit-learn torch torchvision torchaudio

# Data processing
pip install numpy pandas pyyaml

# System utilities
pip install psutil cryptography

# Web API (optional)
pip install fastapi uvicorn websockets
```

### Complete Manual Installation
```bash
# Install all dependencies from requirements.txt
pip install -r requirements.txt

# Then install VMDragonSlayer
pip install -e .
```

## Platform-Specific Instructions

### Windows
```bash
# Use PowerShell or Command Prompt
python -m pip install --upgrade pip
pip install vmdragonslayer[ml]

# If you encounter permission issues:
pip install --user vmdragonslayer[ml]
```

### Linux (Ubuntu/Debian)
```bash
# Update system packages
sudo apt update
sudo apt install python3-pip python3-dev build-essential

# Install VMDragonSlayer
pip3 install vmdragonslayer[ml]
```

### macOS
```bash
# Install via Homebrew (if needed)
brew install python3

# Install VMDragonSlayer
pip3 install vmdragonslayer[ml]
```

## NVIDIA CUDA Setup

### Automatic CUDA (Recommended)
PyTorch installation includes CUDA runtime - no separate CUDA installation needed for most users.

### Manual CUDA Installation (Advanced)
1. Download NVIDIA drivers from [nvidia.com](https://www.nvidia.com/drivers/)
2. Install CUDA Toolkit from [developer.nvidia.com](https://developer.nvidia.com/cuda-toolkit)
3. Verify installation: `nvidia-smi`

### CUDA Version Compatibility
- **RTX 40xx series**: CUDA 12.1+ required
- **RTX 30xx series**: CUDA 11.8 or 12.1+
- **GTX 16xx/RTX 20xx**: CUDA 11.8
- **GTX 10xx**: CUDA 11.8 (minimum)

## Virtual Environment Setup (Recommended)

### Using venv
```bash
# Create virtual environment
python -m venv vmds_env

# Activate (Linux/macOS)
source vmds_env/bin/activate

# Activate (Windows)
vmds_env\Scripts\activate

# Install VMDragonSlayer
pip install vmdragonslayer[ml]
```

### Using conda
```bash
# Create conda environment
conda create -n vmds python=3.10
conda activate vmds

# Install dependencies
conda install pytorch torchvision torchaudio pytorch-cuda=12.1 -c pytorch -c nvidia
pip install vmdragonslayer
```

## Troubleshooting

### Common Issues

#### ModuleNotFoundError: z3
```bash
# Solution
pip install z3-solver
```

#### CUDA not available
```bash
# Check GPU detection
python -c "import torch; print(torch.cuda.is_available())"

# If False, use CPU-only mode or reinstall PyTorch with CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
```

#### Permission errors (Windows)
```bash
# Use --user flag
pip install --user vmdragonslayer[ml]
```

#### Build tools missing (Windows)
- Install Visual Studio Build Tools
- Or install Visual Studio Community with C++ development tools

#### ImportError: No module named 'dragonslayer'
```bash
# Ensure installation completed successfully
pip install -e . --force-reinstall
```

### Memory Issues
```bash
# For low-memory systems, install without ML dependencies
pip install vmdragonslayer

# Then install lightweight ML alternatives
pip install scikit-learn  # Skip PyTorch if needed
```

### Virtual Machine Limitations
- GPU acceleration requires direct hardware access
- VirtualBox/VMware may not support CUDA
- Use CPU-only mode in VM environments:
  ```python
  from dragonslayer.core.orchestrator import Orchestrator
  # GPU detection is automatic - framework will fallback to CPU
  ```

## Verification

### Test Installation
```python
# Test basic functionality
from dragonslayer.core.orchestrator import Orchestrator, AnalysisType

print("VMDragonSlayer imported successfully")

# Test GPU availability (optional)
try:
    import torch
    print(f"PyTorch available: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
except ImportError:
    print("PyTorch not installed - CPU-only mode")

# Test symbolic execution
try:
    import z3
    print(f"Z3 solver available: {z3.get_version_string()}")
except ImportError:
    print("ERROR: z3-solver not installed - symbolic execution unavailable")
```

### Quick Test Analysis
```python
from dragonslayer.core.orchestrator import Orchestrator, AnalysisType

orchestrator = Orchestrator()
print("Orchestrator initialized successfully")

# Test with a simple binary (replace with actual path)
# result = orchestrator.analyze_binary("path/to/test.exe", analysis_type=AnalysisType.VM_DISCOVERY)
```

## Support

### Getting Help
- **GitHub Issues**: [Report bugs and get support](https://github.com/poppopjmp/VMDragonSlayer/issues)
- **Documentation**: Check the `documentation/` folder
- **Examples**: See `examples/` folder for working code samples

### Before Reporting Issues
1. Verify Python version: `python --version` (3.8+ required)
2. Check installation: Run verification script above
3. Include error messages and system information
4. Test with virtual environment to isolate dependency conflicts
