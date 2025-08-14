# VMDragonSlayer Data Directory

This directory contains all data-related configurations, models, patterns, and samples for the VMDragonSlayer system.

## Directory Structure

```
data/
├── patterns/               # Pattern databases for VM detection
│   ├── pattern_database.json          # Main pattern database
│   └── pattern_database_dev.json      # Development patterns
├── models/                 # Machine learning models
│   ├── pretrained/         # Pre-trained models
│   ├── model_registry.db   # Model metadata database
│   └── model_registry_config.toml     # Model registry configuration
├── samples/                # Sample files and registry
│   └── sample_registry.json           # Sample metadata
├── training/               # Training data and configurations
│   ├── training_config.json           # ML training configuration
│   ├── bytecode_classification/       # Training data for bytecode classification
│   ├── vm_detection/                  # Training data for VM detection
│   └── handler_classification/        # Training data for handler classification
├── schemas/                # JSON schemas for validation
│   ├── analysis_result_schema.json    # Analysis result validation
│   └── pattern_database_schema.json   # Pattern database validation
├── taint_config.properties            # Taint tracking configuration
├── database_config.json               # Database schemas and configuration
└── .env.template                      # Environment variables template
```

## Configuration Files

### Pattern Databases

- **pattern_database.json**: Comprehensive database of VM bytecode patterns, dispatcher patterns, anti-analysis patterns, and VM architecture signatures
- **pattern_database_dev.json**: Simplified patterns for development and testing

### Model Management

- **model_registry_config.toml**: Configuration for the model registry database
- **training_config.json**: Comprehensive ML training configuration including datasets, feature extractors, model configurations, and evaluation metrics

### Taint Tracking

- **taint_config.properties**: Comprehensive configuration for dynamic taint tracking including:
  - Tool paths for various analysis engines
  - Taint propagation settings
  - VM detection heuristics
  - Anti-analysis mitigation
  - Symbolic execution integration
  - ML integration settings
  - Output and reporting configuration

### Database Configuration

- **database_config.json**: Database schemas for PostgreSQL, Elasticsearch mappings, and migration scripts
- **sample_registry.json**: Registry of test samples with metadata and ground truth information

## Environment Setup

1. Copy `.env.template` to `.env` and customize for your environment
2. Set up required databases (PostgreSQL, Redis, etc.)
3. Configure analysis tool paths
4. Set up security credentials

## Pattern Database Format

The pattern database follows this structure:

```json
{
  "version": "1.0.0",
  "categories": {
    "vm_bytecodes": {
      "patterns": [
        {
          "id": "unique_pattern_id",
          "name": "Human readable name",
          "type": "pattern_type",
          "confidence": 0.95,
          "handler_patterns": ["regex_patterns"],
          "description": "Pattern description"
        }
      ]
    }
  }
}
```

## Model Registry

Models are managed through a SQLite database with the following features:

- Version tracking and history
- Performance metrics storage
- Training history
- Automated model lifecycle management

## Training Data Organization

Training data is organized by task:

- **bytecode_classification/**: Features and labels for VM bytecode pattern classification
- **vm_detection/**: Binary classification data for VM presence detection  
- **handler_classification/**: Multi-class classification for VM handler types

## Security Considerations

- All sensitive configuration should use environment variables
- Database credentials should be properly secured
- API keys and secrets should be rotated regularly
- File uploads should be validated and sandboxed

## Usage Examples

### Loading Pattern Database

```python
from vmdragonslayer import get_config
config = get_config()
pattern_db_path = config.ml.pattern_database_path
```

### Environment Configuration

```python
import os
from vmdragonslayer import configure

# Override configuration via environment
configure(
    api={'host': os.getenv('VMDS_API_HOST', '127.0.0.1')},
    ml={'device_preference': os.getenv('VMDS_ML_DEVICE', 'auto')}
)
```

### Model Management

```python
from vmdragonslayer.ml import ModelTrainer, TrainingConfig

trainer = ModelTrainer()
config = TrainingConfig.from_file('data/training/training_config.json')
model = trainer.train_classifier(config)
```

## Maintenance

- Pattern databases should be updated regularly with new VM patterns
- Model performance should be monitored and retrained as needed
- Training data should be expanded with new samples
- Configuration should be reviewed for security best practices

## Schema Validation

All JSON files should be validated against their corresponding schemas in the `schemas/` directory to ensure data integrity and compatibility.
