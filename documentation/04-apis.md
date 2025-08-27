# APIs

High-level overview of the Python client and the FastAPI server endpoints, with request/response shapes and examples. For per-class/module details see the module docs.

## Python Client quickstart

See `documentation/modules/dragonslayer/api/client.md` for full details and examples.

```python
from dragonslayer.api.client import create_client

with create_client("http://localhost:8000") as client:
		print(client.get_health())
		result = client.analyze_file("sample.exe", analysis_type="hybrid")
		print(result.get("success"))
```

### Enhanced Client Features

```python
from dragonslayer.api.client import APIClient
from dragonslayer.api.transfer import BinaryTransfer

# Advanced client with binary transfer support
client = APIClient(base_url="http://localhost:8000")
transfer = BinaryTransfer(enable_compression=True)

# Optimized binary analysis with chunked transfer
result = client.analyze_binary_optimized("large_sample.exe")
```

Key errors: `APIError`, `NetworkError`. If neither `httpx` nor `requests` is installed, initializing the client raises `ImportError`.

## Server Endpoint reference (FastAPI)

Implementation: `dragonslayer/api/server.py`. Internals registry: `dragonslayer/api/endpoints.py`.

### Core Endpoints

- **GET `/`** — Basic service info (service, version, status, docs URL)
- **GET `/health`** — Liveness and uptime checks
- **GET `/status`** — Detailed status counts and uptime (response: `StatusResponse`)
- **GET `/analysis-types`** — Supported `analysis_types` and `workflow_strategies`
- **GET `/metrics`** — Orchestrator and API metrics (includes websocket connection count)

### Analysis Endpoints

- **POST `/analyze`** — Analyze base64-encoded binary
	- Request JSON:
		```json
		{
			"sample_data": "UEsDBAoAAAAAAA==",
			"analysis_type": "hybrid",
			"options": {
				"timeout": 300,
				"enable_ml": true,
				"enable_symbolic": true,
				"enable_realtime": false
			},
			"metadata": {"filename": "sample.exe"}
		}
		```
	- Response JSON: conforms to Analysis Result response model:
		```json
		{
			"request_id": "uuid",
			"success": true,
			"results": {
				"vm_patterns": [],
				"handlers": [],
				"confidence": 0.85,
				"analysis_engines": ["pattern", "ml", "symbolic"],
				"extended_features": {}
			},
			"errors": [],
			"warnings": [],
			"execution_time": 1.23,
			"metadata": {}
		}
		```

- **POST `/upload-analyze`** — Multipart upload + analysis
	- Form fields: `file` (application/octet-stream), `analysis_type` (default `hybrid`)
	- Optional parameters: `enable_ml`, `enable_symbolic`, `enable_realtime`
	- On success, returns the same response model as `/analyze`

### Real-time Communication

- **WS `/ws`** — WebSocket for:
	- Periodic status updates
	- Real-time analysis progress
	- `analysis_complete` broadcasts
	- Live ML model updates
	- System health monitoring

### Analysis Types

The system supports multiple analysis strategies:

- `"hybrid"` — Combined pattern matching, ML, and symbolic analysis
- `"vm_discovery"` — VM structure detection and mapping  
- `"pattern_analysis"` — Extended pattern recognition with metamorphic support
- `"taint_tracking"` — Dynamic taint analysis
- `"symbolic_execution"` — Path exploration and constraint solving
- `"ml_detection"` — Machine learning ensemble methods
- `"realtime"` — Streaming analysis with live monitoring
- `"unified"` — All-engines orchestrated analysis

### Response Enhancements

Extended result schema includes:

```json
{
	"results": {
		"vm_patterns": ["vmprotect_3x", "themida"],
		"ml_confidence": 0.92,
		"symbolic_paths": 15,
		"realtime_events": [],
		"multi_arch_support": ["x86", "x64", "arm"],
		"security_features": {
			"anti_debugging": true,
			"packing_detected": true,
			"obfuscation_level": "high"
		}
	}
}
```

Common errors:

- 400 — Validation or domain errors (e.g., invalid base64). Returns a structured error via `create_error_response`.
- 413 — File too large for `/upload-analyze` (based on `max_file_size_mb` config)
- 429 — Rate limit exceeded (simple sliding-window/IP-based)
- 500 — Internal server error

Result schema: The `results` object follows the Analysis Result Schema; see [Data & Models](./06-data-and-models.md).

OpenAPI: a minimal spec is available at `documentation/assets/openapi.json` for import into Swagger/Postman.

## Examples (curl)

Analyze with JSON (base64 payload):

```pwsh
curl -X POST "http://localhost:8000/analyze" `
	-H "Content-Type: application/json" `
	-d '{
		"sample_data": "UEsDBAoAAAAAAA==",
		"analysis_type": "vm_discovery",
		"options": {},
		"metadata": {"filename": "sample.bin"}
	}'
```

Upload a file (multipart):

```pwsh
curl -X POST "http://localhost:8000/upload-analyze" `
	-F "analysis_type=hybrid" `
	-F "file=@sample.exe;type=application/octet-stream"
```

If auth is enabled, add `-H "Authorization: Bearer <token>"`.

## Running the server

Programmatic:

```python
from dragonslayer.api.server import run_server

run_server(host="127.0.0.1", port=8000, workers=1)
```

Module entry (PowerShell):

```pwsh
python -m dragonslayer.api.server
```

Requirements: install the web extras (FastAPI, Uvicorn). For local installs, use your preferred environment and include the `web` extra.

## Core API facade

The convenience facade `dragonslayer/core/api.py` wraps the orchestrator. See the module doc for examples of sync/async analysis.

Back to [Modules](./03-modules.md).
