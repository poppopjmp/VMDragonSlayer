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

Key errors: `APIError`, `NetworkError`. If neither `httpx` nor `requests` is installed, initializing the client raises `ImportError`.

## Server Endpoint reference (FastAPI)

Implementation: `dragonslayer/api/server.py`. Internals registry: `dragonslayer/api/endpoints.py`.

- GET `/` — Basic service info (service, version, status, docs URL)
- GET `/health` — Liveness and uptime
- GET `/status` — Status counts and uptime (response: `StatusResponse`)
- GET `/analysis-types` — Supported `analysis_types` and `workflow_strategies`
- GET `/metrics` — Orchestrator and API metrics (includes websocket connection count)
- POST `/analyze` — Analyze base64-encoded binary
	- Request JSON:
		```json
		{
			"sample_data": "UEsDBAoAAAAAAA==",
			"analysis_type": "hybrid",
			"options": {"timeout": 300},
			"metadata": {"filename": "sample.exe"}
		}
		```
	- Response JSON: conforms to Analysis Result response model:
		```json
		{
			"request_id": "uuid",
			"success": true,
			"results": {},
			"errors": [],
			"warnings": [],
			"execution_time": 1.23,
			"metadata": {}
		}
		```
- POST `/upload-analyze` — Multipart upload + analysis
	- Form fields: `file` (application/octet-stream), `analysis_type` (default `hybrid`)
	- On success, returns the same response model as `/analyze`
- WS `/ws` — WebSocket for periodic status updates and `analysis_complete` broadcasts

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
