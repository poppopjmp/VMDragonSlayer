# dragonslayer.api.server

Path: `dragonslayer/api/server.py`

## Purpose
FastAPI-based REST server exposing analysis functionality with auth, rate limiting, and WebSockets.

## Endpoints
- `GET /` — service info
- `GET /health` — health check
- `GET /status` — status summary (active/total analyses, uptime)
- `GET /metrics` — orchestrator + API metrics
- `GET /analysis-types` — supported analysis types and workflow strategies
- `POST /analyze` — analyze base64-encoded binary data
- `POST /upload-analyze` — multipart upload + analyze
- `WS /ws` — real-time status and analysis-complete events

## Models
- Request: `AnalysisRequest { sample_data: base64, analysis_type: str, options: dict, metadata: dict }`
- Response: `AnalysisResponse { request_id, success, results, errors, warnings, execution_time, metadata }`

## Example
```python
# Run server (programmatic):
from dragonslayer.api.server import run_server
run_server(host="127.0.0.1", port=8000)
```

## Related
- Client: `dragonslayer/api/client.py`
- Facade: `dragonslayer/core/api.py`
- Back to [APIs](../../../04-apis.md)
