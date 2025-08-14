# dragonslayer.api

Purpose: REST API server and Python client for VMDragonSlayer.

## Public Modules
- `server.py` — FastAPI server exposing `/analyze`, `/upload-analyze`, `/status`, `/metrics`, `/analysis-types`, and `/ws`
- `client.py` — Sync/async HTTP client based on `httpx` or `requests`

## Quick Usage
```python
from dragonslayer.api.client import create_client

client = create_client("http://localhost:8000")
print(client.get_health())
result = client.analyze_file("sample.exe", analysis_type="hybrid")
print(result["success"]) 
```

## Related
- Source: `dragonslayer/api/`
- See [APIs](../../../04-apis.md)
- Back to [Modules](../../../03-modules.md)
