# dragonslayer.api.client

Path: `dragonslayer/api/client.py`

## Purpose
HTTP client for the VMDragonSlayer REST API with sync/async methods, optional API key auth, and convenient helpers for analyzing files or raw bytes.

## Public API

- Class `APIClient(base_url: str = "http://localhost:8000", api_key: str | None = None, timeout: float = 300.0)`
  - `analyze_file(file_path, analysis_type="hybrid", **options) -> dict`
    - Reads a file, base64-encodes its content into JSON (`sample_data`), and POSTs to `/analyze`.
    - Options are passed through under an `options` object; filename is included in `metadata`.
  - `analyze_binary_data(binary_data: bytes, analysis_type="hybrid", metadata=None, **options) -> dict`
    - Like `analyze_file` but accepts in-memory bytes and optional `metadata`.
  - `upload_and_analyze(file_path, analysis_type="hybrid") -> dict`
    - Uses multipart form upload to `/upload-analyze` with field `file` and `analysis_type`.
  - `get_status() -> dict`, `get_health() -> dict`, `get_metrics() -> dict`, `get_analysis_types() -> dict`
  - Async variants (require `httpx`): `analyze_file_async(...)`, `analyze_binary_data_async(...)`
  - Lifecycle: `close()`, `aclose()`; supports sync and async context managers
- Factory: `create_client(base_url: str = ..., api_key: str | None = None, timeout: float = 300.0) -> APIClient`

Transport behavior:

- Prefers `httpx` and falls back to `requests` for sync methods. Async methods require `httpx` (else `NotImplementedError`).
- Default headers include `Content-Type: application/json`; when `api_key` is provided, `Authorization: Bearer <key>` is added.
- Default timeout is 300s.

## Request/Response shapes

- `/analyze` request (client-generated):
  - JSON: `{ sample_data: <base64>, analysis_type: <str>, options: { ... }, metadata: { ... } }`
- `/upload-analyze` request:
  - multipart/form-data with `file=<octet-stream>`, `analysis_type=<str>`.
- Responses:
  - Dicts conforming to the Analysis Result Schema; see [Data & Models](../../../06-data-and-models.md).

## Errors and exceptions

- File handling: `FileNotFoundError` if the provided path does not exist.
- Transport: `NetworkError` wraps GET/POST failures with `error_code` like `GET_REQUEST_FAILED`, `POST_REQUEST_FAILED`, `ASYNC_*` variants.
- Upload: `APIError` with `error_code="UPLOAD_ANALYZE_FAILED"` if multipart upload fails.
- Environment: `ImportError` at initialization if neither `httpx` nor `requests` is installed.
- Async: `NotImplementedError` if async methods are used without `httpx`.

## Examples

Basic usage (sync):

```python
from dragonslayer.api.client import create_client

with create_client("http://localhost:8000", api_key=None, timeout=120.0) as client:
    print(client.get_analysis_types())
    result = client.analyze_file(r"samples\foo.bin", analysis_type="vm_discovery", depth=2)
    print(result["status"], result.get("results", {}))
```

Analyze raw bytes (sync):

```python
from dragonslayer.api.client import APIClient

data = b"\x00\x01\x02..."
client = APIClient(base_url="http://localhost:8000")
try:
    out = client.analyze_binary_data(data, analysis_type="pattern_analysis", metadata={"label": "test"}, top_k=5)
finally:
    client.close()
```

Async usage (requires httpx):

```python
import asyncio
from dragonslayer.api.client import APIClient

async def main():
    async with APIClient(base_url="http://localhost:8000") as client:
        result = await client.analyze_file_async(r"samples\foo.bin", analysis_type="hybrid")
        print(result["status"]) 

asyncio.run(main())
```

Error handling:

```python
from dragonslayer.api.client import create_client
from dragonslayer.core.exceptions import NetworkError, APIError

client = create_client()
try:
    client.get_health()
    client.upload_and_analyze("missing.bin")
except FileNotFoundError:
    print("file not found")
except NetworkError as e:
    print("network error:", e.error_code)
except APIError as e:
    print("api error:", e.error_code)
finally:
    client.close()
```

## Endpoints used

- `GET /health` — liveness
- `GET /status` — server status
- `GET /metrics` — performance metrics
- `GET /analysis-types` — supported analysis types
- `POST /analyze` — base64-JSON body
- `POST /upload-analyze` — multipart form upload

## Related

- Server: `dragonslayer/api/server.py`
- Result schema: see [Data & Models](../../../06-data-and-models.md)
- Back to [APIs](../../../04-apis.md)
