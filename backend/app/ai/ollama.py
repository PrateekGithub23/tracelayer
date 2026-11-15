"""
Minimal Ollama HTTP client (https://github.com/ollama/ollama/blob/main/docs/api.md).

Ollama is free, MIT-licensed and runs models locally on Apple Silicon using
Metal. No API key, account or network egress is needed. We use:
  GET  /api/tags  - is the server up, and is the configured model pulled?
  POST /api/chat  - non-streaming chat with a JSON schema in `format`
                    (structured outputs; supported since Ollama 0.5).
"""

import time
from typing import Any

import httpx


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout_s: float = 180.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s

    def status(self) -> dict[str, Any]:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=2.0)
            r.raise_for_status()
            listing = r.json().get("models", [])
            version = httpx.get(f"{self.base_url}/api/version", timeout=2.0).json().get("version")
        except (httpx.HTTPError, ValueError) as exc:
            return {"reachable": False, "model": self.model, "model_available": False, "models": [], "version": None,
                    "digest": None, "error": f"{type(exc).__name__}: {exc}"[:300]}  # fmt: skip
        models = [m.get("name", "") for m in listing]
        match = next(
            (m for m in listing if m.get("name") == self.model or m.get("name", "").split(":")[0] == self.model), None
        )
        details = (match or {}).get("details") or {}
        return {"reachable": True, "model": self.model, "model_available": match is not None, "models": models,
                "version": version, "digest": (match or {}).get("digest"), "size_bytes": (match or {}).get("size"),
                "parameter_size": details.get("parameter_size"), "quantization": details.get("quantization_level"),
                "error": None}  # fmt: skip

    def chat_json(self, system: str, user: str, schema: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        body = {
            "model": self.model,
            "stream": False,
            "format": schema,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            # Low temperature: we want faithful extraction, not creativity. 8k context fits the pack.
            "options": {"temperature": 0.1, "num_ctx": 8192},
        }
        t0 = time.perf_counter()
        try:
            r = httpx.post(f"{self.base_url}/api/chat", json=body, timeout=self.timeout_s)
            r.raise_for_status()
            data = r.json()
        except httpx.HTTPStatusError as exc:
            raise OllamaError(f"Ollama returned HTTP {exc.response.status_code}: {exc.response.text[:200]}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise OllamaError(f"Ollama request failed: {type(exc).__name__}: {exc}") from exc
        content = (data.get("message") or {}).get("content", "")
        meta = {
            "wall_ms": round((time.perf_counter() - t0) * 1000, 1),
            "prompt_tokens": data.get("prompt_eval_count"),
            "output_tokens": data.get("eval_count"),
            "model_reported_ms": round((data.get("total_duration") or 0) / 1e6, 1),
        }
        if not content:
            raise OllamaError("Ollama returned an empty response")
        return content, meta
