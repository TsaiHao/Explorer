"""Schema fetching and caching with daily refresh."""

import json
import time

import httpx

SCHEMA_URL = "http://explorer.zaijun.org/config-schema.json"
REFRESH_INTERVAL = 86400  # 24 hours


class SchemaCache:
    def __init__(self) -> None:
        self._schema: dict | None = None
        self._session_schema: dict | None = None
        self._fetched_at: float = 0.0

    @property
    def is_stale(self) -> bool:
        return (time.monotonic() - self._fetched_at) > REFRESH_INTERVAL

    async def fetch(self, client: httpx.AsyncClient) -> dict:
        """Fetch schema from remote, updating cache. Returns full schema."""
        try:
            resp = await client.get(SCHEMA_URL, timeout=10.0)
            resp.raise_for_status()
            self._schema = resp.json()
            self._session_schema = (
                self._schema.get("properties", {})
                .get("sessions", {})
                .get("items")
            )
            self._fetched_at = time.monotonic()
            return self._schema
        except Exception:
            if self._schema is not None:
                return self._schema
            raise

    async def get_schema(self, client: httpx.AsyncClient) -> dict:
        """Return cached schema, refreshing if stale."""
        if self._schema is None or self.is_stale:
            return await self.fetch(client)
        return self._schema

    async def get_session_schema(self, client: httpx.AsyncClient) -> dict | None:
        """Return the single-session sub-schema for validation."""
        await self.get_schema(client)
        return self._session_schema

    def get_schema_text(self) -> str:
        """Return cached schema as formatted JSON string."""
        if self._schema is None:
            return json.dumps({"error": "Schema not yet fetched"})
        return json.dumps(self._schema, indent=2)
