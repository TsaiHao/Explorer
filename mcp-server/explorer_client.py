"""Async HTTP client wrapper for the Explorer daemon API."""

from typing import Any

import httpx

_TIMEOUT_HEALTH = 5.0
_TIMEOUT_INFO = 10.0
_TIMEOUT_SESSION = 30.0


class ExplorerClient:
    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client

    async def _get(self, path: str, timeout: float) -> dict[str, Any]:
        resp = await self._client.get(
            f"{self.base_url}{path}", timeout=timeout
        )
        resp.raise_for_status()
        return resp.json()

    async def _post_session(
        self, path: str, action: str, data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"action": action}
        if data is not None:
            body["data"] = data
        else:
            body["data"] = {}
        resp = await self._client.post(
            f"{self.base_url}{path}",
            json=body,
            timeout=_TIMEOUT_SESSION,
        )
        resp.raise_for_status()
        return resp.json()

    async def health(self) -> dict[str, Any]:
        return await self._get("/health", _TIMEOUT_HEALTH)

    async def health_detailed(self) -> dict[str, Any]:
        return await self._get("/api/v1/health", _TIMEOUT_HEALTH)

    async def metrics(self) -> dict[str, Any]:
        return await self._get("/api/v1/metrics", _TIMEOUT_INFO)

    async def stats(self) -> dict[str, Any]:
        return await self._get("/api/v1/daemon/stats", _TIMEOUT_INFO)

    async def start_session(self, config: dict[str, Any]) -> dict[str, Any]:
        return await self._post_session(
            "/api/v1/session/start", "start", config,
        )

    async def stop_session(self, session_id: str) -> dict[str, Any]:
        return await self._post_session(
            "/api/v1/session/stop", "stop", {"session": session_id},
        )

    async def session_status(self, session_id: str) -> dict[str, Any]:
        return await self._post_session(
            "/api/v1/session/status", "status", {"session": session_id},
        )

    async def list_sessions(self) -> dict[str, Any]:
        return await self._post_session(
            "/api/v1/session/list", "list",
        )

    async def drain_messages(self, session_id: str) -> dict[str, Any]:
        return await self._post_session(
            "/api/v1/session/messages", "drain", {"session": session_id},
        )
