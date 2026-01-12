import httpx
from typing import Optional


class AsyncHTTPClient:
    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "AsyncHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "whatwaff-async/1.0"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client:
            await self._client.aclose()

    async def fetch(self, url: str) -> httpx.Response:
        if not self._client:
            raise RuntimeError("HTTP client not initialized")
        return await self._client.get(url)

    async def probe(self, base_url: str, payload: str) -> httpx.Response:
        if not self._client:
            raise RuntimeError("HTTP client not initialized")
        return await self._client.get(f"{base_url}{payload}")
