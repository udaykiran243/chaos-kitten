"""HTTP Executor - Async HTTP client for executing attacks."""

from typing import Any
import httpx


class Executor:
    """Async HTTP executor for attack requests.
    
    Features:
    - Async requests with httpx
    - Rate limiting
    - Timeout handling
    - Multiple auth methods
    - Response analysis
    """
    
    def __init__(
        self,
        base_url: str,
        auth_type: str = "none",
        auth_token: str | None = None,
        rate_limit: int = 10,
        timeout: int = 30,
    ) -> None:
        """Initialize the executor.
        
        Args:
            base_url: Base URL of the target API
            auth_type: Authentication type (bearer, basic, oauth, none)
            auth_token: Authentication token/credentials
            rate_limit: Maximum requests per second
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.auth_type = auth_type
        self.auth_token = auth_token
        self.rate_limit = rate_limit
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
    
    async def __aenter__(self) -> "Executor":
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._build_headers(),
        )
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        """Context manager exit."""
        if self._client:
            await self._client.aclose()
    
    def _build_headers(self) -> dict[str, str]:
        """Build request headers including authentication."""
        headers = {"User-Agent": "ChaosKitten/0.1.0"}
        
        if self.auth_type == "bearer" and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_type == "basic" and self.auth_token:
            headers["Authorization"] = f"Basic {self.auth_token}"
        
        return headers
    
    async def execute_attack(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute an attack request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            payload: Request body/parameters
            headers: Additional headers
            
        Returns:
            Response data including status, body, and timing
        """
        if not self._client:
            raise RuntimeError("Executor context not initialized. Use 'async with' block.")

        url = path.lstrip("/")
        
        # Merge headers
        # Start timing
        import time
        start_time = time.time()
        
        try:
            # Handle different payload types based on method usually, 
            # but httpx handles 'json' or 'data' or 'params'
            # simplified: use 'json' for body if method is POST/PUT/PATCH, 'params' otherwise
            # This is a simplification for the MVP
            
            kwargs = {}
            if headers:
                kwargs["headers"] = headers
                
            if method.upper() in ["POST", "PUT", "PATCH"]:
                 kwargs["json"] = payload
            else:
                 kwargs["params"] = payload
                 
            response = await self._client.request(method, url, **kwargs)
            duration = time.time() - start_time
            
            return {
                "status_code": response.status_code,
                "response_body": response.text,
                "duration": duration,
                "headers": dict(response.headers),
                "url": str(response.url)
            }
            
        except httpx.RequestError as e:
            duration = time.time() - start_time
            return {
                "status_code": 0,
                "error": str(e),
                "duration": duration,
                "response_body": "",
                "url": url
            }
