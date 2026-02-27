"""HTTP Executor - Async HTTP client for executing attacks."""

import asyncio
import logging
import time
import random
from typing import Any, Dict, Optional, Union
import httpx
import asyncio
import time

logger = logging.getLogger(__name__)


class Executor:
    """Async HTTP executor for attack requests.
    
    Features:
    - Async requests with httpx
    - Rate limiting
    - Timeout handling
    - Multiple auth methods
    - Response analysis
    - Retry logic for rate-limited responses (429)
    """
    
    def __init__(
        self,
        base_url: str,
        auth_type: str = "none",
        auth_token: Optional[str] = None,
        rate_limit: int = 10,
        timeout: int = 30,
        retry_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the executor.
        
        Args:
            base_url: Base URL of the target API
            auth_type: Authentication type (bearer, basic, none)
            auth_token: Authentication token/credentials
            rate_limit: Maximum requests per second
            timeout: Request timeout in seconds
            retry_config: Configuration for retry logic
        
        Raises:
            ValueError: If auth_type is not supported.
        """
        self.base_url = base_url.rstrip("/")
        
        if auth_type not in ["bearer", "basic", "none"]:
            raise ValueError(f"Unsupported auth_type: {auth_type}. Supported types: bearer, basic, none")
            
        self.auth_type = auth_type
        self.auth_token = auth_token
        self.rate_limit = rate_limit
        self.timeout = timeout
        
        # Retry configuration
        self.retry_config = retry_config or {}
        self.max_retries = self.retry_config.get("max_retries", 3)
        self.base_backoff = self.retry_config.get("base_backoff", 1.0)
        self.max_backoff = self.retry_config.get("max_backoff", 60.0)
        self.jitter = self.retry_config.get("jitter", True)
        
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0.0
    
    async def __aenter__(self) -> "Executor":
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._build_headers(),
        )
        # Initialize rate limiter semaphore
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        """Context manager exit."""
        if self._client:
            await self._client.aclose()
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including authentication."""
        headers = {"User-Agent": "ChaosKitten/0.1.0"}
        
        if self.auth_type in ("bearer", "oauth") and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_type == "basic" and self.auth_token:
            headers["Authorization"] = f"Basic {self.auth_token}"
        
        return headers
    
    async def execute_attack(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        graphql_query: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute an attack request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            payload: Request body/parameters
            files: Files to upload (for multipart/form-data)
            graphql_query: Raw GraphQL query string (will be wrapped in JSON)
            headers: Additional headers
            
        Returns:
            Response data including status, body, and timing
        """
        if not self._client:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed_ms": 0.0,
                "error": "Client not initialized. Use 'async with Executor(...)' pattern.",
            }
        
        method = method.upper()
        
        # Merge additional headers
        request_headers = self._client.headers.copy()
        if headers:
            request_headers.update(headers)

        last_result = {}
        
        for attempt in range(self.max_retries + 1):
            # Apply rate limiting
            await self._apply_rate_limit()

            start_time = time.perf_counter()
            response = None
            error_msg = None
            
            try:
                # Execute request based on method
                if method == "GET":
                    response = await self._client.get(
                        path,
                        params=payload,
                        headers=request_headers,
                    )
                elif method in ("POST", "PUT", "PATCH"):
                    # Handle GraphQL
                    if graphql_query:
                        if method != "POST":
                            logger.debug(
                                "GraphQL queries are typically sent via POST, "
                                "but '%s' was requested for %s", method, path
                            )
                        json_body = {"query": graphql_query}
                        if payload:
                            json_body["variables"] = payload
                        
                        response = await self._client.request(
                            method,
                            path,
                            json=json_body,
                            headers=request_headers,
                        )
                    # Handle multipart/form-data vs json
                    elif files:
                        response = await self._client.request(
                            method,
                            path,
                            data=payload,
                            files=files,
                            headers=request_headers,
                        )
                    else:
                        response = await self._client.request(
                            method,
                            path,
                            json=payload,
                            headers=request_headers,
                        )
                elif method == "DELETE":
                    response = await self._client.delete(
                        path,
                        headers=request_headers,
                    )
                else:
                    return {
                        "status_code": 0,
                        "headers": {},
                        "body": "",
                        "elapsed_ms": 0.0,
                        "error": f"Unsupported HTTP method: {method}",
                    }

                elapsed_ms = (time.perf_counter() - start_time) * 1000
                
                last_result = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                    "elapsed_ms": elapsed_ms,
                    "error": None,
                }

                # Check for 429 Rate Limit
                if response.status_code == 429:
                    if attempt < self.max_retries:
                        await self._handle_429_backoff(attempt, response)
                        continue
                    else:
                        logger.warning(f"Max retries ({self.max_retries}) exceeded for {method} {path} (429 Too Many Requests)")
                        return last_result
                
                # Successful or non-retriable response
                return last_result
                
            except httpx.TimeoutException as e:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                error_msg = f"Request timeout: {str(e)}"
                logger.warning(f"Timeout executing {method} {path}: {e}")
                last_result = {
                    "status_code": 0,
                    "headers": {},
                    "body": "",
                    "elapsed_ms": elapsed_ms,
                    "error": error_msg,
                }
                # Consider retrying on timeout? Usually yes, but 429 is the main focus here.
                # Let's retry on timeout too if configured, but keeping scope to 429 for now as per issue.
                return last_result

            except (httpx.ConnectError, httpx.HTTPError) as e:
                 elapsed_ms = (time.perf_counter() - start_time) * 1000
                 error_msg = f"HTTP/Connection error: {str(e)}"
                 logger.warning(f"HTTP error executing {method} {path}: {e}")
                 last_result = {
                     "status_code": 0,
                     "headers": {},
                     "body": "",
                     "elapsed_ms": elapsed_ms,
                     "error": error_msg,
                 }
                 return last_result
                 
            except Exception as e:
                 elapsed_ms = (time.perf_counter() - start_time) * 1000
                 error_msg = f"Unexpected error: {str(e)}"
                 logger.warning(f"Unexpected error executing {method} {path}: {e}")
                 return {
                     "status_code": 0,
                     "headers": {},
                     "body": "",
                     "elapsed_ms": elapsed_ms,
                     "error": error_msg,
                 }

        return last_result

    async def _handle_429_backoff(self, attempt: int, response: httpx.Response) -> None:
        """Handle 429 rate limiting with backoff."""
        if response and "Retry-After" in response.headers:
            try:
                # Retry-After can be seconds or a date. We handle seconds for now or simple int.
                header_val = response.headers["Retry-After"]
                if header_val.isdigit():
                    wait_time = float(header_val)
                else:
                    # Todo: Handle date format if needed
                    wait_time = self.base_backoff

                logger.info(f"Rate limited. Waiting {wait_time}s as per Retry-After header.")
                await asyncio.sleep(wait_time)
                return
            except ValueError:
                pass # Fallback to exponential backoff

        # Exponential backoff: base * 2^attempt
        backoff = min(self.max_backoff, self.base_backoff * (2 ** attempt))
        
        if self.jitter:
            # Jitter: randomized between 0.5 * backoff and 1.5 * backoff
            backoff = backoff * (0.5 + random.random())
            
        logger.info(f"Rate limited (429). Retrying in {backoff:.2f}s (Attempt {attempt + 1}/{self.max_retries})")
        await asyncio.sleep(backoff)
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting using token bucket algorithm."""
        if not self._rate_limiter:
            return
        
        # Acquire semaphore token
        async with self._rate_limiter:
            # Calculate time since last request
            current_time = time.perf_counter()
            time_since_last = current_time - self._last_request_time
            
            # Minimum time between requests (in seconds)
            min_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
            
            # Sleep if we're going too fast
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            # Update last request time
            self._last_request_time = time.perf_counter()
