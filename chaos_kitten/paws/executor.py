"""HTTP Executor - Async HTTP client for executing attacks."""

import asyncio
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
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
    """
    
    def __init__(
        self,
        base_url: str,
        auth_type: str = "none",
        auth_token: Optional[str] = None,
        rate_limit: int = 10,
        timeout: int = 30,
        logging_enabled: bool = False,
        log_file: Optional[str] = None,
    ) -> None:
        """Initialize the executor.
        
        Args:
            base_url: Base URL of the target API
            auth_type: Authentication type (bearer, basic, none)
            auth_token: Authentication token/credentials
            rate_limit: Maximum requests per second
            timeout: Request timeout in seconds
            logging_enabled: Enable request/response logging
            log_file: Path to log file for request/response logging
        
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
        self.logging_enabled = logging_enabled
        self.log_file = log_file
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0.0
        self._request_logger: Optional[logging.Logger] = None
        self._log_handlers: List[logging.Handler] = []
    
    async def __aenter__(self) -> "Executor":
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._build_headers(),
        )
        # Initialize rate limiter semaphore
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
        
        # Set up logging if enabled
        if self.logging_enabled:
            self._setup_logging()
        
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        """Context manager exit."""
        if self._client:
            await self._client.aclose()
        
        # Clean up log handlers
        if self._request_logger:
            for handler in self._log_handlers:
                handler.close()
                self._request_logger.removeHandler(handler)
            self._log_handlers.clear()
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including authentication."""
        headers = {"User-Agent": "ChaosKitten/0.1.0"}
        
        if self.auth_type in ("bearer", "oauth") and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_type == "basic" and self.auth_token:
            headers["Authorization"] = f"Basic {self.auth_token}"
        
        return headers
    
    def _setup_logging(self) -> None:
        """Set up request/response logging."""
        # Use a unique logger name to avoid conflicts with other loggers
        logger_name = f"chaos_kitten.executor.{id(self)}"
        self._request_logger = logging.getLogger(logger_name)
        self._request_logger.setLevel(logging.DEBUG)
        
        # Add file handler if log_file is specified
        if self.log_file:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            self._request_logger.addHandler(file_handler)
            self._log_handlers.append(file_handler)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        self._request_logger.addHandler(console_handler)
        self._log_handlers.append(console_handler)
    
    def _redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive data from URLs and request bodies.
        
        Args:
            text: Text to redact sensitive data from
            
        Returns:
            Text with sensitive data redacted
        """
        if not text:
            return text
        
        # Redact API keys and tokens from URLs and request bodies
        # Pattern matches: api_key, api-key, apikey (but NOT bare 'key')
        # Stops at & or # to handle URL fragments correctly
        pattern = r"(api[-_]?key|apikey)=([^&#]*)"
        redacted = re.sub(pattern, r"\1=***REDACTED***", text, flags=re.IGNORECASE)
        
        # Redact Authorization headers
        redacted = re.sub(
            r"(Authorization['\"]?\s*:\s*['\"]?)(Bearer|Basic)\s+[^\s'\"]+",
            r"\1\2 ***REDACTED***",
            redacted,
            flags=re.IGNORECASE
        )
        
        # Redact password fields
        redacted = re.sub(
            r"(password['\"]?\s*:\s*['\"]?)([^'\"]+)",
            r"\1***REDACTED***",
            redacted,
            flags=re.IGNORECASE
        )
        
        return redacted
    
    def _log_request_response(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]],
        headers: Dict[str, str],
        response_data: Dict[str, Any],
    ) -> None:
        """Log request and response details.
        
        Args:
            method: HTTP method
            path: Request path
            payload: Request payload
            headers: Request headers
            response_data: Response data including status, body, etc.
        """
        if not self._request_logger:
            return
        
        # Build full URL
        full_url = f"{self.base_url}{path}"
        redacted_url = self._redact_sensitive_data(full_url)
        
        # Redact sensitive data from headers
        redacted_headers = {k: "***REDACTED***" if k.lower() in ("authorization", "api-key") else v 
                           for k, v in headers.items()}
        
        # Redact sensitive data from payload
        redacted_payload = self._redact_sensitive_data(str(payload)) if payload else None
        
        # Log request
        self._request_logger.info(f"Request: {method} {redacted_url}")
        self._request_logger.debug(f"Headers: {redacted_headers}")
        if redacted_payload:
            self._request_logger.debug(f"Payload: {redacted_payload}")
        
        # Redact sensitive data from response
        response_body = response_data.get("body", "")
        redacted_response = self._redact_sensitive_data(response_body) if response_body else ""
        
        # Log response
        status_code = response_data.get("status_code", 0)
        elapsed_ms = response_data.get("elapsed_ms", 0)
        self._request_logger.info(
            f"Response: {status_code} ({elapsed_ms:.2f}ms)"
        )
        if redacted_response:
            # Truncate long responses
            max_length = 1000
            if len(redacted_response) > max_length:
                redacted_response = redacted_response[:max_length] + "... (truncated)"
            self._request_logger.debug(f"Body: {redacted_response}")
        
        # Log errors if present
        error = response_data.get("error")
        if error:
            self._request_logger.error(f"Error: {error}")
    
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
        
        # Apply rate limiting
        await self._apply_rate_limit()
        
        # Merge additional headers
        request_headers = self._client.headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Prepare request parameters
        method = method.upper()
        start_time = time.perf_counter()
        
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
                    # GraphQL is typically POST-only; warn if a different method was requested
                    if method != "POST":
                        logger.debug(
                            "GraphQL queries are typically sent via POST, "
                            "but '%s' was requested for %s", method, path
                        )
                    # GraphQL usually expects {"query": "...", "variables": {...}}
                    # payload can be used for variables if provided
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
                    # If files are present, payload usually goes into 'data' form fields
                    # httpx handles boundary and content-type for files automatically
                    response = await self._client.request(
                        method,
                        path,
                        data=payload, # Form fields
                        files=files,  # File uploads
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
            
            response_data = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
                "elapsed_ms": elapsed_ms,
                "error": None,
            }
            
            # Log request and response
            if self.logging_enabled:
                self._log_request_response(method, path, payload, request_headers, response_data)
            
            return response_data
            
        except httpx.TimeoutException as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            error_msg = f"Request timeout: {str(e)}"
            logger.warning(f"Timeout executing {method} {path}: {e}")
            response_data = {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed_ms": elapsed_ms,
                "error": error_msg,
            }
            
            # Log request and response
            if self.logging_enabled:
                self._log_request_response(method, path, payload, request_headers, response_data)
            
            return response_data
            
        # ... (rest of exception handling remains similar, ensuring closing indent)
        except httpx.ConnectError as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"Connection error: {str(e)}"
             logger.warning(f"Connection error executing {method} {path}: {e}")
             response_data = {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
             # Log request and response
             if self.logging_enabled:
                 self._log_request_response(method, path, payload, request_headers, response_data)
             
             return response_data
             
        except httpx.HTTPError as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"HTTP error: {str(e)}"
             logger.warning(f"HTTP error executing {method} {path}: {e}")
             response_data = {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
             # Log request and response
             if self.logging_enabled:
                 self._log_request_response(method, path, payload, request_headers, response_data)
             
             return response_data
             
        except Exception as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"Unexpected error: {str(e)}"
             logger.warning(f"Unexpected error executing {method} {path}: {e}")
             response_data = {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
             # Log request and response
             if self.logging_enabled:
                 self._log_request_response(method, path, payload, request_headers, response_data)
             
             return response_data
    
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
