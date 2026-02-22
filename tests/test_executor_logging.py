"""Tests for Executor request/response logging functionality."""

import pytest
import respx
import logging
import re
from pathlib import Path
import tempfile
from chaos_kitten.paws.executor import Executor


@pytest.fixture
def base_url():
    return "http://api.example.com"


@pytest.fixture
def temp_log_file():
    """Create a temporary log file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        yield f.name
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_logging_enabled_with_file(base_url, temp_log_file):
    """Test that logging is enabled and writes to file."""
    async with Executor(
        base_url=base_url,
        logging_enabled=True,
        log_file=temp_log_file
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/users").respond(200, json={"users": []})
            
            await executor.execute_attack("GET", "/users")
            
            # Check that log file was created and has content
            log_content = Path(temp_log_file).read_text()
            assert "Request: GET" in log_content
            assert "Response: 200" in log_content


@pytest.mark.asyncio
async def test_sensitive_data_redaction_api_key(base_url, caplog):
    """Test that API keys are redacted in logs."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        logging_enabled=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/search").respond(200, json={"results": []})
            
            # Test with api_key parameter
            await executor.execute_attack("GET", "/search?api_key=secret123")
            
            # Check that the API key is redacted in logs
            log_output = caplog.text
            assert "secret123" not in log_output
            assert "***REDACTED***" in log_output


@pytest.mark.asyncio
async def test_sensitive_data_redaction_variations(base_url, caplog):
    """Test that various API key formats are redacted."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        logging_enabled=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/search").respond(200, json={"results": []})
            
            # Test various API key formats
            test_cases = [
                "/search?api_key=secret123",
                "/search?api-key=secret123",
                "/search?apikey=secret123",
            ]
            
            for path in test_cases:
                caplog.clear()
                await executor.execute_attack("GET", path)
                
                log_output = caplog.text
                assert "secret123" not in log_output, f"API key leaked in {path}"
                assert "***REDACTED***" in log_output


@pytest.mark.asyncio
async def test_bare_key_not_redacted(base_url, caplog):
    """Test that bare 'key' parameter is NOT redacted (fix #1)."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        logging_enabled=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/products").respond(200, json={"product": "test"})
            
            # Test with legitimate 'key' parameter
            await executor.execute_attack("GET", "/products?key=product_id")
            
            log_output = caplog.text
            # 'product_id' should NOT be redacted since it's a bare 'key=' parameter
            # The regex should only match api_key, api-key, apikey
            assert "product_id" in log_output or "key=product_id" in log_output


@pytest.mark.asyncio
async def test_url_fragment_handling(base_url, caplog):
    """Test that URL fragments are handled correctly (fix #2)."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        logging_enabled=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            # Mock the path without the fragment (httpx strips fragments)
            mock.get("/search").respond(200, json={"results": []})
            
            # Test with URL fragment
            await executor.execute_attack("GET", "/search?api_key=secret#/fragment?key=data")
            
            log_output = caplog.text
            # The API key should be redacted
            assert "secret" not in log_output or "***REDACTED***" in log_output
            # The fragment should not cause issues
            assert "fragment" in log_output or "***REDACTED***" in log_output


@pytest.mark.asyncio
async def test_authorization_header_redaction(base_url, caplog):
    """Test that Authorization headers are redacted."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        auth_type="bearer",
        auth_token="secret_token_12345",
        logging_enabled=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/protected").respond(200, json={"data": "protected"})
            
            await executor.execute_attack("GET", "/protected")
            
            log_output = caplog.text
            # The token should be redacted
            assert "secret_token_12345" not in log_output
            assert "***REDACTED***" in log_output


@pytest.mark.asyncio
async def test_unique_logger_name(base_url):
    """Test that each executor instance has a unique logger (fix #3)."""
    executor1 = Executor(base_url=base_url, logging_enabled=True)
    executor2 = Executor(base_url=base_url, logging_enabled=True)
    
    async with executor1:
        async with executor2:
            # Both should have different logger names to avoid conflicts
            assert executor1._request_logger.name != executor2._request_logger.name
            # Logger names should include instance ID
            assert "chaos_kitten.executor." in executor1._request_logger.name
            assert "chaos_kitten.executor." in executor2._request_logger.name


@pytest.mark.asyncio
async def test_handler_cleanup(base_url, temp_log_file):
    """Test that FileHandler resources are properly cleaned up (fix #4)."""
    executor = Executor(
        base_url=base_url,
        logging_enabled=True,
        log_file=temp_log_file
    )
    
    async with executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/test").respond(200, json={"status": "ok"})
            await executor.execute_attack("GET", "/test")
        
        # Verify handlers exist during execution
        assert len(executor._log_handlers) > 0
    
    # After exiting context, handlers should be cleared
    assert len(executor._log_handlers) == 0
    # Logger should still exist but handlers removed
    if executor._request_logger:
        assert len(executor._request_logger.handlers) == 0


@pytest.mark.asyncio
async def test_logging_disabled_by_default(base_url):
    """Test that logging is disabled by default."""
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/test").respond(200, json={"status": "ok"})
            
            result = await executor.execute_attack("GET", "/test")
            
            # Should execute successfully
            assert result["status_code"] == 200
            # Logger should not be set up
            assert executor._request_logger is None


@pytest.mark.asyncio
async def test_redaction_regex_pattern(base_url):
    """Test the regex pattern directly."""
    executor = Executor(base_url=base_url, logging_enabled=True)
    
    async with executor:
        # Test the redaction method directly
        test_cases = [
            # (input, should_contain_secret)
            ("api_key=secret123", False),  # Should redact
            ("api-key=secret123", False),  # Should redact
            ("apikey=secret123", False),   # Should redact
            ("key=product_id", True),      # Should NOT redact (bare 'key')
            ("api_key=secret#fragment", False),  # Should redact and stop at #
            ("api_key=secret&other=value", False),  # Should redact and stop at &
        ]
        
        for test_input, should_contain_secret in test_cases:
            redacted = executor._redact_sensitive_data(test_input)
            
            if should_contain_secret:
                # Bare 'key' should not be redacted
                assert "product_id" in redacted, f"Failed for: {test_input}"
            else:
                # API keys should be redacted
                assert "secret" not in redacted or "***REDACTED***" in redacted, f"Failed for: {test_input}"
                assert "***REDACTED***" in redacted, f"Failed for: {test_input}"


@pytest.mark.asyncio
async def test_response_body_redaction(base_url, caplog):
    """Test that sensitive data in response bodies is redacted."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        logging_enabled=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            # Response contains sensitive data
            mock.get("/config").respond(
                200,
                json={"api_key": "secret_key_123", "data": "normal"}
            )
            
            await executor.execute_attack("GET", "/config")
            
            log_output = caplog.text
            # The API key in response should be redacted
            assert "secret_key_123" not in log_output
            assert "***REDACTED***" in log_output
