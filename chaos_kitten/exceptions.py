"""Chaos Kitten - Custom Exception Hierarchy.

This module defines a standardized exception hierarchy for the Chaos Kitten
security testing framework. All custom exceptions should inherit from the
base ChaosKittenError class to ensure consistent error handling across
all modules.
"""

from typing import Optional


class ChaosKittenError(Exception):
    """Base exception class for all Chaos Kitten framework errors.
    
    This is the root exception that all other Chaos Kitten exceptions should
    inherit from. It provides a consistent interface for error handling
    throughout the framework and allows users to catch all Chaos Kitten
    specific errors with a single except clause.
    
    Attributes:
        message: Human-readable error message
        details: Optional additional error details or context
    """
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        """Initialize the base Chaos Kitten error.
        
        Args:
            message: Human-readable error message
            details: Optional additional error details or context
        """
        super().__init__(message)
        self.message = message
        self.details = details
    
    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


class ChaosKittenParsingError(ChaosKittenError):
    """Exception raised for parsing-related errors in the brain module.
    
    This exception is used for errors that occur during parsing of API
    specifications, configuration files, or other structured data
    within the brain module.
    
    Examples:
        - OpenAPI/Swagger specification parsing failures
        - GraphQL schema parsing errors
        - Configuration file format errors
    """
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        """Initialize parsing error.
        
        Args:
            message: Human-readable error message
            details: Optional additional error details or context
        """
        super().__init__(f"Parsing error: {message}", details)


class ChaosKittenNetworkError(ChaosKittenError):
    """Exception raised for network-related errors in the paws module.
    
    This exception is used for errors that occur during HTTP requests,
    network connectivity issues, or other network operations within
    the paws module.
    
    Examples:
        - HTTP connection timeouts
        - Authentication failures
        - Rate limiting errors
        - SSL/TLS certificate issues
    """
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        """Initialize network error.
        
        Args:
            message: Human-readable error message
            details: Optional additional error details or context
        """
        super().__init__(f"Network error: {message}", details)


class ChaosKittenConfigError(ChaosKittenError):
    """Exception raised for configuration-related errors.
    
    This exception is used for errors that occur during configuration
    loading, validation, or processing across any module.
    
    Examples:
        - Invalid configuration file format
        - Missing required configuration parameters
        - Invalid configuration values
        - Configuration file access permissions
    """
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        """Initialize configuration error.
        
        Args:
            message: Human-readable error message
            details: Optional additional error details or context
        """
        super().__init__(f"Configuration error: {message}", details)


class ChaosKittenReportingError(ChaosKittenError):
    """Exception raised for reporting-related errors in the litterbox module.
    
    This exception is used for errors that occur during report generation,
    file I/O operations, or template processing within the litterbox module.
    
    Examples:
        - Template rendering failures
        - Report file write permission errors
        - Invalid report format specifications
        - Missing template files
    """
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        """Initialize reporting error.
        
        Args:
            message: Human-readable error message
            details: Optional additional error details or context
        """
        super().__init__(f"Reporting error: {message}", details)
