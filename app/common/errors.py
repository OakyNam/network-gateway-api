"""Shared gateway exception types."""


class GatewayError(Exception):
    """Base exception for gateway errors."""


class ConfigNotFoundError(GatewayError):
    """Required application or database-backed configuration is missing."""


class DeviceNotFoundError(GatewayError):
    """A device is not present in the configured registry."""


class ProxyNotFoundError(GatewayError):
    """A proxy mapping is not present."""


class ProxyMappingError(GatewayError):
    """A proxy mapping cannot be resolved."""


class ClientMappingError(GatewayError):
    """A device client mapping cannot be resolved."""


class DatabaseError(GatewayError):
    """A database operation failed."""
