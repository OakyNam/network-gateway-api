"""Typed input and deliberately allow-listed public management contracts."""

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

Protocol = Literal["ssh", "netconf", "telnet"]
ClientType = Literal["network", "fake"]
ProxyType = Literal["ssh_tunnel", "ssh_shell", "socks5", "http_connect"]
ConnectorType = Literal["direct", "ssh_tunnel", "ssh_shell", "socks5", "http_connect"]


class WriteModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AuthenticationWrite(WriteModel):
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=16384, repr=False)
    private_key_path: str | None = Field(default=None, max_length=4096)
    known_hosts_path: str | None = Field(default=None, max_length=4096)
    role_account_id: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def exclusive_role(self):
        if self.role_account_id and any(
            getattr(self, key) is not None
            for key in ("username", "password", "private_key_path")
        ):
            raise ValueError("A role account cannot be combined with inline authentication.")
        return self


class ConnectorWrite(AuthenticationWrite):
    type: ConnectorType = "direct"
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def endpoint(self):
        if self.type != "direct" and (not self.host or self.port is None):
            raise ValueError("A proxy endpoint is required.")
        return self


class ConnectionWrite(AuthenticationWrite):
    name: str = Field(min_length=1, max_length=255)
    client_type: ClientType = "network"
    protocol: Protocol
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    proxy_id: str | None = Field(default=None, min_length=1, max_length=128)
    connector: ConnectorWrite | None = None

    @model_validator(mode="after")
    def exclusive_proxy(self):
        if self.proxy_id and self.connector is not None:
            raise ValueError("A saved proxy cannot be combined with an inline connector.")
        return self


class ProxyWrite(AuthenticationWrite):
    name: str = Field(min_length=1, max_length=255)
    type: ProxyType
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)


class RoleAccountWrite(WriteModel):
    name: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=255)
    authentication_type: Literal["password", "ssh_key"]
    password: str | None = Field(default=None, max_length=16384, repr=False)
    private_key: str | None = Field(default=None, max_length=65536, repr=False)
    key_passphrase: str | None = Field(default=None, max_length=16384, repr=False)

    @model_validator(mode="after")
    def exclusive_authentication(self):
        if self.authentication_type == "password" and (
            self.private_key is not None or self.key_passphrase is not None
        ):
            raise ValueError("Password authentication cannot include SSH key credentials.")
        if self.authentication_type == "ssh_key" and self.password is not None:
            raise ValueError("SSH key authentication cannot include a password.")
        if self.key_passphrase is not None and self.private_key is None:
            raise ValueError("A passphrase requires a replacement key.")
        return self


class PublicAuthentication(BaseModel):
    username: str | None = None
    private_key_path: str | None = None
    known_hosts_path: str | None = None
    role_account_id: str | None = None
    password_configured: bool = False
    private_key_configured: bool = False


class PublicConnector(PublicAuthentication):
    type: ConnectorType
    host: str | None = None
    port: int | None = None


class PublicConnection(PublicAuthentication):
    id: str
    name: str
    client_type: ClientType = "network"
    protocol: Protocol
    host: str
    port: int
    timeout_seconds: int = 10
    proxy_id: str | None = None
    connector: PublicConnector = Field(default_factory=lambda: PublicConnector(type="direct"))


class PublicProxy(PublicAuthentication):
    id: str
    name: str
    type: ProxyType
    host: str
    port: int


class PublicRoleAccount(BaseModel):
    id: str
    name: str
    username: str
    authentication_type: Literal["password", "ssh_key"]
    password_configured: bool = False
    private_key_configured: bool = False


class ConnectionCollection(BaseModel):
    items: list[PublicConnection]


class ProxyCollection(BaseModel):
    items: list[PublicProxy]


class RoleAccountCollection(BaseModel):
    items: list[PublicRoleAccount]


class ConnectorCapability(BaseModel):
    type: ConnectorType
    label: str
    protocols: list[Protocol]
    description: str


class Capabilities(BaseModel):
    protocols: list[Protocol]
    connectors: list[ConnectorCapability]


class TestResult(BaseModel):
    success: bool
    simulated: bool = False
    stage: str
    detail: str
    duration_ms: float = Field(ge=0, allow_inf_nan=False)


class ConnectionTestWrite(WriteModel):
    """Optional empty JSON body for a single saved-profile test."""


class BatchResult(TestResult):
    connection_id: str
    name: str
    protocol: Protocol
    host: str
    port: int
    connector_type: ConnectorType


class BatchWrite(WriteModel):
    connection_ids: list[str] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def unique_ids(self):
        if any(not item or len(item) > 128 for item in self.connection_ids):
            raise ValueError("Invalid connection identifier.")
        if len(set(self.connection_ids)) != len(self.connection_ids):
            raise ValueError("Connection identifiers must be unique.")
        return self


class PublicJob(BaseModel):
    id: str
    status: Literal["queued", "running", "completed", "failed"]
    total: int = Field(ge=0)
    completed: int = Field(ge=0)
    results: list[BatchResult]
    error: str | None = None


SettingsName = Literal["device_lookup", "client_mapping", "proxy_mapping"]
ClientClass = Literal[
    "app.dal.device.nccclient_adva.AdvaFSP114ProNCCClient",
    "app.dal.device.nccclient_alcatel.AlcatelNCCClient",
    "app.dal.device.nccclient_ceina.CeinaNCCClient",
    "app.dal.device.nccclient_ios.IOSNCCClient",
    "app.dal.device.nccclient_iox.IOXNCCClient",
    "app.dal.device.nccclient_juniper.JuniperNCCClient",
    "app.dal.device.telnet_client.GenericTelnetNCCClient",
]


def _identifier(value):
    if value.lower() == "none":
        raise ValueError("A metadata identifier is required.")
    return value


def _mapping_key(value):
    if value != value.lower() or any(ord(character) < 32 for character in value):
        raise ValueError("Mapping keys must be lowercase and contain no control characters.")
    return value


MetadataIdentifier = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$"),
    AfterValidator(_identifier),
]
MappingKey = Annotated[
    str, Field(min_length=1, max_length=255), AfterValidator(_mapping_key),
]
ProxyHost = Annotated[
    str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.:-]+$"),
]


class DeviceLookupSettings(WriteModel):
    """device_lookup: metadata table and lookup-column identifiers, not a database URL."""

    table: MetadataIdentifier
    search_column: MetadataIdentifier


class MappingSettings(WriteModel):
    key_columns: list[MetadataIdentifier] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def unique_columns(self):
        if len(set(self.key_columns)) != len(self.key_columns):
            raise ValueError("Mapping columns must be unique.")
        return self


class ClientMappingSettings(MappingSettings):
    """client_mapping: map lowercase metadata keys to supported gateway client classes."""

    map: dict[MappingKey, ClientClass] = Field(min_length=1, max_length=1000)


class ProxyMappingSettings(MappingSettings):
    """proxy_mapping: map lowercase metadata keys to proxy hosts or null for direct access."""

    map: dict[MappingKey, ProxyHost | None] = Field(max_length=1000)


SettingsPayload = DeviceLookupSettings | ClientMappingSettings | ProxyMappingSettings
SETTINGS_MODELS = {
    "device_lookup": DeviceLookupSettings,
    "client_mapping": ClientMappingSettings,
    "proxy_mapping": ProxyMappingSettings,
}
