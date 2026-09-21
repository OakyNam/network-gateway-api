"""Allow-listed simulated inventory and static-route HTTP contracts."""

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.api.schemas.management import ConnectorType, Protocol, WriteModel


class SimulatedResponse(BaseModel):
    provider: Literal["fake"]
    simulated: Literal[True]


class DeviceIdentity(BaseModel):
    id: str
    name: str
    protocol: Protocol
    host: str
    port: int


class DeviceAccess(BaseModel):
    role_account_id: str
    proxy_id: str
    proxy_role_account_id: str
    connector_type: ConnectorType


class SystemInventory(BaseModel):
    hostname: str
    model: str
    software_version: str
    serial_number: str
    uptime_seconds: int = Field(ge=0)


class InterfaceInventory(BaseModel):
    name: str
    description: str
    admin_status: str
    oper_status: str
    mtu: int
    mac_address: str
    addresses: list[str]
    rx_bytes: int = Field(ge=0)
    tx_bytes: int = Field(ge=0)


class BGPNeighbor(BaseModel):
    address: str
    remote_asn: int
    state: str
    uptime_seconds: int = Field(ge=0)
    prefixes_received: int = Field(ge=0)
    prefixes_sent: int = Field(ge=0)


class BGPInventory(BaseModel):
    local_asn: int
    router_id: str
    neighbors: list[BGPNeighbor]


class MPLSInterface(BaseModel):
    name: str
    enabled: bool


class LDPNeighbor(BaseModel):
    router_id: str
    address: str
    state: str
    uptime_seconds: int = Field(ge=0)


class LabelSwitchedPath(BaseModel):
    name: str
    source: str
    destination: str
    state: str
    label: int


class MPLSInventory(BaseModel):
    interfaces: list[MPLSInterface]
    ldp_neighbors: list[LDPNeighbor]
    lsps: list[LabelSwitchedPath]


class DeviceInventory(SimulatedResponse):
    device: DeviceIdentity
    access: DeviceAccess
    system: SystemInventory
    interfaces: list[InterfaceInventory]
    bgp: BGPInventory
    mpls: MPLSInventory


class StaticRouteWrite(WriteModel):
    destination: str = Field(min_length=1, max_length=64, pattern=r"^[^/%]+/[0-9]{1,3}$")
    next_hop: str = Field(min_length=1, max_length=45)
    interface: Literal["eth0", "eth1", "lo"] | None = None
    metric: int = Field(default=1, ge=0, le=65535)
    description: str = Field(default="", max_length=200)
    enabled: bool = True

    @model_validator(mode="after")
    def network_family(self):
        destination = ipaddress.ip_network(self.destination, strict=True)
        next_hop = ipaddress.ip_address(self.next_hop)
        if destination.version != next_hop.version or "%" in self.next_hop:
            raise ValueError("The next hop must match the network address family.")
        self.destination = str(destination)
        self.next_hop = str(next_hop)
        return self


class StaticRoute(StaticRouteWrite):
    id: str
    connection_id: str


class StaticRouteCollection(SimulatedResponse):
    items: list[StaticRoute]


class StaticRouteItem(SimulatedResponse):
    item: StaticRoute
