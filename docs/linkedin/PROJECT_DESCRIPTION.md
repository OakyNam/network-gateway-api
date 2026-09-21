# Network Gateway API

## LinkedIn project description

Network Gateway API is an API-first network automation platform that provides a
consistent way to inventory, test, and manage network devices across different
vendors, protocols, and protected access paths.

The application separates its UI, API, business logic, and data-access layers.
It supports SSH, NETCONF-over-SSH, and custom-port Telnet connections, including
SSH bastions, SSH jump shells, SOCKS5 proxies, and HTTP CONNECT proxies. Device
and bastion credentials are stored as encrypted reusable network role accounts,
so application users do not need individual access to every device.

Microsoft Entra ID integration provides Viewer, Operator, and Administrator
application roles. Supported configuration changes generate immutable,
user-attributed transaction records containing correlation IDs, outcomes, and
normalized before/after state. The current demonstration includes persistent
simulated static-route management, a normalized device-information view, seven
real loopback transport paths, and one full-stack simulated network device.

The project includes 257 Python tests and 31 JavaScript tests covering
authentication, authorization, persistence, connector behavior, audit
atomicity, secret redaction, browser models, and API integration.

## Short project summary

Built an API-first network automation gateway that normalizes device access
across SSH, NETCONF, Telnet, bastions, and proxies. Added encrypted reusable
network credentials, Microsoft Entra ID role-based access, persistent device
inventory, connection testing, and immutable user-attributed configuration
auditing with before/after state.

## LinkedIn post draft

I recently completed a major milestone on my Network Gateway API project.

The goal is to reduce the vendor-specific tribal knowledge required to navigate
and operate network equipment. Instead of giving every engineer separate access
to each device, the gateway centralizes connectivity and exposes consistent,
API-first device resources.

Highlights:

- Layered UI / API / business logic / data-access architecture
- SSH, NETCONF-over-SSH, and custom-port Telnet support
- SSH bastion, SSH jump-shell, SOCKS5, and HTTP CONNECT proxy paths
- Encrypted reusable credentials for devices and bastions
- Microsoft Entra ID authentication
- Viewer, Operator, and Administrator application roles
- Normalized device, interface, BGP, MPLS, and static-route views
- Immutable user-attributed configuration transaction history
- Correlation IDs and normalized before/after state for audited changes
- Persistent SQLite demo storage with PostgreSQL-ready SQLAlchemy support
- Seven real local transport paths and one full-stack simulated device
- 257 Python tests and 31 JavaScript tests

The current write demonstration intentionally uses simulated static routes.
Real vendor configuration support will be added adapter by adapter so the API
never claims compatibility that has not been verified against actual equipment.

Source: https://github.com/OakyNam/network-gateway-api

#NetworkAutomation #Python #FastAPI #NetDevOps #Networking #NETCONF #SSH
#MicrosoftEntra #APIDesign #SoftwareEngineering

## Suggested LinkedIn project fields

**Name:** Network Gateway API

**Associated skills:** Python, FastAPI, SQLAlchemy, SQLite, PostgreSQL,
Microsoft Entra ID, OAuth 2.0, OpenID Connect, PKCE, REST APIs, Network
Automation, NETCONF, SSH, Telnet, RBAC, JavaScript, Integration Testing

**Project URL:** https://github.com/OakyNam/network-gateway-api
