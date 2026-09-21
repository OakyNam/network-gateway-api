"""Factory for creating proxy clients from fresh database-backed mappings."""

from typing import Any, Dict, Optional

from loguru import logger

from app.dal.proxy.proxy_client import ProxyClient
from app.common.errors import ProxyMappingError
from app.dal.db.store import get_store


class ProxyFactory:
    @staticmethod
    def get_proxy(router_info: Dict[str, Any]) -> Optional[ProxyClient]:
        try:
            cfg = get_store().get_config("proxy_mapping")

            key_columns = cfg.get("key_columns", ["owner"])
            proxy_map = cfg.get("map", {})
            key_parts = [str(router_info.get(col, "*") or "*").lower() for col in key_columns]
            key = ":".join(key_parts)

            candidates = [key]
            if len(key_parts) > 1:
                candidates.append(":".join(key_parts[:-1] + ["*"]))
            if key_parts:
                candidates.append(key_parts[0])
            candidates.extend(("default", "*:*"))
            proxy_host = next((proxy_map[candidate] for candidate in candidates if candidate in proxy_map), None)

            if not proxy_host:
                return None

            logger.info(f"Using proxy {proxy_host} for key {key}")
            return ProxyClient(proxy_host)
        except Exception:
            logger.error("Proxy database mapping is missing, invalid, or unavailable")
            raise ProxyMappingError("Proxy database mapping is missing, invalid, or unavailable") from None
