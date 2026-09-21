"""Unified device controller with factory-based client dispatch."""

from typing import Callable, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.common.errors import ClientMappingError, DeviceNotFoundError, GatewayError
from app.bl.factories.client_factory import NCCClientFactory

router = APIRouter()


class XmlPayload(BaseModel):
    config_xml: str


def _run_for_device(device: str, action: Callable):
    client = None
    try:
        client = NCCClientFactory.get_client(device)
        return action(client)
    except DeviceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ClientMappingError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except GatewayError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        if client is not None:
            client.cleanup()


@router.get("/{device}/show-interface")
def show_interface(device: str, interface_name: Optional[str] = None) -> Dict[str, str]:
    return _run_for_device(
        device, lambda client: client.show_interface(interface_name=interface_name)
    )


@router.get("/{device}/config")
def get_device_config(device: str) -> Dict[str, str]:
    return _run_for_device(device, lambda client: {"config": client.get_config()})


@router.put("/{device}/config")
def set_device_config(device: str, payload: XmlPayload) -> Dict[str, str]:
    return _run_for_device(device, lambda client: client.set_config(payload.config_xml))


@router.put("/{device}/interfaces/{interface_name}")
def configure_interface(device: str, interface_name: str, payload: XmlPayload) -> Dict[str, str]:
    return _run_for_device(
        device, lambda client: client.configure_interface(interface_name, payload.config_xml)
    )


@router.get("/{device}/protocols/bgp")
def get_bgp(device: str) -> Dict[str, str]:
    return _run_for_device(device, lambda client: {"bgp": client.get_bgp()})


@router.put("/{device}/protocols/bgp")
def set_bgp(device: str, payload: XmlPayload) -> Dict[str, str]:
    return _run_for_device(device, lambda client: client.set_bgp(payload.config_xml))


@router.post("/{device}/firewall/rules")
def apply_firewall_rule(device: str, payload: XmlPayload) -> Dict[str, str]:
    return _run_for_device(device, lambda client: client.configure_firewall(payload.config_xml))
