

"""
Interface Controller
-------------------
Handles CRUD operations for device interfaces.
All endpoints are type hinted and include Google-style docstrings. Logging and error handling are included for all major actions.
"""


from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from loguru import logger
from app.common.errors import DeviceNotFoundError, ConfigNotFoundError, GatewayError

router = APIRouter()

# ==================== Interface Management ====================

@router.get('/{device}/interfaces')
def get_all_interfaces(device: str) -> Dict[str, Any]:
    """
    Get all interfaces for a device.

    Args:
        device (str): Device identifier.

    Returns:
        Dict[str, Any]: List of interfaces.
    """
    try:
        logger.info(f"Fetching all interfaces for device={device}")
        # Replace with actual interface retrieval logic
        interfaces = []
        logger.success(f"Interfaces retrieved for device {device}")
        return {"device": device, "interfaces": interfaces}
    except DeviceNotFoundError as ve:
        logger.error(f"Device not found: {ve}")
        raise HTTPException(status_code=404, detail=str(ve))
    except (ConfigNotFoundError, GatewayError) as ce:
        logger.error(f"Config or gateway error: {ce}")
        raise HTTPException(status_code=400, detail=str(ce))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get('/{device}/interfaces/{interface_id}')
def get_interface(device: str, interface_id: str) -> Dict[str, Any]:
    """
    Get configuration for a specific interface.

    Args:
        device (str): Device identifier.
        interface_id (str): Interface identifier.

    Returns:
        Dict[str, Any]: Interface details.
    """
    try:
        logger.info(f"Fetching interface config for device={device}, interface_id={interface_id}")
        # Replace with actual interface retrieval logic
        interface = {}
        logger.success(f"Interface {interface_id} retrieved for device {device}")
        return {"device": device, "interface_id": interface_id, "interface": interface}
    except DeviceNotFoundError as ve:
        logger.error(f"Device not found: {ve}")
        raise HTTPException(status_code=404, detail=str(ve))
    except (ConfigNotFoundError, GatewayError) as ce:
        logger.error(f"Config or gateway error: {ce}")
        raise HTTPException(status_code=400, detail=str(ce))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put('/{device}/interfaces/{interface_id}')
def modify_interface(device: str, interface_id: str, interface_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Modify configuration for a specific interface.

    Args:
        device (str): Device identifier.
        interface_id (str): Interface identifier.
        interface_data (Dict[str, Any]): New interface configuration.

    Returns:
        Dict[str, Any]: Result of modification.
    """
    try:
        logger.info(f"Modifying interface config for device={device}, interface_id={interface_id}: {interface_data}")
        # Replace with actual modification logic
        logger.success(f"Interface {interface_id} modified for device {device}")
        return {"device": device, "interface_id": interface_id, "result": "interface modified", "data": interface_data}
    except DeviceNotFoundError as ve:
        logger.error(f"Device not found: {ve}")
        raise HTTPException(status_code=404, detail=str(ve))
    except (ConfigNotFoundError, GatewayError) as ce:
        logger.error(f"Config or gateway error: {ce}")
        raise HTTPException(status_code=400, detail=str(ce))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/{device}/interfaces')
def create_interface(device: str, interface_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new interface for a device.

    Args:
        device (str): Device identifier.
        interface_data (Dict[str, Any]): Interface configuration.

    Returns:
        Dict[str, Any]: Result of creation.
    """
    try:
        logger.info(f"Creating interface for device={device}: {interface_data}")
        # Replace with actual creation logic
        logger.success(f"Interface created for device {device}")
        return {"device": device, "result": "interface created", "data": interface_data}
    except DeviceNotFoundError as ve:
        logger.error(f"Device not found: {ve}")
        raise HTTPException(status_code=404, detail=str(ve))
    except (ConfigNotFoundError, GatewayError) as ce:
        logger.error(f"Config or gateway error: {ce}")
        raise HTTPException(status_code=400, detail=str(ce))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete('/{device}/interfaces/{interface_id}')
def delete_interface(device: str, interface_id: str) -> Dict[str, Any]:
    """
    Delete an interface from a device.

    Args:
        device (str): Device identifier.
        interface_id (str): Interface identifier.

    Returns:
        Dict[str, Any]: Result of deletion.
    """
    try:
        logger.info(f"Deleting interface for device={device}, interface_id={interface_id}")
        # Replace with actual deletion logic
        logger.success(f"Interface {interface_id} deleted for device {device}")
        return {"device": device, "interface_id": interface_id, "result": "interface deleted"}
    except DeviceNotFoundError as ve:
        logger.error(f"Device not found: {ve}")
        raise HTTPException(status_code=404, detail=str(ve))
    except (ConfigNotFoundError, GatewayError) as ce:
        logger.error(f"Config or gateway error: {ce}")
        raise HTTPException(status_code=400, detail=str(ce))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
