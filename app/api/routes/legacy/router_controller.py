"""
Router Controller
-----------------
Handles NETCONF device operations: configuration and operational state retrieval.
All endpoints are type hinted and include Google-style docstrings. Logging and error handling are robust and consistent.
"""


from fastapi import APIRouter, HTTPException
from typing import Dict
from loguru import logger
from app.bl.factories.client_factory import NCCClientFactory
from app.common.errors import DeviceNotFoundError, ConfigNotFoundError, ClientMappingError, GatewayError

router = APIRouter()

# ==================== Configuration Retrieval ====================

@router.get('/{device}/get-config')
def get_config(device: str) -> Dict[str, str]:
    """
    Retrieve the NETCONF configuration for a given device.

    Args:
        device (str): Device identifier.

    Returns:
        Dict[str, str]: Configuration data.
    """
    try:
        logger.info(f"API call: get_config for device {device}")
        client = NCCClientFactory.get_client(device)
        config_data = client.get_config()
        logger.success(f"Config retrieved for device {device}")
        return {"config": config_data}
    except DeviceNotFoundError as ve:
        logger.error(f"Device not found: {ve}")
        raise HTTPException(status_code=404, detail=str(ve))
    except (ConfigNotFoundError, ClientMappingError) as ce:
        logger.error(f"Config or mapping error: {ce}")
        raise HTTPException(status_code=400, detail=str(ce))
    except GatewayError as ge:
        logger.error(f"Gateway error: {ge}")
        raise HTTPException(status_code=502, detail=str(ge))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==================== Operational State Retrieval ====================

@router.get('/{device}/operational-state')
def get_operational_state(device: str) -> Dict[str, str]:
    """
    Retrieve the operational state of the device.

    Args:
        device (str): Device identifier.

    Returns:
        Dict[str, str]: Operational state data.
    """
    try:
        logger.info(f"API call: get_operational_state for device {device}")
        client = NCCClientFactory.get_client(device)
        state_data = client.get_operational_state()
        logger.success(f"Operational state retrieved for device {device}")
        return {"operational_state": state_data}
    except DeviceNotFoundError as ve:
        logger.error(f"Device not found: {ve}")
        raise HTTPException(status_code=404, detail=str(ve))
    except (ConfigNotFoundError, ClientMappingError) as ce:
        logger.error(f"Config or mapping error: {ce}")
        raise HTTPException(status_code=400, detail=str(ce))
    except GatewayError as ge:
        logger.error(f"Gateway error: {ge}")
        raise HTTPException(status_code=502, detail=str(ge))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
