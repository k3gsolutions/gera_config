from fastapi import APIRouter, Depends, HTTPException
from typing import List
from ..services.netbox_service import NetboxService
from ..dependencies import get_netbox_service

router = APIRouter(prefix="/api/netbox", tags=["netbox"])

@router.get("/tenants")
async def get_tenants(
    netbox_service: NetboxService = Depends(get_netbox_service)
) -> List[dict]:
    """Endpoint para buscar todos os tenants"""
    return await netbox_service.get_tenants()

@router.get("/devices/{site_id}")
async def get_devices_by_site(
    site_id: int,
    service_type: str = None,
    netbox_service: NetboxService = Depends(get_netbox_service)
) -> List[dict]:
    """Endpoint para buscar dispositivos por site"""
    return await netbox_service.get_devices_by_site(site_id, service_type)