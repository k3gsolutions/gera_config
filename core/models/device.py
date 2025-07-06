from pydantic import BaseModel
from typing import Optional, List

class Interface(BaseModel):
    name: str
    enabled: bool = True
    description: Optional[str] = None

class Device(BaseModel):
    id: int
    name: str
    site_id: int
    tenant_id: Optional[int]
    interfaces: List[Interface] = []