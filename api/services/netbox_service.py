from typing import List, Dict
import requests
from fastapi import HTTPException

class NetboxService:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json"
        }

    async def get_tenants(self) -> List[Dict]:
        """Busca todos os tenants do Netbox"""
        tenants = []
        next_url = f"{self.base_url}/tenancy/tenants/"
        
        try:
            while next_url:
                response = requests.get(next_url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                tenants.extend(data.get("results", []))
                next_url = data.get("next")
            return tenants
        except requests.exceptions.RequestException as e:
            raise HTTPException(status_code=500, detail=f"Erro ao consultar Netbox: {str(e)}")