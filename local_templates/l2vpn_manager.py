from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class L2VPNConfig:
    customer_name: str
    vlan_id: int
    device_id: int
    selected_interfaces: List[str]
    untag_interfaces: Dict[str, bool]

class L2VPNManager:
    VLAN_MIN = 2
    VLAN_MAX = 4094
    
    def __init__(self):
        self.config = None
    
    def validate_vlan_id(self, vlan_id: int) -> bool:
        return self.VLAN_MIN <= vlan_id <= self.VLAN_MAX
    
    def validate_customer_name(self, name: str) -> bool:
        return bool(name and (name.startswith("CL-") or name.startswith("AS")))
    
    def generate_vlan_config(self, config: L2VPNConfig) -> str:
        final_lines = []
        final_lines.append(f"vlan {config.vlan_id}")
        final_lines.append(f"description {config.customer_name}")
        
        for iface_name in config.selected_interfaces:
            final_lines.append(f"interface {iface_name}")
            if config.untag_interfaces.get(iface_name, False):
                final_lines.extend([
                    f"port hybrid untagged vlan {config.vlan_id}",
                    f"port hybrid pvid vlan {config.vlan_id}"
                ])
            else:
                final_lines.append(f"port hybrid tagged vlan {config.vlan_id}")
        
        return "\n".join(final_lines)