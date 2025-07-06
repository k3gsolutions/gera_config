# utils/rp_name.py
import ipaddress

class RpNameFormatter:
    """
    Classe responsável por converter um prefixo (ex.: 45.169.160.0/24) 
    em uma string rp_name (ex.: 045-169-160-000-24).
    """

    @staticmethod
    def convert(prefix_cidr: str) -> str:
        """
        Converte um prefixo IPv4 ou IPv6 em 'rp_name'.
        Exemplo IPv4: 45.169.160.0/24 -> 045-169-160-000-24
        Exemplo IPv6: 2804:5984::/32  -> 2804-5984-0000-0000-32 (ajuste conforme sua regra)
        """
        if "/" in prefix_cidr:
            net, mask = prefix_cidr.split("/")
        else:
            net, mask = prefix_cidr, ""

        try:
            ip_obj = ipaddress.ip_address(net)
            if ip_obj.version == 4:
                # IPv4
                octets = net.split(".")
                # zero-padding até 3 dígitos
                octets_zp = [o.zfill(3) for o in octets]
                rp_name = "-".join(octets_zp + [mask])
            else:
                # IPv6
                ip6 = ipaddress.IPv6Address(net)
                exploded = ip6.exploded.split(":")
                # Ex.: ['2804','5984','0000','0000','0000','0000','0000','0000']
                # Pega alguns blocos (ajuste conforme sua necessidade)
                rp_name = "-".join(exploded[:4] + [mask])
        except ValueError:
            # fallback simples se der erro
            rp_name = prefix_cidr.replace(".", "-").replace(":", "-").replace("/", "-")

        return rp_name
