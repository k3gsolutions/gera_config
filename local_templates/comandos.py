# comandos.py

# Define os comandos como dicionário para diferentes cenários
COMANDOS = {
    "l2vpn-vlan": [
        "vlan $vlan_id_c",
        "description $customer_name",
        {
            "repeat": "interfaces", 
            "block": [
                "interface $interface", 
                "port hybrid tagged vlan $vlan_id_c"
            ]
        }
    ],
    
    "l2vpn-ptp": [
        "vlan $vlan_id_a",
        "interface vlanif $vlan_id_a",
        "mpls l2vc 10.200.1.1 $vlan_id_a mtu 2000",
        {
            "repeat": "interfaces", 
            "block": [
                "interface $interface", 
                "port hybrid tagged vlan $vlan_id_"
            ]
        },
        "# Configuração do lado B",
        "vlan $vlan_id_b",
        "interface vlanif $vlan_id_b",
        {
            "repeat": "interfaces", 
            "block": [
                "interface $interface", 
                "port hybrid tagged vlan $vlan_id_b"
            ]
        },
        "mpls l2vc 10.200.1.1 $vlan_id_b mtu 2000"
    ],    
    "l2vpn-ptmp-ldp": [
        "vsi $vpls_name",
        "description $DESCRIPTION",
        "pwsignal ldp",
        "vsi-id $vpls_id",
        "mtu 2000",
        {
            "repeat": "loopback_ips", 
            "block": [
                "peer $loopback_ip",
            ]
        },
        # Configuracao de Interface
        "vlan $vlan_id",
        "interface $interface",
        "port hybrid tagged vlan $vlan_id_a",
        "$sites_b_configs"
    ],
    "l2vpn-ptmp-bgpad": [
        "vsi $vpls_name",
        "description $DESCRIPTION"
        "bgp-ad"
        "vpls-id 123456:602"
        "vpn-target 123456:602 import-extcommunity"
        "vpn-target 123456:602 export-extcommunity"
        "mtu 2000"
        "encapsulation ethernet"
        "vlan $vlan_id_a",
        "interface xg 0/0/1",
        "port hybrid tagged vlan $vlan_id_a",
        "",
        "# Configurações dos sites adicionais",
        "$sites_b_configs"
    ],
    "l3vpn-cl-ded": [
        "vlan   $vlan_id_c",
        "description $customer_name",
        "interface vlanif $vlan_id_c",
        "description $customer_name",
        "interface $interface",
        "port hybrid tagged vlan $vlan_id_c",
        "ipv6 enable",
        "ipv6 address $ipv6_prefix",
        "statistic enable",
        "quit"
    ],
        "l3vpn-cl-dedic-rt": [
        "vlan   $vlan_id_c",
        "description $customer_name",
        "interface vlanif $vlan_id_c",
        "description $customer_name",
        "interface $interface",
        "port hybrid tagged vlan $vlan_id_c",
        "ipv6 enable",
        "ipv6 address $ipv6_prefix",
        "statistic enable",
        "quit"
    ]
}

def obter_comandos(tipo_cenario, substitutos=None, customer_name=None):
    """
    Retorna os comandos para o cenário especificado com variáveis substituídas.
    
    Args:
        tipo_cenario (str): Nome do cenário (ex: "l2vpn-vlan")
        substitutos (dict, optional): Dicionário com variáveis para substituir.
                                     Ex: {"vlan_id_c": "100", "interfaces": ["Eth1", "Eth2"]}
    
    Returns:
        list: Lista de comandos com as substituições aplicadas
    """
    if tipo_cenario not in COMANDOS:
        return []
    
    comandos = COMANDOS[tipo_cenario].copy()
    resultado = []
    
    for comando in comandos:
        # Se for uma string simples, faz a substituição normal
        if isinstance(comando, str):
            if substitutos:
                for var, valor in substitutos.items():
                    # Ignora a variável que será tratada em bloco repetitivo
                    if var != "interfaces" and var != "sites_b_configs":
                        comando = comando.replace(f"${var}", str(valor))
            resultado.append(comando)
        
        # Se for um bloco repetitivo
        elif isinstance(comando, dict) and "repeat" in comando:
            repeat_key = comando["repeat"]
            block = comando.get("block", [])
            # Verifica se há substituição para a chave de repetição e se é uma lista
            if substitutos and repeat_key in substitutos and isinstance(substitutos[repeat_key], list):
                for item in substitutos[repeat_key]:
                    for linha in block:
                        nova_linha = linha
                        # Substitui o marcador especial $interface pelo valor do item
                        nova_linha = nova_linha.replace("$interface", str(item))
                        # Realiza as demais substituições (exceto a variável repetida)
                        for var, valor in substitutos.items():
                            if var != repeat_key and var != "sites_b_configs":
                                nova_linha = nova_linha.replace(f"${var}", str(valor))
                        resultado.append(nova_linha)
            else:
                # Se não houver dado para repetir, ignora o bloco ou pode inserir um valor padrão
                pass
        else:
            resultado.append(str(comando))
    
    return resultado

def gerar_configs_sites_b(sites_info):
    """
    Gera as configurações para múltiplos sites B no cenário l2vpn-ptmp.
    
    Args:
        sites_info (list): Lista de dicionários com informações dos sites B.
                          Ex: [{"site_name": "Site B1", "vlan_id_b": 100}, ...]
    
    Returns:
        list: Lista de comandos para todos os sites B
    """
    configs = []
    
    for site in sites_info:
        configs.append(f"# Configuração para {site['site_name']}")
        configs.append(f"vlan {site['vlan_id_b']}")
        configs.append(f"interface vlanif {site['vlan_id_b']}")
        configs.append(f"port hybrid tagged vlan {site['vlan_id_b']}")
        configs.append("")  # Linha em branco para separar as configurações
    
    return configs
