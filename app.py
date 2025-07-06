import sys
import os
import requests
import streamlit as st
from streamlit_tree_select import tree_select
import subprocess
from dotenv import load_dotenv
from local_templates import comandos
import re
import ipwhois
import ipaddress
import base64
from io import StringIO
from script import NetboxTenant, sync_tenants_to_db, Session, Base, engine
from local_templates.l2vpn_manager import L2VPNManager, L2VPNConfig
from bgp_config import BGPConfig
from jinja2 import Environment, BaseLoader, TemplateNotFound




class HierarchicalLoader(BaseLoader):
    def __init__(self, template_file):
        with open(template_file, "r", encoding='utf-8') as f:
            self.data = f.read()
        self.templates = self._parse_templates(self.data)

    def _parse_templates(self, data):
        """Parse the templates from the data"""
        templates = {}
        parts = data.split('---')
        for part in parts:
            if not part.strip():
                continue
            lines = part.strip().splitlines()
            if  not lines:
                continue
            # A primeira linha é o caminho do template, ex: "template/l2vpn/vlan"
            template_path = lines[0].strip()
            # O restante são as linhas do template
            template_content = "\n".join(lines[1:]).strip()
            templates[template_path] = template_content
        return templates

    def get_source(self, environment, template):
        if template in self.templates:
            source = self.templates[template]
            return source, None, lambda: True
        else:
            raise TemplateNotFound(template)

loader = HierarchicalLoader('templates/templates.txt')
env = Environment(loader=loader)


load_dotenv()

# Injeção de CSS para customizar a lista de interfaces
st.markdown(
    """
    <style>
    .interface-list * {
        font-family: "Courier New", Courier, monospace;
        font-size: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Endereços de API
NETBOX_URL = os.getenv('NETBOX_URL')
API_TOKEN = os.getenv('API_TOKEN')
JS_TOKEN = os.getenv('JS_TOKEN')

TENANT_LIST_URL = f"{NETBOX_URL}/tenancy/tenants/"
SITE_URL = f"{NETBOX_URL}/dcim/sites/"
DEVICE_URL = f"{NETBOX_URL}/dcim/devices/"
EXTRA_TAG = f"{NETBOX_URL}/extras/tags/"
INTERFACES_URL = f"{NETBOX_URL}/dcim/interfaces/"
IPAM_URL = f"{NETBOX_URL}/ipam/ip-addresses/"

# Cabeçalhos da requisição
HEADERS = {
    "Authorization": f"Token {API_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# Título e estilo da sidebar
st.sidebar.title("Selecione o Dispositivo")
st.markdown(
    """
    <style>
    [data-testid="stSidebar"] > div:first-child {
        background-color: #4682B4;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Cabeçalho da aplicação
col_icon, col_title=st.columns([0.4, 0.6])
with col_icon:
    st.image("https://k3gsolutions.com.br/wp-content/uploads/2025/01/logo-monitoring-k3g-e1738253202895.png", width=300)
with col_title:
    st.title("K3G Device Manager")

# -----------------------------------------------------------------------------
# Funções auxiliares
# -----------------------------------------------------------------------------
# IPv4 and IPv6 regex patterns
# Bloco L3VPN
IPV4_PATTERN = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
IPV6_PATTERN = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"


def is_ipv4(prefix):
    """Check if a prefix is IPv4 using regex pattern"""
    network = prefix.split('/')[0] if '/' in prefix else prefix
    return bool(re.match(IPV4_PATTERN, network))

def is_ipv6(prefix):
    """Check if a prefix is IPv6 using regex pattern"""
    network = prefix.split('/')[0] if '/' in prefix else prefix
    return bool(re.match(IPV6_PATTERN, network))

def get_asn_prefixes(asn):
    """Retrieve prefixes for an ASN using RIPE API and categorize them"""
    try:
        asn_number = str(asn).lstrip('AS')
        response = requests.get(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_number}")
        asn_info_response = requests.get(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_number}")
        asn_info = asn_info_response.json()
        full_asn_name = asn_info.get('data', {}).get('holder', 'Unknown ASN')
        asn_name = full_asn_name.split()[0] if full_asn_name else 'Unknown'
        data = response.json()
        ipv4_prefixes = []
        ipv6_prefixes = []
        if 'data' in data and 'prefixes' in data['data']:
            for prefix_entry in data['data']['prefixes']:
                if 'prefix' in prefix_entry:
                    prefix = prefix_entry['prefix']
                    if is_ipv4(prefix):
                        ipv4_prefixes.append(prefix)
                    elif is_ipv6(prefix):
                        ipv6_prefixes.append(prefix)
        return ipv4_prefixes, ipv6_prefixes, asn_name
    except Exception as e:
        st.error(f"Error fetching ASN data: {str(e)}")
        return [], []

def prefix_to_rp_name(prefix_cidr: str) -> str:
    """
    Converte um prefixo em uma string 'rp_name'.
    Exemplos:
      45.169.160.0/24 -> 45-169-160-000-24
      2804:5984::/32  -> 2804-5984-0000-32
    """
    # Separa rede e máscara
    if "/" in prefix_cidr:
        net, mask = prefix_cidr.split("/")
    else:
        net, mask = prefix_cidr, ""

    try:
        ip_obj = ipaddress.ip_address(net)
        # Se for IPv4
        if ip_obj.version == 4:
            octets = net.split(".")
            # Se o octet for "0", vira "000"; caso contrário, mantém
            octets_form = [o if o != "0" else "000" for o in octets]
            rp_name = "-".join(octets_form + [mask])
        # Se for IPv6
        else:
            ip6 = ipaddress.IPv6Address(net)
            exploded = ip6.exploded.split(":")  # ex: ['2804','5984','0000','0000','0000','0000','0000','0000']
            # Pega apenas os 3 primeiros blocos e depois adiciona a máscara
            rp_name = "-".join(exploded[:3] + [mask])
    except ValueError:
        # Se der erro no parse, faz um fallback simples
        rp_name = prefix_cidr.replace(".", "-").replace(":", "-").replace("/", "-")

    return rp_name

def split_prefix_mask(prefix_cidr):
    """Split CIDR notation into prefix and mask"""
    if '/' in prefix_cidr:
        prefix, mask = prefix_cidr.split('/')
        return prefix, mask
    return prefix_cidr, ""

def create_download_link(text_content, filename="config.txt"):
    """Create a download link for text content"""
    b64 = base64.b64encode(text_content.encode()).decode()
    href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">Download {filename}</a>'
    return href

def get_device_primary_ip(device_id):
    """
    Retorna o IP primário (IPv4 ou IPv6) de um dispositivo no NetBox, 
    consultando primeiro o device e depois o ip-address pelo ID.
    """
    # 1) Consulta o device para descobrir o ID do primary_ip
    device_url = f"{DEVICE_URL}{device_id}/"
    resp_device = requests.get(device_url, headers=HEADERS)
    if resp_device.status_code != 200:
        return "N/A"  # ou lançar uma exceção
    
    device_data = resp_device.json()
    primary_ip_obj = device_data.get("primary_ip")
    if not primary_ip_obj:
        return "N/A"

    # 2) Extrai o ID do primary_ip
    primary_ip_id = primary_ip_obj.get("id")
    if not primary_ip_id:
        return "N/A"
    
    # 3) Consulta o /ipam/ip-addresses/<id> para obter o campo "address"
    ip_url = f"{NETBOX_URL}/ipam/ip-addresses/{primary_ip_id}/"
    resp_ip = requests.get(ip_url, headers=HEADERS)
    if resp_ip.status_code != 200:
        return "N/A"
    
    ip_data = resp_ip.json()
    address_with_mask = ip_data.get("address", "N/A")  # ex: "10.201.1.1/32"
    if address_with_mask == "N/A":
        return "N/A"
    
    # 4) Extrai apenas o IP (sem /32, /24 etc.)
    ip_only = address_with_mask.split("/")[0]  # "10.201.1.1"
    return ip_only

def generate_config(variables,
                    ipv4_prefixes=None,
                    ipv6_prefixes=None,
                    template_file=None,
                    check_md5=False
):
    """Generate configuration by replacing variables in the template"""
    
    # Lê o template a partir do arquivo local "templates/*.txt"
    # with open("templates/hw_bgp_ups_comm.txt", "r") as f:
    #     template = f.read()
    with open(template_file, "r") as f:
        template = f.read()

    if not check_md5:
        template = '\n'.join([
            line for line in template.split('\n')
            if 'password simple $MD5' not in line
        ])
    config = template
    
    if ipv4_prefixes:
        v4_prefix_lines = []
        for i, prefix in enumerate(ipv4_prefixes, 100):
            prefix_addr, mask = split_prefix_mask(prefix)
            v4_prefix_lines.append(f"ip ip-prefix C{variables['CIRCUITO']}-PREFIX-PREFERENCE-IPV4 index {i} permit {prefix_addr} {mask} less-equal 24")
        config = config.replace("ip ip-prefix C$CIRCUITO-PREFIX-PREFERENCE-IPV4 index 100 permit $PREFIXOSv4 $MASKv4 less-equal 24", "\n".join(v4_prefix_lines))
    
    if ipv6_prefixes:
        v6_prefix_lines = []
        for i, prefix in enumerate(ipv6_prefixes, 100):
            prefix_addr, mask = split_prefix_mask(prefix)
            v6_prefix_lines.append(f"ip ipv6-prefix C{variables['CIRCUITO']}-PREFIX-PREFERENCE-IPV6 index {i} permit {prefix_addr} {mask}")
        config = config.replace("ip ipv6-prefix C$CIRCUITO-PREFIX-PREFERENCE-IPV6 index 100 permit $PREFIXOSv6 $MASKv6", "\n".join(v6_prefix_lines))


    for var, value in variables.items():
        config = config.replace(f"${var}", value)
    
    for i in range(10000, 10010):
        original = f"C$CIRCUITO-"
        replacement = f"C{variables['CIRCUITO']}-"
        config = config.replace(original, replacement)
    
    return config

if 'ipv4_prefixes' not in st.session_state:
    st.session_state.ipv4_prefixes = []
if 'ipv6_prefixes' not in st.session_state:
    st.session_state.ipv6_prefixes = []
if 'asn_lookup_done' not in st.session_state:
    st.session_state.asn_lookup_done = False

# -----------------------------------------------------------------------------



def load_template_from_comandos(tipo_cenario, substitutos):
    """Carrega e processa comandos do módulo comandos.py."""
    comandos_lista = comandos.obter_comandos(tipo_cenario, substitutos)
    return "\n".join(comandos_lista)

def get_interfaces_by_device(device_id):
    """Consulta as interfaces de um dispositivo no NetBox."""
    interfaces = []
    interfaces_url = f"{INTERFACES_URL}?device_id={device_id}"
    next_interface_url = interfaces_url

    while next_interface_url:
        interface_response = requests.get(next_interface_url, headers=HEADERS)
        if interface_response.status_code != 200:
            st.error(f"Erro ao consultar interfaces: {interface_response.status_code}")
            break
        interface_data = interface_response.json()
        interfaces.extend(interface_data.get("results", []))
        next_interface_url = interface_data.get("next")
    return interfaces

def show_device_selector(devices, title="Selecione o dispositivo", container=None, unique_id=None):
    """Exibe um selectbox simples de dispositivos."""
    display_container = container if container else st.sidebar
    if devices:
        device_options = {device["id"]: device["name"] for device in devices}
        
        # Monta a key usando o title e o unique_id, se houver
        if unique_id is not None:
            final_key = f"device_selector_{title}_{unique_id}"
        else:
            final_key = f"device_selector_{title}"
        
        selected_device_id = display_container.selectbox(
            title,
            options=list(device_options.keys()),
            format_func=lambda did: device_options[did],
            key=final_key
        )
        return selected_device_id
    else:
        st.sidebar.info("Nenhum dispositivo encontrado.")
        return None



# -----------------------------------------------------------------------------
# Lógica principal
# -----------------------------------------------------------------------------

# Consulta de tenants (com paginação)
tenants = []
next_url = TENANT_LIST_URL
while next_url:
    response = requests.get(next_url, headers=HEADERS)
    if response.status_code != 200:
        st.error(f"Erro na consulta de tenants: {response.status_code}")
        break
    data = response.json()
    tenants.extend(data.get("results", []))
    next_url = data.get("next")

if tenants:
    with st.spinner("Sincronizando tenants com o banco de dados local..."):
        try:
            # Cria as tabelas se não existirem
            Base.metadata.create_all(engine)
            # Sincroniza os dados
            sync_tenants_to_db(tenants)
            st.success("Tenants sincronizados com sucesso!")
        except Exception as e:
            st.error(f"Erro ao sincronizar tenants: {str(e)}")

# Após a sincronização, carrega os tenants do banco local
session = Session()
try:
    db_tenants = session.query(NetboxTenant).all()
    tenant_options = {tenant.netbox_id: tenant.name for tenant in db_tenants}
finally:
    session.close()

if not tenant_options:
    st.warning("Nenhum tenant disponível.")
    st.stop()
    
# Mapeia tenant_id -> tenant_name
tenant_options = {tenant["id"]: tenant["name"] for tenant in tenants}
tenant_list = ["< Selecione o Tenante >"] + list(tenant_options.keys())

selected_tenant_id = st.sidebar.selectbox(
    "Selecione o Tenant",
    options=tenant_list,
    format_func=lambda x: tenant_options[x] if x in tenant_options else x
)

if selected_tenant_id != "< Selecione o Tenante >":
    # Cria a árvore de serviços
    nodes = [
        {
            "label": "L2VPN",
            "value": "l2vpn",
            "expanded": True,
            "selected": False,
            "children": [
                {"label": "✅ VLAN", "value": "l2vpn-vlan", "selectable": True},
                {"label": "✅ Point-to-point", "value": "l2vpn-ptp", "selectable": True},
                {"label": "✅ Point-to-multipoint", "value": "l2vpn-ptmp", "selectable": True}
            ]
        },
        {
            "label": "L3VPN",
            "value": "l3vpn",
            "children": [
                {
                    "label": "✅ Cliente Dedicado", "value": "cl_dedicado"
                    },
                {
                    "label": "Peering BGP Simples", "value": "peering_bgp", "children": [
                        {"label": "✅ Cliente de Transito", "value": "bgp_cl_trans", "expanded": True, "selectable": False}, # Config de Cliente de Transito
                        {"label": "✅ Upstream / Operadora", "value": "bgp_ups"}, # Config de Operadora por route-policy
                    ]
                },
                {
                    "label": "Peering BGP Community", "value": "peering_bgp_comm", "children": [
                        {"label": "✅ Upstream / Operadora (Comm)", "value": "bgp_ups_comm"}, # Config de Operadora por Community
                        {"label": "✅ Peering CDN", "value": "peering_cdn_comm"},
                        {"label": "Peering IX", "value": "bgp_ixbr_comm"},
                    ]
                }
            ]
        },

    ]
    
    with st.sidebar:
        selected_service_dict = tree_select(nodes=nodes, show_expand_all=True)
    
    # Consulta sites do tenant selecionado
    sites_filtrados_url = f"{SITE_URL}?tenant_id={selected_tenant_id}"
    tenant_sites = []
    next_site_url = sites_filtrados_url
    while next_site_url:
        site_response = requests.get(next_site_url, headers=HEADERS)
        if site_response.status_code != 200:
            st.error(f"Erro ao consultar sites: {site_response.status_code}")
            break
        site_data = site_response.json()
        tenant_sites.extend(site_data.get("results", []))
        next_site_url = site_data.get("next")
    
    # Funções para buscar dispositivos
    def get_devices_by_site(site_id):
        devices = []
        devices_url = f"{DEVICE_URL}?site_id={site_id}&role=10-ativos-de-malha&role=12-ativos-de-borda"
        next_device_url = devices_url
        while next_device_url:
            device_response = requests.get(next_device_url, headers=HEADERS)
            if device_response.status_code != 200:
                st.error(f"Erro ao consultar os dispositivos: {device_response.status_code}")
                break
            device_data = device_response.json()
            devices.extend(device_data.get("results", []))
            next_device_url = device_data.get("next")
        return devices
    
    def get_devices_by_tenant(tenant_id):
        all_devices = []
        for site in tenant_sites:
            site_id = site["id"]
            devices = get_devices_by_site(site_id)
            all_devices.extend(devices)
        return all_devices
    
    # Caso nenhum serviço esteja selecionado
    if not selected_service_dict or not selected_service_dict.get("checked"):
        st.write(f"Exibindo todos os dispositivos do tenant: {tenant_options[selected_tenant_id]}")
        tenant_devices = get_devices_by_tenant(selected_tenant_id)
        show_device_selector(tenant_devices, "Selecione um dispositivo do tenant")
    
    else:
        # Algum serviço foi selecionado
        service_val = selected_service_dict["checked"][0]
 #       st.write("Serviço selecionado:", service_val)

        # ---------------------------------------------------------------------
        # LÓGICA ESPECÍFICA: L2VPN - VLAN
        # ---------------------------------------------------------------------
        if service_val == "l2vpn-vlan":

            customer_name = st.text_input("Nome do Cliente: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)",
            help="Nome deve começar com CL- ou AS")
           
            # Seleciona site
            site_dict = {site["id"]: site["name"] for site in tenant_sites}
            selected_site_id = st.sidebar.selectbox(
                "Selecione o Site",
                options=list(site_dict.keys()),
                format_func=lambda sid: site_dict[sid]
            )
            
            # Seleciona dispositivo do site
            colC1, colC2 = st.sidebar.columns([0.70, 0.25])
            site_devices = get_devices_by_site(selected_site_id)
            selected_device_id = show_device_selector(site_devices, "Dispositivos disponíveis", container=colC1)
            vlan_id_c = colC2.number_input("VLAN C", min_value=2,max_value=4094,
            step=1)

            # -- Inicializa o estado para as interfaces e untag se necessário --
            if "vlan_selected_interfaces" not in st.session_state:
                st.session_state["vlan_selected_interfaces"] = []  # lista de nomes de interfaces
            if "vlan_untag_dict" not in st.session_state:
                st.session_state["vlan_untag_dict"] = {}  # dict iface -> bool (True se untag)
            
            # Exibir a interface side-by-side APENAS se houver um dispositivo selecionado
            if selected_device_id:
                st.subheader("Seleção de Interfaces do Dispositivo")

                # -----------------------------------------------------------------
                # Carrega as interfaces disponíveis (ativas)
                # -----------------------------------------------------------------
                all_intfs = get_interfaces_by_device(selected_device_id)
                active_intfs = [i for i in all_intfs if i.get("enabled", True)]

                # Se uma interface não estiver na lista st.session_state["vlan_selected_interfaces"],
                # significa que está "disponível"
                available_intfs = [
                    i["name"] for i in active_intfs
                    if i["name"] not in st.session_state["vlan_selected_interfaces"]
                ]

                # Cria layout de 3 colunas:
                #  - col_left: lista de interfaces disponíveis
                #  - col_mid: botões Adicionar e Remover
                #  - col_right: lista de interfaces selecionadas + checkbox untag
                col_left, col_mid, col_right = st.columns([2, 1, 2])

                # 1) Coluna da esquerda: Interfaces disponíveis
                with col_left:
                    st.markdown("**Interfaces Disponíveis**")
                    selected_for_add = st.multiselect(
                        label="",
                        options=available_intfs,
                        default=[]
                    )

                # 2) Coluna do meio: Botões
                with col_mid:
                    st.write("")  # espaçamento
                    if st.button("Adicionar >>"):
                        for iface_name in selected_for_add:
                            if iface_name not in st.session_state["vlan_selected_interfaces"]:
                                st.session_state["vlan_selected_interfaces"].append(iface_name)
                                # Se não existir no dict untag, define como False por padrão
                                if iface_name not in st.session_state["vlan_untag_dict"]:
                                    st.session_state["vlan_untag_dict"][iface_name] = False
                    st.write("")
                    st.write("")
                    # Para remover, precisamos selecionar quais da lista da direita remover
                    # Faremos outro multiselect (ou checkboxes) na coluna da direita
                    # Aqui só colocamos o botão:
                    if st.button("<< Remover"):
                        # A remoção será tratada logo abaixo (col_right)
                        # ou podemos remover aqui se quisermos. 
                        # Para simplificar, faremos a remoção no loop da direita com checkboxes
                        pass

                # 3) Coluna da direita: Interfaces selecionadas + checkbox untag
                with col_right:
                    st.markdown("**Interfaces Selecionadas**")
                    # Precisamos exibir cada interface com:
                    #  - um checkbox "Untag"
                    #  - um checkbox ou algo para marcar a remoção
                    # Aqui usaremos checkboxes de remoção também, ou um multiselect

                    to_remove = []
                    for iface_name in st.session_state["vlan_selected_interfaces"]:
                        # Exibe a interface + checkbox untag
                        untag_value = st.session_state["vlan_untag_dict"].get(iface_name, False)

                        cols_intf = st.columns([6, 4])
                        # Nome da interface
                        cols_intf[0].write(f"**{iface_name}**")
                        # Checkbox untag
                        new_untag = cols_intf[1].checkbox(
                            "Untag",
                            value=untag_value,
                            key=f"untag_{iface_name}"
                        )
                        st.session_state["vlan_untag_dict"][iface_name] = new_untag

                        # Checkbox para remover do quadro
                        if st.checkbox(f"Remover {iface_name}", key=f"remove_{iface_name}"):
                            to_remove.append(iface_name)

                    # Efetua a remoção
                    if to_remove:
                        for iface_name in to_remove:
                            if iface_name in st.session_state["vlan_selected_interfaces"]:
                                st.session_state["vlan_selected_interfaces"].remove(iface_name)
                            if iface_name in st.session_state["vlan_untag_dict"]:
                                st.session_state["vlan_untag_dict"].pop(iface_name, None)

                # -----------------------------------------------------------------
                # Botão final de Execução
                # -----------------------------------------------------------------
                st.write("---")
                if st.button("Confirmar seleção e Executar"):
                    if not all([customer_name, selected_device_id, vlan_id_c]):
                        st.error("Todos os campos são obrigatórios")
                    else:
                        config = L2VPNConfig(
                            customer_name=customer_name,
                            vlan_id=vlan_id_c,
                            device_id=selected_device_id,
                            selected_interfaces=st.session_state["vlan_selected_interfaces"],
                            untag_interfaces=st.session_state["vlan_untag_dict"]
                        )
                        

                    template = env.get_template('template/l2vpn/vlan')
                    # Prepara os dados para o template
                    template_data = {
                        'device_name': next(d['name'] for d in site_devices if d['id'] == selected_device_id),
                        'customer_name': customer_name,
                        'vlan_id_a': str(vlan_id_c),
                        'interfaces': [
                            {
                                'name': iface_name,
                                'untag': st.session_state["vlan_untag_dict"].get(iface_name, False)
                            }
                            for iface_name in st.session_state["vlan_selected_interfaces"]
                        ]
                    }
                    # Renderiza o template com os dados
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    # Adiciona botão de download
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l2vpn_vlan_{customer_name}_{vlan_id_c}.txt"
                        ),
                        unsafe_allow_html=True
                    )
        # ---------------------------------------------------------------------
        # L2VPN - Point-to-point
        # ---------------------------------------------------------------------
        elif service_val == "l2vpn-ptp":
            customer_name = st.text_input("Nome do Cliente: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)")
            
            # Site A selection
            selected_site_a = st.sidebar.selectbox(
                "Selecione o Site A",
                options=[site["id"] for site in tenant_sites],
                format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            colA1, colA2, colA3 = st.sidebar.columns([0.55, 0.15, 0.25])
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site A", container=colA1)
            vlan_id_a = colA2.number_input("VLAN A", min_value=2, max_value=4094, step=1)
            untag_a = colA3.checkbox("Untag", value=False, key="untag_vlan_a")
            
            # Interface selection for Device A
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a"
                )
            
            # Site B selection
            site_options_b = {k: v for k, v in {site["id"]: site["name"] for site in tenant_sites}.items() if k != selected_site_a}
            selected_site_b = st.sidebar.selectbox(
                "Selecione o Site B",
                options=list(site_options_b.keys()),
                format_func=lambda sid: site_options_b[sid]
            )
            colB1, colB2, colB3 = st.sidebar.columns([0.55, 0.15, 0.25])
            site_b_devices = get_devices_by_site(selected_site_b)
            selected_device_b = show_device_selector(site_b_devices, "Dispositivo do Site B", container=colB1)
            vlan_id_b = colB2.number_input("VLAN B", min_value=2, max_value=4094, step=1)
            untag_b = colB3.checkbox("Untag", value=False, key="untag_vlan_b")
            
            # Interface selection for Device B
            if selected_device_b:
                interfaces_b = get_interfaces_by_device(selected_device_b)
                active_interfaces_b = [i["name"] for i in interfaces_b if i.get("enabled", True)]
                selected_interface_b = st.sidebar.selectbox(
                    "Interface do Device B",
                    options=active_interfaces_b,
                    key="interface_b"
                )

            if st.sidebar.button("Executar"):
                if all([customer_name, selected_device_a, selected_device_b, vlan_id_a, vlan_id_b, selected_interface_a, selected_interface_b]):
                    template = env.get_template('template/l2vpn/ptp')
                    template_data = {
                        'customer_name': customer_name,
                        'device_name_a': next(d['name'] for d in site_a_devices if d['id'] == selected_device_a),
                        'device_name_b': next(d['name'] for d in site_b_devices if d['id'] == selected_device_b),
                        'vlan_id_a': str(vlan_id_a),
                        'vlan_id_b': str(vlan_id_b),
                        'interface_a': {
                            'name': selected_interface_a,
                            'untag': untag_a
                        },
                        'interface_b': {
                            'name': selected_interface_b,
                            'untag': untag_b
                        }
                    }
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l2vpn_ptp_{customer_name}_{vlan_id_a}_{vlan_id_b}.txt"
                        ),
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Por favor, preencha todos os campos obrigatórios.")
                    
        # ---------------------------------------------------------------------
        # L2VPN - Point-to-multipoint
        # ---------------------------------------------------------------------
        elif service_val == "l2vpn-ptmp":
            selected_site_a = st.sidebar.selectbox(
            "Selecione o Site A",
            options=[site["id"] for site in tenant_sites],
            format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            # st.sidebar.markdown("**Dispositivos do Site A:**")
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site A")
            loopback_a = None
            # Add interface selection for Device A
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a_ptmp"
                )
                loopback_a = get_device_primary_ip(selected_device_a)
            st.sidebar.markdown("--------------------------------------------------")
            # Initialize sites_b_data dictionary
            sites_b_data = {}
            site_b_loopbacks = []

            site_options_b = {
            k: v for k, v in {site["id"]: site["name"] for site in tenant_sites}.items()
            if k != selected_site_a
            }
            select_all_b = st.sidebar.checkbox("Selecionar todos os Demais sites?")
            if select_all_b:
                selected_sites_b = list(site_options_b.keys())
            else:
                selected_sites_b = st.sidebar.multiselect(
                "Selecione o(s) demais Site(s)",
                options=list(site_options_b.keys()),
                format_func=lambda sid: site_options_b[sid]
            )

            if selected_sites_b:
                st.sidebar.markdown("**Dispositivos dos sites adicionais:**")
                for site_b_id in selected_sites_b:
                    site_b_devices = get_devices_by_site(site_b_id)
                    selected_device_b = show_device_selector(site_b_devices, f"Dispositivo do Site {site_options_b[site_b_id]}")
                    if selected_device_b:
                        interfaces_b = get_interfaces_by_device(selected_device_b)
                        active_interfaces_b = [i["name"] for i in interfaces_b if i.get("enabled", True)]
                        selected_interface_b = st.sidebar.selectbox(
                            f"Interface do Device {site_options_b[site_b_id]}",
                            options=active_interfaces_b,
                            key=f"interface_b_{site_b_id}"
                        )

                    st.sidebar.markdown("--------------------------------------------------")

                    loop_b = get_device_primary_ip(selected_device_b)
                    site_b_loopbacks.append(loop_b)
                

                st.write("### Configuração dos Sites")
                col_header, col_descr, col_vpls_id = st.columns([0.35, 0.50, 0.15])
                with col_header:
                    customer_name = st.text_input("Nome da VPLS: (Ex.: PTMP-100-FULANO)")
                with col_descr:
                    description = st.text_input("Descricao: (Descreva o serviço e o Cliente)")
                with col_vpls_id:
                    vpls_id = st.number_input("VPLS ID", min_value=1, max_value=40000000, step=1, key="vpls_id")
                col_vpls_id, col_device_name, col_device_vlan = st.columns([0.15, 0.40, 0.15])
                with col_vpls_id:
                    st.write("VPLS ID")
                with col_device_name:
                    st.write("DISPOSITIVO")
                with col_device_vlan:
                    st.write("VLAN")
                
                col_vpls_id, col_device_name, col_device_loopback, col_device_vlan = st.columns([0.15, 0.30, 0.25, 0.15])
                with col_vpls_id:
                     st.write(vpls_id)
                with col_device_name:
                    st.write(next(device["name"] for device in site_a_devices if device["id"] == selected_device_a))
                with col_device_loopback:
                    st.write(loopback_a or "N/A")
                with col_device_vlan:
                    vlan_id = st.number_input("VLAN", min_value=2, max_value=4094, step=1, key=f"vlan_{selected_device_a}")

                col_vpls_id, col_device_name, col_device_loopback, col_device_vlan = st.columns([0.15, 0.30, 0.25, 0.15])
                with col_vpls_id:
                     st.write(vpls_id)
                with col_device_name:
                    if selected_device_b:
                        st.write(next((device["name"] for device in site_b_devices if device["id"] == selected_device_b), "Dispositivo não encontrado"))
                    else:
                        st.write("Nenhum dispositivo selecionado")
                with col_device_loopback:
                    if selected_device_b:
                        loopback_b = get_device_primary_ip(selected_device_b)
                        st.write(loopback_b or "N/A")
                    else:
                        st.write("N/A")
                with col_device_vlan:
                    st.number_input("VLAN", min_value=2, max_value=4094, step=1, key=f"vlan_{selected_device_b}")
                    vlan_id_b = st.session_state[f"vlan_{selected_device_b}"]

                    sites_b_data[site_b_id] = {
                        'site_name': site_options_b[site_b_id],
                        'device_name': next(d['name'] for d in site_b_devices if d['id'] == selected_device_b),
                        'interface': selected_interface_b,
                        'vlan_id': vlan_id_b,
                        'loopback': loop_b
                    }    
                # -----------------------------------------------------------------
                # Botão final de Execução
                # -----------------------------------------------------------------
            st.write("---")
            if st.button("Gerar Configuração"):
                    if all([customer_name, selected_device_a, vpls_id, selected_interface_a]) and sites_b_data:
                        template = env.get_template('template/l2vpn/ptmp')
                        
                        # Get device A name and loopback
                        device_a_name = next(d['name'] for d in site_a_devices if d['id'] == selected_device_a)
                        
                        # Prepare site B configurations
                        sites_b_configs = []
                        for site_id, site_data in sites_b_data.items():
                            site_config = {
                                'device_name_b': site_data['device_name'],
                                'selected_interface_b': site_data['interface'],
                                'vlan_id': site_data['vlan_id'],
                                'loopback': site_data['loopback']
                            }
                            sites_b_configs.append(site_config)

                        template_data = {
                            'customer_name': customer_name,
                            'description': description,
                            'vpls_id': vpls_id,
                            'device_name_a': device_a_name,
                            'selected_interface_a': selected_interface_a,
                            'vlan_id': vlan_id,
                            'loopback_a': loopback_a,
                            'site_b_loopbacks': [site['loopback'] for site in sites_b_configs],
                            'selected_sites_b': selected_sites_b,
                            'site_options_b': site_options_b,
                            'device_name_b': next(site['device_name_b'] for site in sites_b_configs),
                            'selected_interface_b': next(site['selected_interface_b'] for site in sites_b_configs)
                        }
                        
                        config_output = template.render(**template_data)
                        st.code(config_output, language="bash")
                        st.markdown(
                            create_download_link(
                                config_output,
                                f"l2vpn_ptmp_{customer_name}_{vpls_id}.txt"
                            ),
                            unsafe_allow_html=True
                        )
                    else:
                        st.error("Por favor, preencha todos os campos obrigatórios.")

        # ---------------------------------------------------------------------
        # L3VPN  - Cliente Dedicado
        # ---------------------------------------------------------------------
        elif service_val == "cl_dedicado":
            customer_name = st.text_input("Nome do Cliente: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)")
            selected_site_a = st.sidebar.selectbox(
                "Selecione o Site",
                options=[site["id"] for site in tenant_sites],
                format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            colA1, colA2 = st.sidebar.columns([0.75, 0.25])
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site", container=colA1)
            vlan_id_a = colA2.number_input("VLAN ID", min_value=2, max_value=4094, step=1)
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a_ptmp"
                )
                loopback_a = get_device_primary_ip(selected_device_a)
            st.subheader("L3VPN - Informações de Enlace")
            col_local, col_local_mask, col_remote, col_remote_mask = st.columns([0.2, 0.05, 0.2, 0.05])
            with col_local:
                st.subheader("Peer Local")
                peer_local_v4 = st.text_input("Endereço IPv4 Local", value="", help="Endereço IPv4 da interface local")
                peer_local_v6 = st.text_input("Endereço IPv6 Local", value="", help="Endereço IPv6 da interface local")
            with col_local_mask:
                st.subheader("")
                peer_local_mask_v4 = st.text_input("Mask", value="", help="Máscara IPv4 da interface local")
                peer_local_mask_v6 = st.text_input("Mask", value="", help="Máscara IPv6 da interface local")
            with col_remote:
                st.subheader("Peer Remoto")
                peer_remoto_v4 = st.text_input("Endereço IPv4 Remoto", value="", help="Endereço IPv4 do peer remoto")
                peer_remoto_v6 = st.text_input("Endereço IPv6 Remoto", value="", help="Endereço IPv6 do peer remoto")
            with col_remote_mask:
                st.subheader("")
                peer_remoto_mask_v4 = st.text_input("Mask", value="", help="Máscara IPv4 do peer remoto")
                peer_remoto_mask_v6 = st.text_input("Mask", value="", help="Máscara IPv6 do peer remoto")

            col_check_rt, col_rt_v4, col_rt_mask4, col_rt_v6, col_rt_mask6 = st.columns([0.15,0.25,0.07,0.25,0.07])
            with col_check_rt:
                check_rt = st.checkbox("IP Roteado")
                rt_v4 = ""
                rt_mask4 = ""
                rt_v6 = ""
                rt_mask6 = ""
            if check_rt: 
                    with col_rt_v4:
                        rt_v4 = st.text_input("Rota IPv4", value="", help="Rota Ipv4 - ex.: 123.1.1.0/30")
                    with col_rt_mask4:
                        rt_mask4 = st.text_input("Mask", value="", help="Máscara IPv4 - ex.: 30") 
                    with col_rt_v6:
                        rt_v6 = st.text_input("Rota IPv6", value="", help="Rota IPv6 - ex.: 2001:1234:cad3:caf3::/64")
                    with col_rt_mask6:
                        rt_mask6 = st.text_input("Mask", value="", help="Máscara IPv6 - ex.: 64")

            # -----------------------------------------------------------------
            # Botão final de Execução
            # -----------------------------------------------------------------
            st.write("---")
            if st.button("Gerar Configuração"):
                if all([customer_name, selected_device_a, vlan_id_a, selected_interface_a, peer_local_v4, peer_remoto_v4]):
                    template = env.get_template('template/l3vpn/cl_ded')
                    template_data = {
                        'customer_name': customer_name,
                        'vlan_id_a': vlan_id_a,
                        'selected_interface_a': selected_interface_a,
                        'peer_local_v4': peer_local_v4,
                        'peer_remoto_v4': peer_remoto_v4,
                        'peer_local_mask_v4': peer_local_mask_v4,
                        'peer_remoto_mask_v4': peer_remoto_mask_v4,
                        'peer_local_v6': peer_local_v6,
                        'peer_local_mask_v6': peer_local_mask_v6,
                        'peer_remoto_mask_v6': peer_remoto_mask_v6,
                        'peer_remoto_v6': peer_remoto_v6,
                        'check_rt': check_rt,
                        'rt_v4': rt_v4,
                        'rt_mask4': rt_mask4,
                        'rt_v6': rt_v6,
                        'rt_mask6': rt_mask6
                    }
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l3vpn_cl_ded_{customer_name}.txt"
                        ),
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Por favor, preencha todos os campos obrigatórios.")

        # ---------------------------------------------------------------------
        # L3VPN  - Peering Cliente de Transito
        # ---------------------------------------------------------------------
        elif service_val == "bgp_cl_trans": # Peering de Cliente de Transito
            customer_name = st.text_input("Nome do Cliente: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)")
            selected_site_a = st.sidebar.selectbox(
                "Selecione o Site",
                options=[site["id"] for site in tenant_sites],
                format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            colA1, colA2 = st.sidebar.columns([0.75, 0.25])
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site", container=colA1)
            vlan_id_a = colA2.number_input("VLAN ID", min_value=2, max_value=4094, step=1)
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a_ptmp"
                )
                loopback_a = get_device_primary_ip(selected_device_a)

            st.subheader("L3VPN - Configuração do Peering com Cliente")
            col_asn_local, col_asn_remote = st.columns(2)
            with col_asn_local:
                asn_local = st.text_input("ASN Local", value="64777", help="Número do sistema autônomo local")
            with col_asn_remote:
                asn_remoto = st.text_input("ASN Remoto", value="", help="Número do sistema autônomo remoto")

            col_local, col_local_mask, col_remote, col_remote_mask = st.columns([0.2, 0.05, 0.2, 0.05])
            with col_local:
                st.subheader("Peer Local")
                peer_local_v4 = st.text_input("Endereço IPv4 Local", value="", help="Endereço IPv4 da interface local")
                peer_local_v6 = st.text_input("Endereço IPv6 Local", value="", help="Endereço IPv6 da interface local")
            with col_local_mask:
                st.subheader("")
                peer_local_mask_v4 = st.text_input("Mask", value="", help="Máscara IPv4 da interface local")
                peer_local_mask_v6 = st.text_input("Mask", value="", help="Máscara IPv6 da interface local")
            with col_remote:
                st.subheader("Peer Remoto")
                peer_remoto_v4 = st.text_input("Endereço IPv4 Remoto", value="", help="Endereço IPv4 do peer remoto")
                peer_remoto_v6 = st.text_input("Endereço IPv6 Remoto", value="", help="Endereço IPv6 do peer remoto")
            with col_remote_mask:
                st.subheader("")
                peer_remoto_mask_v4 = st.text_input("Mask", value="", help="Máscara IPv4 do peer remoto")
                peer_remoto_mask_v6 = st.text_input("Mask", value="", help="Máscara IPv6 do peer remoto")
                
            col_check_md5, col_md5_v4, col_md5_v6 = st.columns([0.1,0.45,0.45])
            with col_check_md5:
                check_md5 = st.checkbox("MD5")
            md5_v4 = ""
            md5_v6 = ""
            if check_md5: 
                    with col_md5_v4:
                        md5_v4 = st.text_input("Senha MD5 IPv4", value="", help="Senha MD5 para autenticação BGP")  
                    with col_md5_v6:
                        md5_v6 = st.text_input("Senha MD5 IPv6", value="", help="Senha MD5 para autenticação BGP")
            if asn_remoto and not st.session_state.asn_lookup_done:
                with st.spinner(f"Buscando informações do ASN Remoto {asn_remoto}..."):
                    ipv4_prefixes, ipv6_prefixes,asn_name = get_asn_prefixes(asn_remoto)
                    st.session_state.ipv4_prefixes = ipv4_prefixes
                    st.session_state.ipv6_prefixes = ipv6_prefixes
                    st.session_state.asn_name = asn_name
                    st.session_state.asn_lookup_done = True
            if 'previous_asn' not in st.session_state:
                st.session_state.previous_asn = ""
            if asn_remoto != st.session_state.previous_asn:
                st.session_state.asn_lookup_done = False
                st.session_state.previous_asn = asn_remoto

            if 'asn_name' not in st.session_state:
                st.session_state.asn_name = ""

            if st.session_state.asn_lookup_done:
                col_ipv4, col_ipv6 = st.columns(2)
                with col_ipv4:
                    st.subheader(f"Prefixos IPv4 do AS{asn_remoto}")
                    if st.session_state.ipv4_prefixes:
                        ipv4_data = []
                        for prefix in st.session_state.ipv4_prefixes:
                            ip, mask = prefix.split("/")
                            ipv4_data.append({
                                'Prefixo': ip,
                                'Máscara': mask
                                })
                        st.session_state.ipv4_prefixes_data = ipv4_data

                        import pandas as pd
                        ipv4_df = pd.DataFrame(st.session_state.ipv4_prefixes, columns=["Prefixo"])
                        st.dataframe(ipv4_df, height=200)

                    else:
                        st.warning("Nenhum prefixo IPv4 encontrado para este ASN")
                with col_ipv6:
                    st.subheader(f"Prefixos IPv6 do AS{asn_remoto}")
                    if st.session_state.ipv6_prefixes:
                        ipv6_data = []
                        for prefix in st.session_state.ipv6_prefixes:
                            ip, mask = prefix.split('/')
                            ipv6_data.append({
                                'Prefixo': ip,
                                'Máscara': mask
                            })
                        st.session_state.ipv6_prefixes_data = ipv6_data

                        import pandas as pd
                        ipv6_df = pd.DataFrame(st.session_state.ipv6_prefixes, columns=["Prefixo"])
                        st.dataframe(ipv6_df, height=200)

                    else:
                        st.warning("Nenhum prefixo IPv6 encontrado para este ASN")

            st.write("---")
            if st.button("Gerar Configuração"):
                if all([customer_name, selected_device_a, vlan_id_a, selected_interface_a, peer_local_v4, peer_remoto_v4]):
                    template = env.get_template('template/l3vpn/cl_trans_ip')
                    template_data = {
                        'customer_name': customer_name,
                        'asn_local': asn_local,
                        'asn_remoto': asn_remoto,
                        'default_prefix_v4': st.session_state.ipv4_prefixes_data, # Get the default prefix from session state
                        'MASKv4': st.session_state.get('MASKv4', ''), # Get the mask from session state
                        'default_prefix_v6': st.session_state.ipv6_prefixes_data, # Get the default prefix from session state
                        'MASKv6': st.session_state.get('MASKv6', ''), # Get the mask from session state
                        'vlan_id_a': vlan_id_a,
                        'selected_interface_a': selected_interface_a,
                        'peer_local_v4': peer_local_v4,
                        'peer_remoto_v4': peer_remoto_v4,
                        'peer_local_mask_v4': peer_local_mask_v4,
                        'peer_remoto_mask_v4': peer_remoto_mask_v4,
                        'peer_local_v6': peer_local_v6,
                        'peer_local_mask_v6': peer_local_mask_v6,
                        'peer_remoto_mask_v6': peer_remoto_mask_v6,
                        'peer_remoto_v6': peer_remoto_v6
                    }
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l3vpn_cl_ded_{customer_name}.txt"
                        ),
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Por favor, preencha todos os campos obrigatórios.")

        # ---------------------------------------------------------------------
        # L3VPN  - Peering BGP Simples
        # ---------------------------------------------------------------------
        elif service_val == "bgp_ups": # Peering de Cliente de Transito
            customer_name = st.text_input("Nome do Cliente: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)")

            bgp_config = BGPConfig()
            selected_site_a = st.sidebar.selectbox(
                "Selecione o Site",
                options=[site["id"] for site in tenant_sites],
                format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            colA1, colA2 = st.sidebar.columns([0.75, 0.25])
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site", container=colA1)
            vlan_id_a = colA2.number_input("VLAN ID", min_value=2, max_value=4094, step=1)
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a_ptmp"
                )
                loopback_a = get_device_primary_ip(selected_device_a)

            # Use the new BGP configuration methods
            asn_local, asn_remoto = bgp_config.show_basic_info()
            peer_info = bgp_config.show_peer_info()
            check_md5, md5_v4, md5_v6 = bgp_config.show_md5_config()
            
            # Update ASN information
            bgp_config.update_asn_info(asn_remoto, get_asn_prefixes)
            ipv4_data, ipv6_data = bgp_config.show_prefixes(asn_remoto)
            
            st.write("---")
            if st.button("Gerar Configuração"):
                if all([customer_name, selected_device_a, vlan_id_a, selected_interface_a]):
                    template = env.get_template('template/l3vpn/bgp_ups')
                    template_data = {
                        'customer_name': customer_name,
                        'asn_local': asn_local,
                        'asn_name': st.session_state.get('asn_name', ''),
                        'asn_remoto': asn_remoto,
                        'default_prefix_v4': st.session_state.ipv4_prefixes_data, # Get the default prefix from session state
                        'MASKv4': st.session_state.get('MASKv4', ''), # Get the mask from session state
                        'default_prefix_v6': st.session_state.ipv6_prefixes_data, # Get the default prefix from session state
                        'MASKv6': st.session_state.get('MASKv6', ''), # Get the mask from session state
                        'vlan_id_a': vlan_id_a,
                        'selected_interface_a': selected_interface_a,
                        **peer_info
                    }
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l3vpn_cl_ded_{customer_name}.txt"
                        ),
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Por favor, preencha todos os campos obrigatórios.")

        # ---------------------------------------------------------------------
        # L3VPN  - Peering BGP com Community
        # ---------------------------------------------------------------------
        elif service_val == "bgp_ups_comm":
            col_circuit, col_cust_name = st.columns([0.10, 0.65])
            with col_circuit:
                circuito = st.text_input("ID", value="", help="Identificador único do circuito")
            with col_cust_name:
                customer_name = st.text_input("Nome do Peering: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)")

            bgp_config = BGPConfig()
            selected_site_a = st.sidebar.selectbox(
                "Selecione o Site",
                options=[site["id"] for site in tenant_sites],
                format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            colA1, colA2 = st.sidebar.columns([0.75, 0.25])
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site", container=colA1)
            vlan_id_a = colA2.number_input("VLAN ID", min_value=2, max_value=4094, step=1)
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a_ptmp"
                )
                loopback_a = get_device_primary_ip(selected_device_a)
                # Use the new BGP configuration methods
                asn_local, asn_remoto = bgp_config.show_basic_info()
                peer_info = bgp_config.show_peer_info()
                check_md5, md5_v4, md5_v6 = bgp_config.show_md5_config()
                
                # Update ASN information
                bgp_config.update_asn_info(asn_remoto, get_asn_prefixes)
                ipv4_data, ipv6_data = bgp_config.show_prefixes(asn_remoto)

                st.write("---")
            if st.button("Gerar Configuração"):
                if all([customer_name, selected_device_a, vlan_id_a, selected_interface_a]):
                    template = env.get_template('template/l3vpn/bgp_ups_comm')
                    template_data = {
                        'customer_name': customer_name,
                        'circuito': circuito,  
                        'asn_local': asn_local,
                        'asn_name': st.session_state.get('asn_name', ''),
                        'asn_remoto': asn_remoto,
                        'default_prefix_v4': st.session_state.ipv4_prefixes_data, # Get the default prefix from session state
                        'MASKv4': st.session_state.get('MASKv4', ''), # Get the mask from session state
                        'default_prefix_v6': st.session_state.ipv6_prefixes_data, # Get the default prefix from session state
                        'MASKv6': st.session_state.get('MASKv6', ''), # Get the mask from session state
                        'vlan_id_a': vlan_id_a,
                        'selected_interface_a': selected_interface_a,
                        **peer_info
                    }
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l3vpn_cl_ded_{customer_name}.txt"
                        ),
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Por favor, preencha todos os campos obrigatórios.")
        # ---------------------------------------------------------------------
        # L3VPN  - Peering CDN com Community
        # ---------------------------------------------------------------------
        elif service_val == "peering_cdn_comm":
            col_circuit, col_cust_name = st.columns([0.10, 0.65])
            with col_circuit:
                circuito = st.text_input("ID", value="", help="Identificador único do circuito")
            with col_cust_name:
                customer_name = st.text_input("Nome do Peering: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)")

            bgp_config = BGPConfig()
            selected_site_a = st.sidebar.selectbox(
                "Selecione o Site",
                options=[site["id"] for site in tenant_sites],
                format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            colA1, colA2 = st.sidebar.columns([0.75, 0.25])
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site", container=colA1)
            vlan_id_a = colA2.number_input("VLAN ID", min_value=2, max_value=4094, step=1)
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a_ptmp"
                )
                loopback_a = get_device_primary_ip(selected_device_a)
                # Use the new BGP configuration methods
                asn_local, asn_remoto = bgp_config.show_basic_info()
                peer_info = bgp_config.show_peer_info()
                check_md5, md5_v4, md5_v6 = bgp_config.show_md5_config()
                
                # Update ASN information
                bgp_config.update_asn_info(asn_remoto, get_asn_prefixes)
                ipv4_data, ipv6_data = bgp_config.show_prefixes(asn_remoto)

                st.write("---")
            if st.button("Gerar Configuração"):
                if all([customer_name, selected_device_a, vlan_id_a, selected_interface_a]):
                    template = env.get_template('template/l3vpn/bgp_ups_comm')
                    template_data = {
                        'customer_name': customer_name,
                        'circuito': circuito,
                        'asn_local': asn_local,
                        'asn_name': st.session_state.get('asn_name', ''),
                        'asn_remoto': asn_remoto,
                        'default_prefix_v4': st.session_state.ipv4_prefixes_data, # Get the default prefix from session state
                        'MASKv4': st.session_state.get('MASKv4', ''), # Get the mask from session state
                        'default_prefix_v6': st.session_state.ipv6_prefixes_data, # Get the default prefix from session state
                        'MASKv6': st.session_state.get('MASKv6', ''), # Get the mask from session state
                        'vlan_id_a': vlan_id_a,
                        'selected_interface_a': selected_interface_a,
                        **peer_info
                    }
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l3vpn_cl_ded_{customer_name}.txt"
                        ),
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Por favor, preencha todos os campos obrigatórios.")

        # ---------------------------------------------------------------------
        # L3VPN  - Peering BGP IX-BR
        # ---------------------------------------------------------------------
        elif service_val == "bgp_ixbr_comm": # Peering de Cliente de Transito
            customer_name = st.text_input("Nome do Cliente: (CL-FULANO_DE_TAL / AS1234-FULANO_DE_TAL)")

            bgp_config = BGPConfig()
            selected_site_a = st.sidebar.selectbox(
                "Selecione o Site",
                options=[site["id"] for site in tenant_sites],
                format_func=lambda sid: {s["id"]: s["name"] for s in tenant_sites}[sid]
            )
            colA1, colA2 = st.sidebar.columns([0.75, 0.25])
            site_a_devices = get_devices_by_site(selected_site_a)
            selected_device_a = show_device_selector(site_a_devices, "Dispositivo do Site", container=colA1)
            vlan_id_a = colA2.number_input("VLAN ID", min_value=2, max_value=4094, step=1)
            if selected_device_a:
                interfaces_a = get_interfaces_by_device(selected_device_a)
                active_interfaces_a = [i["name"] for i in interfaces_a if i.get("enabled", True)]
                selected_interface_a = st.sidebar.selectbox(
                    "Interface do Device A",
                    options=active_interfaces_a,
                    key="interface_a_ptmp"
                )
                loopback_a = get_device_primary_ip(selected_device_a)

            # Use the new BGP configuration methods
            asn_local, asn_remoto = bgp_config.show_basic_info()
            peer_info = bgp_config.show_peer_info()
            check_md5, md5_v4, md5_v6 = bgp_config.show_md5_config()
            
            # Update ASN information
            bgp_config.update_asn_info(asn_remoto, get_asn_prefixes)
            ipv4_data, ipv6_data = bgp_config.show_prefixes(asn_remoto)
            
            st.write("---")
            if st.button("Gerar Configuração"):
                if all([customer_name, selected_device_a, vlan_id_a, selected_interface_a]):
                    template = env.get_template('template/l3vpn/bgp_ixbr_comm')
                    template_data = {
                        'customer_name': customer_name,
                        'asn_local': asn_local,
                        'asn_name': st.session_state.get('asn_name', ''),
                        'asn_remoto': asn_remoto,
                        'default_prefix_v4': st.session_state.ipv4_prefixes_data, # Get the default prefix from session state
                        'MASKv4': st.session_state.get('MASKv4', ''), # Get the mask from session state
                        'default_prefix_v6': st.session_state.ipv6_prefixes_data, # Get the default prefix from session state
                        'MASKv6': st.session_state.get('MASKv6', ''), # Get the mask from session state
                        'vlan_id_a': vlan_id_a,
                        'selected_interface_a': selected_interface_a,
                        **peer_info
                    }
                    config_output = template.render(**template_data)
                    st.code(config_output, language="bash")
                    st.markdown(
                        create_download_link(
                            config_output,
                            f"l3vpn_cl_ded_{customer_name}.txt"
                        ),
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Por favor, preencha todos os campos obrigatórios.")


else:
    st.info("Por favor, selecione um tenant para continuar.")
