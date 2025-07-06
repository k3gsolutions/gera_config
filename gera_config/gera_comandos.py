import streamlit as st
import re
import ipwhois
import ipaddress
import requests
import base64
from io import StringIO

# Set page title and layout
st.set_page_config(page_title="Huawei BGP Peering Generator", layout="wide")

# IPv4 and IPv6 regex patterns
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
        asn_name = asn_info.get('data', {}).get('holder', 'Unknown ASN')
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

def generate_config(variables, ipv4_prefixes=None, ipv6_prefixes=None):
    """Generate configuration by replacing variables in the template"""
    
    # Lê o template a partir do arquivo local "templates/hw_bgp_ups_comm.txt"
    with open("templates/hw_bgp_ups_comm.txt", "r") as f:
        template = f.read()
    
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

# Removido o bloco que criava e salvava o template localmente.
# Agora, o template deve estar disponível no arquivo: templates/hw_bgp_ups_comm.txt

if 'ipv4_prefixes' not in st.session_state:
    st.session_state.ipv4_prefixes = []
if 'ipv6_prefixes' not in st.session_state:
    st.session_state.ipv6_prefixes = []
if 'asn_lookup_done' not in st.session_state:
    st.session_state.asn_lookup_done = False

st.title("Huawei BGP Peering Configuration Generator")
st.write("Esta ferramenta gera configurações para peering BGP em roteadores Huawei NE8000")

st.subheader("Informações Básicas")
col_circuit, col_asn_local, col_asn_remote = st.columns(3)
with col_circuit:
    circuito = st.text_input("Número do Circuito", value="", help="Identificador único do circuito")
with col_asn_local:
    asn_local = st.text_input("ASN Local", value="64777", help="Número do sistema autônomo local")
with col_asn_remote:
    asn_remoto = st.text_input("ASN Remoto", value="", help="Número do sistema autônomo remoto")

if asn_remoto and not st.session_state.asn_lookup_done:
    with st.spinner(f"Buscando informações do ASN {asn_remoto}..."):
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

col_local, col_remote = st.columns(2)
with col_local:
    st.subheader("Dados do Peer Local")
    peer_local_v4 = st.text_input("Endereço IPv4 Local", value="", help="Endereço IPv4 da interface local")
    peer_local_v6 = st.text_input("Endereço IPv6 Local", value="", help="Endereço IPv6 da interface local")
with col_remote:
    st.subheader("Dados do Peer Remoto")
    peer_remoto_v4 = st.text_input("Endereço IPv4 Remoto", value="", help="Endereço IPv4 do peer remoto")
    peer_remoto_v6 = st.text_input("Endereço IPv6 Remoto", value="", help="Endereço IPv6 do peer remoto")

if st.session_state.asn_lookup_done:
    col_ipv4, col_ipv6 = st.columns(2)
    with col_ipv4:
        st.subheader(f"Prefixos IPv4 do AS{asn_remoto}")
        if st.session_state.ipv4_prefixes:
            import pandas as pd
            ipv4_df = pd.DataFrame(st.session_state.ipv4_prefixes, columns=["Prefixo"])
            st.dataframe(ipv4_df, height=200)
        else:
            st.warning("Nenhum prefixo IPv4 encontrado para este ASN")
    with col_ipv6:
        st.subheader(f"Prefixos IPv6 do AS{asn_remoto}")
        if st.session_state.ipv6_prefixes:
            import pandas as pd
            ipv6_df = pd.DataFrame(st.session_state.ipv6_prefixes, columns=["Prefixo"])
            st.dataframe(ipv6_df, height=200)
        else:
            st.warning("Nenhum prefixo IPv6 encontrado para este ASN")

if st.button("Gerar Configuração BGP"):
    if not all([asn_remoto, circuito, asn_local, peer_local_v4, peer_remoto_v4, peer_local_v6, peer_remoto_v6]):
        st.error("Por favor, preencha todos os campos obrigatórios")
    else:
        try:
            ipv4_prefixes = st.session_state.ipv4_prefixes
            ipv6_prefixes = st.session_state.ipv6_prefixes
            asn_name = st.session_state.asn_name
            default_prefix_v4 = "0.0.0.0"
            default_mask_v4 = "0"
            default_prefix_v6 = "::"
            default_mask_v6 = "0"
            if ipv4_prefixes:
                default_prefix_v4, default_mask_v4 = split_prefix_mask(ipv4_prefixes[0])
            if ipv6_prefixes:
                default_prefix_v6, default_mask_v6 = split_prefix_mask(ipv6_prefixes[0])
            variables = {
                "ASNREMOTO": asn_remoto,
                "PEERLOCALv4": peer_local_v4,
                "PEERREMOTOv4": peer_remoto_v4,
                "PEERLOCALv6": peer_local_v6,
                "PEERREMOTOv6": peer_remoto_v6,
                "CIRCUITO": circuito,
                "ASNLOCAL": asn_local,
                "PREFIXOSv4": default_prefix_v4,
                "MASKv4": default_mask_v4,
                "PREFIXOSv6": default_prefix_v6,
                "MASKv6": default_mask_v6,
                "ASNNAME": asn_name
            }
            config = generate_config(variables, ipv4_prefixes, ipv6_prefixes)
            st.subheader("Comandos a Executar")
            st.code(config, language="bash")
            st.markdown(create_download_link(config, f"bgp_peering_{circuito}_{asn_remoto}.txt"), unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Erro ao gerar configuração: {str(e)}")

st.markdown("---")
st.write("Esta ferramenta gera configurações para peering BGP em roteadores Huawei NE8000 (VRP) usando BGP communities.")
st.write("Desenvolvida com Streamlit, processa automaticamente informações ASN via RIPE API.")
