import streamlit as st
import ipaddress
from typing import Dict, Tuple, List

class BGPConfig:
    def __init__(self):
        if 'asn_lookup_done' not in st.session_state:
            st.session_state.asn_lookup_done = False
        if 'previous_asn' not in st.session_state:
            st.session_state.previous_asn = ""
        if 'asn_name' not in st.session_state:
            st.session_state.asn_name = ""

    def show_basic_info(self, default_asn: str = "64777") -> Tuple[str, str, str]:
        """Display basic BGP information fields"""
        
        col_asn_local, col_asn_remote = st.columns(2)
        with col_asn_local:
            asn_local = st.text_input("ASN Local", value=default_asn, 
                                    help="Número do sistema autônomo local")
        with col_asn_remote:
            asn_remoto = st.text_input("ASN Remoto", value="", 
                                     help="Número do sistema autônomo remoto")
        
        return asn_local, asn_remoto

    def show_peer_info(self) -> Dict[str, str]:
        """Display peer information fields"""
        col_local, col_local_mask, col_remote, col_remote_mask = st.columns([0.2, 0.05, 0.2, 0.05])
        
        peer_info = {}
        
        with col_local:
            st.subheader("Peer Local")
            peer_info['peer_local_v4'] = st.text_input("Endereço IPv4 Local", value="")
            peer_info['peer_local_v6'] = st.text_input("Endereço IPv6 Local", value="")
            
        with col_local_mask:
            st.subheader("")
            peer_info['peer_local_mask_v4'] = st.text_input("Mask", key="local_mask_v4")
            peer_info['peer_local_mask_v6'] = st.text_input("Mask", key="local_mask_v6")
            
        # Similar structure for remote peer
        with col_remote:
            st.subheader("Peer Remoto")
            peer_info['peer_remoto_v4'] = st.text_input("Endereço IPv4 Remoto", value="")
            peer_info['peer_remoto_v6'] = st.text_input("Endereço IPv6 Remoto", value="")
            
        with col_remote_mask:
            st.subheader("")
            peer_info['peer_remoto_mask_v4'] = st.text_input("Mask", key="remote_mask_v4")
            peer_info['peer_remoto_mask_v6'] = st.text_input("Mask", key="remote_mask_v6")
            
        return peer_info

    def show_md5_config(self) -> Tuple[bool, str, str]:
        """Display MD5 configuration fields"""
        col_check_md5, col_md5_v4, col_md5_v6 = st.columns([0.1, 0.45, 0.45])
        
        with col_check_md5:
            check_md5 = st.checkbox("MD5")
            
        md5_v4 = ""
        md5_v6 = ""
        
        if check_md5:
            with col_md5_v4:
                md5_v4 = st.text_input("Senha MD5 IPv4", value="")
            with col_md5_v6:
                md5_v6 = st.text_input("Senha MD5 IPv6", value="")
                
        return check_md5, md5_v4, md5_v6

    def update_asn_info(self, asn: str, get_asn_prefixes_func) -> None:
        """Update ASN information and prefixes"""
        if asn and not st.session_state.asn_lookup_done:
            with st.spinner(f"Buscando informações do ASN {asn}..."):
                ipv4_prefixes_all, ipv6_prefixes_all, asn_name = get_asn_prefixes_func(asn)
                
                # Filter for less specific prefixes
                ipv4_networks = [ipaddress.ip_network(prefix) for prefix in ipv4_prefixes_all]
                ipv4_prefixes = [str(net) for net in ipv4_networks 
                               if not any(net.subnet_of(other) for other in ipv4_networks if net != other)]
                
                ipv6_networks = [ipaddress.ip_network(prefix) for prefix in ipv6_prefixes_all]
                ipv6_prefixes = [str(net) for net in ipv6_networks 
                               if not any(net.subnet_of(other) for other in ipv6_networks if net != other)]
                
                st.session_state.ipv4_prefixes = ipv4_prefixes
                st.session_state.ipv6_prefixes = ipv6_prefixes
                st.session_state.asn_name = asn_name
                st.session_state.asn_lookup_done = True

    def show_prefixes(self, asn: str) -> Tuple[List[Dict], List[Dict]]:
        """Display prefix information"""
        if st.session_state.asn_lookup_done:
            col_ipv4, col_ipv6 = st.columns(2)
            
            ipv4_data = []
            ipv6_data = []
            
            with col_ipv4:
                st.subheader(f"Prefixos IPv4 do AS{asn}")
                if st.session_state.ipv4_prefixes:
                    for prefix in st.session_state.ipv4_prefixes:
                        ip, mask = prefix.split("/")
                        ipv4_data.append({'Prefixo': ip, 'Máscara': mask})
                    st.session_state.ipv4_prefixes_data = ipv4_data
                    
                    import pandas as pd
                    ipv4_df = pd.DataFrame(st.session_state.ipv4_prefixes, columns=["Prefixo"])
                    st.dataframe(ipv4_df, height=200)
                else:
                    st.warning("Nenhum prefixo IPv4 encontrado para este ASN")
                    
            with col_ipv6:
                st.subheader(f"Prefixos IPv6 do AS{asn}")
                if st.session_state.ipv6_prefixes:
                    for prefix in st.session_state.ipv6_prefixes:
                        ip, mask = prefix.split("/")
                        ipv6_data.append({'Prefixo': ip, 'Máscara': mask})
                    st.session_state.ipv6_prefixes_data = ipv6_data
                    
                    import pandas as pd
                    ipv6_df = pd.DataFrame(st.session_state.ipv6_prefixes, columns=["Prefixo"])
                    st.dataframe(ipv6_df, height=200)
                else:
                    st.warning("Nenhum prefixo IPv6 encontrado para este ASN")
                    
            return ipv4_data, ipv6_data
        return [], []