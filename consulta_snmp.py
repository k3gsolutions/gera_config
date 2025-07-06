#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess

def get_sysdescr(ip, community):
    """Realiza uma consulta SNMP GET para o OID sysDescr usando snmpget."""
    oid = '1.3.6.1.2.1.1.1.0'
    try:
        result = subprocess.run(
            ['snmpget', '-v', '2c', '-c', community, ip, oid],
            capture_output=True, text=True, check=True
        )
        # Extrair apenas o valor (após o '=' na saída)
        if '=' in result.stdout:
            return result.stdout.split('=')[1].strip()
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Erro SNMP: {e}")
        print(f"Saída de erro: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)
    return None

def main():
    if len(sys.argv) < 2:
        print("Uso: python busca_peer.py {ip-address} [community]")
        sys.exit(1)
    
    ip = sys.argv[1]
    community = sys.argv[2] if len(sys.argv) > 2 else "public"

    sysdescr = get_sysdescr(ip, community)
    if sysdescr:
        print("sysDescr:", sysdescr)
        if "Huawei" in sysdescr:
            print("Fabricante: Huawei")
        elif "Mikrotik" in sysdescr or "RouterOS" in sysdescr:
            print("Fabricante: Mikrotik")
        else:
            print("Fabricante: Desconhecido")
    else:
        print("Não foi possível obter a sysDescr do dispositivo.")

if __name__ == '__main__':
    main()