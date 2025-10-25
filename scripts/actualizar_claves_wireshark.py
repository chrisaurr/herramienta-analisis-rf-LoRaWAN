#!/usr/bin/env python3
"""
Obtiene Session Keys desde TTN API y actualiza configuración de Wireshark
Permite desencriptación automática de payloads LoRaWAN
"""

import requests
import sys
import os

TTN_APP_ID = "TU_TTN_APP_ID_AQUI"
TTN_DEVICE_ID = "TU_TTN_DEVICE_ID_AQUI"
TTN_API_KEY = "TU_TTN_API_KEY_AQUI"

TTN_API_BASE = "https://nam1.cloud.thethings.network/api/v3"


def obtener_session_keys():
    headers = {
        "Authorization": f"Bearer {TTN_API_KEY}",
        "Accept": "application/json"
    }

    params = {"field_mask": "session.keys,session.dev_addr"}

    try:
        url_ns = f"{TTN_API_BASE}/ns/applications/{TTN_APP_ID}/devices/{TTN_DEVICE_ID}"
        response_ns = requests.get(url_ns, headers=headers, params=params)
        response_ns.raise_for_status()

        url_as = f"{TTN_API_BASE}/as/applications/{TTN_APP_ID}/devices/{TTN_DEVICE_ID}"
        response_as = requests.get(url_as, headers=headers, params=params)
        response_as.raise_for_status()

        ns_data = response_ns.json()
        as_data = response_as.json()

        ns_session = ns_data.get('session', {})
        as_session = as_data.get('session', {})

        dev_addr = ns_session.get('dev_addr', '') or as_session.get('dev_addr', '')

        ns_keys = ns_session.get('keys', {})
        as_keys = as_session.get('keys', {})

        nwk_s_key = ns_keys.get('nwk_s_enc_key', {}).get('key', '')
        app_s_key = as_keys.get('app_s_key', {}).get('key', '')

        if not all([dev_addr, nwk_s_key, app_s_key]):
            print("Error: Dispositivo no tiene sesión activa")
            print("Conecta el dispositivo y espera el Join")
            return None

        return {
            'dev_addr': dev_addr.upper(),
            'nwk_s_key': nwk_s_key.upper(),
            'app_s_key': app_s_key.upper()
        }

    except requests.exceptions.RequestException as e:
        print(f"Error conectando a TTN API: {e}")
        return None


def actualizar_wireshark(keys):
    session_keys_file = os.path.expanduser("~/.config/wireshark/session_keys_lorawan")
    os.makedirs(os.path.dirname(session_keys_file), exist_ok=True)

    existing_keys = []
    if os.path.exists(session_keys_file):
        with open(session_keys_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.startswith('"'):
                        existing_dev = line.split(',')[0].strip('"')
                        if existing_dev.upper() != keys['dev_addr']:
                            existing_keys.append(line)

    new_entry = f'"{keys["dev_addr"]}","{keys["nwk_s_key"]}","{keys["app_s_key"]}"'

    with open(session_keys_file, 'w') as f:
        f.write("# Generado automáticamente desde TTN API\n")
        f.write('# Formato: "DevAddr","NwkSKey","AppSKey"\n')
        f.write(f"{new_entry}\n")

        for key in existing_keys:
            f.write(f"{key}\n")

    return session_keys_file


def main():
    print("="*70)
    print("ACTUALIZAR CLAVES WIRESHARK DESDE TTN")
    print("="*70)
    print()

    keys = obtener_session_keys()

    if not keys:
        sys.exit(1)

    print("Session Keys obtenidas:")
    print(f"  DevAddr: {keys['dev_addr']}")
    print(f"  NwkSKey: {keys['nwk_s_key']}")
    print(f"  AppSKey: {keys['app_s_key']}")
    print()

    archivo = actualizar_wireshark(keys)

    print("="*70)
    print(f"Configuración actualizada: {archivo}")
    print("Reinicia Wireshark para aplicar cambios")
    print("="*70)


if __name__ == '__main__':
    main()