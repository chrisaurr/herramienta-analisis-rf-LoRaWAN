#!/usr/bin/env python3
"""
Proxy UDP bidireccional entre Gateway LoRaWAN y TTN Network Server
Intercepta tráfico Semtech UDP para captura y análisis
"""

import socket
import json
import threading
from datetime import datetime

TTN_SERVER = 'nam1.cloud.thethings.network'
LOCAL_PORT = 1700
TTN_PORT = 1700
ARCHIVO_SALIDA = '../captures/paquetes_rxpk_limpios.json'

paquetes = []
gateway_addr = None
ttn_sockets = {}


def escuchar_respuestas_ttn(gateway_port, ttn_sock, gateway_sock):
    global gateway_addr

    while True:
        try:
            ttn_sock.settimeout(10.0)
            data, _ = ttn_sock.recvfrom(4096)

            if gateway_addr and len(data) >= 4:
                target = (gateway_addr[0], gateway_port)
                gateway_sock.sendto(data, target)

        except socket.timeout:
            continue
        except Exception:
            break


def extraer_rxpk(data):
    if len(data) < 12 or data[3] != 0x00:
        return []

    try:
        json_str = data[12:].decode('utf-8')
        obj = json.loads(json_str)

        if 'rxpk' not in obj:
            return []

        gateway_eui = data[4:12].hex().upper()
        timestamp = datetime.now().isoformat()

        for rxpk in obj['rxpk']:
            rxpk['timestamp'] = timestamp
            rxpk['gateway_eui'] = gateway_eui

        return obj['rxpk']

    except (UnicodeDecodeError, json.JSONDecodeError):
        return []


def main():
    global gateway_addr, paquetes

    gateway_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gateway_sock.bind(('0.0.0.0', LOCAL_PORT))

    ttn_ip = socket.gethostbyname(TTN_SERVER)

    print("="*70)
    print("PROXY GATEWAY <-> TTN")
    print("="*70)
    print(f"Escuchando:  0.0.0.0:{LOCAL_PORT}")
    print(f"Reenviando:  {TTN_SERVER} ({ttn_ip}:{TTN_PORT})")
    print(f"Guardando:   {ARCHIVO_SALIDA}")
    print("="*70)
    print()

    try:
        while True:
            data, addr = gateway_sock.recvfrom(4096)

            if gateway_addr is None:
                gateway_addr = addr

            gateway_port = addr[1]

            rxpk_list = extraer_rxpk(data)
            if rxpk_list:
                paquetes.extend(rxpk_list)

                for rxpk in rxpk_list:
                    freq = rxpk.get('freq', 0)
                    datr = rxpk.get('datr', '')
                    rssi = rxpk.get('rssi', 0)
                    snr = rxpk.get('lsnr', 0)
                    print(f"[{len(paquetes):3d}] {freq}MHz {datr:8s} "
                          f"RSSI={rssi:4d}dBm SNR={snr:5.1f}dB")

            if gateway_port not in ttn_sockets:
                ttn_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ttn_sockets[gateway_port] = ttn_sock

                thread = threading.Thread(
                    target=escuchar_respuestas_ttn,
                    args=(gateway_port, ttn_sock, gateway_sock),
                    daemon=True
                )
                thread.start()

            ttn_sockets[gateway_port].sendto(data, (ttn_ip, TTN_PORT))

    except KeyboardInterrupt:
        with open(ARCHIVO_SALIDA, 'w') as f:
            json.dump(paquetes, f, indent=2)

        print(f"\n{'='*70}")
        print(f"Total: {len(paquetes)} paquetes rxpk")
        print(f"Guardado en {ARCHIVO_SALIDA}")
        print("="*70)

    finally:
        gateway_sock.close()
        for sock in ttn_sockets.values():
            try:
                sock.close()
            except:
                pass


if __name__ == '__main__':
    main()