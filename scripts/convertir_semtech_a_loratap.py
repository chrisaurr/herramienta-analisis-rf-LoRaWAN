#!/usr/bin/env python3
"""
Convierte capturas UDP Semtech a formato LoRaTap para análisis en Wireshark
"""

import struct
import base64
import json
import subprocess
import sys


def crear_header_loratap(freq_hz, bw_khz, sf, rssi, snr):
    """
    Crea header LoRaTap de 15 bytes según especificación oficial
    Formato big-endian, linktype 270
    """
    header = struct.pack('>BBH', 0, 0, 15)
    header += struct.pack('>I', freq_hz)

    bw_steps = bw_khz // 125
    header += struct.pack('>BB', bw_steps, sf)

    rssi_value = max(0, min(255, rssi + 139))
    header += struct.pack('>BBB', rssi_value, rssi_value, rssi_value)

    snr_db = snr / 10.0
    snr_value = int(snr_db * 4)
    if snr_value < 0:
        snr_value = (256 + snr_value) & 0xFF
    header += struct.pack('>B', snr_value)

    header += struct.pack('>B', 0x34)

    return header


def escribir_header_pcap(f, linktype=270):
    magic = 0xa1b2c3d4
    f.write(struct.pack('<IHHIIII', magic, 2, 4, 0, 0, 65535, linktype))


def escribir_paquete_pcap(f, data, timestamp):
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)

    f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
    f.write(data)


def extraer_rxpk_desde_pcap(pcap_file):
    cmd = f'tshark -r {pcap_file} -Y "udp.port == 1700 and data.len > 200" -T json'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        return []

    tshark_packets = json.loads(result.stdout)
    rxpk_list = []

    for packet in tshark_packets:
        try:
            layers = packet['_source']['layers']
            data_hex = layers['data']['data.data'].replace(':', '')
            raw_bytes = bytes.fromhex(data_hex)

            if len(raw_bytes) < 12 or raw_bytes[3] != 0x00:
                continue

            json_payload = raw_bytes[12:].decode('utf-8')
            payload_obj = json.loads(json_payload)

            if 'rxpk' in payload_obj:
                rxpk_list.extend(payload_obj['rxpk'])

        except Exception:
            continue

    return rxpk_list


def convertir_a_loratap(rxpk_list, output_file):
    import time

    with open(output_file, 'wb') as f:
        escribir_header_pcap(f, linktype=270)

        contador = 0

        for rxpk in rxpk_list:
            try:
                freq = rxpk.get('freq', 904.0)
                datr = rxpk.get('datr', 'SF7BW125')
                rssi = rxpk.get('rssi', -100)
                lsnr = rxpk.get('lsnr', 0.0)
                data_b64 = rxpk.get('data', '')

                sf = int(datr[2:datr.index('BW')])
                bw_khz = int(datr[datr.index('BW')+2:])

                freq_hz = int(freq * 1e6)
                snr_scaled = int(lsnr * 10)

                lorawan_payload = base64.b64decode(data_b64)
                loratap_header = crear_header_loratap(freq_hz, bw_khz, sf, rssi, snr_scaled)

                paquete_completo = loratap_header + lorawan_payload
                escribir_paquete_pcap(f, paquete_completo, time.time())

                contador += 1
                print(f"[{contador:3d}] {freq}MHz {datr:8s} RSSI={rssi:4d}dBm SNR={lsnr:5.1f}dB")

            except Exception:
                continue

    return contador


def main():
    if len(sys.argv) < 2:
        input_pcap = '../captures/captura_udp_semtech.pcap'
    else:
        input_pcap = sys.argv[1]

    output_pcap = '../captures/capturas_loratap_convertidas.pcap'

    print("="*70)
    print("CONVERSIÓN SEMTECH UDP -> LoRaTap")
    print("="*70)
    print(f"Entrada:  {input_pcap}")
    print(f"Salida:   {output_pcap}")
    print("="*70)
    print()

    rxpk_list = extraer_rxpk_desde_pcap(input_pcap)

    if not rxpk_list:
        print("No se encontraron paquetes rxpk")
        return 1

    total = convertir_a_loratap(rxpk_list, output_pcap)

    print()
    print("="*70)
    print(f"Total: {total} paquetes LoRaTap")
    print(f"Guardado en {output_pcap}")
    print("="*70)

    return 0


if __name__ == '__main__':
    exit(main())