#!/usr/bin/env python3
"""
Captura en tiempo real desde interfaz de red y convierte a LoRaTap
Requiere ejecución con sudo para sniffing de red
"""

from scapy.all import sniff, UDP, Raw
import struct
import base64
import json

ARCHIVO_SALIDA = "/home/chris/VsCodeProjects/proyecto-telecomunicaciones/captures/captura_tiempo_real.pcap"

contador = 0
archivo = None


def crear_header_loratap(freq_hz, bw_khz, sf, rssi, snr):
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


def escribir_header_pcap(f):
    magic = 0xa1b2c3d4
    f.write(struct.pack('<IHHIIII', magic, 2, 4, 0, 0, 65535, 270))
    f.flush()


def escribir_paquete(f, data, timestamp):
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
    f.write(data)
    f.flush()


def procesar_paquete(pkt):
    global contador, archivo

    if UDP in pkt and pkt[UDP].dport == 1700:
        if Raw in pkt:
            udp_payload = bytes(pkt[Raw].load)

            if len(udp_payload) < 12 or udp_payload[3] != 0x00:
                return

            try:
                json_str = udp_payload[12:].decode('utf-8')
                obj = json.loads(json_str)

                if 'rxpk' not in obj:
                    return

                for rxpk in obj['rxpk']:
                    freq = rxpk.get('freq', 904.0)
                    datr = rxpk.get('datr', 'SF7BW125')
                    rssi = rxpk.get('rssi', -100)
                    lsnr = rxpk.get('lsnr', 0.0)
                    data_b64 = rxpk.get('data', '')

                    sf = int(datr[2:datr.index('BW')])
                    bw_khz = int(datr[datr.index('BW')+2:])
                    freq_hz = int(freq * 1e6)
                    snr_scaled = int(lsnr * 10)

                    lorawan = base64.b64decode(data_b64)
                    loratap = crear_header_loratap(freq_hz, bw_khz, sf, rssi, snr_scaled)

                    timestamp = float(pkt.time)
                    escribir_paquete(archivo, loratap + lorawan, timestamp)

                    contador += 1
                    print(f"[{contador:3d}] {freq}MHz {datr:8s} RSSI={rssi:4d}dBm SNR={lsnr:5.1f}dB")

            except:
                pass


def main():
    global archivo

    archivo = open(ARCHIVO_SALIDA, 'wb')
    escribir_header_pcap(archivo)

    print("="*70)
    print("CAPTURA EN TIEMPO REAL: Interfaz -> LoRaTap")
    print("="*70)
    print(f"Interfaz:  wlan0 (UDP port 1700)")
    print(f"Salida:    {ARCHIVO_SALIDA}")
    print("="*70)
    print()

    try:
        sniff(iface="wlan0", filter="udp port 1700", prn=procesar_paquete, store=False)
    except KeyboardInterrupt:
        print(f"\n{'='*70}")
        print(f"Total: {contador} paquetes")
        print("="*70)
    finally:
        archivo.close()


if __name__ == '__main__':
    main()