#!/usr/bin/env python3
"""
Genera estadísticas RF desde capturas LoRaTap PCAP
Exporta CSV con métricas y resumen de análisis
"""

import subprocess
import csv
from statistics import mean, stdev

PCAP_ENTRADA = 'captures/captura_tiempo_real.pcap'
CSV_SALIDA = 'results/estadisticas_rf.csv'
RESUMEN_SALIDA = 'results/resumen_analisis_rf.txt'


def extraer_campo(pcap_file, field_name):
    cmd = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', field_name]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def main():
    print("="*70)
    print("ANÁLISIS ESTADÍSTICO RF - LoRaTap")
    print("="*70)
    print()

    frames = extraer_campo(PCAP_ENTRADA, 'frame.number')
    frecuencias = extraer_campo(PCAP_ENTRADA, 'loratap.channel.frequency')
    sfs = extraer_campo(PCAP_ENTRADA, 'loratap.channel.sf')
    rssis = extraer_campo(PCAP_ENTRADA, 'loratap.rssi.packet')
    snrs = extraer_campo(PCAP_ENTRADA, 'loratap.rssi.snr')
    devaddrs = extraer_campo(PCAP_ENTRADA, 'lorawan.fhdr.devaddr')
    fcnts = extraer_campo(PCAP_ENTRADA, 'lorawan.fhdr.fcnt')
    mic_status = extraer_campo(PCAP_ENTRADA, 'lorawan.mic.status')

    total_paquetes = len(frames)

    freq_mhz = [float(f) / 1_000_000 for f in frecuencias if f]
    rssi_values = [int(r) - 139 for r in rssis if r]
    snr_values = [float(s) / 4.0 for s in snrs if s]

    with open(CSV_SALIDA, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Frame', 'Frequency_MHz', 'SF', 'RSSI_dBm', 'SNR_dB',
                        'DevAddr', 'FCnt', 'MIC_Status'])

        max_len = max(len(frames), len(freq_mhz), len(sfs), len(rssi_values),
                     len(snr_values), len(devaddrs), len(fcnts), len(mic_status))

        for i in range(max_len):
            writer.writerow([
                frames[i] if i < len(frames) else '',
                f"{freq_mhz[i]:.1f}" if i < len(freq_mhz) else '',
                sfs[i] if i < len(sfs) else '',
                rssi_values[i] if i < len(rssi_values) else '',
                f"{snr_values[i]:.1f}" if i < len(snr_values) else '',
                devaddrs[i] if i < len(devaddrs) else '',
                fcnts[i] if i < len(fcnts) else '',
                mic_status[i] if i < len(mic_status) else ''
            ])

    if rssi_values:
        rssi_avg = mean(rssi_values)
        rssi_min = min(rssi_values)
        rssi_max = max(rssi_values)
        rssi_std = stdev(rssi_values) if len(rssi_values) > 1 else 0

        print("RSSI:")
        print(f"  Promedio: {rssi_avg:.1f} dBm")
        print(f"  Rango:    {rssi_min} a {rssi_max} dBm")
        print(f"  Desv.Est: {rssi_std:.2f} dB")
        print()

    if snr_values:
        snr_avg = mean(snr_values)
        snr_min = min(snr_values)
        snr_max = max(snr_values)
        snr_std = stdev(snr_values) if len(snr_values) > 1 else 0

        print("SNR:")
        print(f"  Promedio: {snr_avg:.1f} dB")
        print(f"  Rango:    {snr_min:.1f} a {snr_max:.1f} dB")
        print(f"  Desv.Est: {snr_std:.2f} dB")
        print()

    if freq_mhz:
        freq_unique = set(freq_mhz)
        print(f"Canales: {len(freq_unique)}")
        for freq in sorted(freq_unique):
            count = freq_mhz.count(freq)
            print(f"  {freq:.1f} MHz ({count} paquetes)")
        print()

    if sfs:
        sf_unique = set(sfs)
        print("Spreading Factors:")
        for sf in sorted(sf_unique):
            count = sfs.count(sf)
            print(f"  SF{sf} ({count} paquetes)")
        print()

    with open(RESUMEN_SALIDA, 'w') as f:
        f.write("="*70 + "\n")
        f.write("RESUMEN DE ESTADÍSTICAS RF - LoRaWAN\n")
        f.write("="*70 + "\n\n")
        f.write(f"Total de paquetes: {total_paquetes}\n\n")

        if rssi_values:
            f.write("RSSI:\n")
            f.write(f"  - Promedio: {rssi_avg:.1f} dBm\n")
            f.write(f"  - Rango: {rssi_min} a {rssi_max} dBm\n")
            f.write(f"  - Desviación estándar: {rssi_std:.2f} dB\n\n")

        if snr_values:
            f.write("SNR:\n")
            f.write(f"  - Promedio: {snr_avg:.1f} dB\n")
            f.write(f"  - Rango: {snr_min:.1f} a {snr_max:.1f} dB\n")
            f.write(f"  - Desviación estándar: {snr_std:.2f} dB\n\n")

        if freq_unique:
            f.write(f"Canales utilizados: {len(freq_unique)}\n")
            for freq in sorted(freq_unique):
                count = freq_mhz.count(freq)
                pct = (count / len(freq_mhz)) * 100
                f.write(f"  - {freq:.1f} MHz: {count} paquetes ({pct:.1f}%)\n")
            f.write("\n")

        if sf_unique:
            f.write("Spreading Factors:\n")
            for sf in sorted(sf_unique):
                count = sfs.count(sf)
                pct = (count / len(sfs)) * 100
                f.write(f"  - SF{sf}: {count} paquetes ({pct:.1f}%)\n")

    print("="*70)
    print(f"CSV:     {CSV_SALIDA}")
    print(f"Resumen: {RESUMEN_SALIDA}")
    print("="*70)


if __name__ == '__main__':
    main()