#!/usr/bin/env python3
"""
Traceroute Map (macOS robust edition)

Uso:
    python traceroute_map.py <host_or_ip>
Esempio:
    python traceroute_map.py wikipedia.org
"""

import sys
import subprocess
import re
import requests
import time
import webbrowser
from statistics import mean

import folium
from folium.plugins import PolyLineTextPath

# Configurazione
GEO_API = "http://ip-api.com/json/{}"
REQUESTS_SLEEP = 0.6
OUTPUT_HTML = "traceroute_map.html"

# Regex per IP v4
IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.", "169.254.")

def run_traceroute(target):
    """Esegue traceroute su macOS/Linux in formato numerico (-n)."""
    cmd = ["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20", target]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, check=False)
    return proc.stdout.splitlines()

def parse_hops(traceroute_lines):
    """Estrae IP dalle righe di traceroute. Restituisce lista di IP o None."""
    hops = []
    for line in traceroute_lines:
        line = line.strip()
        if not line or line.startswith("traceroute"):
            continue
        ips = IP_RE.findall(line)
        if ips:
            hops.append(ips[0])  # prendi il primo IP della riga
        else:
            hops.append(None)    # nessuna risposta (*)
    return hops

def geolocate_ip(ip):
    """Geolocalizza un IP pubblico. Restituisce (lat, lon, city, country) o None."""
    if ip is None:
        return None
    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        return None
    try:
        r = requests.get(GEO_API.format(ip), timeout=10)
        data = r.json()
        if data.get("status") != "success":
            return None
        return (data["lat"], data["lon"], data.get("city"), data.get("country"))
    except Exception:
        return None

def build_map(locations, target):
    coords = [(latlon[0], latlon[1]) for (_, _, latlon) in locations if latlon]
    center = (mean([c[0] for c in coords]), mean([c[1] for c in coords])) if coords else (0, 0)
    m = folium.Map(location=center, zoom_start=2)

    # Marker per ogni hop
    for hop_index, ip, latlon in locations:
        if latlon:
            lat, lon, city, country = latlon
            popup = f"Hop {hop_index}<br>IP: {ip}<br>{city or ''} {country or ''}"
            folium.Marker(location=(lat, lon), popup=popup,
                          tooltip=f"{hop_index}: {ip}").add_to(m)

    # Linee con frecce tra hop consecutivi validi
    path = []
    for hop_index, ip, latlon in locations:
        if latlon:
            path.append((latlon[0], latlon[1]))
        else:
            if len(path) >= 2:
                pl = folium.PolyLine(path, weight=3).add_to(m)
            path = []

    if len(path) >= 2:
        pl = folium.PolyLine(path, weight=3).add_to(m)


    return m

def main():
    if len(sys.argv) < 2:
        print("Uso: python traceroute_map.py <host_or_ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[+] Eseguo traceroute verso {target} ...")
    lines = run_traceroute(target)

    hops_ips = parse_hops(lines)
    locations = []

    for idx, ip in enumerate(hops_ips, 1):
        if ip is None:
            print(f"Hop {idx}: nessuna risposta (*)")
            locations.append((idx, None, None))
            continue
        if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
            print(f"Hop {idx}: {ip} (IP privato, salto geoloc)")
            locations.append((idx, ip, None))
            continue

        print(f"Hop {idx}: {ip} -> geolocalizzo...", end=" ")
        geo = geolocate_ip(ip)
        if geo:
            lat, lon, city, country = geo
            print(f"{lat:.2f},{lon:.2f} ({city}, {country})")
            locations.append((idx, ip, geo))
        else:
            print("geoloc non trovata")
            locations.append((idx, ip, None))
        time.sleep(REQUESTS_SLEEP)

    valid_coords = sum(1 for (_, _, latlon) in locations if latlon)
    if valid_coords < 2:
        print("[!] Attenzione: meno di 2 hop pubblici geolocalizzati → la mappa sarà limitata.")

    print("[+] Creo la mappa...")
    m = build_map(locations, target)
    m.save(OUTPUT_HTML)
    print(f"[+] Mappa salvata in '{OUTPUT_HTML}'")
    webbrowser.get("open -a 'Google Chrome' %s").open(OUTPUT_HTML)
    # webbrowser.open(OUTPUT_HTML)

if __name__ == "__main__":
    main()
