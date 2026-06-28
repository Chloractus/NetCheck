import os
import sys
import requests

OUI_FILE = "oui.txt"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

def getOUI(mac: str) -> str:
    return mac[:8]

def download_OUI() -> None:
    print("[*] Downloading IEEE OUI Database...")

    response = requests.get(OUI_URL, timeout=5)
    response.raise_for_status()

    with open(OUI_FILE, "w", encoding="utf-8") as f:
        f.write(response.text)

    print(f"[+] Saved database to {OUI_FILE}")
    sys.exit(1)

def loadOUI() -> dict:
    
    if not os.path.exists(OUI_FILE):
        print("[!] Database not found. (Run NetCheck -u or NetCheck --update)")
        return sys.exit(1)

    ouiDB = {}

    with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" not in line:
                continue

            parts = line.split("(hex)")
            if len(parts) != 2:
                continue
            oui = parts[0].strip().replace("-", ":")
            vendor = parts[1].strip()

            ouiDB[oui.lower()] = vendor

    return ouiDB

def getVendor(mac: str, ouiDB: dict) -> str:

    try:
        oui = getOUI(mac)

    except ValueError:
        return "Inavlid Mac Address"
    
    return ouiDB.get(oui, "Unknown Vendor")