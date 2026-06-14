import argparse
import sys
import datetime
import subprocess
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, srp, conf

from NetCheck.util.reverseDNS import *
from NetCheck.util.NetBIOS import *
from NetCheck.util.mDNS import *
from NetCheck.util.SSDP import *

conf.verb = 0

KnownDevices = {
	"ff:ff:ff:ff:ff:ff"
}

def scan(subnet: str, timeout: int = 1) -> list[dict]:

	frame = Ether(dst="ff:ff:ff:ff:ff:ff")
	seen_ips = set()
	arpRequest = ARP(pdst=subnet)
	packet = frame / arpRequest

	print(f"\n[*] Scanning subnet: {subnet}")
	print(f"[*] Waiting up to {timeout}s for ARP replies...\n")

	ans, unans = srp(packet, timeout=timeout, multi=True)

	devices = []

	for sent, recieved in ans:
		if recieved.psrc not in seen_ips:
			seen_ips.add(recieved.psrc)
			ip = recieved[ARP].psrc
			mac = recieved[Ether].src
			macL = mac.replace(':','').replace('-','').replace('.','').lower()
			macClean = ':'.join(macL[i:i+2] for i in range(0, 12, 2))
			isKnown = macClean in KnownDevices

			ssdpDetails = {
				"name" : "N/A",
				"manufacturer" : "N/A",
				"model" : "N/A",
				"server" : "N/A"
			}

			devices.append({
				"ip": ip,
				"mac": mac,
				"known": isKnown,
				"dns" : "N/A",
				"nbns" : "N/A",
				"mdns" : "N/A",
				"ssdp" : ssdpDetails
			})

	totalS = len(devices)
	totalR = len(ans)
	print(f"[*] Received {totalR} ARP reply packet(s) -- {totalS} unique device(s)\n")

	devices.sort(key=lambda d:tuple(int(x) for x in d["ip"].split(".")))

	return devices

def resolveNames(devices: list[dict], inSSDP: bool) -> None:
	if not devices:
		return
	
	ips = [d['ip'] for d in devices]
	print("[*] Resolving hostnames...")

	with ThreadPoolExecutor(max_workers=min(len(ips), 50)) as executor:
		dns = {ip: executor.submit(reverseDNS, ip) for ip in ips}
		nbns = {ip: executor.submit(netBIOS, ip) for ip in ips}
		mdns = {ip: executor.submit(mdnsQ, ip) for ip in ips}
		if inSSDP:
			ssdp = {ip: executor.submit(SSDP, ip) for ip in ips}
		
	for device in devices:
		ip = device['ip']
		device['dns'] = dns[ip].result()
		device['nbns'] = nbns[ip].result()
		device['mdns'] = mdns[ip].result()
		if inSSDP:
			device['ssdp'] = ssdp[ip].result()

	print("[*] Resolution complete.\n")

def display(devices: list[dict], subnet: str, inSSDP: bool) -> None:

	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print("=" * 130)
	print(f"  NETWORK MAP - {subnet}")
	print(f"  Scanned at: {timestamp}")
	print("=" * 130)
	print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'DNS Hostname': <32} {'NetBIOS Name': <20} {'mDNS Name':<20} STATUS")
	print("-" * 130)

	if not devices:
		print("  No devices found. Check your subnet or try a longer timeout.")

	else:
		for device in devices:
			status = "[$]  Known" if device["known"] else "[!] UNKNOWN"
			dnsName = device.get('dns', 'N/A')
			nbnsName = device.get('nbns', 'N/A')
			mdnsName = device.get("mdns", "N/A")
			print(f"  {device['ip']:<18} {device['mac']:<20} {dnsName:<32} {nbnsName:<20} {mdnsName:<20} {status}")

	print("-" * 130)
	total = len(devices)
	unknown = sum(1 for d in devices if not d["known"])
	print(f"  Total devices found : {total}")
	print(f"  Unknown devices     : {unknown}")
	print("=" * 130)

	if unknown > 0:
		print(f"  [!] WARNING: {unknown} unrecognized device(s) found on your network!")
		print("    Add trusted MACs to KnownDevices at the top of this script.")

		for d in devices:
			if not d["known"]:
				print(f"      -> {d['ip']:>15}   MAC: {d['mac']}")
	if inSSDP:
		print("=" * 130)
		print("  SSDP Results")
		print("=" * 130)
		print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'NAME':<20} {'MANUFACTURER':<20} {'MODEL':<20} SERVER")
		print("-" * 130)
		for device in devices:
			dets = device.get("ssdp")
			name = dets['name']
			manufacturer = dets["manufacturer"]
			model = dets["model"]
			server = dets["server"]
			print(f"  {device['ip']:<18} {device['mac']:<20} {name:<20} {manufacturer:<20} {model:<20} {server}")

def parse_args() -> argparse.Namespace:

	parser = argparse.ArgumentParser(
		description="ARP Network Scanner — discover devices on your LAN",
		epilog="Example: sudo python3 arp_scanner.py --subnet 192.168.0.0/24"
	)

	parser.add_argument(
		"--subnet",
		type=str,
		default="192.168.1.0/24",
		help="Target subnet in CIDR notation (default: 192.168.1.0/24)"
	)

	parser.add_argument(
		"--timeout",
		type=int,
		default=1,
		help="Seconds to wait for ARP replies (default: 1)"
	)

	parser.add_argument(
		"-C",
		"--clear",
		action="store_true",
		help="Clear the screen before starting"
	)

	parser.add_argument(
		"-U",
		"--SSDP",
		action="store_true",
		help="Attempt to find SSDP details"
	)

	parser.add_argument(
		"-S",
		"--scan",
		action="store_true",
		help="Scan for open ports on all hosts"
	)

	return parser.parse_args()