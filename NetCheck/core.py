import argparse
import sys
import datetime
import subprocess
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, ICMP, IP, Ether, conf, sniff, sr1, srp

from util.reverseDNS import *
from util.NetBIOS import *
from util.mDNS import *
from util.SSDP import *
from util.OUI import *
from util.PScan import *

conf.verb = 0

KnownDevices = {
	"ff:ff:ff:ff:ff:ff"
}

_LAN_NETWORKS = [
	ipaddress.ip_network("10.0.0.0/8"),
	ipaddress.ip_network("172.16.0.0/12"),
	ipaddress.ip_network("192.168.0.0/16"),
	ipaddress.ip_network("127.0.0.0/8"),
	ipaddress.ip_network("169.254.0.0/16")
]

def is_ts_LAN(ip: str) -> bool:
	try:
		addr = ipaddress.ip_address(ip)

		if addr.is_multicast or str(addr) in ("255.255.255.255", "0.0.0.0"):
			return False
		
		matched = next((net for net in _LAN_NETWORKS if addr in net), None)
		if matched is None:
			return False
		
		if addr in (matched.network_address, matched.broadcast_address):
			return False
		
		return True
	except ValueError:
		return False

discovered: set[str] = set() #Type hints that this is going to be a set of str
mac_table: dict[str, str] = {} #Table for us to keep the MAC addresses found by ARP (Gets appended to devices later on)
hLock = threading.Lock()
sEvent = threading.Event()

def _add_host(ip: str, source: str) -> None:
	with hLock:
		if ip not in discovered:
			discovered.add(ip)

			timestamp = time.strftime("%H:%M:%S")
			print(f"  [{timestamp}] [{source:^14}] NEW HOST -> {ip}")

def _is_known(ip: str) -> bool:
	with hLock:
		return ip in discovered
	
def lARP(subnet: str, timeout: int = 2, retry: int = 1) -> None:
	print(f"\n[lARPing/ ARP Sweep] - Starting on {subnet}")
	try:
		network = ipaddress.ip_network(subnet, strict=False)

		targets = [str(h) for h in network.hosts() if is_ts_LAN(str(h))]
		
		print(f"  [lARPing/ ARP Sweep] - Sending {len(targets)} ARP request(s)")

		pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in targets]
		ans, _ = srp(pkts, timeout=timeout, retry=retry, verbose=0)

		for _, rcv in ans:
			if sEvent.is_set():
				break
			ip = rcv[ARP].psrc
			mac = rcv[Ether].src
			if is_ts_LAN(ip):
				_add_host(ip, "ARP Sweep")

				clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()
				with hLock:
					mac_table[ip] = ":".join(clean[i:i+2] for i in range(0, 12, 2))

		print(f"  [lARPing/ ARP Sweep] - {len(ans)} host(s) responded.")

	except Exception as exc:
		print(f"  [lARPing/ ARP Sweep] - Error: {exc}")

	print("[lARPing/ ARP Sweep] - Complete.")

def _ping(ip: str, timeout: int = 1) -> None:
	if _is_known(ip):
		return
	
	try:
		result = subprocess.run(
			['ping', '-n', '1','-w', str(timeout * 1000), ip],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
			timeout=timeout
		)
		if result.returncode == 0 and is_ts_LAN(ip):
			_add_host(ip, "Ping Sweep")
	except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
		pass

def ping_sweep(subnet: str, max_workers: int = 100) -> None:
	print(f"\n[Ping Sweep] - Starting on {subnet} (max {max_workers} workers)")

	try:
		network = ipaddress.ip_network(subnet, strict=False)
		targets = [str(h) for h in network.hosts() if not _is_known(str(h))]

		with ThreadPoolExecutor(max_workers=min(len(targets), max_workers)) as exec:
			futures = {exec.submit(_ping, ip): ip for ip in targets}
			for future in futures:
				if sEvent.is_set():
					break
				future.result()

	except Exception as exc:
		print(f"  [Ping Sweep] - Error: {exc}")

	print("[Ping Sweep] - Finished.")



def passive(iface: str | None, duration: float, subnet: str) -> None:
	label = iface or conf.iface
	network = ipaddress.ip_network(subnet, strict=False)
	print(f"\n[Passive] - '{label}' for {duration}s")

	def _callback(pkt) -> None:
		if pkt.haslayer(IP):
			src = pkt[IP].src
			try:
				if ipaddress.ip_address(src) in network and is_ts_LAN(src) and not _is_known(src):
					_add_host(src, "Passive Sniff")
			except ValueError:
				pass

	try:
		sniff(
			iface=iface,
			prn=_callback,
			store=False,
			timeout=duration,
			stop_filter=lambda _: sEvent.is_set()
		)

	except Exception as exc:
		print(f"  [Passive] - Error: {exc}")

	print("[Passive] - Finished.")

def do_ts(
		subnet: str,
		iface: str | None = None,
		duration: float = 30,
		max_workers: int = 150,
		arp_time: int = 2,
		arp_retry: int = 1
) -> set[str]:
	
	print("=" * 60)
	print("  Concurrent Discovery: ARP + Ping + Passive Sniff")
	print(f"  Subnet    : {subnet}")
	print(f"  Interface : {iface or 'default'}")
	print(f"  Sniff     : {duration}s")
	print("=" * 60)

	threads = [
		threading.Thread(
			target=lARP,
			args=(subnet, arp_time, arp_retry),
			name="ARP-Sweep",
			daemon=True
		),
		threading.Thread(
			target=ping_sweep,
			args=(subnet, max_workers),
			name="Ping-Sweep",
			daemon=True
		),
		threading.Thread(
			target=passive,
			args=(iface, duration, subnet),
			name="Passive-Sniff",
			daemon=True
		)
	]

	start = time.time()
	for t in threads:
		t.start()

	try:
		for t in threads:
			t.join()
	except KeyboardInterrupt:
		print("\n[!] - Interrupted: stopping...")
		sEvent.set()
		for t in threads:
			t.join(timeout=3)

	elapsed = time.time() - start
	print(f"\n[*] - Discovery complete in {elapsed:.1f}s : {len(discovered)} unique host(s) found.")
	return discovered

def scan(subnet: str, timeout: int = 2, iface: str | None = None, duration: float = 30, max_workers: int = 150) -> list[dict]:

	live = do_ts(subnet, iface=iface, duration=duration, max_workers=max_workers, arp_time=timeout)

	if not live:
		print("[!] - No hosts found.")
		return []
	
	with hLock:
		macT = dict(mac_table)

	no_mac = len(live) - len(macT)
	if no_mac > 0:
		print(f"[*] {no_mac} host(s) found via ping/sniff with no ARP reply (MAC: UNKNOWN)")

	devices = []
	for ip in live:
		mac = macT.get(ip, "UNKNOWN")
		macClean = mac if mac == "UNKNOWN" else mac
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
			"vendor" : "N/A",
			"best name" : "N/A",
			"ports" :"N/A",
			"dns" : "N/A",
			"nbns" : "N/A",
			"mdns" : "N/A",
			"ssdp" : ssdpDetails
		})

	devices.sort(key=lambda d:tuple(int(x) for x in d["ip"].split(".")))
	return devices

def resolveNames(devices: list[dict], inSSDP: bool) -> None:
	if not devices:
		return
	
	OUI = loadOUI()

	ips = [d['ip'] for d in devices]
	macs = [d['mac'] for d in devices]

	print("[*] Resolving hostnames...")

	with ThreadPoolExecutor(max_workers=min(len(ips) * 4, 150)) as executor:
		dns = {ip: executor.submit(reverseDNS, ip) for ip in ips}
		nbns = {ip: executor.submit(netBIOS, ip) for ip in ips}
		mdns = {ip: executor.submit(mdnsQ, ip) for ip in ips}
		oui = {mac: executor.submit(getVendor, mac, OUI) for mac in macs if mac}
		ports = {ip: executor.submit(PScan, ip) for ip in ips}
		if inSSDP:
			ssdp = {ip: executor.submit(SSDP, ip) for ip in ips}
		
	for device in devices:
		ip = device['ip']
		mac = device['mac']
		device['ports'] = ports[ip].result()
		device['dns'] = dns[ip].result()
		device['nbns'] = nbns[ip].result()
		device['mdns'] = mdns[ip].result()

		if mac:
			device['vendor'] = oui[mac].result()

		if inSSDP:
			device['ssdp'] = ssdp[ip].result()

	print("[*] Resolution complete.\n")

def update(update: bool) -> None:
	if update:
		download_OUI()

def getBest(device:dict) ->str:
	for key in ('dns', 'nbns'):
		value = device.get(key)
		if isinstance(value, str) and value not in ('', 'N/A'):
			return value
		
	ssdp = device.get('ssdp')
	if isinstance(ssdp, dict) and ssdp.get('name') not in ('', 'N/A'):
		return ssdp.get('name')
	
	for key in ('mdns', 'vendor'):
		value = device.get(key)
		if isinstance(value, str) and value not in ('', 'N/A'):
			return value

def display(devices: list[dict], subnet: str, inSSDP: bool) -> None:

	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print("=" * 130)
	print(f"  NETWORK MAP - {subnet}")
	print(f"  Scanned at: {timestamp}")
	print("=" * 130)
	print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'Best Name': <32} {'Ports': <20} {'Vendor':<20}")
	print("-" * 130)

	for device in devices:
		bestName = getBest(device)
		ports = device.get('ports', 'N/A')
		vendor = device.get('vendor', "N/A")
		print(f"  {device['ip']:<18} {device['mac']:<20} {bestName:<32} {ports:<20} {vendor:<20}")

	print("-" * 130)
	total = len(devices)
	unknown = sum(1 for d in devices if not d["known"])
	print(f"  Total devices found : {total}")
	print(f"  Unknown devices     : {unknown}")
	print("=" * 130)
	print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'DNS Hostname': <32} {'NetBIOS Name': <20} {'mDNS Name':<22} STATUS")
	print("-" * 130)

	if not devices:
		print("  No devices found. Check your subnet or try a longer timeout.")

	else:
		for device in devices:
			status = "[$]  Known" if device["known"] else "[!] UNKNOWN"
			dnsName = device.get('dns', 'N/A')
			nbnsName = device.get('nbns', 'N/A')
			mdnsName = device.get("mdns", "N/A")
			print(f"  {device['ip']:<18} {device['mac']:<20} {dnsName:<32} {nbnsName:<20} {mdnsName:<22} {status}")


	print("-" * 130)

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
		description="NetCheck — discover devices on your LAN",
		epilog="Example: sudo python3 NetCheck --subnet 192.168.0.0/24"
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
		"-c",
		"--clear",
		action="store_true",
		help="Clear the screen before starting"
	)

	parser.add_argument(
		"-d",
		"--SSDP",
		action="store_true",
		help="Attempt to find SSDP details"
	)

	parser.add_argument(
		"-u",
		"--update",
		action="store_true",
		help="Update dependencies"
	)

	return parser.parse_args()