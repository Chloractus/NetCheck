import argparse
import sys
import datetime
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, Ether, srp, conf

conf.verb = 0

KnownDevices = {
	"ff:ff:ff:ff:ff:ff",
	"30:56:0f:20:59:46",
	"84:a9:3e:51:99:a8",
	"5c:62:8b:ee:bb:e0"
}

def mdnsEncode(name: str) -> bytes:
	encoded = b''
	for label in name.split('.'):
		if label:
			encoded += bytes([len(label)]) + label.encode('ascii')

	return encoded + b'\x00'

def mdnsDecode(data: bytes, offset:int) -> tuple[str, int]: #we in trouble if this tuple gets augmented
	labels = []
	visited = set()

	while offset < len(data):
		if offset in visited:
			break

		visited.add(offset)

		length = data[offset]

		if length == 0:
			offset += 1
			break

		elif (length & 0xC0) == 0xC0:
			ptr = ((length & 0x3F) << 8 | data[offset  + 1])
			sub, _ = mdnsDecode(data, ptr)

			if sub:
				labels.append(sub)
			
			offset += 2
			break

		else:
			label = data[offset+1:offset+1+length.decode('ascii', errors='replace')]
			labels.append(label)
			offset += 1 + length

	return '.'.join(labels), offset

def mdns(ip: str) -> str:
	reverse = ".".join(reversed(ip.split('.'))) + '.in-addr.arpa'

	header = struct.pack(
		'>HHHHHH',
		0x0001,
		0x0000,
		1,
		0, 0, 0
	)

	qName = mdnsEncode(reverse)
	qType = struct.pack('>H', 12)
	qClass = struct.pack('>H', 0x8001)

	query = header + qName + qType + qClass
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(1)
		sock.sendto(query, (ip, 5353))
		data, _ = sock.recvfrom(4096)
		sock.close()

		if len(data) < 12:
			return "N/A"
		
		qdCount = struct.unpack('>H', data[4:6])[0]
		anCount = struct.unpack('<H', data[6:8])[0]

		if anCount == 0:
			return "N/A"
		
		offset = 12
		for _ in range(qdCount):
			_, offset = mdnsDecode(data, offset)
			offset += 4

		for _ in range(anCount):
			_, offset = mdnsDecode(data, offset)

			if offset + 10 > len(data):
				break

			rrType, _, _, rdLength = struct.unpack('>HHIH', data[offset:offset+10])
			offset += 10

			if rrType == 12:
				hostname, _ = mdnsDecode(data, offset)
				
				if hostname:
					return hostname.rstrip('.')

			offset += rdLength
		
		return "N/A"
	
	except (socket.timeout, OSError):
		return "N/A"

def nbnsEncode(name: str) -> bytes:

	padded = (name + '\x00' * 16)[:16].encode('ascii')

	encoded = bytearray()
	for byte in padded:
		encoded.append(0x41 + ((byte >> 4) & 0x0F))
		encoded.append(0x41 + (byte & 0x0F))

	return bytes([32]) + bytes(encoded) + b'\x00\x00'

def netBIOS(ip: str) -> str:
	
	header = struct.pack(
		">HHHHHH",
		0xABCD,
		0x0000,
		1,
		0, 0, 0
	)

	qName = nbnsEncode("*")
	qType = struct.pack(">H", 0x0021)
	qClass = struct.pack(">H", 0x0001)

	query = header + qName + qType + qClass

	try:

		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(1)
		sock.sendto(query, (ip, 137))
		data, _ = sock.recvfrom(1024)
		sock.close()

		if len(data) < 57:
			return "N/A"
		
		ansStart = 51
		rrNameLen = 2 if data[ansStart] == 0xC0 else 35
		rdataOffset = ansStart + rrNameLen + 10

		if rdataOffset >= len(data):
			return "N/A"
		
		numNames = data[rdataOffset]
		entryStart = rdataOffset + 1

		for i in range(numNames):
			offset = entryStart + i * 18
			if offset + 16 > len(data):
				break

			nameRaw = data[offset : offset + 15]
			suffix = data[offset + 15]
			nameStr = nameRaw.decode('ascii', errors='replace').rstrip(' \x00').strip()

			if suffix == 0x00 and nameStr:
				return nameStr
			
		return "N/A"
	
	except (socket.timeout, OSError):
		return "N/A"

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

			devices.append({
				"ip": ip,
				"mac": mac,
				"known": isKnown,
				"dns" : "N/A",
				"nbns" : "N/A"
			})

	totalS = len(devices)
	totalR = len(ans)
	print(f"[*] Received {totalR} ARP reply packet(s) -- {totalS} unique device(s)\n")

	devices.sort(key=lambda d:tuple(int(x) for x in d["ip"].split(".")))

	return devices

def reverseDNS(ip: str) -> str:
	try:
		hostname, _, _ = socket.gethostbyaddr(ip)
		return hostname
	
	except socket.herror:
		return "N/A"
	
	except socket.gaierror:
		return "N/A"

def resolveNames(devices: list[dict]) -> None:
	if not devices:
		return
	
	ips = [d['ip'] for d in devices]
	print("[*] Resolving hostnames (DNS + NetBIOS in parallel)...")

	with ThreadPoolExecutor(max_workers=min(len(ips), 50)) as executor:
		dns = {ip: executor.submit(reverseDNS, ip) for ip in ips}
		nbns = {ip: executor.submit(netBIOS, ip) for ip in ips}

	for device in devices:
		ip = device['ip']
		device['dns'] = dns[ip].result()
		device['nbns'] = nbns[ip].result()

	print("[*] Resolution complete.\n")

def display(devices: list[dict], subnet: str) -> None:

	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print("=" * 110)
	print(f"  NETWORK MAP - {subnet}")
	print(f"  Scanned at: {timestamp}")
	print("=" * 110)
	print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'DNS Hostname': <32} {'NetBIOS Name': <20} STATUS")
	print("-" * 110)

	if not devices:
		print("  No devices found. Check your subnet or try a longer timeout.")

	else:
		for device in devices:
			status = "[$]  Known" if device["known"] else "[!] UNKNOWN"
			dnsName = device.get('dns', 'N/A')
			nbnsName = device.get('nbns', 'N/A')
			print(f"  {device['ip']:<18} {device['mac']:<20} {dnsName:<32} {nbnsName:<20} {status}")

	print("-" * 110)
	total = len(devices)
	unknown = sum(1 for d in devices if not d["known"])
	print(f"  Total devices found : {total}")
	print(f"  Unknown devices     : {unknown}")
	print("=" * 110)

	if unknown > 0:
		print(f"  [!] WARNING: {unknown} unrecognized device(s) found on your network!")
		print("    Add trusted MACs to KnownDevices at the top of this script.")

		for d in devices:
			if not d["known"]:
				print(f"      -> {d['ip']:>15}   MAC: {d['mac']}")

	print()

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
		"-S",
		"--scan",
		action="store_true",
		help="Scan for open ports on all hosts"
	)

	return parser.parse_args()

if __name__ == "__main__":

	args = parse_args()

	try:
		if args.clear:
			subprocess.run('cls', shell=True)
		else:
			pass
		devices = scan(subnet=args.subnet, timeout=args.timeout)
		resolveNames(devices)
		display(devices, subnet=args.subnet)

	except PermissionError:
		print("\n[!] Permission denied. Please run with sudo:")
		print(f"   sudo python3 {sys.argv[0]}\n")
		sys.exit(1)

	except KeyboardInterrupt:
		print("\n\n[!] Scan interrupted by user. Goodbye!\n")
		sys.exit(0)
