import struct
import socket

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
			ptr = ((length & 0x3F) << 8) | data[offset  + 1]
			sub, _ = mdnsDecode(data, ptr)

			if sub:
				labels.append(sub)
			
			offset += 2
			break

		else:
			label = data[offset+1 : offset+1+length].decode('ascii', errors='replace')
			labels.append(label)
			offset += 1 + length

	return '.'.join(labels), offset

def mdnsQ(ip: str) -> str:
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
		sock.settimeout(0.3)
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