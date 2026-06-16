import struct
import socket

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
		sock.settimeout(0.3)
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