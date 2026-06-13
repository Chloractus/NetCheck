import socket

def reverseDNS(ip: str) -> str:
	try:
		hostname, _, _ = socket.gethostbyaddr(ip)
		return hostname
	
	except socket.herror:
		return "N/A"
	
	except socket.gaierror:
		return "N/A"