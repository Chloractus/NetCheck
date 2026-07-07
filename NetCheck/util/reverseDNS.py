import socket                       #Allows for use to get / use socket information

def reverseDNS(ip: str) -> str:
	"""
	Takes in an IPv4 Adddress and attempts to find the hostname for it
	by reversing the DNS Lookup.

	Args:
		ip: This is the IPv4 Address that the function attempts to find a hostname for

	Returns:
		String. This program returns a String value representing either a found hostname or N/A
	"""
	try:
		hostname, _, _ = socket.gethostbyaddr(ip)     #Creates a variable to hold the Hostname value then attempts to find it for the given IPv4 Address
		return hostname                               #If it finds a name for the IPv4 Address, it returns the name.
	
	except socket.herror:               #If at any point during the resolution we get nothing back for the hostname of the IPv4 Address
		return "N/A"                    #We return "N/A" so that we know it failed to find the hostname
