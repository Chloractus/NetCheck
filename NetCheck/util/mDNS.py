import struct            #Allows the script to turn python data into packed raw bytes
import socket            #Allows the script to create and use basic socket connections

def mdnsEncode(name: str) -> bytes:
	"""
	Handles encoding a name into bytes in a format for mDNS.

	Args:
		name: A String representing a name that is going to be encoded into a format for mDNS

	Returns:
		Bytes. This function returns the bytes for an encoded version of the given name.
	"""
	encoded = b''                         #Creates the start of returned byte object
	for label in name.split('.'):         #Loops through every item in "name" when you split it at all the "."
		if label:                         #If the label exists
			encoded += bytes([len(label)]) + label.encode('ascii')     #We add a byte of the label's length followed by the label's ASCII bytes (Same thing is done with DNS)

	return encoded + b'\x00'            #returns the fully encoded name followed by a null (or zero) byte. Note: Null bytes mark the end of the name

def mdnsDecode(data: bytes, offset:int) -> tuple[str, int]:
	"""
	Handles decoding the raw bytes from an mDNS reply given a
	starting offset.

	Args:
		data: A set of bytes that represent the information obtained from an mDNS reply
		offset: An Integer that determines the starting point of the name decode

	Returns:
		Tuple[String, Int]. This function returns a Tuple containing a String for the decoded name and and Integer for the new offset.
	"""
	labels = []             #A list to store the pieces of the name as we decode them
	visited = set()         #A set that is going to hold the offsets that we already visited (Helps prevent DNS Compression Pointer issues)

	while offset < len(data):     #Continue to loop as long as we are not at the end of the data yet.
		if offset in visited:     #Check to see if we are at an offset that we have already visited
			break                 #If we have, then we break

		visited.add(offset)       #We add the current offset to our visited offsets

		length = data[offset]     #We get the length of the message/payload (Remember that the first part of mDNS replies contains the length of the response)

		if length == 0:           #If there is nothing in length / length is 0
			offset += 1           #Increase the offset by 1
			break                 #And break

		elif (length & 0xC0) == 0xC0:                           #Otherwise, we check for a compression pointer which can be found by checking the length
			ptr = ((length & 0x3F) << 8) | data[offset  + 1]    #Takes the last 6 bits and shifts them to the left by 8 bits, then it uses the bitwise OR to combine it with the next bit in the data.
			sub, _ = mdnsDecode(data, ptr)          #It recursively calls mdnsDecode

			if sub:                       #If it gets something back
				labels.append(sub)        #We add it to the labels
			
			offset += 2                   #Then we increase the offset by 2
			break                         #and break the loop

		else:                   #If we pass all the previous checks
			label = data[offset+1 : offset+1+length].decode('ascii', errors='replace')      #Gets a slice of data from one after the offset to one after the offset plus the length. This slice is then decoded.
			labels.append(label)               #Then we add the discovered label to labels
			offset += 1 + length               #and add 1 + our length to offset

	return '.'.join(labels), offset            #After everything is done, it adds all the labels together with "." between them. It also returns the final value of offset.

def mdnsQ(ip: str) -> str:
	"""
	Takes a specific IPv4 Address and does an mDNS query on it

	Args:
		ip: A String representing a given IPv4 Address

	Returns:
		String. This function returns a String of the discovered mDNS name.
	"""
	reverse = ".".join(reversed(ip.split('.'))) + '.in-addr.arpa'      #Creates a reverse mDNS query name for the IPv4 Address

	header = struct.pack(    #Creates the header for the mDNS packet
		'>HHHHHH',           #">" formats the header to use big-endian byte order. Each "H" stands for one unsigned 2 byte integer (12 bytes total in this case)
		0x0001,              #Sets the transaction ID to 0x0001
		0x0000,              #0x0000 means that we aren't going to use any special flags
		1,                   #This tells the recipient that this packet is only going to contain 1 question
		0, 0, 0              #These stand for ANCOUNT, NSCOUNT, and ARCOUNT. Since this is a query, we don't need to include any of these records
	)

	qName = mdnsEncode(reverse)            #This creates the endcoded message that will be in the mDNS packet
	qType = struct.pack('>H', 12)          #12 in DNS stands for a PTR record. This is the record type used for reverse lookups. ">H" makes it soe that this value is stored as a big-endian 2-byte value
	qClass = struct.pack('>H', 0x8001)     #0x8001 does two things. The upper bits, 0x8000, tell the recipient to send a unicast response instead of a multicast. While the lower bits, 0x0001, tell the recipient to use the standard DNS class

	query = header + qName + qType + qClass   #With all 4 parts made, we put them together into a query
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     #Creates a socket object for IPv4 and UDP
		sock.settimeout(0.3)                            #Sets the socket timeout to 0.3 seconds
		sock.sendto(query, (ip, 5353))                  #Sends the query to port 5353 of the given IPv4 Address
		data, _ = sock.recvfrom(4096)                   #Captures up to 4096 bytes from the host
		sock.close()                                    #Lastly, we close the socket connection

		if len(data) < 12:                              #Checks if the data is less than 12 bytes long
			return "N/A"                                #If so, we return N/A
		
		qdCount = struct.unpack('>H', data[4:6])[0]     #Unpacks bytes 4 - 6 from the data to get the QDCOUNT (These are the same positions as we did for the header). Then, using [0], we get the number of questions that are going to be in the data.
		anCount = struct.unpack('>H', data[6:8])[0]     #Unpacks bytes 6 - 8 from the data to get the ANCOUNT (These are the same positions as we did for the header). Then, using [0], we get the number of answers that are going to be in the data.

		if anCount == 0:           #If we get 0 answers
			return "N/A"           #We can go ahead and return N/A since there will not be an answer to get from the data
		
		offset = 12                #Sets an offset of 12
		for _ in range(qdCount):   #Then we loop through all the questions
			_, offset = mdnsDecode(data, offset)     #And use the offset inside of mdnsDecode(), keeping only the offset that we get back
			offset += 4                              #Then we add 4 to the offset for each question as well. The reason we do this is because the offset that gets returned marks the end of the question name but not the stuff after it like QTYPE and QCLASS

		for _ in range(anCount):                     #Now we can loop through all the answers
			_, offset = mdnsDecode(data, offset)     #For each of the answers, we call mdnsDecode and take only the offset back. This skips all the stuff before rrtype

			if offset + 10 > len(data):              #We then double check that there is at least 10 bytes left (AKA making sure that there is still an answer to check)
				break                                #If there is not at least 10 more bytes, we break.

			rrType, _, _, rdLength = struct.unpack('>HHIH', data[offset:offset+10])    #This takes the next 10 bytes and unpacks it in the ">HHIH" format. This means that it will go (2-byte int, 2-byte int, 4-byte int, 2-byte int). We then keep the stuff we want and toss the rest
			offset += 10                           #Moves the offset by 10 to account for the bytes we just read

			if rrType == 12:                              #Checks to see if the rrtype recorded earlier is 12 (having a 12 there means it is a PTR record / the one we want).
				hostname, _ = mdnsDecode(data, offset)    #Now we use mdnsDecode and take the hostname it gives back
				
				if hostname:                              #If we something back
					return hostname.rstrip('.')           #We return the discovered hostname and remove any trailing dots

			offset += rdLength              #If this wasn't a PTR record, we skip past the data by addign the length of the data to the offset
		
		return "N/A"                        #If all else fails, we return N/A
	
	except (socket.timeout, OSError):       #If we hit any OSError or if we hit the socket timeout
		return "N/A"                        #We return N/A