import struct            #Allows for the script to convert python values into raw bytes
import socket            #Allows for basic socket creation and use

def nbnsEncode(name: str) -> bytes:
	"""
	Encodes a given name into bytes that can be used for NetBIOS

	Args:
		name: A String representing the name that is going to be encoded

	Returns:
		Bytes. This function returns a series of bytes that represent the encoded version
		of a given name.
	"""

	padded = (name + '\x00' * 16)[:16].encode('ascii')   #Takes the given name, makes sure it is 16 characters long by filling in the empty spaces with null values, and encodes the string into ASCII (This turns it into bytes)

	encoded = bytearray()                                #Creates an array of bytes
	for byte in padded:                                  #Loops through all the bytes in padded
		encoded.append(0x41 + ((byte >> 4) & 0x0F))      #Isolates the upper nibble (first 4 bits) and interprets it as an ASCII Character
		encoded.append(0x41 + (byte & 0x0F))             #Isolates the lower nibble (last 4 bits) and interprets it as an ASCII Chracter

	return bytes([32]) + bytes(encoded) + b'\x00\x00'    #Return 35 encoded bytes like so: [1 Byte at the beginning that represents length (in this it would be 32)][32 bytes of encoded ASCII characters from earlier][2 Null bytes at the end stading as "end of name" bytes]

def netBIOS(ip: str) -> str:
	"""
	Sends out a NetBIOS packet to a specific IPv4 Address and records the response.

	Args:
		ip: A String representing a given IPv4 Address

	Returns:
		String. This function returns a String representing either the discovered NetBIOS name or N/A.
	"""
	header = struct.pack(    #Creates a variable for the header of the packet (uses struct.pack() to pack python values into raw bytes)
		">HHHHHH",           #!THIS PART DEFINES THE FORMAT OF THE PACKAGE! '>' means we are going to do the most significant byte first while 'H' represents an unsigned 16 bit integer
		0xABCD,              #First 4 bytes are an identifier (in this case, they are ABCD)
		0x0000,              #This part says that we dont want to do any funny business like recursion
		1,                   #Represents the number of questions in the pack
		0, 0, 0              #This is a query so we don't care about any additional modifiers / identifiers
	)

	qName = nbnsEncode("*")             #Creates a variable that has the correctly encoded nbns wildcard name "*"
	qType = struct.pack(">H", 0x0021)   #Crates a variable that has a pack containing a single 16 bit integer (in this case, that integer is 0x0021 which is the nbns question identifier)
	qClass = struct.pack(">H", 0x0001)  #Creates a variale that has a pack containign a single 16 bit integer (in this case, that integer is 0x0001 which is the nbns question class identifier that specifies the question is concerning internet class)

	query = header + qName + qType + qClass   #Adds all the stuff we made so far into a single query

	try:

		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   #Creates a socket connection for IPv4 and UDP
		sock.settimeout(0.3)                 #Sets the timeout before moving on to be 0.3 seconds
		sock.sendto(query, (ip, 137))        #Sends a packet with the query we made to the specific IPv4 Address at port 137
		data, _ = sock.recvfrom(1024)        #We then recieve 1024 bits of data as a response
		sock.close()                         #Then, we close the socket connection

		if len(data) < 57:                   #First, we check to see if the amount of data recieved is the correct length
			return "N/A"                     #If the length is too short, we return N/A
		
		ansStart = 51                        #This is the byte offset for where the answer we want starts
		rrNameLen = 2 if data[ansStart] == 0xC0 else 35  #Checks the byte at the offset position. If that byte is a callback to earlier, the length is 2, otherwise, the length is 35
		rdataOffset = ansStart + rrNameLen + 10          #Computes where the data we want is.

		if rdataOffset >= len(data):      #Checks to see if the offset calculated is longer than the data recieved
			return "N/A"                  #If it is, we return N/A
		
		numNames = data[rdataOffset]      #Checks the first byte which represents the number of NetBIOS names present
		entryStart = rdataOffset + 1      #Creates a variable to represent the start of the payload (rdataOffset that we calculated + 1 so we skip the identifier for the number of names)

		for i in range(numNames):         #Loops through the number of names present
			offset = entryStart + i * 18  #Each name is always 18 bytes long so this variable represents the length of a given name
			if offset + 16 > len(data):   #Checks to make sure that the possible offset length is not too long
				break                     #If it is, we break

			nameRaw = data[offset : offset + 15]    #Takes a slice of the bytes we recieved (This slice contains the name)
			suffix = data[offset + 15]              #Takes the last byte of the data containing the name
			nameStr = nameRaw.decode('ascii', errors='replace').rstrip(' \x00').strip()   #Decodes and strips the name 

			if suffix == 0x00 and nameStr:      #Checks to make sure that the suffix is correct. Nbns uses a suffix at the end of the name in order to determine the placement of the name (eg. Primary, Secondary, etc.). We make sure it is 0x00 because that represents the primary name.
				return nameStr                  #If we pass the checks, we return the nbns name for the given IPv4 Host
			
		return "N/A"                            #Otherwise, we return N/A
	
	except (socket.timeout, OSError):           #This captures any OSError as well as if the timeout was hit
		return "N/A"                            #In either case, we want to return N/A