import argparse                                   #Allows for arguements when running program
import sys                                        #Pre-Import for __main__.py - Used to properly exit the program
import datetime                                   #Allows for properly recording time with date
import subprocess                                 #Allows for running terminal processes like "ping"
import ipaddress                                  #Allows for creating/mapping out IP Addresses/Networks as their own data type
import threading                                  #Allows for threading within the program - Utilized for longer processes individual processes rather than a "Grapeshot"
import time                                       #Allows for basic time recording 
from concurrent.futures import ThreadPoolExecutor #Allows for simpler threading - Utilized to be the "Grapeshot" / used for resolving names instead of discovering hosts

from scapy.all import ARP, ICMP, IP, Ether, conf, sniff, sr1, srp #Allows for all the necessary network functions we need - Makes sure to only get the ones we actually need.

from util.reverseDNS import *  #Imports our Reverse DNS Module
from util.NetBIOS import *     #Imports our NetBIOS Module
from util.mDNS import *        #Imports our mDNS Module
from util.SSDP import *        #Imports our SSDP Module
from util.OUI import *         #Imports our OUI Module
from util.PScan import *       #Imports our Port Scan Module

conf.verb = 0 #Makes Scapy shut its loud mouth / Not destroy the console with useless Jargon

KnownDevices = {            #List of Known Devices to help sus out imposters
	"ff:ff:ff:ff:ff:ff"     #Broadcast known by default
}

_LAN_NETWORKS = [                            #List of possible LAN Networks to keep our discovery reasonable
	ipaddress.ip_network("10.0.0.0/8"),      #Class A Private
	ipaddress.ip_network("172.16.0.0/12"),   #Class B Private
	ipaddress.ip_network("192.168.0.0/16"),  #Class C Private
	ipaddress.ip_network("127.0.0.0/8"),     #Loopback
	ipaddress.ip_network("169.254.0.0/16")   #Link-Local
]

def is_ts_LAN(ip: str) -> bool:
	"""
	Determines if any given IPv4 Address is a LAN Address / Local Area Network Address

	Args:
		ip: IPv4 Address to check for LAN Status

	Returns:
		Bool. Determines if the address is a LAN address.
	"""

	try:
		addr = ipaddress.ip_address(ip)  #Addr represents the IPv4Address Object associated with the given IPv4 Address 

		if addr.is_multicast or str(addr) in ("255.255.255.255", "0.0.0.0"):  #Checks if Addr is a Multicast, A Limited Multicast (255.255.255.255), or a Non-Routable Address (0.0.0.0)
			return False                                                      #If it is, return False
		
		matched = next((net for net in _LAN_NETWORKS if addr in net), None)   #Checks if the IPv4 Address is inside any of the predetermined LAN Networks, if not then None.
		if matched is None:                                                   #If matched is None / if the IPv4 Address is not in the LAN Networks
			return False                                                      #IPv4 Address is not in the LAN Networks so we return False
		
		if addr in (matched.network_address, matched.broadcast_address):      #Checks to see if the IPv4 Address is one of the 2 that can never be assigned to a host (ae. first and last possible address)
			return False                                                      #If it is one of the non-assignable addresses, we return False
		
		return True                                                           #If the IPv4 Address makes it through all of the checks, we return True
	except ValueError:                      #Catches ValueErrors / errors caused by malformed IPv4 Addresses.
		return False                        #Returns False if the IPv4 Address is invalid.

discovered: set[str] = set()   #Type hints that this is going to be a set of str
mac_table: dict[str, str] = {} #Table for us to keep the MAC addresses found by ARP (Gets appended to devices later on)
hLock = threading.Lock()       #A "Lock" on our Threading so that only one Thread can access our discovered and mac_table variables. Prevents issues caused by a Race Condition.
sEvent = threading.Event()     #A Stop event so that we can directly tell the Threads to stop at any given point.

def _add_host(ip: str, source: str) -> None:
	"""
	Private function used to add a new host to a list of discovered hosts.

	Args:
		ip: A given IPv4 Address that has been found via one of the available methods.
		source: An identifier used to keep track of which IPv4 Addresses were added by which method.

	Returns:
		None. This function does not / should not return anything.
		It's primary purpose is to allow threads to add their discoveries if they have not already
		been added.
	"""

	with hLock:                                                         #Uses the hLock during this process so that only one thread can add a new host at a time.
		if ip not in discovered:                                        #Checks if the IPv4 Address has already been discovered.
			discovered.add(ip)                                          #If the address hasn't, then we add it to our discovered set.

			timestamp = time.strftime("%H:%M:%S")                       #Gets a timestamp for when the host was discovered.
			print(f"  [{timestamp}] [{source:^14}] NEW HOST -> {ip}")   #Prints out a notifier when a new host is found. Includes a timestamp, a source, and the IPv4 of the host.

def _is_known(ip: str) -> bool:
	"""
	Private function used to retroactively determine if a given IPv4 Address is already known.
	(This is useful because it allows for self-optimization during discovery)

	Args:
		ip: A given IPv4 Address that is checked for inside of the already discovered IPv4 Addresses.

	Returns:
		Bool. This function returns a bool for if the IPv4 Address is already inside of the discovered set.
	"""
	with hLock:                      #Uses hLock to prevent multiple Threads from accessing this function at the same time.
		return ip in discovered      #Returns a Boolean for if the IPv4 Address is already inside of our discovered set.
	
def lARP(subnet: str, timeout: int = 2, retry: int = 1) -> None:
	"""
	Performs an ARP Broadcast to all devices on the given subnet and captures their MAC Addresses.

	Args:
		subnet: A subnet in CIDR Notation defining the network that the ARP Broadcast is going to be performed on.
		timeout: Waits a certain amount of time on each host before giving up/moving on
		retry: Attempts the broadcast this many extra times to ensure all hosts (that accept ARP) are found

	Returns:
		None. This function does not / should not return anything. It's main purpose is sweeping the given subnet
		for hosts and MAC Addresses, then adding those to either the discovered set or the mac_table dictionary.
	"""
	print(f"\n[lARPing/ ARP Sweep] - Starting on {subnet}")                                 #Prints out a message that the ARP Sweep has started
	try:
		network = ipaddress.ip_network(subnet, strict=False)                                #Creates an IPv4Network Object from the given subnet.

		targets = [str(h) for h in network.hosts() if is_ts_LAN(str(h))]                    #Gathers all possible targets that fall within the IPv4Network Object
		
		print(f"  [lARPing/ ARP Sweep] - Sending {len(targets)} ARP request(s)")            #Prints our the number of targets that the ARP Sweep is sending requests to.

		pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in targets]            #Creates ARP Broadcast packets for all possible IPv4 Host Addresses
		ans, _ = srp(pkts, timeout=timeout, retry=retry, verbose=0)                         #Performs a Send and Recieve Packets function and records the packets that answered it.

		for _, rcv in ans:                                                                  #For loop to loop through the answer packets obtained by srp.
			if sEvent.is_set():                                                             #First, checks for if the Stop Event is active.
				break                                                                       #If it is, we break
			ip = rcv[ARP].psrc                                                              #Otherwise, we get the IPv4 Address of the host that answered
			mac = rcv[Ether].src                                                            #And the MAC Address of that host
			if is_ts_LAN(ip):                                                               #We then double check that the IPv4 Address is a LAN Address
				_add_host(ip, "ARP Sweep")                                                  #And we add the IPv4 Address to our discovered set via _add_host()

				clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()      #Cleans the MAC Address so that it is just the characters
				with hLock:                                                                 #Then, with hLock active
					mac_table[ip] = ":".join(clean[i:i+2] for i in range(0, 12, 2))         #We reformat the MAC Address into a more universal format and add it to our mac_table dictionary

		print(f"  [lARPing/ ARP Sweep] - {len(ans)} host(s) responded.")                    #Prints our the number of hosts that responded to the ARP Sweep

	except Exception as exc:                                      #If there is an error at any point during the Sweep
		print(f"  [lARPing/ ARP Sweep] - Error: {exc}")           #We print it out so that users can fix / report the problem

	print("[lARPing/ ARP Sweep] - Finished.")                     #Finally, We print out a notifier that the ARP Sweep is done.

def _ping(ip: str, timeout: int = 1) -> None:
	"""
	Private function to reduce repetition of ping subprocesses
	
	Args:
		ip: A given IPv4 Address to ping
		timeout: Amount of time before moving on / finding host to be inactive.

	Returns:
		None. This function does not / should not return anything. It's main purpose is to handle performing Ping requests
		to different IPv4 Addresses.
	"""
	if _is_known(ip):           #Checks if the IPv4 Address is already a known host
		return                  #If it is, skip the ping / move on to the next possible address
	
	try:
		result = subprocess.run(                                   #Performs a subprocess and gathers the result (Success / Failure)
			['ping', '-n', '1','-w', str(timeout * 1000), ip],     #This is the subprocess command that we want to run
			stdout=subprocess.DEVNULL,                             #Pipes the output from the ping subprocess to DEVNULL (basically the void)
			stderr=subprocess.DEVNULL,                             #Pipes any errors generated by the sybprocess to DEVNULL (basically the void)
			timeout=timeout                                        #Sets the timeout period to the timeout parameter
		)
		if result.returncode == 0 and is_ts_LAN(ip):               #Checks if the ping was successful and if the IPv4 Address is a LAN Address
			_add_host(ip, "Ping Sweep")                            #Adds the host to our discovered set via _add_host()
	except (subprocess.TimeoutExpired, OSError, FileNotFoundError):   #Catches a variety of errors that could happen
		pass                                                          #Passes if any of the exceptions is met.

def ping_sweep(subnet: str, max_workers: int = 100) -> None:
	"""
	Assigns workers to perform ping requests on a given subnet

	Args:
		subnet: A given IPv4 Subnet in CIDR Notation to be pinged for hosts
		max_workers: The maximum number of workers to use during the ping sweep

	Returns:
		None. This function does not / should not return anything. It's main purpose is to designate workers to
		ping all the possible devices on a given subnet.
	"""
	print(f"\n[Ping Sweep] - Starting on {subnet} (max {max_workers} workers)")    #Prints out a notifier that the Ping Sweep has started.

	try:
		network = ipaddress.ip_network(subnet, strict=False)                           #Creates an IPv4Network Object based on the given subnet
		targets = [str(h) for h in network.hosts() if not _is_known(str(h))]           #Creates a list of all possible IPv4 Addresses that are not already known

		with ThreadPoolExecutor(max_workers=min(len(targets), max_workers)) as exec:   #Opens the ThreadPoolExecutor with a minimum of Target workers and a max of max_workers
			futures = {exec.submit(_ping, ip): ip for ip in targets}                   #Submits all of the ping functions for each IPv4 Address to the workers
			for future in futures:                         #Goes through all the futures that the workers obtained
				if sEvent.is_set():                        #Checks if the Stop Event is active
					break                                  #If it is, we Break
				future.result()                            #If not, we return the results from the given future (This doesn't actually give us a return value but rather it solidifies the results from the workers)

	except Exception as exc:                       #If we run into any errors
		print(f"  [Ping Sweep] - Error: {exc}")    #We print a notifier about the error

	print("[Ping Sweep] - Finished.")              #Finally, we print out a notifier that the Ping Sweep was completed



def passive(iface: str | None, duration: float, subnet: str) -> None:
	"""
	Handles the Passive Sniffing of a given IPv4 Subnet in CIDR Notation on a given interface for a given duration

	Args:
		iface: The interface on which the Sniffing is going to be performed
		duration: How long the Passive Sniff is going to last
		subnet: An IPv4 Subnet in CIDR Notation that is going to be filtered for

	Returns:
		None. This function does not / should not return anything. It's main purpose is to passively sniff
		the network for active hosts and add them to the discovered set.
	"""
	label = iface or conf.iface                              #The interface that we are going to sniff on
	network = ipaddress.ip_network(subnet, strict=False)     #Creates an IPv4Network Object based on the given subnet
	print(f"\n[Passive] - '{label}' for {duration}s")        #Prints a notifier that the Passive Sniff has started

	def _callback(pkt) -> None:
		"""
		Private function to look at all valid packets that are sniffed from the network
		and determine if they are a new host, if so, they are added to the discovered set

		Args:
			pkt: The given packet that is going to be checked for a possible new host

		Returns:
			None. This function does not / should not return anything. It's main purpose is to look into
			every packet that is found via the Passive Sniff.
		"""
		if pkt.haslayer(IP):            #Checks if the packet has the IP layer
			src = pkt[IP].src           #If it does, we get the src or source
			try:
				if ipaddress.ip_address(src) in network and is_ts_LAN(src) and not _is_known(src):    #We then check if the src meets the necessary requirements
					_add_host(src, "Passive Sniff")                 #If it does, we add it to the discovered set via _add_host()
			except ValueError:                 #This catches any possible ValueErrors caused by malformed packets or invalid IPs
				pass                           #We then pass if there is an error

	try:
		sniff(                                    #This part acually starts the Passive Sniff
			iface=iface,                          #We set the interface to the interface we found earlier
			prn=_callback,                        #We also send each packet over to _callback so that they can be checked for a new host
			store=False,                          #We tell the sniffer to not keep any of the packets as they are only needed once for the _callback function
			timeout=duration,                     #We tell the sniffer to go for a specific duration
			stop_filter=lambda _: sEvent.is_set() #We also use a lambda to tell the sniffer to stop if the Stop Event is active
		)

	except Exception as exc:                      #This catches all exceptions that we may run into
		print(f"  [Passive] - Error: {exc}")      #And sends a notifier about the specific error

	print("[Passive] - Finished.")                #Finally, we print a notifier that the Passive Sniff is complete

def do_ts(subnet: str, iface: str | None = None, duration: float = 30, max_workers: int = 150, arp_time: int = 2, arp_retry: int = 1) -> set[str]:
	"""
	Handles coordinating the 3 discovery methods at the same time.

	Args:
		subnet: An IPv4 Subnet in CIDR Notation that is going to be used in the 3 discovery methods
		iface: The interface that is going to be used for the Passive Sniff
		duration: The time that the Passive Sniff is going to be active
		max_workers: The maximum allotted workers for the Ping Sweep
		arp_time: The amount of time that the ARP Sweep is going to wait for each reply
		arp_retry: The amount of times that the ARP Sweep is going to reattempt IPv4 Addresses

	Returns:
		set[str]. This function returns a set of string values that correspond to the found hosts 
	"""
	
	print("=" * 60)                                                   #Prints out 60 "=" as a buffer
	print("  Concurrent Discovery: ARP + Ping + Passive Sniff")       #Prints out that we are going to be doing 3 specific discoveries
	print(f"  Subnet    : {subnet}")                                  #Prints out the subnet that we are going to be discovering on
	print(f"  Interface : {iface or 'default'}")                      #Prints out the interface that we are going to be discovering with
	print(f"  Sniff     : {duration}s")                               #Prints out the duration that we are going to be sniffing for
	print("=" * 60)                                                   #Prints out another 60 "=" as a buffer

	threads = [                                    #Creates a list of Threads
		threading.Thread(                          #Creates the first Thread Object which is going to handle ARP
			target=lARP,                           #Sets the Threads target / objective to our ARP Sweep function
			args=(subnet, arp_time, arp_retry),    #Submits the necessary arguements for the ARP Sweep
			name="ARP-Sweep",                      #Gives the Thread a name
			daemon=True                            #Makes it so that this Thread stops when the program stops
		),
		threading.Thread(                          #Creates the second Thread Object which is going to handle ping
			target=ping_sweep,                     #Sets the Threads target / objective to our ping sweep function
			args=(subnet, max_workers),            #Submits the necessary arguements for the ping sweep
			name="Ping-Sweep",                     #Gives the Thread a name
			daemon=True                            #Makes it so that this Thread stops when the program stops
		),
		threading.Thread(                          #Creates the third Thread Object which is going to handle sniffing
			target=passive,                        #Sets the Threads target / objective to our passive sniffing function
			args=(iface, duration, subnet),        #Submits the necessary arguements for the passive sniff
			name="Passive-Sniff",                  #Gives the Thread a name
			daemon=True                            #Makes it so that this Thread stops when the program stops
		)
	]

	start = time.time()          #Gets the start time 
	for t in threads:            #Then for each Thread in threads
		t.start()                #We start our threads

	try:
		for t in threads:        #For each of our Threads
			t.join()             #We do .join which forces the program to wait for all the threads to finish before moving on.
	except KeyboardInterrupt:                      #Captures the exception for if the user interupts the program with CTRL + C
		print("\n[!] - Interrupted: stopping...")  #Prints out a notifier so that we know the Threads are stopping
		sEvent.set()                               #Sets the Stop Event to active
		for t in threads:                          #For each of our Threads
			t.join(timeout=3)                      #We give them the same wait as earlier but this time we limit the wait to 3 seconds

	elapsed = time.time() - start                  #Determine how much time overall has passed
	print(f"\n[*] - Discovery complete in {elapsed:.1f}s : {len(discovered)} unique host(s) found.")  #Prints out a notifier that the discovery finished with the elapsed time and number of discovered hosts
	return discovered                 #return the set[str] (also known as discovered)

def scan(subnet: str, timeout: int, iface: str | None = None, duration: float = 30, max_workers: int = 150) -> list[dict]:
	"""
	Wraps everything together with a nice bow. Starts the discovery and creates a log for the different
	pieces of information that we can gather for each IPv4 Address host found.

	Args:
		subnet: An IPv4 Subnet in CIDR Notation that we are going to be discovering on
		timeout: The amount of time that the program waits before moving on regardless of answer status
		iface: The interface that we are going to be discovering on
		duration: The amount of time that the Passive Sniff is going to last
		max_workers: The maximum allotted workers for the Ping Sweep

	Returns:
		list[dict]. This function returns a list of dictionaries with each dictionary representing a found host.
	"""
	live = do_ts(subnet, iface=iface, duration=duration, max_workers=max_workers, arp_time=timeout)  #Performs the do_ts() function and gets the discovered set

	if not live:                           #Checks if the discovery methods don't return anything
		print("[!] - No hosts found.")     #If they don't return anything, then we print out a notifier about it
		return []                          #We also return a blank list as no dictionaries can be made with no hosts
	
	with hLock:                            #Turns on hLock
		macT = dict(mac_table)             #and grabs the mac_table that we generated during the ARP discovery

	no_mac = len(live) - len(macT)         #Determines the number of hosts that did not respond to the ARP request
	if no_mac > 0:                         #If more than 0 IPv4 Hosts didnt respond then
		print(f"[*] {no_mac} host(s) found via ping/sniff with no ARP reply (MAC: UNKNOWN)")  #We print out a notifier that we found some devices that didn't give us their MAC

	devices = []                                #Creates a blank list to hold our devices
	for ip in live:                             #Iterates through each IPv4 Host
		mac = macT.get(ip, "UNKNOWN")           #Sets the Hosts MAC Address to whatever we got from the ARP Sweep or "UNKNNOWN" if we didn't find anything
		isKnown = mac in KnownDevices           #Determines if the MAC Address is one of the ones that is "Known"

		ssdpDetails = {                         #Creates a dictionary for the details that SSDP can get
			"name" : "N/A",                     #Sets name to N/A by default
			"manufacturer" : "N/A",             #Sets manufacturer to N/A by default
			"model" : "N/A",                    #Sets model to N/A by default
			"server" : "N/A"                    #Sets server to N/A by default
		}

		devices.append({                        #Appends a new Dictionary to devices
			"ip": ip,                           #Sets ip to the hosts IPv4 Address
			"mac": mac,                         #Sets mac to the hosts MAC Address
			"known": isKnown,                   #Sets known to True or False depending on if the Hosts MAC Address is in KnownDevices
			"vendor" : "N/A",                   #Sets vendor to N/A by default
			"best name" : "N/A",                #Sets best name to N/A by default
			"ports" :"N/A",                     #Sets ports to N/A by default
			"dns" : "N/A",                      #Sets dns to N/A by default
			"nbns" : "N/A",                     #Sets nbns to N/A by default
			"mdns" : "N/A",                     #Sets mdns to N/A by default
			"ssdp" : ssdpDetails                #Sets ssdp to the ssdp dictionary from earlier
		})

	devices.sort(key=lambda d:tuple(int(x) for x in d["ip"].split(".")))   #Sorts the devices list by ip
	return devices         #Returns the sorted and complete list of devices

def resolveNames(devices: list[dict], inSSDP: bool) -> None:
	"""
	Attempts multiple different methods of finding a name / information on a host.

	Args:
		devices: A list of dictionaries containing information about discovered devices
		inSSDP: A boolean to determine if resolveNames is going to attempt SSDP

	Returns:
		None. This function does not / should not return anything. It's main purpose is to gather as much
		information on hosts as it can.
	"""
	if not devices:                   #If we don't find any devices
		return                        #We don't want to try and find information
	
	OUI = loadOUI()                   #This calls the "loadOUI" function which returns a list regarding different possible OUIs

	ips = [d['ip'] for d in devices]      #This gathers a list of all the IPv4 Addresses
	macs = [d['mac'] for d in devices]    #This gathers a list of all the available MAC Addresses

	print("[*] Resolving hostnames...")     #Prints out a notifier so that we know we are finding information

	with ThreadPoolExecutor(max_workers=min(len(ips) * 4, 150)) as executor:        #Using the ThreadPoolExecutor, we assign a certain number of workers
		dns = {ip: executor.submit(reverseDNS, ip) for ip in ips}                   #We submit every IPv4 we found into reverseDNS
		nbns = {ip: executor.submit(netBIOS, ip) for ip in ips}                     #We submit every IPv4 we found into netBIOS
		mdns = {ip: executor.submit(mdnsQ, ip) for ip in ips}                       #We submit every IPv4 we found into mdnsQ
		oui = {mac: executor.submit(getVendor, mac, OUI) for mac in macs if mac}    #We submit every MAC we found into getVendor as we as our OUI
		ports = {ip: executor.submit(PScan, ip) for ip in ips}                      #We submit every IPv4 we found into PScan
		if inSSDP:                                                                  #Lastly, we check if the user wants to use SSDP
			ssdp = {ip: executor.submit(SSDP, ip) for ip in ips}                    #And submit every IPv4 we found into SSDP if so
		
	for device in devices:                        #We then loop through every device in our devices list
		ip = device['ip']                         #Assign the IPv4 to a Variable
		mac = device['mac']                       #Assign the MAC to a Variable
		device['ports'] = ports[ip].result()      #Assign the ports we found for that specific device
		device['dns'] = dns[ip].result()          #Assign the DNS we found for that specific device
		device['nbns'] = nbns[ip].result()        #Assign the NBNS we found for that specific device
		device['mdns'] = mdns[ip].result()        #Assign the mDNS we found for that specific device

		if mac:                                   #If we found a MAC Address for the device
			device['vendor'] = oui[mac].result()  #Assign the vendor information for that specific device

		if inSSDP:                                #If the user included SSDP
			device['ssdp'] = ssdp[ip].result()    #Assign the SSDP information for that specific device

	print("[*] Resolution complete.\n")    #Print out a notifier that we finished finding all of the information

def update(update: bool) -> None:
	"""
	This function exists solely so that we can download the OUI if it is not already present

	Args:
		update: This is a boolean repersenting whether or not the user wants to download the OUI

	Returns:
		None. This function can not / should not return anything. It's main purpose is to allow the program to call
		on the download function without having to make extra imports.
	"""
	if update:                        #If the user wants to update the OUI
		download_OUI()                #We call the update function

def getBest(device:dict) -> str:
	"""
	Determines the best name by using a set of predetermined checks to see if a specific name is present.

	Args:
		device: This is a dictionary of information on a specific device

	Returns:
		String. This function returns a string representing whatever name the function decided was the best
		discriptior for the device.
	"""
	for key in ('dns', 'nbns'):                                    #First, we do a loop for both of the values we are checking for
		value = device.get(key)                                    #We then record that value in a variable (eg. value could be the dns OR the mbns for the given device)
		if isinstance(value, str) and value not in ('', 'N/A'):    #We then do a few simple checks: 1. Make sure it exist. 2. Make sure the value is useable
			return value                                           #If the value is useable, then we use it. If not, then we move forward
		
	ssdp = device.get('ssdp')                                           #Records the ssdp value for the given device
	if isinstance(ssdp, dict) and ssdp.get('name') not in ('', 'N/A'):  #Then checks if it is present and useable
		return ssdp.get('name')                                         #If it is, then we use it. If not, then we move on
	
	for key in ('mdns', 'vendor'):                                                    #Loops through the mDNS and Vendor values for the given device
		value = device.get(key)                                                       #Records that value to a variable
		if isinstance(value, str) and value not in ('', 'N/A', 'Unknown Vendor'):     #Then checks to see if that value exists and is useable
			return value                                                              #If it is, then we use it. If not, then we move on
		
	return device.get('ip')                                                           #If all else fails, then we use the IPv4 Address for the device

def display(devices: list[dict], subnet: str, inSSDP: bool) -> None:
	"""
	Properly formats and displays the relevant information on each device found on the network

	Args:
		devices: This is a list of dictionaries with each dictionary containing all the relevant information for each device
		subnet: A String value containing the subnet for the scan in CIDR Notation
		inSSDP: A boolean value representing whether or not the user chose to check for SSDP

	Returns:
		None. This program can not / should not return anything. It's main purpose is to cleanly 
		display human-readable information on the devices found.
	"""

	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")      #Gets a timestamp of when display was run
	print("=" * 130)                            #Prints out 130 "="
	print(f"  NETWORK MAP - {subnet}")          #Prints out a notifier on what subnet was mapped by the scan
	print(f"  Scanned at: {timestamp}")         #Prints out a notifier on when the scanned subnet was found
	print("=" * 130)                            #Prints out 120 "="
	print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'Best Name': <32} {'Ports': <20} {'Vendor':<20}")    #Cleanly prints out columns for the basic information
	print("-" * 130)                #Prints out 130 "-"

	
	if not devices:                     #If we didn't find any devices
		print("  No devices found. Check your subnet or try a longer timeout.")    #Print out a notifier about not finding any devices
		return                                  #Return so that we don't try and do anything else

	for device in devices:                      #Loops through every device
		bestName = getBest(device)              #Gets the best name for the device
		ports = device.get('ports', 'N/A')      #Gets the open ports for the device (found earlier using PScan)
		vendor = device.get('vendor', "N/A")    #Gets the vendor for the device (found earlier using getVendor)
		print(f"  {device['ip']:<18} {device['mac']:<20} {bestName:<32} {ports:<20} {vendor:<20}")     #Cleanly prints out the basic information for each device (Properly spaced with the columns)

	print("-" * 130)             #Prints out 130 "-"
	total = len(devices)         #Gets the total number of devices
	unknown = sum(1 for d in devices if not d["known"])   #Gets the total number of devices that are not in KnownDevices
	print(f"  Total devices found : {total}")             #Prints out the total number of devices
	print(f"  Unknown devices     : {unknown}")           #Prints out the number of devices that are not known
	print("=" * 130)                                      #Prints out 130 "="
	print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'DNS Hostname': <32} {'NetBIOS Name': <20} {'mDNS Name':<22} STATUS") #Prints out the columns for relevant (but less user friendly) information
	print("-" * 130)                    #Prints out 130 "-"

	for device in devices:                                             #We once again loop through all the devices (Might be able to remove this part but would require restructuring the print statements)
		status = "[$]  Known" if device["known"] else "[!] UNKNOWN"    #Gets whether of not the device is a "known" device
		dnsName = device.get('dns', 'N/A')                             #Gets the DNS for the device (found earlier using reverseDNS)
		nbnsName = device.get('nbns', 'N/A')                           #Gets the nbns for the device (found earlier using netBIOS)
		mdnsName = device.get("mdns", "N/A")                           #Gets the mDNS for the device (found earlier using mdnsQ)
		print(f"  {device['ip']:<18} {device['mac']:<20} {dnsName:<32} {nbnsName:<20} {mdnsName:<22} {status}")    #Cleanly prints out relevant (but less user friendly) information

	print("-" * 130)            #Prints out 130 "-"

	if unknown > 0:            #If there are any unknown devices
		print(f"  [!] WARNING: {unknown} unrecognized device(s) found on your network!")    #Print out a notifier that the scan found unknown devices (Sort of like a warning system)
		print("    Add trusted MACs to KnownDevices at the top of core.py")            #Reminds users to add the MAC addresses of trusted devices (This could be more fleshed out so that it checks for differences rather than just mysterious MACs)

		for d in devices:                                           #Loops through all of the devices
			if not d["known"]:                                      #Checks if they are not known
				print(f"      -> {d['ip']:>15}   MAC: {d['mac']}")  #Then prints out the IPv4 and MAC Address of the unknown device
	if inSSDP:                      #Checks to see if the user decided to include SSDP
		print("=" * 130)            #Prints out 130 "="
		print("  SSDP Results")     #Prints out the we are going to display the SSDP results
		print("=" * 130)            #Prints out 130 "="
		print(f"  {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'NAME':<20} {'MANUFACTURER':<20} {'MODEL':<20} SERVER")    #Creates columns for the different SSDP information
		print("-" * 130)                          #Prints out 130 "-"
		for device in devices:                    #Loops through all of our devices
			dets = device.get("ssdp")             #Gets their SSDP information (found earlier using SSDP)
			name = dets['name']                   #Gets the name found using SSDP
			manufacturer = dets["manufacturer"]   #Gets the manufacturer found using SSDP
			model = dets["model"]                 #Gets the model found using SSDP
			server = dets["server"]               #Gets the server found using SSDP
			print(f"  {device['ip']:<18} {device['mac']:<20} {name:<20} {manufacturer:<20} {model:<20} {server}")   #Prints out the relevant information for each device in lne with the columns

def parse_args() -> argparse.Namespace:
	"""
	This function does exactly what it sounds like it does. It parses arguements so that users can change specific aspects

	Returns:
		argparse.Namespace. This function returns an argparse.Namespace object which represents the arguements that the user submited
	"""

	parser = argparse.ArgumentParser(                                      #Creates our arguement parser (The stuff inside of this will be displayed if the user input the arguement "-h" or "--help")
		description="NetCheck — discover devices on your LAN",             #Gives it a description
		epilog="Example: sudo python3 NetCheck --subnet 192.168.0.0/24"    #Gives and example on how to use the program
	)

	parser.add_argument(                                                  #Adds an arguement to our parser
		"--subnet",                                                       #Determines how users will call this arguement (eg. --subnet to change the subnet mask)
		type=str,                                                         #Determines what data type this argeuement should be
		default="192.168.1.0/24",                                         #Determines the default value / the value used if the user does not use this arguement
		help="Target subnet in CIDR notation (default: 192.168.1.0/24)"   #Prints out a description for this arguement when users use "-h" or "--help"
	)

	parser.add_argument(                                                  #Adds another arguement to our parser
		"--timeout",                                                      #Determines how users will call this arguement (eg. --timeout to change the timeout duration)
		type=int,                                                         #Determines what data type this arguement should be
		default=1,                                                        #Determines the default timeout duration
		help="Seconds to wait for various functions (default: 1)"         #Prints out a description for this arguement when users use "-h" or "--help"
	)

	parser.add_argument(                                                  #Adds another arguement to our parser
		"-c",                                                             #Determines one of the ways that users can call this arguement (eg. -c will clear the console before starting)
		"--clear",                                                        #Determines an alternative way to call this arguement (eg. calling --clear does the same thing as -c)
		action="store_true",                                              #This arguement doesn't take in any user input, instead it returns true or false depending on if the arguement was called at all
		help="Clear the screen before starting"                           #Prints out a description for this arguement when users use "-h" or "--help"
	)

	parser.add_argument(                                                  #Adds another arguement to our parser
		"-d",                                                             #Determines one of the ways that users can call this arguement (eg. -d will tell the program to check for SSDP)
		"--SSDP",                                                         #Determines an alternative way to call this arguement (eg. calling --SSDP does the same thing as -d)
		action="store_true",                                              #This arguement doesn't take in any user input, instead it returns true or false depending on if the arguement was called at all
		help="Attempt to find SSDP details"                               #Prints out a description for this arguement when users use "-h" or "--help"
	)

	parser.add_argument(                                                  #Adds another arguement to our parser
		"-u",                                                             #Determines one of the ways that users can call this arguement (eg. -u will tell the program to update the OUI)
		"--update",                                                       #Determines an alternative way to call this arguement (eg. calling --update does the same thing as -u)
		action="store_true",                                              #This arguement doesn't take in any user input, instead it returns true or false depending on if the arguement was called at all
		help="Update dependencies"                                        #Prints out a description for this arguement when users use "-h" or "--help"
	)

	return parser.parse_args()                 #THIS IS NOT A RECURSION. The names are the same but this is a function that is present inside of our parser that handles all the stuff that makes the parser work