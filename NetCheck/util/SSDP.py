import socket                                 # allows for socket operations to create the HTTP Socket for SSDP
import xml.etree.ElementTree as ET            # XML support for python so we can parse XML descriptions
from urllib import request                    # Allows for HTTP Requests
from urllib.error import HTTPError, URLError  # Allows us to use HTTP and URL Error catches

def fetch(location: str | None, server: str | None) -> dict:
    """
    Uses a Location URL to try and make an HTTP GET request for the information regarding the device.
    If it doesn't find it, we default back to the name of the server.

    Args:
        location: A String representing the URL for a UPnP Device's information
        server: A String representing the server name for a given UPnP Device

    Returns:
        Dictionary. This function returns a Dictionary of information relating to a given UPnP Device.
    """

    wanted = {                        #A Dictionary for the information we want to pull from the location URL
        'friendlyName' : None,        #'Freindly Name' is the name assigned to the device (similar to DNS)
        'manufacturer' : None,        #'Manufacturer' is usually the name of the company that produced the device
        'modelName' : None,           #'Model Name' is usually the name of the generic model of the device
        'modelNumber' : None          #'Model Number' is usually a number that belongs to the specific model the device is
    }

    if location:          #First, checks to make sure that we actually have a location
        try:
            with request.urlopen(location, timeout=2) as resp:      #Performs HTTP GET at "loaction" and waits "timeout" seconds for a reply
                xmlData = resp.read()                               #If it gets a reply, it stores the XML data in a variable

            root = ET.fromstring(xmlData)   #Parses the XML data into a tree of Elements

            for elem in root.iter():        #ET.iter() does a depth-first search through all the elements in the tree

                tag = elem.tag.split('}', 1)[-1] if '}' in elem.tag else elem.tag    #Removes the formatting stuff from the XML and takes just the data from each tag

                if tag in wanted and elem.text and wanted[tag] is None:      #Checks to make sure that the element we are on is one we actually want
                    wanted[tag] = elem.text.strip()                          #Strips it down to just the stuff we want and records it
                
                
                if all(v is not None for v in wanted.values()):   #Checks to see if we already have all the elements we want
                    break                                         #If we do, then we don't need to keep looking and we can move on
                    
        except (URLError, HTTPError):       #URLError happens when we can't reach the device and HTTPError happens when the device returns an HTTP status code that isn't a 2xx
            pass
        
        except ET.ParseError:               #ET.ParseError happens when the XML file is invalid
            pass
        
        
        except (OSError, ValueError):       #OSError is for low-level socket errors, ValueError happens when we get a url that isn't a String or a None type
            pass
    
    return {                                                        #Returns a Dictionary of all the stuff we found for the given UPnP Device
        'name' : wanted['friendlyName'] or server or 'N/A',
        'manufacturer' : wanted['manufacturer'] or 'N/A',
        'model' : wanted['modelName'] or 'N/A',
        'server' : server or 'N/A'
    }

def SSDP(ip: str) -> dict:
    """
    Handles sending out a M-SEARCH packet to find out if a given IPv4 Host is a UPnP Device.
    It also handles extracting the URL from the reply.

    Args:
        ip: A String representing the IPv4 Address that we are sending the packet to

    Returns:
        Dictionary. This function returns a Dictionary that contains the relevant information for
        the given IPv4 Address.
    """

    msearch = (                      #Craft the SSDP M-SEARCH packet to the given IPv4 Address
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode('utf-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)   #Creates a socket object that is IPv4 and UDP

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                    #Makes sure that we can do still use the correct port even if it was used recently

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)                #Safety net to make sure that the packet doesn't travel outside of the LAN

    sock.settimeout(3)                  # Wait "timeout" seconds before moving on, with or without results

    sock.sendto(msearch, (ip, 1900))    # Send out the packet

    raw = {}      #A Dictionary to hold the results from the packet

    try:
        while True:         #Loop through this until we timeout
            try:
                data, (src_ip, ips) = sock.recvfrom(65535)     #Recieve the reply from the packet we sent

                if src_ip in raw:         #Skip the IPv4 Address if it is already done (basically just a catch to make sure we don't repeat information)
                    continue

                location = None           #Set location to None by default
                server = None             #Set server to None by default

                for line in data.decode('utf-8', errors='replace').split('\r\n'):     #For each line in the reply packet
                    upper = line.upper()                                              #Make the line all uppercase

                    if upper.startswith('LOCATION:'):             #Look for the location information
                        location = line[9:].strip()               #If we find it, we take it

                    elif upper.startswith('SERVER:'):             #Look for the server information
                        server = line[7:].strip()                 #If we find it, we take it

                raw[src_ip] = (location, server)                  #Add the IPv4 Address and the information to 'raw' so that we dont repeat it

            except socket.timeout:            #If we hit the timeout
                break                         #We break

    except OSError:          #If we run into any OSError
        pass                 #We move on past it

    finally:
        sock.close()         #Once we are all done, we close the socket

    if not raw:                         #If we got nothing in raw
        return fetch(None, None)        #We return fetch with None as both the location and server
    else:                               #If we DO get something in raw
        return fetch(location, server)  #We return fetch with the location and server we found
