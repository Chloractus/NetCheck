"""
========================================================
                    SSDP Explained:
========================================================

Step 1: Send out an M-SEARCH packet (UDP + Plain text) to the
        multicast group 239.255.255.250:1900. All UPnP devices
        that are listening to the multicast group on the LAN
        recieves it and replies with some HTTP headers including
        a LOCATION URL and a SERVER string.

Step 2: Perform an HTTP GET request with the LOCATION URL for each device.
        The device then gives an XML file with the information we want. These
        fields are human-readable (ex. <friendlyName> and <manufacturer>).

Why/What is mutlicast?
        Instead of trying to individually query all 254 IPs, we send one packet
        to the "Multicast Group" that all UPnP devices join on startup. This
        eliminates the need to send a bunch of packets as all of the UPnP devices
        will reply if the Multicast Group is queried.
What is an MX field???
        Since we don't want to kill the network with the replies we get back, we
        add an "MX Field" which makes each device pick a random delay between 0 and
        "MX" seconds which spreads out the replies.
"""

import socket                                 # allows for socket operations to create the HTTP Socket for SSDP
import xml.etree.ElementTree as ET            # XML support for python so we can parse XML descriptions
from urllib import request                    # Allows for HTTP Requests
from urllib.error import HTTPError, URLError  # Allows us to use HTTP and URL Error catches

def fetch(location: str | None, server: str | None) -> dict:
    # "fetch" has parameters "location" and "server"
    # location has to be either a String or a None type
    # server has to be either a String or a None type
    # "fetch" has to return a dict type

    #It's HTTP GET request time baby!

    """
    =========================================================
                    What dat fetch do?
    =========================================================

        This fetch function takes in the LOCATION URL and 
        SERVER String, then it attempts to make an HTTP 
        GET request to the LOCATION URL. It then parses the
        XML to get the values we want. If the LOCATION URL
        doesn't exist or doesn't return what we want,
        we fall back to using the SERVER String.
    """
    wanted = {
        'friendlyName' : None,
        'manufacturer' : None,
        'modelName' : None,
        'modelNumber' : None
    }

    if location:
        try:
            #Performs HTTP GET at "loaction" and waits "timeout" seconds for a reply
            with request.urlopen(location, timeout=2) as resp:
                xmlData = resp.read()

            #Parses the XML data into a tree of Elements
            #Throws a fit if it isn't a valid XML (ET.ParseError)
            root = ET.fromstring(xmlData)

            #ET.iter() does a depth-first search through all the elements in the tree
            for elem in root.iter():

                #The elements return a format like this: "{urn:schemas-upnp-org:device-1-0}friendlyName"
                #But since we only want "friendlyName" if it exists,
                #We split at '}' and only keep the last part [-1].
                #Then, if there isn't a '}' we just grab the whole statement.
                tag = elem.tag.split('}', 1)[-1] if '}' in elem.tag else elem.tag

                #Only record the Element if it is one of the elements we want,
                #The element isn't empty, and we haven't recorded that element yet
                if tag in wanted and elem.text and wanted[tag] is None:
                    wanted[tag] = elem.text.strip()
                
                #Early exit if all our fields are found.
                if all(v is not None for v in wanted.values()):
                    break
                    
        # URLError happens when we can't reach the device
        # HPPTError happens when the device returns an HTTP status code that isn't a 2xx
        except (URLError, HTTPError):
            pass
        
        # ET.ParseError happens when the XML file is invalid
        except ET.ParseError:
            pass
        
        # OSError is for low-level socket errors
        # ValueError happens when we get a url that isn't a String or a None type
        except (OSError, ValueError):
            pass
    
    return {
        'name' : wanted['friendlyName'] or server or 'N/A',
        'manufacturer' : wanted['manufacturer'] or 'N/A',
        'model' : wanted['modelName'] or 'N/A',
        'server' : server or 'N/A'
    }

def SSDP(ip: str) -> dict[str, dict]:

    #Craft and send SSDP M-SEARCH packet to multicast group + Capture all replies

    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode('utf-8')

    # -- Creates Socket --
    # AF_INET means it uses the IPv4 addresses
    # SOCK_DGRAM specifies that we are using UDP
    # IPPROTO_UDP is the bigger, more agressive version of SOCK_DGRAM
    # SOCK_DGRAM suggest UDP while IPPROTO_UDP forces it
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # SO_REUSEADDR allows us to bind to port 1900 even if a previous instance is still using it
    # Helps to make sure that we can still use the script even if we used it recently
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # IP_MULTICAST_TTL determines how many routers the multicast can hop.
    # 2 is a save bet for a LAN but can be changed to fit larger networks

    """ POTENTIALLY ADD ARG TO CHANGE IP_MULTICAST_TTL"""
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    # Wait "timeout" seconds before moving on, with or without results
    sock.settimeout(3)

    #Send it to the multicast
    sock.sendto(msearch, (ip, 1900))

    raw = {}

    try:
        while True:
            try:
                data, (src_ip, ips) = sock.recvfrom(65535)

                #Continue if we already did this IP
                if src_ip in raw:
                    continue

                location = None
                server = None

                for line in data.decode('utf-8', errors='replace').split('\r\n'):
                    upper = line.upper()

                    if upper.startswith('LOCATION:'):
                        location = line[9:].strip()

                    elif upper.startswith('SERVER:'):
                        server = line[7:].strip()

                raw[src_ip] = (location, server)

            except socket.timeout:
                break

    except OSError:
        pass

    finally:
        sock.close()

    if not raw:
        return fetch(None, None)
    else:
        return fetch(location, server)
