# Utilities!

This section handles all of the custom made utility modules for this program.
This includes a variety of different ways to gather pieces of infomation on a host device.
All of these were specifically made to obtain as much useful information on hosts as possible in as little time as possible.

## For more in-depth information

- Basic Host Information Methods:
  - See [Reverse DNS](#reverse-dns)
  - See [NetBIOS](#netbios)
  - See [mDNS](#mdns)
  - See [SSDP](#ssdp)
  - See [OUI](#oui)
  - See [Port Scan](#port-scan)

## Reverse DNS

The idea of Reverse DNS is pretty stright forward. Instead of using a hostname to find an IPv4 Address, we use an IPv4 Address to find a hostname.

In this case, we use the Build-in Socket Module in order to search for a hostname that has the given IPv4 Address attached to it.

```python
import socket
hostname, _, _ = socket.gethostbyaddr(ip)
```

Python makes it super simple to use Reverse DNS and it all boils down to that line!

(There is a LOT more technical stuff that goes into how DNS and Reverse DNS work. You can read about it [here](https://www.cloudflare.com/learning/dns/glossary/reverse-dns/))

## NetBIOS

*(Coming Soon!)*

## mDNS

*(Coming Soon!)*

## SSDP

SSDP (or Simple Service Discovery Protocol) is a method similar to DNS but instead of using a central server / router, the device does it by itself. This method involves sending and recieving a specially crafted packet in order to get a URL for a given UPnP (or Universal Plug and Play) device. This is one of the more annoying and usually dangerous methods. While it is useful for getting device information, it can be easily exploited.

The first thing we do in our script is craft an M-SEARCH packet for a given IPv4 Address.

```python
msearch = (
  "M-SEARCH * HTTP/1.1\r\n"
  f"HOST: {ip}:1900\r\n"
  'MAN: "ssdp:discover"\r\n'
  f"MX: 3\r\n"
  "ST: ssdp:all\r\n"
  "\r\n"
).encode('utf-8')
```

After creating the specific packet we need, we send out the packet...

```python
sock.sendto(msearch, (ip, 1900))
```

...and parse the results to get a URL and a Server for the UPnP Device

```python
for line in data.decode('utf-8', errors='replace').split('\r\n'):
  upper = line.upper()

  if upper.startswith('LOCATION:'):
    location = line[9:].strip()

  elif upper.startswith('SERVER:'):
    server = line[7:].strip()
```

Once we have the URL and the Server, we can query the URL with an HTTP GET Request.

```python
with request.urlopen(location, timeout=2) as resp:
  xmlData = resp.read()
```

If the URL responds, we parse the XML results that we get and the information we want. Otherwise, we use the Server name or just None

```python
return {
  'name' : wanted['friendlyName'] or server or 'N/A',
  'manufacturer' : wanted['manufacturer'] or 'N/A',
  'model' : wanted['modelName'] or 'N/A',
  'server' : server or 'N/A'
}
```

(For more information on how SSDP works, See [here](https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol)

| Yes, It's a wikipedia article. Cry about it |
## OUI

OUI (or Organizationally Unique Identifier) is the practice that many companies use where the first 6 characters in a device's MAC Address are the same across everything the company provides. This is a great tool for identifying devices because we can check for those specific nuances.

That being said, IEEE has a database of known OUIs (See it [here](https://standards-oui.ieee.org))

This database is obtained in our script so that we can check for known OUIs.

```python
print("[*] Downloading IEEE OUI Database...")

response = requests.get(OUI_URL, timeout=5)
```

Our script downloads the database locally as a text file so that we don't have to keep checking the online database.

```python
with open(OUI_FILE, "w", encoding="utf-8") as f:
  f.write(response.text)
```
Then it uses that database to easily look through any given MAC Address and determine if it contains an OUI.

```python
try:
  oui = getOUI(mac)

except ValueError:
  return "Inavlid Mac Address"

return ouiDB.get(oui, "Unknown Vendor")
```

(See more about how OUIs work / what they mean [here](https://en.wikipedia.org/wiki/Organizationally_unique_identifier))

| Yes, it is a wikipedia link, cry about it. |
## Port Scan

Port scanning is the action of checking for open ports on a given device / IPv4 Address. In our case, we use port scanning in order to find more information about a given host. Unfortunately, I'm not going to try and explain ports... (See [here](https://www.cloudflare.com/learning/network-layer/what-is-a-computer-port/))

That being said, the way we perform a port scan on a specific IPv4 Address is by creating a socket and attempting to connect with the port of a specific IPv4 Address.

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((ip, port))
```

After attempting a connection, we record the whether or not we were allowed to connect.

```python
if result == 0:
  return COMMON_PORTS.get(port)
```

##

[Back to top](#utilities)

##

>⚠️ WARNING: These scripts are for educational purposes only and are not to be used for malicious actions. ⚠️
