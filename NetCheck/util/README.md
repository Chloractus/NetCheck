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

*(Coming Soon!)*

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
