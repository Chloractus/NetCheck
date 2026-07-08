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

NetBIOS (or Network Basic Input/Output System) is a legacy network protocol that was primarily used in older Windows operating systems to perform various tasks. One of which was a method of name resolution similar to that of DNS. NetBIOS has a few distinct caveats though, one of these being that it only works on LANs.

For the most part, NetBIOS has been phased out and replaced with new protocols like DNS. Yet, since it is very similar to DNS and is still used in some older devices, I decided to include it in this project. When it comes to using NetBIOS in Python, its mch more difficult than DNS because it is far less prominent. That being said...

The NetBIOS name system works in a pretty interesting fashion. It requires us to make our own packet at the byte level but before we get into that, we have to understand how to encode/decode a name for NetBIOS. NetBIOS, like many other protocols, is very picky about how a packet is formated. For example, to encode a name for a NetBIOS packet, we have to first pad the name to be exactly 16 bytes (with each byte being 8 bits) long by using null byte values and encoding the whole message using ASCII so it turns into usable bytes.

```python
padded = (name + '\x00' * 16)[:16].encode('ascii')
```

Then we have to create an array of bytes to hold all of the different byte values. When we do this, we also have to loop through all of the bytes and seperate them into their upper and lower nibbles (The upper nibble is the first 4 bits in the byte and the lower nibble is the last 4 bits in the byte. Once we seperate them into nibbles, we have to add 0x41 to both so that they can be interpreted as ASCII characters.

```python
encoded = bytearray()
for byte in padded:
  encoded.append(0x41 + ((byte >> 4) & 0x0F))
  encoded.append(0x41 + (byte & 0x0F))
```

The last part of the encoding process involves returning an array of bytes with the first byte being the length of the message and the last 2 bytes being null bytes so that NetBIOS knows where the name ends.

```python
return bytes([32]) + bytes(encoded) + b'\x00\x00'
```

Now that the encoding is done, its time to make the packet. Before we can send out anything, we have to make all 4 of the parts of the packet. First, we have to make the header. The header is the first part of the packet, it tells the recipient some basic information about the packet. For example, we tell the recipient we are sending 6 bytes that are 16 bits each (<- Thats what the H's mean) and we give them an identifier for the reply (Thats what 0xABCD means). There is some more stuff that we do in the header but we don't need to get into that for this.

```python
header = struct.pack(
  ">HHHHHH",
  0xABCD,
  0x0000,
  1,
  0, 0, 0
)
```

Once we make the header, we can knock out the other 3 parts super easily. First, we make the qName (or the payload) an encoded "*". The reason we use an "*" for this because NetBIOS uses the "*" as a wildcard name that is interpreted as "Please gimme all your stuff". Next, we make qType which tells NetBIOS that we are querying it. Lastly, we make the qClass which, once again, tells NetBIOS that we are querying it (main difference between qType and qClass is that qClass tells it the type of class we want to use for the query. This one is known as IN).

```python
qName = nbnsEncode("*")
qType = struct.pack(">H", 0x0021)
qClass = struct.pack(">H", 0x0001)
```

Now that we finally have the pieces for the packet, we can put everything together to form our packet.

```python
query = header + qName + qType + qClass
```

With the packet made, we can finally send it out to a specific IPv4 Host.

```python
sock.sendto(query, (ip, 137))
```

If the target device has NetBIOS enabled, it will recieve this packet and reply with it's NetBIOS information (which includes its name). Now of course we have to do some manipulation and stripping of the reply to eventually obtain the desired NetBIOS name.

```python
nameStr = nameRaw.decode('ascii', errors='replace').rstrip(' \x00').strip()
```

(There is still a LOT more that goes on with NetBIOS which you can read about [here](https://wirexsystems.com/resource/protocols/netbios/))

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
