# This is where the magic happens

This section is where the core functionality of this program lies.
It is also linked to the util section which contains all of the necessary utilities for this program.
This part contains the part of the program that is called to start everything as well as the code for the 3 main discovery methods.
This section also includes the arguement parsing at runtime that allows users to change certain behaviors within the program.

## For more in-depth explainations:
See [Core](#core)

See [Main Entry](#main-entry)

## Core

Core.py handles basically everything that this program needs to function. It handles gathering the functionality from the utility scripts.
It also handles all 3 of the discovery methods and all the hostname resolution with the added bonus of handling displaying the information the 
program gathers. Here's a bit of a deeper dive into it's different functionalities.

- Host Discovery Methods:
  - ARP Sweep:
    - This discovery method includes attempting to find hosts by sending out an ARP (Address Resolution Protocol) broadcast packet.
    - This packet is recieved by all hosts on the available subnet.
    - In order to find hosts, we look for responces to this packet.
    - IMPORTANT: Not all devices will respond to this type of packet, in fact, some networks block this type of packet from being sent out.
  - Ping Sweep:
    - This discovery method includes attempting to find hosts by sending out ping requests (or ICMP packets).
    - These packets are primarily used to check if a host is alive by asking its IPv4 Address if it is active.
    - Most devices will respond to ping requests but some devices that don't have the correct functionality or have specific security restrictions might not.
    - In terms of how this program does a ping sweep, it takes the subnet and generates a list of all possible IPv4 Addresses and pings each of them.
    - IMPORTANT: Pinging a host only tells you that there is a device at that IPv4 Address nothing else.
  - Passive Sniffing:
    - This is the last, and generally most reliable discovery method.
    - It works by sitting on the network and capturing packets that pass through it.
    - This means that ANY traffic moving through the subnet can be searched for host information like IPv4 and MAC Addresses
    - This is the most reliable method because a network has to be specifically configured to ignore devices trying to sniff the network.
    - IMPORTANT: This is typically the discovery method that takes the longest because it just sits and waits for packets it can use.

- Name Resolution Methods:
  - This program uses a variety of name resolution methods inside of the util section of this program.
  - These methods include:
    - Reverse DNS
      - See [Reverse DNS](util/README.md#reverse-dns)
    - NetBIOS
      - See [NetBIOS](util/README.md#netbios)
    - mDNS
      - See [mDNS](util/README.md#mdns)
    - SSDP
      - See [SSDP](util/README.md#ssdp)
    - OUI
      - See [OUI](util/README.md#oui)
    - Port Scan
      - See [Port Scan](util/README.md#port-scan)

- Other important functions:
  - There is a list at the top of the script that allows users to set specific MAC Addresses as "known" or legitimate devices. This isn't the absolute best method for this but it gets the job done for now.
  - This script also determines what the best human-readable name for each device would be.
  - This part also handles setting up the parser for the arguements and the cleanly formatted display

## Main Entry

This part is pretty straight forward. We use the default Python file name as the entry point so that users can call the NetCheck folder
as a starting point for the program.

This part also handles the ordering in which events happen inside of the program (eg. making it scan before trying to find host information).
This part also handles making sure that the program exits without causing a giant scene over a sudden stop.

[Back to top](#this-is-where-the-magic-happens)

##

>⚠️ WARNING: These scripts are for educational purposes only and are not to be used for malicious actions. ⚠️
