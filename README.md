![Project Name](images/NetCheck-ASCII-Art.png)

---

NetCheck is a Python-based beginner's guide to LAN discovery protocols (e.g., mDNS, NetBIOS, SSDP), exploring how they work under the hood, implemented from scratch.

NetCheck covers network reconnaissance techniques from passive sniffing to port scanning with write-ups explaining the implementation of each.

This is phase one of my plan to create an open-source network reconnaissance tool in C++ with a built-in GUI and a broader range of protocols.

## For more information
- Check out [Core Functionality](NetCheck/README.md#this-is-where-the-magic-happens)
- Check out [Utilities](NetCheck/util/README.md#utilities)

---

## How to use

First, move to your desired file location and git clone this repo using this command:

```bash
git clone https://github.com/Chloractus/NetCheck.git
```

Then, move to where the repo is located and download the OUI using this command:

```bash
sudo NetCheck -u
```

Once the OUI is downloaded, you can run the program using

```bash
sudo NetCheck --subnet 192.168.0.1/24 -cd
```

---

>⚠️ WARNING: These scripts are for educational purposes only. They are not to be used against networks you do not own or have explicit permission to test and are not to be used for malicious actions. ⚠️
