import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: 'FTP',
    22:   'SSH',
    23:   'Telnet',
    25:   'SMTP',
    53:   'DNS',
    80:   'HTTP',
    110:  'POP3',
    135:  'MS-RPC',
    139:  'NetBIOS-SSN',
    143:  'IMAP',
    443:  'HTTPS',
    445:  'SMB',
    554:  'RTSP',
    993:  'IMAPS',
    995:  'POP3S',
    1900: 'SSDP/UPnP',
    3306: 'MySQL',
    3389: 'RDP',
    5000: 'UPnP/HTTP-Alt',
    5357: 'WSDAPI',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt'
}

def checkPort(ip: str, port: int, timeout: float = 0.5) -> str:

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            return COMMON_PORTS.get(port)
    
    except OSError:
        return 'N/A'
    
    finally:
        sock.close()

def PScan(ip: str, ports: dict = COMMON_PORTS, timeout: float = 0.5, max_workers: int = 100) -> tuple:

    open_ports = []

    with ThreadPoolExecutor(max_workers=min(len(ports), max_workers)) as executor:
        futures = {executor.submit(checkPort, ip, port, timeout): port for port in ports}

        for future in futures:
            port = futures[future]
            if future.result():
                open_ports.append(port)

        if not open_ports:
            return "N/A"
        
        open_ports.sort()
        return ", ".join(str(p) for p in open_ports)
