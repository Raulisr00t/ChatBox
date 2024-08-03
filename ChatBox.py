import socket
import sys
import threading
from colorama import Fore, Style
from datetime import datetime
from scapy.all import ARP, Ether, srp

def get_local_ip():
    """Get the local IP address of the current machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('8.8.8.8', 1)) 
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_local_network():
    """Get the local network address."""
    local_ip = get_local_ip()
    ip_parts = local_ip.split('.')
    network = '.'.join(ip_parts[:-1]) + '.0/24'
    return network

def scan_ips(network):
    """Scan the network to find all active devices."""
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def receive_messages(conn, addr):
    """Receive messages from the client."""
    while True:
        try:
            msg = conn.recv(4096).decode()
            if msg:
                print(Fore.GREEN + "\n[Received message from Client {}]: {}".format(addr, msg) + Style.RESET_ALL)
                print(Fore.YELLOW + "[>>] Please enter something for chat with {}: ".format(addr) + Style.RESET_ALL, end='')
                sys.stdout.flush()
                if msg.lower() in ["exit", "quit"]:
                    print(Fore.GREEN + "[#] Client {} disconnected!".format(addr) + Style.RESET_ALL)
                    conn.close()
                    break
            else:
                break
            
        except ConnectionError:
            print(Fore.RED + "\n[-] Connection lost with client {}\n".format(addr) + Style.RESET_ALL)
            sys.exit()

def send_messages(conn, addr):
    """Send messages to the client."""
    while True:
        yourmsg = input(Fore.YELLOW + "[>>] Please enter something for chat with {}: ".format(addr) + Style.RESET_ALL)
        if yourmsg.lower() in ["exit", "quit"]:
            conn.close()
            sys.exit()
        conn.send(yourmsg.encode())

def handle_client(conn, addr):
    """Handle incoming connections from clients."""
    print(Fore.LIGHTBLUE_EX + "[+] Connection received from " + str(addr) + Style.RESET_ALL)
    print(Fore.RED + "Type Exit or Quit to <Quit>" + Style.RESET_ALL)
    
    threading.Thread(target=receive_messages, args=(conn, addr), daemon=True).start()
    send_messages(conn, addr)

def start_server(port):
    """Start the server and listen for incoming connections."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen(3)
        print(Fore.RED + "[+] Server listening on port 1234" + Style.RESET_ALL)
        
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

    except Exception as e:
        print(Fore.RED + "[-] Server error: {}".format(e) + Style.RESET_ALL)
        server.close()
        sys.exit()

if __name__ == "__main__":
    print(Fore.RED + "[+] Welcome to chat [+]" + Style.RESET_ALL)
    today = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    print(Fore.LIGHTBLUE_EX + today + Style.RESET_ALL)

    network = get_local_network()
    devices = scan_ips(network)

    print(Fore.GREEN + "[#] Online User's" + Style.RESET_ALL)
    for device in devices:
        print(f"IP: {device['ip']}")

    start_server(1234)
