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
        s.connect(('8.8.8.8', 1))  # Use Google's DNS server to get the IP
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

    result = srp(packet, timeout=2, verbose=1)[0]  # Set verbose to 1 for debugging
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def receive_messages(client):
    """Receive messages from the server."""
    while True:
        try:
            msg = client.recv(4096).decode()
            if msg:
                print(Fore.GREEN + "\n[Received message from Server]: " + msg + Style.RESET_ALL)
                print(Fore.YELLOW + "[>>] Please enter something for chatting with {}: ".format(ip) + Style.RESET_ALL, end='')
                sys.stdout.flush()
            else:
                break
        
        except ConnectionError:
            print(Fore.RED + "\n[-] Connection lost!" + Style.RESET_ALL)
            sys.exit()
            

def start_client(ip, port):
    """Start the client and connect to the server."""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, port))
        
        print(Fore.RED + "[i] Connection successful with " + ip + Style.RESET_ALL)
        print("Type Exit or Quit to <Quit>")

        # Start a thread to receive messages
        threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

        while True:
            yourmsg = input(Fore.YELLOW + "[>>] Please enter something for chatting with {}: ".format(ip) + Style.RESET_ALL)
            if yourmsg.lower() in ["exit", "quit"]:
                client.close()
                sys.exit()
            client.send(yourmsg.encode())

    except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError) as e:
        print(Fore.RED + "[-] Check Your Connection [-]\n" + Style.RESET_ALL)
        sys.exit()

if __name__ == "__main__":
    print(Fore.RED + "[+] Welcome Chat [+]" + Style.RESET_ALL)
    today = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    print(Fore.LIGHTBLUE_EX + today + Style.RESET_ALL)
   
    network = get_local_network()
    devices = scan_ips(network)

    print(Fore.GREEN + "[#] Online User's" + Style.RESET_ALL)
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    ip = input("[i] Please type an address for chat: ")
    
    port = 1234
    
    if not ip:
        print("[-] Try Again, IP cannot be null!\n")
        sys.exit()

    start_client(ip, port)
