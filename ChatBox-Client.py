import sys
import socket
import threading
from datetime import datetime
from colorama import Fore, Style
from scapy.all import ARP, Ether, srp
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit)

class ChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Chat Client')
        self.setGeometry(100,100,600,500)
        
        self.layout = QVBoxLayout()
        self.grid = QGridLayout()

        self.ip_label = QLabel('IP:')
        self.ip_input = QLineEdit()
        self.port_label = QLabel('Port:')
        self.port_input = QLineEdit()
        self.port_input.setText('1234')
        self.connect_btn = QPushButton('Connect')
        self.connect_btn.clicked.connect(self.start_client)

        self.grid.addWidget(self.ip_label, 0, 0)
        self.grid.addWidget(self.ip_input, 0, 1)
        self.grid.addWidget(self.port_label, 1, 0)
        self.grid.addWidget(self.port_input, 1, 1)
        self.grid.addWidget(self.connect_btn, 2, 0, 1, 2)

        self.layout.addLayout(self.grid)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.layout.addWidget(self.chat_display)

        self.message_input = QLineEdit()
        self.send_btn = QPushButton('Send')
        self.send_btn.clicked.connect(self.send_message)

        self.layout.addWidget(self.message_input)
        self.layout.addWidget(self.send_btn)

        self.setLayout(self.layout)
        self.client = None

    def start_client(self):
        ip = self.ip_input.text()
        port = int(self.port_input.text())

        if not ip:
            self.chat_display.append("[-] IP cannot be null!\n")
            return

        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((ip, port))

            self.chat_display.append(Fore.RED + "[i] Connection successful with " + ip + Style.RESET_ALL)
            self.chat_display.append("Type Exit or Quit to <Quit>")

            # Start a thread to receive messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError) as e:
            self.chat_display.append(Fore.RED + "[-] Check Your Connection [-]\n" + Style.RESET_ALL)

    def receive_messages(self):
        while True:
            try:
                msg = self.client.recv(4096).decode()
                if msg:
                    self.chat_display.append(Fore.GREEN + "[Received message from Server]: " + msg + Style.RESET_ALL)
                else:
                    break
            except ConnectionError:
                self.chat_display.append(Fore.RED + "\n[-] Connection lost!" + Style.RESET_ALL)
                self.client.close()
                break

    def send_message(self):
        if self.client:
            msg = self.message_input.text()
            if msg.lower() in ["exit", "quit"]:
                self.client.close()
                sys.exit()
            self.client.send(msg.encode())
            self.chat_display.append(Fore.YELLOW + "[You]: " + msg + Style.RESET_ALL)
            self.message_input.clear()

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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    network = get_local_network()
    devices = scan_ips(network)

    print(Fore.GREEN + "[#] Online User's" + Style.RESET_ALL)
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    window = ChatClient()
    window.show()

    sys.exit(app.exec_())
