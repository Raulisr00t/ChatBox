import sys
import socket
import threading
from colorama import Fore, Style
from datetime import datetime
from scapy.all import ARP, Ether, srp
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit)
import warnings
warnings.simplefilter(action=Warning,category=UserWarning)

class ChatServer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.server = None
        self.client_threads = []

    def init_ui(self):
        self.setWindowTitle('Chat Server')
        self.setGeometry(100,100,600,500)

        self.layout = QVBoxLayout()
        self.grid = QGridLayout()

        self.port_label = QLabel('Port:')
        self.port_input = QLineEdit()
        self.port_input.setText('1234')
        self.start_btn = QPushButton('Start Server')
        self.start_btn.clicked.connect(self.start_server)

        self.grid.addWidget(self.port_label, 0, 0)
        self.grid.addWidget(self.port_input, 0, 1)
        self.grid.addWidget(self.start_btn, 1, 0, 1, 2)

        self.layout.addLayout(self.grid)

        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.layout.addWidget(self.status_display)

        self.setLayout(self.layout)
        
        self.display_online_users()

    def display_online_users(self):
        network = self.get_local_network()
        devices = self.scan_ips(network)

        self.status_display.append(Fore.GREEN + "[#] Online User's" + Style.RESET_ALL)
        for device in devices:
            self.status_display.append(f"IP: {device['ip']}, MAC: {device['mac']}")

    def get_local_ip(self):
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

    def get_local_network(self):
        local_ip = self.get_local_ip()
        ip_parts = local_ip.split('.')
        network = '.'.join(ip_parts[:-1]) + '.0/24'
        return network

    def scan_ips(self, network):
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, verbose=0)[0]
        devices = []

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        return devices

    def receive_messages(self, conn, addr):
        while True:
            try:
                msg = conn.recv(4096).decode()
                if msg:
                    self.status_display.append(Fore.GREEN + "\n[Received message from Client {}]: {}".format(addr, msg) + Style.RESET_ALL)
                    if msg.lower() in ["exit", "quit"]:
                        self.status_display.append(Fore.GREEN + "[#] Client {} disconnected!".format(addr) + Style.RESET_ALL)
                        conn.close()
                        break
                else:
                    break
            except ConnectionError:
                self.status_display.append(Fore.RED + "\n[-] Connection lost with client {}\n".format(addr) + Style.RESET_ALL)
                conn.close()
                break

    def send_messages(self, conn, addr):
        while True:
            yourmsg = input(Fore.YELLOW + "[>>] Please enter something for chat with {}: ".format(addr) + Style.RESET_ALL)
            if yourmsg.lower() in ["exit", "quit"]:
                conn.close()
                sys.exit()
            conn.send(yourmsg.encode())

    def handle_client(self, conn, addr):
        self.status_display.append(Fore.LIGHTBLUE_EX + "[+] Connection received from " + str(addr) + Style.RESET_ALL)
        self.status_display.append(Fore.RED + "Type Exit or Quit to <Quit>" + Style.RESET_ALL)
        
        threading.Thread(target=self.receive_messages, args=(conn, addr), daemon=True).start()
        self.send_messages(conn, addr)

    def start_server(self):
        port = int(self.port_input.text())

        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind(("0.0.0.0", port))
            self.server.listen(3)
            self.status_display.append(Fore.RED + "[+] Server listening on port {}".format(port) + Style.RESET_ALL)
            
            while True:
                conn, addr = self.server.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
                self.client_threads.append(client_thread)

        except Exception as e:
            self.status_display.append(Fore.RED + "[-] Server error: {}".format(e) + Style.RESET_ALL)
            if self.server:
                self.server.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = ChatServer()
    window.show()

    sys.exit(app.exec_())
