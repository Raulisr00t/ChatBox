import sys
import socket
import threading
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit, QMessageBox)
from PyQt5.QtGui import QColor, QPalette
import base64
import warnings
from scapy.all import Ether, ARP, srp

warnings.filterwarnings("ignore", message="Wireshark is installed, but cannot read manuf")

class ChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.cipher = None
        self.client = None

    def init_ui(self):
        self.setWindowTitle('Chat Client')
        self.setGeometry(100, 100, 600, 500)

        # Set background color
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(230, 230, 250))
        self.setPalette(palette)

        self.layout = QVBoxLayout()
        self.grid = QGridLayout()

        self.ip_label = QLabel('IP:')
        self.ip_input = QLineEdit()
        self.port_label = QLabel('Port:')
        self.port_input = QLineEdit()
        self.port_input.setText('1234')
        self.connect_btn = QPushButton('Connect')
        self.connect_btn.clicked.connect(self.start_client)

        self.scan_btn = QPushButton('See Online Users')
        self.scan_btn.clicked.connect(self.display_online_users)

        self.grid.addWidget(self.ip_label, 0, 0)
        self.grid.addWidget(self.ip_input, 0, 1)
        self.grid.addWidget(self.port_label, 1, 0)
        self.grid.addWidget(self.port_input, 1, 1)
        self.grid.addWidget(self.connect_btn, 2, 0)
        self.grid.addWidget(self.scan_btn, 2, 1)

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

    def start_client(self):
        ip = self.ip_input.text()
        port = int(self.port_input.text())

        if not ip:
            self.chat_display.append(self.format_message("[-] IP cannot be null!", QColor('red')))
            return

        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((ip, port))

            # Receive and decode the Fernet key
            key_str = self.client.recv(64).decode()  # Adjust size based on expected key length
            key = base64.urlsafe_b64decode(key_str)
            self.cipher = Fernet(key)

            self.chat_display.append(self.format_message("[i] Connection successful with " + ip, QColor('green')))
            self.chat_display.append(self.format_message("Type Exit or Quit to <Quit>", QColor('blue')))

            # Start a thread to receive messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError) as e:
            self.chat_display.append(self.format_message("[-] Check Your Connection: " + str(e), QColor('red')))
        except ValueError as e:
            self.chat_display.append(self.format_message(f"[-] Invalid Fernet key: {e}", QColor('red')))
        except Exception as e:
            self.chat_display.append(self.format_message(f"[-] Unexpected error: {e}", QColor('red')))

    def receive_messages(self):
        while True:
            try:
                encrypted_msg = self.client.recv(4096)
                if not encrypted_msg:
                    self.chat_display.append(self.format_message("[-] Server disconnected", QColor('red')))
                    break

                msg = self.cipher.decrypt(encrypted_msg).decode()
                self.chat_display.append(self.format_message("[Received message from Server]: " + msg, QColor('green')))
            except ConnectionError:
                self.chat_display.append(self.format_message("[-] Connection lost!", QColor('red')))
                break
            except Exception as e:
                self.chat_display.append(self.format_message(f"[-] Error: {e}", QColor('red')))
                break
            finally:
                if self.client:
                    self.client.close()

    def send_message(self):
        if self.client:
            msg = self.message_input.text()
            if msg.lower() in ["exit", "quit"]:
                self.client.close()
                self.chat_display.append(self.format_message("[You]: Disconnected", QColor('red')))
                QApplication.quit()
            else:
                try:
                    encrypted_msg = self.cipher.encrypt(msg.encode())
                    self.client.send(encrypted_msg)
                    self.chat_display.append(self.format_message("[You]: " + msg, QColor('yellow')))
                    self.message_input.clear()
                except Exception as e:
                    self.chat_display.append(self.format_message(f"[-] Error sending message: {e}", QColor('red')))

    def display_online_users(self):
        network = self.get_local_network()
        devices = self.scan_ips(network)

        # Format the list of devices with each IP on a new line
        user_list = "\n".join(f"IP:{device['ip']}" for device in devices)
        
        # Append the online users message formatted in green
        self.chat_display.append(self.format_message(f"Online Users:\n{user_list}", QColor('green')))

    def format_message(self, message, color):
        """Format message with color for QTextEdit."""
        return f'<span style="color: {color.name()}">{message}</span>'

    def get_local_ip(self):
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

    def get_local_network(self):
        """Get the local network address."""
        local_ip = self.get_local_ip()
        ip_parts = local_ip.split('.')
        network = '.'.join(ip_parts[:-1]) + '.0/24'
        return network

    def scan_ips(self, network):
        """Scan the network to find all active devices."""
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, verbose=0)[0]
        devices = []

        for sent, received in result:
            devices.append({'ip': received.psrc})

        return devices

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = ChatClient()
    window.show()

    sys.exit(app.exec_())
