import sys
import socket
import threading
from datetime import datetime
from scapy.all import ARP, Ether, srp
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit)
from PyQt5.QtGui import QColor, QPalette, QTextCharFormat, QTextCursor
from PyQt5.QtCore import pyqtSignal, QObject
import warnings
from cryptography.fernet import Fernet
import asyncio

warnings.filterwarnings("ignore", message="Wireshark is installed, but cannot read manuf")

class WorkerSignals(QObject):
    """Signals for communicating from worker thread to the main thread."""
    message_received = pyqtSignal(str, QColor)
    server_status = pyqtSignal(str, QColor)

class ChatServer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.server = None
        self.client_connections = []
        self.worker_signals = WorkerSignals()
        
        self.worker_signals.message_received.connect(self.append_to_display)
        self.worker_signals.server_status.connect(self.append_to_display)

    def init_ui(self):
        self.setWindowTitle('Chat Server')
        self.setGeometry(100, 100, 600, 600)

        # Set background color
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(230, 230, 250))
        self.setPalette(palette)

        self.layout = QVBoxLayout()
        self.grid = QGridLayout()

        self.port_label = QLabel('Port:')
        self.port_input = QLineEdit()
        self.port_input.setText('1234')
        self.start_btn = QPushButton('Start Server')
        self.start_btn.clicked.connect(self.start_server_thread)

        self.scan_btn = QPushButton('See Online Users')
        self.scan_btn.clicked.connect(self.display_online_users)

        self.grid.addWidget(self.port_label, 0, 0)
        self.grid.addWidget(self.port_input, 0, 1)
        self.grid.addWidget(self.start_btn, 1, 0, 1, 2)
        self.grid.addWidget(self.scan_btn, 2, 0, 1, 2)

        self.layout.addLayout(self.grid)

        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.layout.addWidget(self.status_display)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText('Enter your message here...')
        
        # Create a send button with a 3x4 size
        self.send_btn = QPushButton('Send')
        self.send_btn.setFixedSize(110, 30)  # Adjust size to 3x4 ratio (approximately)
        self.send_btn.clicked.connect(self.send_message_from_input)

        # Create a layout for message input and send button
        self.message_layout = QGridLayout()
        self.message_layout.addWidget(self.message_input, 0, 0, 1, 2)
        self.message_layout.addWidget(self.send_btn, 0, 2, 1, 1)

        self.layout.addLayout(self.message_layout)

        self.error_label = QLabel('')  # Label for error messages
        self.error_label.setStyleSheet('color: red;')  # Red text for error messages
        self.layout.addWidget(self.error_label)

        self.setLayout(self.layout)

    def send_message_from_input(self):
        """Send a message from the input field."""
        message = self.message_input.text()
        if message:
            self.broadcast_message(f"[You]: {message}", QColor(0, 0, 0))  # Black text for user messages
            self.message_input.clear()

    def display_online_users(self):
        network = self.get_local_network()
        devices = self.scan_ips(network)

        self.worker_signals.server_status.emit("[#] Online Users", QColor(0, 128, 0))  # Green text
        for device in devices:
            self.worker_signals.server_status.emit(f"IP: {device['ip']}, MAC: {device['mac']}", QColor(0, 128, 0))  # Green text

    def get_local_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0)
                s.connect(('8.8.8.8', 1))
                IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
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
        """Handle receiving messages from a client."""
        while True:
            try:
                msg = conn.recv(4096).decode()
                if msg:
                    self.worker_signals.message_received.emit(f"\n[Received message from Client {addr}]: {msg}", QColor(0, 128, 0))  # Green text
                    if msg.lower() in ["exit", "quit"]:
                        self.worker_signals.message_received.emit(f"[#] Client {addr} disconnected!", QColor(0, 128, 0))  # Green text
                        break
                else:
                    break
            except ConnectionError:
                self.worker_signals.message_received.emit(f"\n[-] Connection lost with client {addr}\n", QColor(255, 0, 0))  # Red text
                break
            except OSError as e:
                self.worker_signals.message_received.emit(f"\n[-] Socket error with client {addr}: {e}\n", QColor(255, 0, 0))  # Red text
                break
            finally:
                conn.close()
                if conn in self.client_connections:
                    self.client_connections.remove(conn)

    def broadcast_message(self, message, color):
        """Send a message to all connected clients and display it."""
        for conn in self.client_connections[:]:
            try:
                conn.send(message.encode())
            except OSError:
                # Handle the case where the socket is no longer valid
                self.client_connections.remove(conn)
        self.worker_signals.message_received.emit(message, color)

    def handle_client(self, conn, addr):
        """Handle a new client connection."""
        self.worker_signals.server_status.emit(f"[+] Connection received from {addr}", QColor(0, 0, 255))  # Blue text
        self.worker_signals.server_status.emit("Type Exit or Quit to <Quit>", QColor(255, 0, 0))  # Red text
        
        threading.Thread(target=self.receive_messages, args=(conn, addr), daemon=True).start()
        self.client_connections.append(conn)

    def start_server_thread(self):
        """Start the server in a new thread."""
        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        """Initialize and start the server."""
        port = self.get_valid_port()

        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind(("0.0.0.0", port))
            self.server.listen(3)
            self.worker_signals.server_status.emit(f"[+] Server listening on port {port}", QColor(255, 0, 0))  # Red text
            
            # Display the current date and time
            current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.worker_signals.server_status.emit(f"[+] Server started at {current_datetime}", QColor(0, 0, 255))  # Blue text
            
            while True:
                try:
                    conn, addr = self.server.accept()
                    threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                except OSError as e:
                    self.worker_signals.server_status.emit(f"[-] Server accept error: {e}", QColor(255, 0, 0))  # Red text
                    break

        except socket.error as e:
            self.set_error_message(f"[-] Server error: {e}")  # Set error message in label
        finally:
            if self.server:
                self.server.close()

    def get_valid_port(self):
        """Get and validate the port number from user input."""
        try:
            port = int(self.port_input.text())
            if not (1024 <= port <= 65535):
                raise ValueError("Port number must be between 1024 and 65535.")
            return port
        except ValueError as e:
            self.set_error_message(str(e))  # Set error message in label
            return 1234  # Default port

    def set_error_message(self, message):
        """Set the error message in the QLabel."""
        self.error_label.setText(message)

    def append_to_display(self, text, color=QColor(0, 0, 0)):
        """Append text to the status display with the specified color."""
        cursor = self.status_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        format = QTextCharFormat()
        format.setForeground(color)
        cursor.insertText(text + '\n', format)
        self.status_display.setTextCursor(cursor)
        self.status_display.ensureCursorVisible()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = ChatServer()
    window.show()

    sys.exit(app.exec_())
