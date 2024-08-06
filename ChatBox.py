import sys
import socket
import threading
from datetime import datetime
from scapy.all import ARP, Ether, srp
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QGridLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit , QInputDialog)
from PyQt5.QtGui import QColor, QPalette, QTextCharFormat, QTextCursor
from PyQt5.QtCore import QTimer, pyqtSignal, QObject
import warnings
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
        self.client_threads = []
        self.worker_signals = WorkerSignals()
        
        self.worker_signals.message_received.connect(self.append_to_display)
        self.worker_signals.server_status.connect(self.append_to_display)
        
        # Add a timer to perform periodic actions
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.periodic_update)
        self.timer.start(5000)  # Update every 5 seconds

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
        self.message_input.returnPressed.connect(self.send_message_from_input)
        self.layout.addWidget(self.message_input)

        self.error_label = QLabel('')  # Label for error messages
        self.layout.addWidget(self.error_label)

        self.setLayout(self.layout)

    def send_message_from_input(self):
        """Send a message from the input field."""
        message = self.message_input.text()
        if message:
            # This will be sent to all connected clients
            self.broadcast_message(f"[You]: {message}", QColor(255, 255, 0))
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
            finally:
                conn.close()

    def broadcast_message(self, message, color):
        """Send a message to all connected clients and display it."""
        for conn in self.client_threads:
            conn.send(message.encode())
        self.worker_signals.message_received.emit(message, color)

    def send_messages(self, conn, addr):
        while True:
            reply = self.get_message(f"Chat with {addr}")
            if reply:
                if reply.lower() in ["exit", "quit"]:
                    conn.close()
                    break
                conn.send(reply.encode())
                self.worker_signals.message_received.emit(f"[You]: {reply}", QColor(255, 255, 0))  # Yellow text

    def get_message(self, title):
        """Display a message input dialog and return the input text."""
        dialog = QInputDialog(self)
        dialog.setWindowTitle(title)
        dialog.setLabelText("Enter your message:")
        dialog.setModal(True)
        if dialog.exec_() == QInputDialog.Accepted:
            return dialog.textValue()
        return None

    def handle_client(self, conn, addr):
        self.worker_signals.server_status.emit(f"[+] Connection received from {addr}", QColor(0, 0, 255))  # Blue text
        self.worker_signals.server_status.emit("Type Exit or Quit to <Quit>", QColor(255, 0, 0))  # Red text
        
        threading.Thread(target=self.receive_messages, args=(conn, addr), daemon=True).start()

    def start_server_thread(self):
        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
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
                conn, addr = self.server.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
                self.client_threads.append(conn)

        except socket.error as e:
            self.set_error_message(f"[-] Server error: {e}")  # Set error message in label
        finally:
            if self.server:
                self.server.close()

    def get_valid_port(self):
        """Get a valid port number from user input."""
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

    def periodic_update(self):
        """Update the status display periodically."""
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.worker_signals.server_status.emit(f"Periodic update at {current_time}", QColor(0, 0, 255))  # Blue text

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = ChatServer()
    window.show()

    sys.exit(app.exec_())
