# ChatBox Application
## Overview
This Chat Server application is a simple server-side chat service built using Python and PyQt5. It allows multiple clients to connect, send, and receive messages. Additionally, it includes functionalities to display online users on the local network.

## Features
1.Multithreaded Server: Supports multiple clients connecting simultaneously.
2.Real-time Messaging: Allows real-time message exchange between the server and connected clients.
3.Periodic Updates: Displays periodic updates in the server status window.
4.Online Users Scan: Scans and displays devices connected to the local network.
5.Graphical User Interface: Easy-to-use interface built with PyQt5.

## Requirements
Python 3.x
PyQt5
Scapy
Manuf
Cryptography

## Installation
1.Clone the repository or download the source code.
2.Install the required dependencies:
```powershell
pip install pyqt5 scapy manuf cryptography
```

## Usage
Start the Server:
Run the ChatServer application
```powershell
python ChatBox.py
```

See Online Users:
Click the See Online Users button to scan and display devices connected to the local network.

Chat with Clients:
When a client connects, a message input dialog will appear. Enter your message and click send.
Messages from clients will be displayed in the status window.

### UI Overview
Port: Input field to specify the server port.
Start Server: Button to start the chat server.
See Online Users: Button to scan and display online users on the local network.
Status Display: Read-only text area displaying server status, messages, and updates.

### Notes
The server periodically updates the status display every 5 seconds.
To disconnect from a client, type "exit" or "quit" in the message input dialog.

## License
This project is licensed under the MIT License.
