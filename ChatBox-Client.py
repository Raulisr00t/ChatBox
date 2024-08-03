import socket
import sys
import threading
from colorama import Fore, Style
from datetime import datetime

# Function to receive messages from the server
def receive_messages(client):
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
            print(Fore.RED + "[-] Connection lost!" + Style.RESET_ALL)
            sys.exit()
            break

# Main client function
def start_client(ip, port):
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

# Entry point for the client
if __name__ == "__main__":
    print(Fore.RED + "[+] Welcome Chat [+]" + Style.RESET_ALL)
    today = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    print(Fore.LIGHTBLUE_EX + today + Style.RESET_ALL)

    ip = input("[i] Please type an address for chat: ")
    port = 1234
    if not ip:
        print("[-] Try Again, IP cannot be null!\n")
        sys.exit()

    start_client(ip, port)
