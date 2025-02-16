import socket
import threading
import json
import os
import time
import select
import sys

CONFIG_FILE = "chat_config.json"
PORT = 5000  # Fixed port for both listening and connecting

# Global variables for connection management
chat_conn = None
chat_conn_lock = threading.Lock()
connection_established = threading.Event()


def load_config():
    """Load saved partner configuration (name and IP) if available."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print("Error reading configuration file:", e)
            return None
    return None


def save_config(partner_name, partner_ip):
    """Save partner configuration for future sessions (with duplicate check)."""
    config = {"partner_name": partner_name, "partner_ip": partner_ip}
    try:
        # If a config exists, check for duplicacy.
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                try:
                    existing_config = json.load(f)
                    if (
                        existing_config.get("partner_name") == partner_name
                        and existing_config.get("partner_ip") == partner_ip
                    ):
                        print("Configuration already saved, no update needed.")
                        return
                except json.JSONDecodeError:
                    # If the file is corrupt, we'll overwrite it.
                    pass
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        print("Configuration saved successfully.")
    except Exception as e:
        print("Error saving configuration:", e)


def server_thread_func():
    """
    Listens on PORT for an incoming connection.
    If a connection is accepted and no connection has yet been established,
    it saves that connection and signals that the chat can begin.
    """
    global chat_conn
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("", PORT))
        server_sock.listen(1)
    except Exception as e:
        print(f"[Listener] Failed to bind/listen on port {PORT}: {e}")
        return

    server_sock.settimeout(1)
    print(f"[Listener] Listening for incoming connections on port {PORT}...")

    while not connection_established.is_set():
        try:
            conn, addr = server_sock.accept()
            with chat_conn_lock:
                if chat_conn is None:
                    chat_conn = conn
                    connection_established.set()
                    print(f"[Listener] Incoming connection established from {addr}")
                else:
                    conn.close()  # Redundant connection; close it.
        except socket.timeout:
            continue
        except Exception as e:
            print(f"[Listener] Error: {e}")
            break
    server_sock.close()


def client_thread_func(partner_ip):
    """
    Continuously attempts to connect to the partner's IP on PORT.
    Once connected (and if no connection exists yet), it saves the connection
    and signals that the chat can begin.
    """
    global chat_conn
    while not connection_established.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((partner_ip, PORT))
            with chat_conn_lock:
                if chat_conn is None:
                    chat_conn = s
                    connection_established.set()
                    print(f"[Connector] Connected to partner at {partner_ip}:{PORT}")
                else:
                    s.close()
            break
        except Exception:
            time.sleep(1)


def chat_loop(sock, my_name):
    """
    Uses the select module to multiplex between user input (stdin) and socket data.
    This loop allows both sending and receiving messages concurrently.
    """
    print("You can start chatting now. Type exit() to quit.")
    sys.stdout.write("> ")
    sys.stdout.flush()
    while True:
        try:
            # Wait for either socket data or user input.
            ready, _, _ = select.select([sock, sys.stdin], [], [])
        except Exception as e:
            print("Select error:", e)
            break

        for r in ready:
            if r == sock:
                try:
                    data = sock.recv(1024)
                    if not data:
                        print("\nConnection closed by the partner.")
                        return
                    msg = data.decode()
                    if msg == "USER_EXIT":
                        print("\nThe partner has exited the chat. They are offline.")
                        return
                    # Print the incoming message and reprint the prompt.
                    sys.stdout.write("\n" + msg + "\n> ")
                    sys.stdout.flush()
                except Exception as e:
                    print("\nError receiving message:", e)
                    return
            elif r == sys.stdin:
                line = sys.stdin.readline()
                if line.strip() == "exit()":
                    try:
                        sock.sendall("USER_EXIT".encode())
                    except Exception:
                        # Silently ignore errors if the connection is already closed.
                        pass
                    print("Exiting chat.")
                    return
                message_to_send = f"{my_name}: {line}"
                try:
                    sock.sendall(message_to_send.encode())
                except Exception as e:
                    print("Error sending message:", e)
                    return
                sys.stdout.write("> ")
                sys.stdout.flush()


def main():
    print("Welcome to the P2P Chat App!")
    my_name = input("Enter your name: ").strip()

    # Get partner configuration from file or prompt the user.
    config = load_config()
    if config:
        use_config = input("Saved configuration found. Use it? (Y/N): ").strip().lower()
        if use_config == "y":
            partner_name = config.get("partner_name")
            partner_ip = config.get("partner_ip")
            print(
                f"Using saved configuration: Partner Name: {partner_name}, IP: {partner_ip}"
            )
        else:
            partner_name = input("Enter your partner's name: ").strip()
            partner_ip = input("Enter your partner's IP address: ").strip()
    else:
        partner_name = input("Enter your partner's name: ").strip()
        partner_ip = input("Enter your partner's IP address: ").strip()

    # Start both the listener (server role) and connector (client role) threads.
    listener = threading.Thread(target=server_thread_func, daemon=True)
    connector = threading.Thread(
        target=client_thread_func, args=(partner_ip,), daemon=True
    )
    listener.start()
    connector.start()

    # Wait up to 60 seconds for a successful connection.
    if not connection_established.wait(timeout=60):
        print(
            "Unable to establish connection. Please check the partner's IP address and try again."
        )
        return

    # Save configuration only after a valid connection is established.
    save_config(partner_name, partner_ip)
    print("Chat connection established.")

    # Start the chat loop.
    chat_loop(chat_conn, my_name)

    listener.join()
    connector.join()


if __name__ == "__main__":
    main()
