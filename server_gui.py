import socket
import pickle
import threading
import tkinter as tk
from crypto_utils import *
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 5000

class ServerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Server")

        self.chat_area = tk.Text(self.root, height=20, width=50)
        self.chat_area.pack()

        self.entry = tk.Entry(self.root, width=40)
        self.entry.pack(side=tk.LEFT)

        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        self.setup_connection()

        threading.Thread(target=self.receive_messages).start()

        self.root.mainloop()

    def setup_connection(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((HOST, PORT))
        self.server.listen(1)
        self.chat_area.insert(tk.END, "Waiting for connection...\n")
        self.conn, addr = self.server.accept()
        self.chat_area.insert(tk.END, f"Connected to {addr}\n")

        parameters = generate_dh_parameters()
        self.private_key, public_key = generate_dh_keypair(parameters)

        self.conn.send(pickle.dumps((
            parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            ),
            public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )))

        client_pub_bytes = pickle.loads(self.conn.recv(4096))
        client_pub = serialization.load_pem_public_key(client_pub_bytes)

        self.shared_key = derive_shared_key(self.private_key, client_pub)
        self.chat_area.insert(tk.END, "Secure Channel Established 🔐\n")

    def send_message(self):
        msg = self.entry.get()
        encrypted = encrypt_message(self.shared_key, msg)
        self.conn.send(encrypted)
        self.chat_area.insert(tk.END, "You: " + msg + "\n")
        self.entry.delete(0, tk.END)

    def receive_messages(self):
        while True:
            encrypted = self.conn.recv(4096)
            if encrypted:
                msg = decrypt_message(self.shared_key, encrypted)
                self.chat_area.insert(tk.END, "Client: " + msg + "\n")

ServerGUI()
