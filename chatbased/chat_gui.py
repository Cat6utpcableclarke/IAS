import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import threading
import socket
import base64
from encrypt_decrypt import generate_keys, encrypt_message, decrypt_message, md5

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Chat App")

      
        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', width=60, height=20)
        self.chat_area.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        
        self.input_field = tk.Entry(root, width=50)
        self.input_field.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.input_field.bind("<Return>", self.send_message)

       
        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, sticky="e", padx=10)

      
        self.client_button = tk.Button(root, text="Start as Client", command=self.start_client)
        self.client_button.grid(row=2, column=0, sticky="w", padx=10, pady=10)

        self.server_button = tk.Button(root, text="Start as Server", command=self.start_server)
        self.server_button.grid(row=2, column=1, sticky="e", padx=10, pady=10)

        self.socket = None
        self.connection = None
        self.running = False
        self.shift = 0
        self.vigkey = ''
        self.public_key = None
        self.private_key = None

    def start_server(self):
        self.setup_keys()
        host = socket.gethostbyname(socket.gethostname())
        port = 5555
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(1)
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"Server started at {host}:{port}\nWaiting for client...\n")
        self.chat_area.config(state='disabled')

        threading.Thread(target=self.accept_client, daemon=True).start()

    def accept_client(self):
        self.connection, addr = self.socket.accept()
        self.running = True
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"Client connected from {addr}\n")
        self.chat_area.config(state='disabled')
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def start_client(self):
        self.setup_keys()
        server_ip = simpledialog.askstring("Client", "Enter server IP address:")
        port = 5555
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((server_ip, port))
            self.running = True
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, f"Connected to server at {server_ip}:{port}\n")
            self.chat_area.config(state='disabled')
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")

    def setup_keys(self):
        self.shift = int(simpledialog.askstring("Caesar Cipher", "Enter Caesar shift value:"))
        self.vigkey = simpledialog.askstring("Vigenère Cipher", "Enter Vigenère key:")
        self.public_key, self.private_key = generate_keys()

    def send_message(self, event=None):
        msg = self.input_field.get()
        if msg and self.running:
            cipher = encrypt_message(msg, self.public_key, self.shift, self.vigkey)
            data = str(cipher).encode()

            if self.connection:  
                self.connection.send(data)
            else:  
                self.socket.send(data)

            self.display_message("You", msg)
            self.input_field.delete(0, tk.END)

    def receive_messages(self):
        while self.running:
            try:
                source = self.connection if self.connection else self.socket
                encrypted = source.recv(4096)
                if not encrypted:
                    break
                cipher = eval(encrypted.decode())
                decrypted = decrypt_message(cipher, self.private_key, self.shift, self.vigkey)
                self.display_message("Partner", decrypted)
            except Exception as e:
                self.display_message("System", f"Error: {e}")
                break

    def display_message(self, sender, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"{sender}: {message}\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
