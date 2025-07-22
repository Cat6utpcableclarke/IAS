# client.py

import socket
from encrypt_decrypt import generate_keys, encrypt_message, decrypt_message, md5

shift = int(input("Enter your Caesar shift value: "))
vigkey = input("Enter your Vigenère key: ").strip()

server_ip = input("Enter server IP address (e.g., 192.168.1.5): ")
port = 5555

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((server_ip, port))
print(f"Connected to server at {server_ip}:{port}")

public_key, private_key = generate_keys()

while True:
    msg = input("You: ")
    print(f"hash:{md5(msg)}")
    cipher = encrypt_message(msg, public_key, shift, vigkey)
    client.send(str(cipher).encode())

    encrypted = client.recv(4096)
    if not encrypted:
        break
    cipher = eval(encrypted.decode())
    decrypted = decrypt_message(cipher, private_key, shift, vigkey)
    print(f"Server: {decrypted}, hash:{md5(decrypted)}")
