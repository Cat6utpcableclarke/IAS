# server.py

import socket
from encrypt_decrypt import generate_keys, encrypt_message, decrypt_message, md5

shift = int(input("Enter your Caesar shift value: "))
vigkey = input("Enter your Vigenère key: ").strip()

host = socket.gethostbyname(socket.gethostname())  # Gets local IP
port = 5555

print(f"Starting server on {host}:{port}...")
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen(1)
print("Waiting for client to connect...")

conn, addr = server.accept()
print(f"Connected by {addr}")

# Generate keys and exchange public keys
public_key, private_key = generate_keys()
conn.send(str(public_key).encode())
partner_key_data = conn.recv(4096)
partner_public_key = eval(partner_key_data.decode())

while True:
    encrypted = conn.recv(4096)
    if not encrypted:
        break
    cipher = encrypted.decode()
    decrypted = decrypt_message(cipher, private_key, shift, vigkey)
    print(f"Client: {decrypted} hash: {md5(decrypted)}")
    msg = input("You: ")
    print(f"hash:{md5(msg)}")
    cipher = encrypt_message(msg, partner_public_key, shift, vigkey)
    conn.send(str(cipher).encode())

conn.close()
