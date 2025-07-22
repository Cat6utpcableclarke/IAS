import struct
import math

def atbash(text):
    result = ''
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr(base + (25 - (ord(char) - base)))
        else:
            result += char
    return result

def caesar(text, shift):
    result = ''
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def vigenere(text, key, decrypt=False):
    result = ''
    key = key.upper()
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            k = ord(key[i % key_len]) - ord('A')
            shift = -k if decrypt else k
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def generate_keys():
    p = 17
    q = 11
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    d = 23  # such that (e * d) % phi == 1
    return (e, n), (d, n)

def rsa_encrypt(text, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in text]

def rsa_decrypt(cipher, private_key):
    d, n = private_key
    return ''.join([chr(pow(c, d, n)) for c in cipher])


def encrypt_message(msg, public_key, shift, vigkey):
    print("\n[Encryption Steps]")
    print(f"Original: {msg}")
    print(f"hash: {md5(msg)}")
    step1 = atbash(msg)
    print(f"Atbash: {step1}")
    
    step2 = caesar(step1, shift)
    print(f"Caesar(+{shift}): {step2}")
    
    step3 = vigenere(step2, vigkey)
    print(f"Vigenère({vigkey}): {step3}")
    
    step4 = rsa_encrypt(step3, public_key)
    print(f"RSA: {step4}\n")
    
    return step4

def decrypt_message(cipher, private_key, shift, vigkey):
    print("\n[Decryption Steps]")
    print(f"RSA Input: {cipher}")
    
    step1 = rsa_decrypt(cipher, private_key)
    print(f"After RSA: {step1}")
    
    step2 = vigenere(step1, vigkey, decrypt=True)
    print(f"After Vigenère({vigkey}): {step2}")
    
    step3 = caesar(step2, -shift)
    print(f"After Caesar(-{shift}): {step3}")
    
    step4 = atbash(step3)
    print(f"After Atbash: {step4}\n Hash: {md5(step4)}")
    
    return step4

def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

def md5(message):

    message = bytearray(message, 'utf-8')  # encode to bytes
    orig_len_bits = (8 * len(message)) & 0xffffffffffffffff

  
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)

  
    message += orig_len_bits.to_bytes(8, byteorder='little')

    
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    
    s = [  
        7, 12, 17, 22,   7, 12, 17, 22,   7, 12, 17, 22,   7, 12, 17, 22,
        5, 9, 14, 20,    5, 9, 14, 20,    5, 9, 14, 20,    5, 9, 14, 20,
        4, 11, 16, 23,   4, 11, 16, 23,   4, 11, 16, 23,   4, 11, 16, 23,
        6, 10, 15, 21,   6, 10, 15, 21,   6, 10, 15, 21,   6, 10, 15, 21
    ]

    K = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]


    for chunk_offset in range(0, len(message), 64):
        a, b, c, d = a0, b0, c0, d0
        chunk = message[chunk_offset:chunk_offset+64]
        M = list(struct.unpack('<16I', chunk))

        for i in range(64):
            if 0 <= i <= 15:
                F = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                F = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                F = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                F = c ^ (b | ~d)
                g = (7 * i) % 16

            F = (F + a + K[i] + M[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + left_rotate(F, s[i])) & 0xFFFFFFFF

 
        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF


    result = struct.pack('<4I', a0, b0, c0, d0)
    return ''.join(f'{byte:02x}' for byte in result)
