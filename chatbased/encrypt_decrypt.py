import struct
import math
import random
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
    
   
    def is_prime(num):
        if num < 2:
            return False
        for i in range(2, int(num ** 0.5) + 1):
            if num % i == 0:
                return False
        return True

    primes = [i for i in range(11, 100) if is_prime(i)]
    p = random.choice(primes)
    q = random.choice([x for x in primes if x != p])
    n = p * q
    phi = (p - 1) * (q - 1)
    # Choose e coprime to phi
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    e_choices = [3, 5, 17, 257, 65537]
    e = next((x for x in e_choices if x < phi and gcd(x, phi) == 1), 3)

    def modinv(a, m):
       
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 % m0
    d = modinv(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(text, public_key):
    e, n = public_key
    cipher_ints = [pow(ord(char), e, n) for char in text]
    
    hex_str = ''.join(f'{c:08x}' for c in cipher_ints)
    return hex_str

def rsa_decrypt(cipher, private_key):
    d, n = private_key
    
    cipher_ints = [int(cipher[i:i+8], 16) for i in range(0, len(cipher), 8)]
    return ''.join([chr(pow(c, d, n)) for c in cipher_ints])


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
