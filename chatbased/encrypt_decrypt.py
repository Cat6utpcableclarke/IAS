# encrypt_decrypt.py

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
    print(f"After Atbash: {step4}\n")
    
    return step4

