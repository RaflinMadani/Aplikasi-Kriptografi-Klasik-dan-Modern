def caesar_cipher(text, key, mode= 'Enkripsi') :
    result = []
    shift = key % 26
    if mode == 'Dekripsi':
        shift = -shift
        
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            new_char = chr((ord(ch) - base + shift) % 26 + base)
            result.append(new_char)
        else:
            result.append(ch)
    return ''.join(result)





def vigenere_cipher(text, key, mode="Enkripsi"):
    result = ""
    key_len = len(key)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            k_char = key[key_index % key_len]
            k_val = ord(k_char.lower()) - ord('a')
            
            if mode == "Dekripsi":
                k_val = -k_val
                
            base = ord('A') if char.isupper() else ord('a')
            p_val = ord(char) - base
            shifted = (p_val + k_val) % 26
            result += chr(shifted + base)
            
            key_index += 1
        else:
            result += char
    return result





def encrypt_rail_fence(text, key):
    if key <= 1:
        return text

    rail = [''] * key
    direction_down = False
    row = 0
    
    for char in text:
        rail[row] += char
        if row == 0 or row == key - 1:
            direction_down = not direction_down
        row += 1 if direction_down else -1
    return ''.join(rail)

def decrypt_rail_fence(cipher, key):
    if key <= 1:
        return cipher
    
    pattern = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    direction_down = None
    row, col = 0, 0
    
    for i in range(len(cipher)):
        if row == 0:
            direction_down = True
        if row == key - 1:
            direction_down = False
        pattern[row][col] = '*'
        col += 1
        row += 1 if direction_down else -1
        
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if pattern[i][j] == '*' and index < len(cipher):
                pattern[i][j] = cipher[index]
                index += 1
    
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            direction_down = True
        if row == key - 1:
            direction_down = False
        result.append(pattern[row][col])
        col += 1
        row += 1 if direction_down else -1
        
    return ''.join(result)





import random

# Function Greatest Common Divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Function inverse e dan phi untuk mencari d
def mod_inverse(e, phi):
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % phi

# Function cek prima
def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Function generate prima
def generate_prime(start=100, end=300):
    while True:
        p = random.randint(start, end)
        if is_prime(p):
            return p

# Function konversi teks ke block
def text_to_blocks(text, block_size):
    data = text.encode()
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

# Function konversi block ke int
def block_to_int(block):
    return int.from_bytes(block, 'big')

# Function konversi int ke block
def int_to_block(num, block_size):
    return num.to_bytes(block_size, 'big').lstrip(b'\x00')

# Generate keys
def generate_keys():
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
        
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    d = mod_inverse(e, phi)
    max_block_size = (n.bit_length() - 1) // 8
    return e, d, n, max_block_size

# Enkripsi RSA
def encrypt(text, e, n, block_size):
    blocks = text_to_blocks(text, block_size)
    cipher_blocks = []
    for block in blocks:
        M = block_to_int(block)
        C = pow(M, e, n)
        cipher_blocks.append(C)
    return cipher_blocks

# Dekripsi RSA
def decrypt(cipher_blocks, d, n, block_size):
    message_bytes = b''
    
    for C in cipher_blocks:
        M = pow(C, d, n)
        
        # hitung panjang blok secara dinamis berdasarkan ukuran n
        byte_len = (n.bit_length() + 7) // 8
    
        try:
            block = M.to_bytes(byte_len, byteorder='big')
            # konversi aman
            message_bytes += block.lstrip(b'\x00')
            # hilangkan null padding di depan
        except OverflowError:
            # kalau nilai terlalu besar, lewati blok ini
            continue
    
    try:
        return message_bytes.decode(errors='ignore')
    except UnicodeDecodeError:
        return message_bytes.decode('utf-8', errors='ignore')
    
    
    
    
    
def rc4_cipher(text, key, mode="Enkripsi"):  
    def rc4_init(key):
        S = list(range(256))
        j = 0
        key_length = len(key)
        for i in range(256):
            j = (j + S[i] + ord(key[i % key_length])) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def rc4_crypt(data, key):
        S = rc4_init(key)
        i = j = 0
        result = ""
        for char in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            rnd = S[(S[i] + S[j]) % 256]
            result += chr(ord(char) ^ rnd)
        return result
    
    def string_to_hex(s):
        return ''.join(format(ord(c), '02x') for c in s)
        
    def hex_to_string(hex_str):   
        result = ""
        for i in range(0, len(hex_str), 2):
            byte = hex_str[i:i+2]
            result += chr(int(byte, 16))
        return result

    if mode == "Enkripsi":
        encrypted = rc4_crypt(text, key)
        return string_to_hex(encrypted)
    elif mode == "Dekripsi":
        decrypted_input = hex_to_string(text)
        return rc4_crypt(decrypted_input, key)
    else:
        raise ValueError("Mode harus 'Enkripsi' atau 'Dekripsi'")





def super_encrypt(text, caesar_key, vigenere_key, rail_key, e, d, n, block_size):
    step1 = caesar_cipher(text, caesar_key, mode='Enkripsi')
    step2 = vigenere_cipher(step1, vigenere_key, mode='Enkripsi')
    step3 = encrypt_rail_fence(step2, rail_key)
    rsa_result = rsa_encrypt(step3, e, n, block_size)
    return {
        'cipher_blocks': rsa_result,
        'rsa_params': {
            'e': e,
            'd': d,
            'n': n,
            'block_size': block_size
        }
    }
    
def super_decrypt(cipher_blocks, rsa_params, caesar_key, vigenere_key, rail_key, e, d, n, block_size):
    d = rsa_params['d']
    n = rsa_params['n']
    block_size = rsa_params['block_size']
    
    rsa_result = rsa_decrypt(cipher_blocks, d, n, block_size)
    step2 = decrypt_rail_fence(rsa_result, rail_key)
    step3 = vigenere_cipher(step2, vigenere_key, mode='Dekripsi')
    final_plaintext = caesar_cipher(step3, caesar_key, mode='Dekripsi')
    
    return final_plaintext