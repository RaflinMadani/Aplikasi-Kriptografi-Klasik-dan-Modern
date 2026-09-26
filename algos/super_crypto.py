"""
Super Enkripsi - Gabungan 4 algoritma secara berantai.
"""
from algos.caesar import caesar_cipher
from algos.scytale import scytale_encrypt, scytale_decrypt
from algos.rc4 import rc4_cipher
from algos.aes import aes_simple_cipher

def super_encrypt(text, caesar_key, scytale_cols, rc4_key, aes_key):
    steps = ["=" * 70, "SUPER ENKRIPSI: CAESAR -> SCYTALE -> RC4 -> AES SIMPLIFIED", "=" * 70, ""]
    
    c1, s1 = caesar_cipher(text, caesar_key, mode='Enkripsi')
    steps.extend(s1); steps.append(f"### Output Caesar = '{c1}' ###\n")
    
    c2, s2 = scytale_encrypt(c1, scytale_cols)
    steps.extend(s2); steps.append(f"### Output Scytale = '{c2}' ###\n")
    
    c3, s3 = rc4_cipher(c2, rc4_key, mode='Enkripsi')
    steps.extend(s3); steps.append(f"### Output RC4 (Hex) = '{c3}' ###\n")
    
    c4, s4 = aes_simple_cipher(c3, aes_key, mode='Enkripsi')
    steps.extend(s4); steps.append(f"### Output AES (Hex) = '{c4}' ###\n")
    
    steps.extend(["=" * 70, f"HASIL AKHIR SUPER ENKRIPSI : '{c4}'", "=" * 70])
    return c4, steps

def super_decrypt(cipher, caesar_key, scytale_cols, rc4_key, aes_key):
    steps = ["=" * 70, "SUPER DEKRIPSI: AES SIMPLIFIED -> RC4 -> SCYTALE -> CAESAR", "=" * 70, ""]
    
    d1, s1 = aes_simple_cipher(cipher, aes_key, mode='Dekripsi')
    steps.extend(s1); steps.append(f"### Output AES = '{d1}' ###\n")
    
    d2, s2 = rc4_cipher(d1, rc4_key, mode='Dekripsi')
    steps.extend(s2); steps.append(f"### Output RC4 = '{d2}' ###\n")
    
    d3, s3 = scytale_decrypt(d2, scytale_cols)
    steps.extend(s3); steps.append(f"### Output Scytale = '{d3}' ###\n")
    
    # --- PEMBERSIHAN PADDING SCYTALE SEBELUM MASUK CAESAR ---
    d3_bersih = d3.rstrip('X')
    if d3 != d3_bersih:
        steps.append(f"### Membuang padding 'X' dari Scytale -> '{d3_bersih}' ###\n")
    
    d4, s4 = caesar_cipher(d3_bersih, caesar_key, mode='Dekripsi')
    steps.extend(s4); steps.append(f"### Output Caesar = '{d4}' ###\n")
    
    steps.extend(["=" * 70, f"HASIL AKHIR SUPER DEKRIPSI : '{d4}'", "=" * 70])
    return d4, steps
