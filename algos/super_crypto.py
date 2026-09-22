"""
Super Enkripsi - Gabungan 4 algoritma secara berantai (chained).

Alur ENKRIPSI : Caesar -> Scytale -> RC4 -> AES Simplified
Alur DEKRIPSI : AES Simplified -> RC4 -> Scytale -> Caesar (urutan kebalikan)

Catatan: karena Scytale dan AES Simplified menambahkan karakter padding 'X'
saat proses berjalan, hasil dekripsi akhir bisa jadi mengandung beberapa
karakter 'X' tambahan di bagian akhir teks. Ini adalah perilaku normal untuk
skema cipher blok/transposisi sederhana semacam ini.
"""

from algos.caesar import caesar_cipher
from algos.scytale import scytale_encrypt, scytale_decrypt
from algos.rc4 import rc4_mod26
from algos.aes import aes_simple_cipher


def super_encrypt(text, caesar_key, scytale_cols, rc4_key, aes_key):
    """
    Enkripsi berantai: Caesar -> Scytale -> RC4 -> AES Simplified.

    Returns:
        (result_text, steps_log)
    """
    steps = []
    steps.append("=" * 70)
    steps.append("SUPER ENKRIPSI: CAESAR -> SCYTALE -> RC4 -> AES SIMPLIFIED")
    steps.append("=" * 70)

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 1 / 4 : CAESAR CIPHER <<<<<<<<<<")
    c1, s1 = caesar_cipher(text, caesar_key, mode='Enkripsi')
    steps.extend(s1)
    steps.append(f"### Output Tahap 1 (Caesar) = '{c1}' ###")

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 2 / 4 : SCYTALE CIPHER <<<<<<<<<<")
    c2, s2 = scytale_encrypt(c1, scytale_cols)
    steps.extend(s2)
    steps.append(f"### Output Tahap 2 (Scytale) = '{c2}' ###")

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 3 / 4 : RC4 CIPHER <<<<<<<<<<")
    c3, s3 = rc4_mod26(c2, rc4_key, mode='Enkripsi')
    steps.extend(s3)
    steps.append(f"### Output Tahap 3 (RC4) = '{c3}' ###")

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 4 / 4 : AES SIMPLIFIED <<<<<<<<<<")
    c4, s4 = aes_simple_cipher(c3, aes_key, mode='Enkripsi')
    steps.extend(s4)
    steps.append(f"### Output Tahap 4 (AES) = '{c4}' ###")

    steps.append("")
    steps.append("=" * 70)
    steps.append(f"HASIL AKHIR SUPER ENKRIPSI (CIPHERTEXT) : '{c4}'")
    steps.append("=" * 70)

    return c4, steps


def super_decrypt(cipher, caesar_key, scytale_cols, rc4_key, aes_key):
    """
    Dekripsi berantai (urutan kebalikan): AES -> RC4 -> Scytale -> Caesar.

    Returns:
        (result_text, steps_log)
    """
    steps = []
    steps.append("=" * 70)
    steps.append("SUPER DEKRIPSI: AES SIMPLIFIED -> RC4 -> SCYTALE -> CAESAR")
    steps.append("=" * 70)

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 1 / 4 : AES SIMPLIFIED (Dekripsi) <<<<<<<<<<")
    d1, s1 = aes_simple_cipher(cipher, aes_key, mode='Dekripsi')
    steps.extend(s1)
    steps.append(f"### Output Tahap 1 (AES) = '{d1}' ###")

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 2 / 4 : RC4 CIPHER (Dekripsi) <<<<<<<<<<")
    d2, s2 = rc4_mod26(d1, rc4_key, mode='Dekripsi')
    steps.extend(s2)
    steps.append(f"### Output Tahap 2 (RC4) = '{d2}' ###")

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 3 / 4 : SCYTALE CIPHER (Dekripsi) <<<<<<<<<<")
    d3, s3 = scytale_decrypt(d2, scytale_cols)
    steps.extend(s3)
    steps.append(f"### Output Tahap 3 (Scytale) = '{d3}' ###")

    steps.append("")
    steps.append(">>>>>>>>>> TAHAP 4 / 4 : CAESAR CIPHER (Dekripsi) <<<<<<<<<<")
    d4, s4 = caesar_cipher(d3, caesar_key, mode='Dekripsi')
    steps.extend(s4)
    steps.append(f"### Output Tahap 4 (Caesar) = '{d4}' ###")

    steps.append("")
    steps.append("=" * 70)
    steps.append(f"HASIL AKHIR SUPER DEKRIPSI (PLAINTEXT) : '{d4}'")
    steps.append("=" * 70)

    return d4, steps
