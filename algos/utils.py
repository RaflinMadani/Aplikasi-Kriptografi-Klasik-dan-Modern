"""
Modul utilitas bersama untuk seluruh algoritma kriptografi.
Semua operasi HANYA berlaku untuk 26 huruf alfabet (A-Z), tanpa ASCII 256 / byte.
"""

import string

ALPHABET = string.ascii_uppercase  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def clean_text(text):
    """
    Membersihkan teks input:
    - Ubah ke huruf besar (uppercase)
    - Buang semua karakter selain A-Z (spasi, angka, tanda baca, dsb)
    """
    if text is None:
        return ""
    return ''.join(ch for ch in text.upper() if ch in ALPHABET)


def char_to_num(ch):
    """Konversi karakter A-Z menjadi angka 0-25."""
    return ord(ch) - ord('A')


def num_to_char(n):
    """Konversi angka (mod 26) menjadi karakter A-Z."""
    return chr((n % 26) + ord('A'))
