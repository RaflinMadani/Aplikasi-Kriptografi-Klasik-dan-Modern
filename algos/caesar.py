"""
Caesar Cipher - Algoritma Klasik Substitusi Monoalfabetik
Beroperasi murni pada 26 huruf alfabet (mod 26).
"""

from algos.utils import clean_text, char_to_num, num_to_char


def caesar_cipher(text, key, mode='Enkripsi'):
    """
    Melakukan enkripsi/dekripsi Caesar Cipher.

    Parameters:
        text (str): teks input (plaintext / ciphertext)
        key (int): jumlah pergeseran (0-25)
        mode (str): 'Enkripsi' atau 'Dekripsi'

    Returns:
        (result_text, steps_log) -> tuple(str, list[str])
    """
    text = clean_text(text)
    try:
        key = int(key) % 26
    except (ValueError, TypeError):
        key = 0

    steps = []
    steps.append(f"Teks setelah dibersihkan (hanya A-Z): '{text}'")
    steps.append(f"Kunci pergeseran (key): {key}")

    if mode == 'Enkripsi':
        steps.append(f"Mode: ENKRIPSI -> setiap huruf digeser MAJU sebanyak {key} posisi "
                      f"menggunakan rumus: C = (P + key) mod 26")
    else:
        steps.append(f"Mode: DEKRIPSI -> setiap huruf digeser MUNDUR sebanyak {key} posisi "
                      f"menggunakan rumus: P = (C - key) mod 26")

    if len(text) == 0:
        steps.append("Teks kosong setelah dibersihkan, tidak ada yang diproses.")
        return "", steps

    result = []
    op_symbol = "+" if mode == 'Enkripsi' else "-"

    for idx, ch in enumerate(text):
        p = char_to_num(ch)
        if mode == 'Enkripsi':
            c = (p + key) % 26
        else:
            c = (p - key) % 26
        new_ch = num_to_char(c)
        result.append(new_ch)
        steps.append(
            f"  [{idx + 1:02d}] '{ch}' (nilai={p:02d})  ->  ({p} {op_symbol} {key}) mod 26 "
            f"= {c:02d}  ->  '{new_ch}'"
        )

    result_text = ''.join(result)
    steps.append(f"Hasil akhir: '{result_text}'")
    return result_text, steps
