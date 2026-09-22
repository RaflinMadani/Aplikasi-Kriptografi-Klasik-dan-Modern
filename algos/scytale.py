"""
Scytale Cipher - Algoritma Klasik Transposisi Baris/Kolom
Teks ditulis ke dalam matriks (baris x kolom), lalu dibaca dengan urutan
berbeda untuk menghasilkan cipherteks (mirip melilitkan pita pada tongkat/rod).
"""

import math
from algos.utils import clean_text


def scytale_encrypt(text, cols):
    """
    Enkripsi Scytale: isi matriks baris demi baris, baca hasil kolom demi kolom.

    Parameters:
        text (str): plaintext
        cols (int): jumlah kolom (diameter tongkat) -> ini adalah "kunci"

    Returns:
        (result_text, steps_log)
    """
    text = clean_text(text)
    try:
        cols = int(cols)
    except (ValueError, TypeError):
        cols = 1
    if cols < 1:
        cols = 1

    steps = []
    steps.append(f"Teks setelah dibersihkan: '{text}' (panjang = {len(text)} karakter)")
    steps.append(f"Kunci jumlah kolom: {cols}")

    if len(text) == 0:
        steps.append("Teks kosong setelah dibersihkan, tidak ada yang diproses.")
        return "", steps

    rows = math.ceil(len(text) / cols)
    pad_len = rows * cols - len(text)
    padded = text + 'X' * pad_len

    steps.append(f"Jumlah baris yang dibutuhkan = ceil(panjang_teks / kolom) = "
                  f"ceil({len(text)}/{cols}) = {rows}")
    if pad_len > 0:
        steps.append(f"Ukuran matriks ({rows}x{cols}) membutuhkan {rows * cols} karakter, "
                      f"teks kurang {pad_len} karakter -> ditambahkan padding 'X'")
        steps.append(f"Teks setelah padding: '{padded}'")
    else:
        steps.append("Teks pas mengisi matriks tanpa perlu padding.")

    # Bangun matriks: isi baris demi baris
    matrix = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows)]

    steps.append("--- Proses Pengisian Matriks (baris demi baris) ---")
    for r_idx, row in enumerate(matrix):
        steps.append(f"  Isi Baris {r_idx + 1}: {' '.join(row)}")

    steps.append("--- Visualisasi Matriks Akhir ---")
    header = "     " + "  ".join(f"K{c + 1}" for c in range(cols))
    steps.append(header)
    for r_idx, row in enumerate(matrix):
        steps.append(f"  B{r_idx + 1}: " + "   ".join(row))

    # Baca kolom demi kolom
    steps.append("--- Proses Pembacaan Hasil (kolom demi kolom) ---")
    result = []
    for c in range(cols):
        col_chars = [matrix[r][c] for r in range(rows)]
        result.extend(col_chars)
        steps.append(f"  Baca Kolom {c + 1} (atas ke bawah): {''.join(col_chars)}")

    result_text = ''.join(result)
    steps.append(f"Hasil akhir (ciphertext): '{result_text}'")
    return result_text, steps


def scytale_decrypt(cipher, cols):
    """
    Dekripsi Scytale: isi matriks kolom demi kolom (sesuai cara pembacaan saat
    enkripsi), lalu baca hasil baris demi baris untuk mendapatkan plaintext.

    Parameters:
        cipher (str): ciphertext
        cols (int): jumlah kolom (kunci yang sama dengan saat enkripsi)

    Returns:
        (result_text, steps_log)
    """
    cipher = clean_text(cipher)
    try:
        cols = int(cols)
    except (ValueError, TypeError):
        cols = 1
    if cols < 1:
        cols = 1

    steps = []
    steps.append(f"Cipherteks setelah dibersihkan: '{cipher}' (panjang = {len(cipher)} karakter)")
    steps.append(f"Kunci jumlah kolom: {cols}")

    if len(cipher) == 0:
        steps.append("Cipherteks kosong setelah dibersihkan, tidak ada yang diproses.")
        return "", steps

    rows = math.ceil(len(cipher) / cols)
    if len(cipher) % cols != 0:
        steps.append("Peringatan: panjang cipherteks tidak habis dibagi jumlah kolom. "
                      "Hasil dekripsi mungkin tidak sempurna (periksa kembali kunci).")

    steps.append(f"Jumlah baris hasil perhitungan = ceil({len(cipher)}/{cols}) = {rows}")

    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    steps.append("--- Proses Pengisian Matriks (kolom demi kolom, kebalikan dari enkripsi) ---")
    for c in range(cols):
        col_chars = []
        for r in range(rows):
            if idx < len(cipher):
                matrix[r][c] = cipher[idx]
                col_chars.append(cipher[idx])
                idx += 1
        steps.append(f"  Isi Kolom {c + 1}: {''.join(col_chars)}")

    steps.append("--- Visualisasi Matriks Akhir ---")
    header = "     " + "  ".join(f"K{c + 1}" for c in range(cols))
    steps.append(header)
    for r_idx, row in enumerate(matrix):
        steps.append(f"  B{r_idx + 1}: " + "   ".join(x if x else '_' for x in row))

    steps.append("--- Proses Pembacaan Hasil (baris demi baris) ---")
    result = []
    for r_idx, row in enumerate(matrix):
        result.extend(row)
        steps.append(f"  Baca Baris {r_idx + 1}: {''.join(row)}")

    result_text = ''.join(result)
    steps.append(f"Hasil akhir (plaintext, mungkin mengandung padding 'X' di akhir): '{result_text}'")
    return result_text, steps
