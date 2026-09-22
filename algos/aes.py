"""
AES Simplified (Modern Block Cipher) - versi sederhana mod 26.
Teks dibagi menjadi blok-blok 4 karakter (padding 'X' bila kurang).
Setiap blok diproses dengan 3 langkah bergaya AES:
    1. AddRoundKey  : (blok + kunci) mod 26
    2. SubBytes     : (+3) mod 26  -- substitusi sederhana
    3. ShiftRows    : blok dianggap matriks 2x2, baris kedua digeser kiri 1

Dekripsi menjalankan proses kebalikannya dengan urutan terbalik:
    1. Inverse ShiftRows
    2. Inverse SubBytes  : (-3) mod 26
    3. Inverse AddRoundKey
"""

from algos.utils import clean_text, char_to_num, num_to_char

BLOCK_SIZE = 4
SUB_SHIFT = 3  # pergeseran SubBytes sederhana


def _prepare_key(key):
    """Menyiapkan kunci agar selalu berukuran tepat 4 karakter (A-Z)."""
    key = clean_text(key)
    if not key:
        key = 'KUNC'
    if len(key) < BLOCK_SIZE:
        key = (key * BLOCK_SIZE)[:BLOCK_SIZE]
    else:
        key = key[:BLOCK_SIZE]
    return key


def _chunk_text(text):
    """Membagi teks menjadi blok-blok berukuran BLOCK_SIZE, padding 'X' bila perlu."""
    blocks = []
    for i in range(0, len(text), BLOCK_SIZE):
        block = text[i:i + BLOCK_SIZE]
        if len(block) < BLOCK_SIZE:
            block = block + 'X' * (BLOCK_SIZE - len(block))
        blocks.append(block)
    return blocks


def aes_simple_cipher(text, key, mode='Enkripsi'):
    """
    Melakukan enkripsi/dekripsi AES Simplified per blok 4 karakter.

    Parameters:
        text (str): plaintext / ciphertext
        key (str): kunci (akan disesuaikan menjadi 4 karakter)
        mode (str): 'Enkripsi' atau 'Dekripsi'

    Returns:
        (result_text, steps_log)
    """
    text = clean_text(text)
    key = _prepare_key(key)
    key_nums = [char_to_num(k) for k in key]

    steps = []
    steps.append(f"Teks setelah dibersihkan: '{text}'")
    steps.append(f"Kunci (disesuaikan menjadi {BLOCK_SIZE} karakter): '{key}' -> {key_nums}")

    if len(text) == 0:
        steps.append("Teks kosong setelah dibersihkan, tidak ada yang diproses.")
        return "", steps

    blocks = _chunk_text(text)
    steps.append(f"Teks dibagi menjadi {len(blocks)} blok @ {BLOCK_SIZE} karakter "
                 f"(padding 'X' ditambahkan jika blok terakhir kurang): {blocks}")

    result_blocks = []

    for b_idx, block in enumerate(blocks):
        steps.append("")
        steps.append(f"--- BLOK {b_idx + 1}: '{block}' ---")
        nums = [char_to_num(c) for c in block]

        if mode == 'Enkripsi':
            # 1. AddRoundKey
            ark = [(nums[i] + key_nums[i]) % 26 for i in range(BLOCK_SIZE)]
            steps.append(f"  1) AddRoundKey : (blok + kunci) mod 26")
            steps.append(f"     {nums} + {key_nums} mod 26 = {ark} -> "
                         f"'{''.join(num_to_char(x) for x in ark)}'")

            # 2. SubBytes
            sb = [(x + SUB_SHIFT) % 26 for x in ark]
            steps.append(f"  2) SubBytes    : (+{SUB_SHIFT}) mod 26")
            steps.append(f"     {ark} -> {sb} -> '{''.join(num_to_char(x) for x in sb)}'")

            # 3. ShiftRows (matriks 2x2: baris0=[b0,b1], baris1=[b2,b3])
            row0 = [sb[0], sb[1]]
            row1 = [sb[2], sb[3]]
            row1_shifted = row1[1:] + row1[:1]
            final_nums = row0 + row1_shifted
            steps.append(f"  3) ShiftRows   : matriks 2x2 -> Baris0={row0} (tetap), "
                         f"Baris1={row1} digeser KIRI 1 -> {row1_shifted}")
            steps.append(f"     Hasil blok: {final_nums} -> "
                         f"'{''.join(num_to_char(x) for x in final_nums)}'")

        else:
            # 1. Inverse ShiftRows
            row0 = [nums[0], nums[1]]
            row1 = [nums[2], nums[3]]
            row1_unshifted = row1[-1:] + row1[:-1]
            unshift_nums = row0 + row1_unshifted
            steps.append(f"  1) Inverse ShiftRows : Baris0={row0} (tetap), "
                         f"Baris1={row1} digeser KANAN 1 -> {row1_unshifted}")
            steps.append(f"     Hasil: {unshift_nums} -> "
                         f"'{''.join(num_to_char(x) for x in unshift_nums)}'")

            # 2. Inverse SubBytes
            isb = [(x - SUB_SHIFT) % 26 for x in unshift_nums]
            steps.append(f"  2) Inverse SubBytes  : (-{SUB_SHIFT}) mod 26")
            steps.append(f"     {unshift_nums} -> {isb} -> "
                         f"'{''.join(num_to_char(x) for x in isb)}'")

            # 3. Inverse AddRoundKey
            iark = [(isb[i] - key_nums[i]) % 26 for i in range(BLOCK_SIZE)]
            steps.append(f"  3) Inverse AddRoundKey : (blok - kunci) mod 26")
            steps.append(f"     {isb} - {key_nums} mod 26 = {iark} -> "
                         f"'{''.join(num_to_char(x) for x in iark)}'")
            final_nums = iark

        block_result = ''.join(num_to_char(x) for x in final_nums)
        result_blocks.append(block_result)
        steps.append(f"  >> Hasil Blok {b_idx + 1}: '{block_result}'")

    result_text = ''.join(result_blocks)
    steps.append("")
    steps.append(f"Hasil akhir (gabungan semua blok): '{result_text}'")
    return result_text, steps
