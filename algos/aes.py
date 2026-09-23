"""
AES Simplified (Modern Block Cipher) - versi sederhana mod 26.
Teks dibagi menjadi blok-blok 4 karakter (padding 'X' bila kurang).
Setiap blok diproses dengan langkah bergaya AES (berjalan dalam 3 iterasi/rounds):
    1. AddRoundKey  : (blok + kunci) mod 26
    2. SubBytes     : (+3) mod 26  -- substitusi sederhana
    3. ShiftRows    : blok dianggap matriks 2x2, baris kedua digeser kiri 1
    4. MixColumns   : Pengacakan kolom matriks linear (dilewati di round terakhir)

Dekripsi menjalankan proses kebalikannya dengan urutan terbalik.
"""

from algos.utils import clean_text, char_to_num, num_to_char

BLOCK_SIZE = 4
SUB_SHIFT = 3  # pergeseran SubBytes sederhana
TOTAL_ROUNDS = 3  # <-- Tambahan: Jumlah iterasi agar memenuhi standar block cipher


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

    # --- Tambahan: Key Expansion ---
    # Membangkitkan kunci berbeda untuk tiap round (R0 sampai R3) dengan geser +1
    round_keys = [key_nums]
    for r in range(1, TOTAL_ROUNDS + 1):
        round_keys.append([(x + 1) % 26 for x in round_keys[-1]])

    steps = []
    steps.append(f"Teks setelah dibersihkan: '{text}'")
    steps.append(f"Kunci Base (disesuaikan menjadi {BLOCK_SIZE} karakter): '{key}' -> {key_nums}")

    steps.append("Key Expansion (Kunci Turunan Per Round):")
    for r, rk in enumerate(round_keys):
        steps.append(f"  -> R{r}: {rk} ('{''.join(num_to_char(x) for x in rk)}')")

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
            # --- 0. Initial AddRoundKey ---
            nums = [(nums[i] + round_keys[0][i]) % 26 for i in range(BLOCK_SIZE)]
            steps.append(f"  0) Initial AddRoundKey (R0) : {nums}")

            # --- Tambahan: Loop Iterasi Round ---
            for r in range(1, TOTAL_ROUNDS + 1):
                steps.append(f"  [ ROUND {r} ]")

                # 1. SubBytes
                sb = [(x + SUB_SHIFT) % 26 for x in nums]
                steps.append(f"    1) SubBytes    : (+{SUB_SHIFT}) -> {sb}")

                # 2. ShiftRows (matriks 2x2: baris0=[b0,b1], baris1=[b2,b3])
                row0 = [sb[0], sb[1]]
                row1 = [sb[2], sb[3]]
                row1_shifted = row1[1:] + row1[:1]
                sr = row0 + row1_shifted
                steps.append(f"    2) ShiftRows   : Baris1 geser KIRI 1 -> {sr}")

                # 3. MixColumns (Lewati di Final Round)
                if r != TOTAL_ROUNDS:
                    mc = [0] * 4
                    mc[0] = (2 * sr[0] + 3 * sr[2]) % 26
                    mc[2] = (3 * sr[0] + 2 * sr[2]) % 26
                    mc[1] = (2 * sr[1] + 3 * sr[3]) % 26
                    mc[3] = (3 * sr[1] + 2 * sr[3]) % 26
                    steps.append(f"    3) MixColumns  : -> {mc}")
                else:
                    mc = sr
                    steps.append(f"    3) MixColumns  : (Dilewati di Final Round)")

                # 4. AddRoundKey
                nums = [(mc[i] + round_keys[r][i]) % 26 for i in range(BLOCK_SIZE)]
                steps.append(f"    4) AddRoundKey : + Kunci R{r} -> {nums}")

            final_nums = nums

        else:
            # --- 0. Initial InvAddRoundKey (R_Final) ---
            nums = [(nums[i] - round_keys[TOTAL_ROUNDS][i]) % 26 for i in range(BLOCK_SIZE)]
            steps.append(f"  0) Initial InvAddRoundKey (R{TOTAL_ROUNDS}) : {nums}")

            # --- Tambahan: Loop Dekripsi Mundur ---
            for r in range(TOTAL_ROUNDS - 1, -1, -1):
                steps.append(f"  [ INVERSE ROUND {TOTAL_ROUNDS - r} ] (Menuju R{r})")

                # 1. Inverse ShiftRows
                row0 = [nums[0], nums[1]]
                row1 = [nums[2], nums[3]]
                row1_unshifted = row1[-1:] + row1[:-1]
                usr = row0 + row1_unshifted
                steps.append(f"    1) InvShiftRows : Baris1 geser KANAN 1 -> {usr}")

                # 2. Inverse SubBytes
                isb = [(x - SUB_SHIFT) % 26 for x in usr]
                steps.append(f"    2) InvSubBytes  : (-{SUB_SHIFT}) -> {isb}")

                # 3. Inverse AddRoundKey
                iark = [(isb[i] - round_keys[r][i]) % 26 for i in range(BLOCK_SIZE)]
                steps.append(f"    3) InvAddRoundKey (R{r}) : -> {iark}")

                # 4. Inverse MixColumns (Dilewati di round paling akhir dekripsi / R0)
                if r != 0:
                    imc = [0] * 4
                    imc[0] = (10 * iark[0] + 11 * iark[2]) % 26
                    imc[2] = (11 * iark[0] + 10 * iark[2]) % 26
                    imc[1] = (10 * iark[1] + 11 * iark[3]) % 26
                    imc[3] = (11 * iark[1] + 10 * iark[3]) % 26
                    nums = imc
                    steps.append(f"    4) InvMixColumns : -> {nums}")
                else:
                    nums = iark
                    steps.append(f"    4) InvMixColumns : (Dilewati)")

            final_nums = nums

        block_result = ''.join(num_to_char(x) for x in final_nums)
        result_blocks.append(block_result)
        steps.append(f"  >> Hasil Blok {b_idx + 1}: '{block_result}'")

    result_text = ''.join(result_blocks)
    steps.append("")
    steps.append(f"Hasil akhir (gabungan semua blok): '{result_text}'")
    return result_text, steps