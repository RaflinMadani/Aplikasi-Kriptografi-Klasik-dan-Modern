"""
AES Simplified (Byte-Level, Hex) - versi lengkap 4 langkah.
Blok = 4 byte (32-bit). Key = 4 byte. 3 round.
"""

SBOX     = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

BLOCK_SIZE = 4
TOTAL_ROUNDS = 3

def gf_mult(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def sub_byte(b, inverse=False):
    box = INV_SBOX if inverse else SBOX
    return (box[(b >> 4) & 0x0F] << 4) | box[b & 0x0F]

def _pad(data):
    pad_len = 4 - (len(data) % 4)
    return data + bytes([pad_len] * pad_len)

def _unpad(data):
    if not data:
        return data
    pad_len = data[-1]
    return data[:-pad_len] if 1 <= pad_len <= 4 else data

def _prepare_key(key):
    key_bytes = key.encode('utf-8')
    return (key_bytes * 4)[:4] if len(key_bytes) < 4 else key_bytes[:4]

def aes_simple_cipher(text, key, mode='Enkripsi', on_block=None):
    """
    on_block (opsional): callback dipanggil SETELAH tiap blok selesai diproses,
    dengan argumen (b_idx, total_blocks, block_in_bytes, final_block_bytes, running_bytes).
    Ini satu-satunya tempat logika AES dieksekusi -- dipakai baik untuk animasi
    (via callback) maupun untuk hasil akhir, supaya keduanya TIDAK PERNAH beda.
    """
    key_bytes = list(_prepare_key(key))
    round_keys = [key_bytes]
    for r in range(1, TOTAL_ROUNDS + 1):
        round_keys.append([(x + 1) % 256 for x in round_keys[-1]])

    steps = [f"Kunci Byte R0: {[hex(x) for x in key_bytes]}"]
    for r, rk in enumerate(round_keys):
        steps.append(f"  -> RoundKey{r}: {[hex(x) for x in rk]}")

    if mode == 'Enkripsi':
        text_bytes = _pad(text.encode('utf-8'))
        steps.append(f"Plaintext di-pad (Byte): {[hex(x) for x in text_bytes]}")
    else:
        try:
            text_bytes = bytes.fromhex(text.replace(" ", ""))
            steps.append(f"Ciphertext (Byte): {[hex(x) for x in text_bytes]}")
        except ValueError:
            return "ERROR_HEX", ["Format Hexadesimal tidak valid!"]

    if len(text_bytes) == 0:
        return "", steps

    blocks = [list(text_bytes[i:i + BLOCK_SIZE]) for i in range(0, len(text_bytes), BLOCK_SIZE)]
    result_bytes = bytearray()
    total_blocks = len(blocks)

    for b_idx, block in enumerate(blocks):
        steps.append(f"\n--- BLOK {b_idx + 1}: {[hex(x) for x in block]} ---")
        nums = block[:]

        if mode == 'Enkripsi':
            nums = [nums[i] ^ round_keys[0][i] for i in range(BLOCK_SIZE)]
            steps.append(f"  0) Initial AddRoundKey (R0) XOR : {[hex(x) for x in nums]}")
            for r in range(1, TOTAL_ROUNDS + 1):
                steps.append(f"  [ ROUND {r} ]")
                sb = [sub_byte(x, False) for x in nums]
                steps.append(f"    1) SubBytes    : -> {[hex(x) for x in sb]}")
                row0, row1 = [sb[0], sb[1]], [sb[2], sb[3]]
                sr = row0 + (row1[1:] + row1[:1])
                steps.append(f"    2) ShiftRows   : -> {[hex(x) for x in sr]}")
                if r != TOTAL_ROUNDS:
                    mc = [0] * 4
                    mc[0] = gf_mult(2, sr[0]) ^ gf_mult(3, sr[2])
                    mc[2] = gf_mult(3, sr[0]) ^ gf_mult(2, sr[2])
                    mc[1] = gf_mult(2, sr[1]) ^ gf_mult(3, sr[3])
                    mc[3] = gf_mult(3, sr[1]) ^ gf_mult(2, sr[3])
                    steps.append(f"    3) MixColumns (GF, XOR) : -> {[hex(x) for x in mc]}")
                else:
                    mc = sr
                    steps.append(f"    3) MixColumns  : (dilewati di final round)")
                nums = [mc[i] ^ round_keys[r][i] for i in range(BLOCK_SIZE)]
                steps.append(f"    4) AddRoundKey (XOR R{r}) : -> {[hex(x) for x in nums]}")
            final_block = nums
        else:
            nums = [nums[i] ^ round_keys[TOTAL_ROUNDS][i] for i in range(BLOCK_SIZE)]
            steps.append(f"  0) Initial InvAddRoundKey (R{TOTAL_ROUNDS}) XOR : {[hex(x) for x in nums]}")
            for r in range(TOTAL_ROUNDS - 1, -1, -1):
                steps.append(f"  [ INVERSE ROUND, membalik round {r + 1} ]")
                row0, row1 = [nums[0], nums[1]], [nums[2], nums[3]]
                usr = row0 + (row1[-1:] + row1[:-1])
                steps.append(f"    1) InvShiftRows : -> {[hex(x) for x in usr]}")
                isb = [sub_byte(x, True) for x in usr]
                steps.append(f"    2) InvSubBytes  : -> {[hex(x) for x in isb]}")
                iark = [isb[i] ^ round_keys[r][i] for i in range(BLOCK_SIZE)]
                steps.append(f"    3) InvAddRoundKey (XOR R{r}) : -> {[hex(x) for x in iark]}")
                if r != 0:
                    imc = [0] * 4
                    imc[0] = gf_mult(2, iark[0]) ^ gf_mult(3, iark[2])
                    imc[2] = gf_mult(3, iark[0]) ^ gf_mult(2, iark[2])
                    imc[1] = gf_mult(2, iark[1]) ^ gf_mult(3, iark[3])
                    imc[3] = gf_mult(3, iark[1]) ^ gf_mult(2, iark[3])
                    nums = imc
                    steps.append(f"    4) InvMixColumns (GF, XOR) : -> {[hex(x) for x in nums]}")
                else:
                    nums = iark
                    steps.append(f"    4) InvMixColumns : (dilewati)")
            final_block = nums

        result_bytes.extend(final_block)
        steps.append(f"  >> Hasil Blok {b_idx + 1}: {[hex(x) for x in final_block]}")

        if on_block is not None:
            on_block(b_idx, total_blocks, block, final_block, bytes(result_bytes))

    if mode == 'Enkripsi':
        result_text = result_bytes.hex().upper()
        steps.append(f"\nHasil Enkripsi (Hex): '{result_text}'")
    else:
        unpadded = _unpad(result_bytes)
        try:
            result_text = unpadded.decode('utf-8')
            steps.append(f"\nHasil Dekripsi (String): '{result_text}'")
        except UnicodeDecodeError:
            result_text = unpadded.hex().upper()
            steps.append(f"\n[Peringatan] Gagal decode string. Raw Hex: {result_text}")

    return result_text, steps