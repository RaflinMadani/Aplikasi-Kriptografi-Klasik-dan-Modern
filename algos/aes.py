"""
AES Simplified (Byte-Level, Hex) - versi lengkap 4 langkah.
Blok = 4 byte (32-bit). Key = 4 byte. 3 round.
Setiap round:
    1. SubBytes    : substitusi nibble pakai S-Box 4-bit
    2. ShiftRows   : blok dianggap matriks 2x2, baris kedua ditukar posisi
    3. MixColumns  : kolom dikalikan matriks [[2,3],[3,2]] mod 256 (dilewati di round terakhir)
    4. AddRoundKey : XOR dengan round key (dilakukan juga sebagai langkah ke-0/initial)

Dekripsi menjalankan proses kebalikannya dengan urutan terbalik.
"""

SBOX     = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

BLOCK_SIZE = 4
TOTAL_ROUNDS = 3
MOD = 256

def gf_mult(a, b):
    """Perkalian di GF(2^8), persis seperti AES asli (poly reduksi 0x11B).
    Ini XOR-based, BUKAN perkalian integer biasa."""
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

# Matriks MixColumns [[2,3],[3,2]] di GF(2^8): determinannya = 1,
# jadi matriks ini adalah inverse dari dirinya sendiri (MixColumns == InvMixColumns).

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

def aes_simple_cipher(text, key, mode='Enkripsi'):
    key_bytes = list(_prepare_key(key))

    round_keys = [key_bytes]
    for r in range(1, TOTAL_ROUNDS + 1):
        round_keys.append([(x + 1) % MOD for x in round_keys[-1]])

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

                row0 = [sb[0], sb[1]]
                row1 = [sb[2], sb[3]]
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

        else:  # Dekripsi
            nums = [nums[i] ^ round_keys[TOTAL_ROUNDS][i] for i in range(BLOCK_SIZE)]
            steps.append(f"  0) Initial InvAddRoundKey (R{TOTAL_ROUNDS}) XOR : {[hex(x) for x in nums]}")

            for r in range(TOTAL_ROUNDS - 1, -1, -1):
                steps.append(f"  [ INVERSE ROUND, membalik round {r + 1} ]")

                row0 = [nums[0], nums[1]]
                row1 = [nums[2], nums[3]]
                usr = row0 + (row1[-1:] + row1[:-1])
                steps.append(f"    1) InvShiftRows : -> {[hex(x) for x in usr]}")

                isb = [sub_byte(x, True) for x in usr]
                steps.append(f"    2) InvSubBytes  : -> {[hex(x) for x in isb]}")

                iark = [isb[i] ^ round_keys[r][i] for i in range(BLOCK_SIZE)]
                steps.append(f"    3) InvAddRoundKey (XOR R{r}) : -> {[hex(x) for x in iark]}")

                if r != 0:
                    # matriks [[2,3],[3,2]] self-inverse di GF(2^8), jadi rumusnya sama dengan MixColumns
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


if __name__ == "__main__":
    tests = ["TEST", "Hello World!", "A", "Serangan Fajar 1234", "Teks yang agak lebih panjang dikit ya kan"]
    key = "KUNCI"
    all_ok = True
    for t in tests:
        enc, _ = aes_simple_cipher(t, key, 'Enkripsi')
        dec, _ = aes_simple_cipher(enc, key, 'Dekripsi')
        ok = (dec == t)
        all_ok &= ok
        print(f"plain={t!r:45} enc={enc!r:45} dec={dec!r:45} match={ok}")
    print("\nSemua round-trip cocok?", all_ok)

    # sanity: cek juga byte yang tadi bikin S-Box lama gagal (nibble 13/14)
    from itertools import product
    fails = 0
    for b in range(256):
        e = sub_byte(b, False)
        d = sub_byte(e, True)
        if d != b:
            fails += 1
    print("S-Box round-trip gagal untuk (dari 256 byte):", fails)