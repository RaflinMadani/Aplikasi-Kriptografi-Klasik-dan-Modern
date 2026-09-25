"""
AES Simplified (Byte-Level)
"""
SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xE, 0xD]

def sub_byte(b, inverse=False):
    box = INV_SBOX if inverse else SBOX
    return (box[(b >> 4) & 0x0F] << 4) | box[b & 0x0F]

def _pad(data):
    pad_len = 4 - (len(data) % 4)
    return data + bytes([pad_len] * pad_len)

def _unpad(data):
    if not data: return data
    pad_len = data[-1]
    return data[:-pad_len] if 1 <= pad_len <= 4 else data

def aes_simple_cipher(text, key, mode='Enkripsi'):
    key_bytes = key.encode('utf-8')
    key_bytes = (key_bytes * 4)[:4] if len(key_bytes) < 4 else key_bytes[:4]
    
    steps = [f"Kunci Byte: {[hex(x) for x in key_bytes]}"]

    if mode == 'Enkripsi':
        text_bytes = _pad(text.encode('utf-8'))
        steps.append(f"Plaintext di-pad (Byte): {[hex(x) for x in text_bytes]}")
    else:
        try:
            text_bytes = bytes.fromhex(text.replace(" ", ""))
            steps.append(f"Ciphertext (Byte): {[hex(x) for x in text_bytes]}")
        except ValueError:
            return "ERROR_HEX", ["Format Hexadesimal tidak valid!"]

    if len(text_bytes) == 0: return "", steps

    blocks = [list(text_bytes[i:i+4]) for i in range(0, len(text_bytes), 4)]
    result_bytes = bytearray()

    for b_idx, block in enumerate(blocks):
        if mode == 'Enkripsi':
            ark = [block[i] ^ key_bytes[i] for i in range(4)]
            sb = [sub_byte(x, False) for x in ark]
            final_block = [sb[0], sb[1], sb[3], sb[2]]
        else:
            isr = [block[0], block[1], block[3], block[2]]
            isb = [sub_byte(x, True) for x in isr]
            final_block = [isb[i] ^ key_bytes[i] for i in range(4)]

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
