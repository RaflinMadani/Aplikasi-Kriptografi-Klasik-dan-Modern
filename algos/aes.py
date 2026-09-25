"""
RC4 Cipher (Standard 256-byte)
"""
def rc4_cipher(text, key, mode='Enkripsi'):
    steps = []
    if not key:
        key = 'KEY'
    key_bytes = key.encode('utf-8')

    if mode == 'Enkripsi':
        text_bytes = text.encode('utf-8')
        steps.append(f"Plaintext dikonversi ke bytes: {list(text_bytes)}")
    else:
        try:
            text_bytes = bytes.fromhex(text.replace(" ", ""))
            steps.append(f"Ciphertext Hex dikonversi ke bytes: {list(text_bytes)}")
        except ValueError:
            steps.append("Error: Input dekripsi RC4 harus berupa format Hexadesimal yang valid.")
            return "ERROR_HEX", steps

    if len(text_bytes) == 0:
        return "", steps

    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result_bytes = bytearray()
    for idx, byte in enumerate(text_bytes):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        ks = S[(S[i] + S[j]) % 256]
        c = byte ^ ks
        result_bytes.append(c)
        if idx < 50:
            steps.append(f"  [{idx:02d}] Teks: {byte:02X} | Keystream: {ks:02X} | {byte:02X} ⊕ {ks:02X} = {c:02X}")
            
    if mode == 'Enkripsi':
        result_text = result_bytes.hex().upper()
        steps.append(f"\nHasil Enkripsi (Hexadesimal): '{result_text}'")
    else:
        try:
            result_text = result_bytes.decode('utf-8')
            steps.append(f"\nHasil Dekripsi (String): '{result_text}'")
        except UnicodeDecodeError:
            result_text = result_bytes.hex().upper()
            steps.append(f"\n[Peringatan] Gagal decode ke teks. Raw Hex: {result_text}")

    return result_text, steps
