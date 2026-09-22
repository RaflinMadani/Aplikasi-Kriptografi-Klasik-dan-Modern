"""
RC4 Cipher (Modern Stream Cipher) - versi termodifikasi mod 26.
Menggunakan S-Box berukuran 26 (bukan 256) agar tetap beroperasi murni
pada alfabet A-Z. Terdiri dari 2 tahap:
    1. KSA  (Key Scheduling Algorithm)  -> mengacak S-Box berdasarkan kunci
    2. PRGA (Pseudo-Random Generation Algorithm) -> menghasilkan keystream
       yang dijumlahkan/dikurangkan (mod 26) dengan teks.
"""

from algos.utils import clean_text, char_to_num, num_to_char


def rc4_mod26(text, key, mode='Enkripsi'):
    """
    Melakukan enkripsi/dekripsi RC4 termodifikasi (basis 26 alfabet).

    Parameters:
        text (str): plaintext / ciphertext
        key (str): kunci berupa huruf-huruf A-Z
        mode (str): 'Enkripsi' atau 'Dekripsi'

    Returns:
        (result_text, steps_log)
    """
    text = clean_text(text)
    key = clean_text(key)
    steps = []

    if not key:
        key = 'KEY'
        steps.append("Kunci kosong, menggunakan kunci default 'KEY'.")

    key_nums = [char_to_num(k) for k in key]
    steps.append(f"Teks input dibersihkan: '{text}'")
    steps.append(f"Kunci dibersihkan: '{key}' -> nilai numerik (A=0..Z=25): {key_nums}")

    if len(text) == 0:
        steps.append("Teks kosong setelah dibersihkan, tidak ada yang diproses.")
        return "", steps

    # ===================== TAHAP 1: KSA =====================
    S = list(range(26))
    steps.append("")
    steps.append("=========== TAHAP 1: KSA (Key Scheduling Algorithm) ===========")
    steps.append(f"Inisialisasi S-Box awal (0..25): {S}")

    j = 0
    for i in range(26):
        j = (j + S[i] + key_nums[i % len(key_nums)]) % 26
        S[i], S[j] = S[j], S[i]
        steps.append(
            f"  i={i:2d} : j = (j + S[i] + key[i mod {len(key_nums)}]) mod 26 = {j:2d}  "
            f"-> tukar S[{i}] <-> S[{j}]"
        )
    steps.append(f"S-Box FINAL setelah KSA: {S}")

    # ===================== TAHAP 2: PRGA =====================
    steps.append("")
    steps.append("=========== TAHAP 2: PRGA (Pseudo-Random Generation Algorithm) ===========")
    steps.append("Keystream dibangkitkan per karakter, lalu dikombinasikan dengan teks "
                  f"menggunakan {'penjumlahan' if mode == 'Enkripsi' else 'pengurangan'} mod 26.")

    i = j = 0
    result = []
    op_symbol = "+" if mode == 'Enkripsi' else "-"

    for idx, ch in enumerate(text):
        i = (i + 1) % 26
        j = (j + S[i]) % 26
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 26
        ks = S[t]

        p = char_to_num(ch)
        if mode == 'Enkripsi':
            c = (p + ks) % 26
        else:
            c = (p - ks) % 26
        new_ch = num_to_char(c)
        result.append(new_ch)

        steps.append(
            f"  [{idx + 1:02d}] '{ch}' | i={i:2d}, j={j:2d}, tukar S[{i}]<->S[{j}], "
            f"t=(S[i]+S[j])mod26={t:2d}, keystream=S[t]={ks:2d} || "
            f"({p} {op_symbol} {ks}) mod 26 = {c:02d} -> '{new_ch}'"
        )

    result_text = ''.join(result)
    steps.append(f"Hasil akhir: '{result_text}'")
    return result_text, steps
