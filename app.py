"""
==============================================================================
 APLIKASI KRIPTOGRAFI - ENKRIPSI & DEKRIPSI TEKS (ALFABET A-Z)
 Tugas Kuliah Kriptografi
==============================================================================
Menu:
    1. Caesar Cipher      (Klasik - Substitusi Monoalfabetik)
    2. Scytale Cipher     (Klasik - Transposisi Baris/Kolom)
    3. RC4 Cipher         (Modern Stream Cipher, basis mod 26)
    4. AES Simplified     (Modern Block Cipher, basis mod 26)
    5. Super Enkripsi     (Gabungan Caesar -> Scytale -> RC4 -> AES)

Jalankan dengan:
    streamlit run app.py
==============================================================================
"""

import streamlit as st

from algos.caesar import caesar_cipher
from algos.scytale import scytale_encrypt, scytale_decrypt
from algos.rc4 import rc4_mod26
from algos.aes import aes_simple_cipher
from algos.super_crypto import super_encrypt, super_decrypt


# ------------------------------------------------------------------------
# KONFIGURASI HALAMAN
# ------------------------------------------------------------------------
st.set_page_config(
    page_title="Aplikasi Kriptografi A-Z",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Aplikasi Enkripsi & Dekripsi Teks")
st.caption("Tugas Kuliah Kriptografi — Seluruh operasi murni pada 26 huruf alfabet (A-Z)")


# ------------------------------------------------------------------------
# SIDEBAR: NAVIGASI
# ------------------------------------------------------------------------
st.sidebar.header("⚙️ Panel Kontrol")

menu = st.sidebar.selectbox(
    "Pilih Menu Algoritma",
    (
        "1. Caesar Cipher",
        "2. Scytale Cipher",
        "3. RC4 Cipher (mod 26)",
        "4. AES Simplified (mod 26)",
        "5. Super Enkripsi (Gabungan 4 Algoritma)",
    ),
)

mode = st.sidebar.radio("Pilih Mode", ("Enkripsi", "Dekripsi"), horizontal=True)

st.sidebar.markdown("---")
st.sidebar.info(
    "ℹ️ Semua teks otomatis dibersihkan: diubah ke huruf besar dan karakter "
    "selain A-Z (spasi, angka, tanda baca) akan dibuang."
)


def show_steps(steps_log):
    """Menampilkan log langkah-langkah di dalam expander."""
    with st.expander("🔍 Lihat Log Visualisasi Langkah-Langkah Proses", expanded=False):
        for line in steps_log:
            if line == "":
                st.write("")
            else:
                st.text(line)


def show_result(label, result_text):
    st.success(f"**{label}:**")
    st.code(result_text if result_text else "(kosong)", language=None)


# ==========================================================================
# MENU 1: CAESAR CIPHER
# ==========================================================================
if menu.startswith("1"):
    st.header("1️⃣ Caesar Cipher — Substitusi Monoalfabetik")
    st.write(
        "Setiap huruf digeser sejauh **key** posisi dalam alfabet. "
        "Rumus: `C = (P + key) mod 26` untuk enkripsi, `P = (C - key) mod 26` untuk dekripsi."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        input_text = st.text_area(
            f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext'})",
            height=120,
            key="caesar_text",
        )
    with col2:
        key = st.number_input("Kunci (Pergeseran)", min_value=0, max_value=25, value=3, step=1)

    if st.button("🚀 Eksekusi Caesar Cipher", type="primary"):
        if not input_text.strip():
            st.warning("Silakan masukkan teks terlebih dahulu.")
        else:
            result, steps = caesar_cipher(input_text, key, mode=mode)
            label = "Ciphertext" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil {label}", result)
            show_steps(steps)


# ==========================================================================
# MENU 2: SCYTALE CIPHER
# ==========================================================================
elif menu.startswith("2"):
    st.header("2️⃣ Scytale Cipher — Transposisi Baris/Kolom")
    st.write(
        "Teks disusun ke dalam matriks berukuran (baris x kolom). Saat **enkripsi**, "
        "matriks diisi baris demi baris lalu dibaca kolom demi kolom. Saat **dekripsi**, "
        "prosesnya dibalik."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        input_text = st.text_area(
            f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext'})",
            height=120,
            key="scytale_text",
        )
    with col2:
        cols = st.number_input("Kunci (Jumlah Kolom)", min_value=1, max_value=50, value=4, step=1)

    if st.button("🚀 Eksekusi Scytale Cipher", type="primary"):
        if not input_text.strip():
            st.warning("Silakan masukkan teks terlebih dahulu.")
        else:
            if mode == "Enkripsi":
                result, steps = scytale_encrypt(input_text, cols)
                show_result("Hasil Ciphertext", result)
            else:
                result, steps = scytale_decrypt(input_text, cols)
                show_result("Hasil Plaintext", result)
            show_steps(steps)


# ==========================================================================
# MENU 3: RC4 CIPHER
# ==========================================================================
elif menu.startswith("3"):
    st.header("3️⃣ RC4 Cipher — Modern Stream Cipher (basis mod 26)")
    st.write(
        "Implementasi RC4 termodifikasi menggunakan S-Box berukuran 26 (bukan 256), "
        "terdiri dari tahap **KSA** (Key Scheduling Algorithm) dan **PRGA** "
        "(Pseudo-Random Generation Algorithm)."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        input_text = st.text_area(
            f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext'})",
            height=120,
            key="rc4_text",
        )
    with col2:
        key = st.text_input("Kunci (huruf A-Z)", value="KUNCI")

    if st.button("🚀 Eksekusi RC4 Cipher", type="primary"):
        if not input_text.strip():
            st.warning("Silakan masukkan teks terlebih dahulu.")
        else:
            result, steps = rc4_mod26(input_text, key, mode=mode)
            label = "Ciphertext" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil {label}", result)
            show_steps(steps)


# ==========================================================================
# MENU 4: AES SIMPLIFIED
# ==========================================================================
elif menu.startswith("4"):
    st.header("4️⃣ AES Simplified — Modern Block Cipher (basis mod 26)")
    st.write(
        "Teks dibagi menjadi blok-blok **4 karakter** (padding 'X' bila kurang). "
        "Setiap blok diproses dengan tahap **AddRoundKey**, **SubBytes** (+3 mod 26), "
        "dan **ShiftRows** (rotasi baris pada matriks 2x2)."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        input_text = st.text_area(
            f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext'})",
            height=120,
            key="aes_text",
        )
    with col2:
        key = st.text_input("Kunci (4 huruf A-Z)", value="KUNC")

    if st.button("🚀 Eksekusi AES Simplified", type="primary"):
        if not input_text.strip():
            st.warning("Silakan masukkan teks terlebih dahulu.")
        else:
            result, steps = aes_simple_cipher(input_text, key, mode=mode)
            label = "Ciphertext" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil {label}", result)
            show_steps(steps)


# ==========================================================================
# MENU 5: SUPER ENKRIPSI
# ==========================================================================
elif menu.startswith("5"):
    st.header("5️⃣ Super Enkripsi — Gabungan 4 Algoritma Berantai")
    st.write(
        "**Alur Enkripsi:** Caesar ➜ Scytale ➜ RC4 ➜ AES Simplified  \n"
        "**Alur Dekripsi:** AES Simplified ➜ RC4 ➜ Scytale ➜ Caesar (urutan kebalikan)"
    )
    st.warning(
        "⚠️ Catatan: karena Scytale dan AES Simplified menambahkan karakter padding "
        "'X', hasil dekripsi akhir bisa saja mengandung beberapa 'X' tambahan di "
        "bagian akhir teks. Ini normal untuk skema cipher sederhana semacam ini."
    )

    input_text = st.text_area(
        f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext'})",
        height=120,
        key="super_text",
    )

    st.subheader("🔑 Kunci untuk Masing-Masing Algoritma")
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        caesar_key = st.number_input("Kunci Caesar", min_value=0, max_value=25, value=3, step=1)
    with k2:
        scytale_cols = st.number_input("Kunci Scytale (kolom)", min_value=1, max_value=50, value=4, step=1)
    with k3:
        rc4_key = st.text_input("Kunci RC4", value="KUNCI")
    with k4:
        aes_key = st.text_input("Kunci AES (4 huruf)", value="KUNC")

    if st.button("🚀 Eksekusi Super Enkripsi", type="primary"):
        if not input_text.strip():
            st.warning("Silakan masukkan teks terlebih dahulu.")
        else:
            if mode == "Enkripsi":
                result, steps = super_encrypt(input_text, caesar_key, scytale_cols, rc4_key, aes_key)
                show_result("Hasil Akhir Ciphertext", result)
            else:
                result, steps = super_decrypt(input_text, caesar_key, scytale_cols, rc4_key, aes_key)
                show_result("Hasil Akhir Plaintext", result)
            show_steps(steps)


# ------------------------------------------------------------------------
# FOOTER
# ------------------------------------------------------------------------
st.markdown("---")
st.caption("Dibuat untuk keperluan pembelajaran Kriptografi — implementasi disederhanakan "
           "pada basis 26 huruf alfabet (A-Z), bukan untuk penggunaan keamanan produksi.")
