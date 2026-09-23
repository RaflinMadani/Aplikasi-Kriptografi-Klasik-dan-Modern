"""
==============================================================================
 APLIKASI KRIPTOGRAFI - ENKRIPSI & DEKRIPSI TEKS (ALFABET A-Z)
 Tugas Kuliah Kriptografi
==============================================================================
"""

import streamlit as st
import time
import string

from algos.caesar import caesar_cipher
from algos.scytale import scytale_encrypt, scytale_decrypt
from algos.rc4 import rc4_mod26
from algos.aes import aes_simple_cipher
from algos.super_crypto import super_encrypt, super_decrypt
from algos.utils import clean_text # Tambahan untuk mengambil fungsi pembersih teks
from algos.utils import clean_text, char_to_num, num_to_char


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
# Tambahan Toggle Animasi
gunakan_animasi = st.sidebar.checkbox("🎬 Aktifkan Animasi Visual", value=True)

st.sidebar.info(
    "ℹ️ Semua teks otomatis dibersihkan: diubah ke huruf besar dan karakter "
    "selain A-Z (spasi, angka, tanda baca) akan dibuang."
)


def show_steps_animated(steps_log, animate=True):
    """Menampilkan log langkah-langkah di dalam expander dengan efek animasi terminal."""
    with st.expander("🔍 Lihat Log Visualisasi Langkah-Langkah Proses", expanded=True):
        if animate:
            log_container = st.empty()
            tampilan_log = ""
            for line in steps_log:
                # Tambahkan baris baru ke tampilan
                tampilan_log += f"{line}\n"
                # Update layar
                log_container.code(tampilan_log, language="plaintext")
                # Efek kecepatan ketik terminal (0.05 detik per baris)
                time.sleep(0.05)
        else:
            # Jika animasi dimatikan, tampilkan langsung semua
            st.code("\n".join(steps_log), language="plaintext")

def show_result(label, result_text):
    st.success(f"**{label}:**")
    st.code(result_text if result_text else "(kosong)", language=None)


# ==========================================================================
# MENU 1: CAESAR CIPHER
# ==========================================================================
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
            teks_bersih = clean_text(input_text)
            
            # --- BLOK ANIMASI PITA ALFABET & HASIL SEMENTARA ---
            if gunakan_animasi and teks_bersih:
                ui_batas = st.empty()
                ui_judul_animasi = st.empty()
                ruang_animasi = st.empty()
                ui_judul_hasil = st.empty()
                ruang_hasil_sementara = st.empty()
                
                ui_batas.write("---")
                ui_judul_animasi.write("### 🎬 Visualisasi Pita Alfabet:")
                ui_judul_hasil.write("### 📝 Hasil Sementara:")
                
                alfabet = list(string.ascii_uppercase)
                arah_geser = key if mode == "Enkripsi" else -key
                hasil_sementara = ""
                
                for char in teks_bersih:
                    indeks_awal = alfabet.index(char)
                    
                    for i in range(abs(arah_geser) + 1):
                        langkah = i if arah_geser > 0 else -i
                        indeks_sekarang = (indeks_awal + langkah) % 26
                        
                        pita_html = "<div style='font-family: monospace; font-size: 20px; text-align: center; padding: 10px; background-color: #262730; color: white; border-radius: 8px;'>"
                        for j, huruf in enumerate(alfabet):
                            if j == indeks_sekarang:
                                pita_html += f"<span style='background-color: #FF4B4B; padding: 2px 6px; border-radius: 4px; margin: 0 1px;'><b>{huruf}</b></span>"
                            elif j == indeks_awal:
                                pita_html += f"<span style='background-color: #555; padding: 2px 6px; border-radius: 4px; margin: 0 1px;'>{huruf}</span>"
                            else:
                                pita_html += f"<span style='padding: 2px; margin: 0 1px;'>{huruf}</span>"
                        pita_html += "</div>"
                        
                        ruang_animasi.markdown(f"Memproses karakter **{char}**...<br>{pita_html}", unsafe_allow_html=True)
                        
                        huruf_berjalan = alfabet[indeks_sekarang]
                        tampilan_hasil = f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara}<span style='color: #FF4B4B;'>{huruf_berjalan}</span></h2>"
                        ruang_hasil_sementara.markdown(tampilan_hasil, unsafe_allow_html=True)
                        
                        time.sleep(0.08) 
                        
                    hasil_sementara += alfabet[(indeks_awal + arah_geser) % 26]
                    ruang_hasil_sementara.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                    time.sleep(0.2) 
                
                time.sleep(0.5) 
                # Bersihkan UI setelah animasi selesai
                ui_batas.empty(); ui_judul_animasi.empty(); ruang_animasi.empty(); ui_judul_hasil.empty(); ruang_hasil_sementara.empty()
            # --- AKHIR BLOK ANIMASI ---

            result, steps = caesar_cipher(input_text, key, mode=mode)
            label = "Ciphertext" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil Akhir {label}", result)
            show_steps_animated(steps, animate=gunakan_animasi)
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
            teks_bersih = clean_text(input_text)
            
            # --- BLOK ANIMASI MATRIKS SCYTALE & HASIL SEMENTARA ---
            if gunakan_animasi and teks_bersih:
                import math
                ui_batas = st.empty()
                ruang_keterangan = st.empty()
                ruang_matriks = st.empty()
                ui_judul_hasil = st.empty()
                ruang_hasil_sementara = st.empty()
                
                ui_batas.write("---")
                ui_judul_hasil.write("### 📝 Hasil Sementara:")
                
                cols_anim = int(cols)
                if cols_anim < 1: cols_anim = 1
                rows_anim = math.ceil(len(teks_bersih) / cols_anim)
                pad_len = rows_anim * cols_anim - len(teks_bersih)
                padded_text = teks_bersih + 'X' * pad_len 
                
                matriks = [['' for _ in range(cols_anim)] for _ in range(rows_anim)]
                hasil_sementara = ""
                
                def render_matriks(m, highlight_r=-1, highlight_c=-1, highlight_color="transparent"):
                    html = "<table style='margin-left: auto; margin-right: auto; text-align: center; font-family: monospace; font-size: 24px; border-collapse: collapse;'>"
                    for r in range(len(m)):
                        html += "<tr>"
                        for c in range(len(m[0])):
                            val = m[r][c] if m[r][c] else "&nbsp;"
                            bg = highlight_color if (r == highlight_r and c == highlight_c) else "transparent"
                            html += f"<td style='border: 2px solid #666; padding: 15px; width: 50px; height: 50px; background-color: {bg}; color: white;'>{val}</td>"
                        html += "</tr>"
                    html += "</table><br>"
                    return html

                ruang_keterangan.info("### 🎬 Fase 1: Mengisi Matriks...")
                idx = 0
                if mode == "Enkripsi":
                    for r in range(rows_anim):
                        for c in range(cols_anim):
                            if idx < len(padded_text):
                                matriks[r][c] = padded_text[idx]
                                ruang_matriks.markdown(render_matriks(matriks, r, c, "#4CAF50"), unsafe_allow_html=True)
                                idx += 1
                                time.sleep(0.1) 
                else:
                    for c in range(cols_anim):
                        for r in range(rows_anim):
                            if idx < len(padded_text):
                                matriks[r][c] = padded_text[idx]
                                ruang_matriks.markdown(render_matriks(matriks, r, c, "#4CAF50"), unsafe_allow_html=True)
                                idx += 1
                                time.sleep(0.1)
                
                time.sleep(0.5)
                
                ruang_keterangan.warning("### 🎬 Fase 2: Membaca Matriks (Menghasilkan Teks)...")
                if mode == "Enkripsi":
                    for c in range(cols_anim):
                        for r in range(rows_anim):
                            char = matriks[r][c]
                            hasil_sementara += char
                            ruang_matriks.markdown(render_matriks(matriks, r, c, "#FF4B4B"), unsafe_allow_html=True)
                            tampilan_hasil = f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara[:-1]}<span style='color: #FF4B4B;'>{char}</span></h2>"
                            ruang_hasil_sementara.markdown(tampilan_hasil, unsafe_allow_html=True)
                            time.sleep(0.15) 
                else:
                    for r in range(rows_anim):
                        for c in range(cols_anim):
                            char = matriks[r][c]
                            hasil_sementara += char
                            ruang_matriks.markdown(render_matriks(matriks, r, c, "#FF4B4B"), unsafe_allow_html=True)
                            tampilan_hasil = f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara[:-1]}<span style='color: #FF4B4B;'>{char}</span></h2>"
                            ruang_hasil_sementara.markdown(tampilan_hasil, unsafe_allow_html=True)
                            time.sleep(0.15)
                
                time.sleep(0.5)
                # Bersihkan UI setelah animasi selesai
                ui_batas.empty(); ruang_keterangan.empty(); ruang_matriks.empty(); ui_judul_hasil.empty(); ruang_hasil_sementara.empty()
            # --- AKHIR BLOK ANIMASI ---

            if mode == "Enkripsi":
                result, steps = scytale_encrypt(input_text, cols)
                show_result("Hasil Ciphertext", result)
            else:
                result, steps = scytale_decrypt(input_text, cols)
                show_result("Hasil Plaintext", result)
            
            show_steps_animated(steps, animate=gunakan_animasi)

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
            teks_bersih = clean_text(input_text)
            kunci_bersih = clean_text(key)
            if not kunci_bersih: kunci_bersih = 'KEY'
            
            # --- BLOK ANIMASI RC4 MOD 26 & HASIL SEMENTARA ---
            if gunakan_animasi and teks_bersih:
                ui_batas = st.empty()
                ui_judul_ksa = st.empty()
                ruang_ksa = st.empty()
                ui_judul_prga = st.empty()
                ruang_prga = st.empty()
                ui_judul_hasil = st.empty()
                ruang_hasil_sementara = st.empty()
                
                ui_batas.write("---")
                
                # FASE 1: KSA 
                ui_judul_ksa.write("### 🎬 Fase 1: KSA (Mengacak S-Box 0-25)")
                
                key_nums = [char_to_num(k) for k in kunci_bersih]
                S = list(range(26))
                j = 0
                
                def render_sbox(s_array, highlight_i=-1, highlight_j=-1):
                    html = "<div style='display: flex; flex-wrap: wrap; gap: 5px; font-family: monospace; font-size: 16px;'>"
                    for idx, val in enumerate(s_array):
                        bg = "#262730" 
                        if idx == highlight_i: bg = "#4CAF50" 
                        elif idx == highlight_j: bg = "#FF9800" 
                        html += f"<div style='background-color: {bg}; color: white; padding: 10px; border-radius: 5px; width: 40px; text-align: center;'>{val}</div>"
                    html += "</div>"
                    return html

                for i in range(26):
                    j = (j + S[i] + key_nums[i % len(key_nums)]) % 26
                    S[i], S[j] = S[j], S[i] 
                    ruang_ksa.markdown(render_sbox(S, i, j), unsafe_allow_html=True)
                    time.sleep(0.05) 
                
                ruang_ksa.markdown(render_sbox(S), unsafe_allow_html=True) 
                time.sleep(0.5)

                # FASE 2: PRGA 
                ui_judul_prga.write("### 🎬 Fase 2: PRGA & Kalkulasi Stream")
                ui_judul_hasil.write("### 📝 Hasil Sementara:")
                
                i_prga = 0
                j_prga = 0
                hasil_sementara = ""
                op_symbol = "+" if mode == 'Enkripsi' else "-"
                
                for char in teks_bersih:
                    i_prga = (i_prga + 1) % 26
                    j_prga = (j_prga + S[i_prga]) % 26
                    S[i_prga], S[j_prga] = S[j_prga], S[i_prga]
                    t = (S[i_prga] + S[j_prga]) % 26
                    ks = S[t]
                    
                    p = char_to_num(char)
                    
                    if mode == 'Enkripsi':
                        c = (p + ks) % 26
                    else:
                        c = (p - ks) % 26
                        
                    new_ch = num_to_char(c)
                    
                    html_prga = f"""
                    <div style='font-family: monospace; font-size: 18px; padding: 15px; background-color: #262730; color: white; border-radius: 8px;'>
                        <span style='color: #87CEFA;'>Teks Input (P):</span> <b>'{char}'</b> (Nilai: {p})<br>
                        <span style='color: #FFD700;'>Keystream (K):</span> <b>{ks}</b><br>
                        <hr style='border-top: 1px dashed #666; margin: 10px 0;'>
                        <span style='color: #FF4B4B;'>Kalkulasi:</span> ({p} {op_symbol} {ks}) mod 26 = <b>{c}</b> ➡️ <b>'{new_ch}'</b>
                    </div>
                    """
                    ruang_prga.markdown(html_prga, unsafe_allow_html=True)
                    
                    hasil_sementara += new_ch
                    tampilan_hasil = f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara[:-1]}<span style='color: #FF4B4B;'>{new_ch}</span></h2>"
                    ruang_hasil_sementara.markdown(tampilan_hasil, unsafe_allow_html=True)
                    
                    time.sleep(0.4) 

                time.sleep(0.5)
                # Bersihkan UI setelah animasi selesai
                ui_batas.empty(); ui_judul_ksa.empty(); ruang_ksa.empty(); ui_judul_prga.empty(); ruang_prga.empty(); ui_judul_hasil.empty(); ruang_hasil_sementara.empty()
            # --- AKHIR BLOK ANIMASI ---

            result, steps = rc4_mod26(input_text, key, mode=mode)
            label = "Ciphertext" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil Akhir {label}", result)
            show_steps_animated(steps, animate=gunakan_animasi)

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
            teks_bersih = clean_text(input_text)
            kunci_bersih = clean_text(key)
            if not kunci_bersih: kunci_bersih = 'KUNC'
            
            # Persiapan kunci menjadi tepat 4 karakter
            if len(kunci_bersih) < 4:
                kunci_bersih = (kunci_bersih * 4)[:4]
            else:
                kunci_bersih = kunci_bersih[:4]

            # --- BLOK ANIMASI AES & HASIL SEMENTARA ---
            if gunakan_animasi and teks_bersih:
                st.write("---")
                
                # Mendeklarasikan placeholder yang NANTINYA AKAN DIKOSONGKAN
                ui_judul_animasi = st.empty()
                ui_animasi = st.empty()
                ui_judul_hasil = st.empty()
                ui_hasil = st.empty()
                
                ui_judul_animasi.write("### 🎬 Animasi Pemrosesan Blok AES:")
                ui_judul_hasil.write("### 📝 Hasil Sementara:")
                
                # Persiapan pemisahan blok teks
                blocks = []
                for i in range(0, len(teks_bersih), 4):
                    block = teks_bersih[i:i + 4]
                    if len(block) < 4:
                        block = block + 'X' * (4 - len(block))
                    blocks.append(block)
                    
                key_nums = [char_to_num(k) for k in kunci_bersih]
                hasil_sementara = ""
                
                for b_idx, block in enumerate(blocks):
                    nums = [char_to_num(c) for c in block]
                    
                    html_animasi = f"<div style='font-family: monospace; font-size: 18px; padding: 15px; background-color: #262730; color: white; border-radius: 8px;'>"
                    html_animasi += f"<h4 style='color: #4CAF50;'>Memproses Blok {b_idx + 1}: '{block}'</h4>"
                    
                    if mode == 'Enkripsi':
                        # 1. AddRoundKey
                        ark = [(nums[i] + key_nums[i]) % 26 for i in range(4)]
                        ark_chars = ''.join(num_to_char(x) for x in ark)
                        html_animasi += f"<b>1. AddRoundKey:</b> {nums} + {key_nums} = {ark} ➡️ <b>'{ark_chars}'</b><br>"
                        ui_animasi.markdown(html_animasi + "</div>", unsafe_allow_html=True)
                        time.sleep(1.2)
                        
                        # 2. SubBytes
                        sb = [(x + 3) % 26 for x in ark]
                        sb_chars = ''.join(num_to_char(x) for x in sb)
                        html_animasi += f"<b>2. SubBytes (+3):</b> {ark} + 3 = {sb} ➡️ <b>'{sb_chars}'</b><br>"
                        ui_animasi.markdown(html_animasi + "</div>", unsafe_allow_html=True)
                        time.sleep(1.2)
                        
                        # 3. ShiftRows
                        row0 = [sb[0], sb[1]]
                        row1 = [sb[2], sb[3]]
                        row1_shifted = row1[1:] + row1[:1]
                        final_nums = row0 + row1_shifted
                        final_chars = ''.join(num_to_char(x) for x in final_nums)
                        
                        html_animasi += f"<b>3. ShiftRows (Geser Baris Bawah Kiri):</b><br>"
                        html_animasi += f"<table style='text-align: center; color: white; border-collapse: collapse; margin-top: 5px; font-size: 20px;'>"
                        html_animasi += f"<tr><td style='padding: 10px; border: 1px solid #666;'>{num_to_char(row0[0])}</td><td style='padding: 10px; border: 1px solid #666;'>{num_to_char(row0[1])}</td><td style='padding: 10px; border: none; color: #aaa;'>&nbsp;(Baris Atas Tetap)</td></tr>"
                        html_animasi += f"<tr><td style='padding: 10px; border: 1px solid #666; color: #FF4B4B;'><b>{num_to_char(row1_shifted[0])}</b></td><td style='padding: 10px; border: 1px solid #666; color: #FF4B4B;'><b>{num_to_char(row1_shifted[1])}</b></td><td style='padding: 10px; border: none; color: #FF4B4B;'>&nbsp;⬅️ (Baris Bawah Digeser)</td></tr>"
                        html_animasi += f"</table>"
                        
                    else:
                        # 1. Inverse ShiftRows
                        row0 = [nums[0], nums[1]]
                        row1 = [nums[2], nums[3]]
                        row1_unshifted = row1[-1:] + row1[:-1]
                        unshift_nums = row0 + row1_unshifted
                        unshift_chars = ''.join(num_to_char(x) for x in unshift_nums)
                        html_animasi += f"<b>1. Inverse ShiftRows (Geser Baris Bawah Kanan):</b> ➡️ <b>'{unshift_chars}'</b><br>"
                        ui_animasi.markdown(html_animasi + "</div>", unsafe_allow_html=True)
                        time.sleep(1.2)
                        
                        # 2. Inverse SubBytes
                        isb = [(x - 3) % 26 for x in unshift_nums]
                        isb_chars = ''.join(num_to_char(x) for x in isb)
                        html_animasi += f"<b>2. Inverse SubBytes (-3):</b> {unshift_nums} - 3 = {isb} ➡️ <b>'{isb_chars}'</b><br>"
                        ui_animasi.markdown(html_animasi + "</div>", unsafe_allow_html=True)
                        time.sleep(1.2)
                        
                        # 3. Inverse AddRoundKey
                        iark = [(isb[i] - key_nums[i]) % 26 for i in range(4)]
                        final_nums = iark
                        final_chars = ''.join(num_to_char(x) for x in final_nums)
                        html_animasi += f"<b>3. Inverse AddRoundKey:</b> {isb} - {key_nums} = {iark} ➡️ <span style='color: #FF4B4B;'><b>'{final_chars}'</b></span><br>"
                    
                    html_animasi += f"<hr style='border-top: 1px dashed #666;'><span style='color: #FF4B4B;'>Hasil Blok: <b>{final_chars}</b></span>"
                    ui_animasi.markdown(html_animasi + "</div>", unsafe_allow_html=True)
                    
                    # Update Hasil Sementara per Blok
                    hasil_sementara += final_chars
                    tampilan_hasil = f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara[:-4]}<span style='color: #FF4B4B;'>{final_chars}</span></h2>"
                    ui_hasil.markdown(tampilan_hasil, unsafe_allow_html=True)
                    
                    time.sleep(1.5) # Jeda antar blok agar pengguna bisa membaca
                
                # SETELAH SEMUA BLOK SELESAI, KOSONGKAN PLACEHOLDER (Hapus Animasi)
                time.sleep(0.8)
                ui_judul_animasi.empty()
                ui_animasi.empty()
                ui_judul_hasil.empty()
                ui_hasil.empty()
            # --- AKHIR BLOK ANIMASI ---

            # Menjalankan Logika Asli (Tampilan Hasil Akhir dan Log Terminal)
            result, steps = aes_simple_cipher(input_text, key, mode=mode)
            label = "Ciphertext" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil Akhir {label}", result)
            show_steps_animated(steps, animate=gunakan_animasi)

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
        "⚠️ Catatan: karena Scytale dan AES Simplified menambahkan padding 'X', "
        "hasil dekripsi akhir bisa saja mengandung beberapa 'X' tambahan."
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
            import math
            teks_bersih = clean_text(input_text)
            
            # --- BLOK ANIMASI SUPER ENKRIPSI (KECEPATAN NORMAL) ---
            if gunakan_animasi and teks_bersih:
                st.write("---")
                ui_judul = st.empty()
                ui_animasi1 = st.empty()
                ui_animasi2 = st.empty()
                ui_hasil = st.empty()
                
                current_text = teks_bersih
                
                if mode == "Enkripsi":
                    tahapan = [
                        ("Caesar Cipher", caesar_cipher, (caesar_key, 'Enkripsi')),
                        ("Scytale Cipher", scytale_encrypt, (scytale_cols,)), 
                        ("RC4 Cipher", rc4_mod26, (rc4_key, 'Enkripsi')),
                        ("AES Simplified", aes_simple_cipher, (aes_key, 'Enkripsi'))
                    ]
                else:
                    tahapan = [
                        ("AES Simplified", aes_simple_cipher, (aes_key, 'Dekripsi')),
                        ("RC4 Cipher", rc4_mod26, (rc4_key, 'Dekripsi')),
                        ("Scytale Cipher", scytale_decrypt, (scytale_cols,)),
                        ("Caesar Cipher", caesar_cipher, (caesar_key, 'Dekripsi'))
                    ]
                
                for i, (nama_tahap, fungsi, argumen) in enumerate(tahapan):
                    ui_judul.markdown(f"<h3 style='color:#FFD700;'>⏳ Tahap {i+1}/4 : Memproses {nama_tahap}...</h3>", unsafe_allow_html=True)
                    hasil_sementara = ""
                    
                    # ---------------------------------------------------------
                    # 1. ANIMASI CAESAR CIPHER
                    # ---------------------------------------------------------
                    if nama_tahap == "Caesar Cipher":
                        alfabet = list(string.ascii_uppercase)
                        arah_geser = argumen[0] if argumen[1] == "Enkripsi" else -argumen[0]
                        
                        for char in current_text:
                            indeks_awal = alfabet.index(char)
                            indeks_sekarang = (indeks_awal + arah_geser) % 26
                            
                            pita_html = "<div style='font-family: monospace; font-size: 18px; text-align: center; padding: 10px; background-color: #262730; color: white; border-radius: 8px;'>"
                            for j, huruf in enumerate(alfabet):
                                if j == indeks_sekarang:
                                    pita_html += f"<span style='background-color: #FF4B4B; padding: 2px 4px; border-radius: 4px; margin: 0 1px;'><b>{huruf}</b></span>"
                                else:
                                    pita_html += f"<span style='padding: 2px; margin: 0 1px;'>{huruf}</span>"
                            pita_html += "</div>"
                            
                            ui_animasi1.markdown(f"Menggeser **{char}**:<br>{pita_html}", unsafe_allow_html=True)
                            
                            hasil_sementara += alfabet[indeks_sekarang]
                            ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                            time.sleep(0.15) # Diperlambat agar geseran per huruf terlihat jelas
                            
                    # ---------------------------------------------------------
                    # 2. ANIMASI SCYTALE CIPHER
                    # ---------------------------------------------------------
                    elif nama_tahap == "Scytale Cipher":
                        cols_anim = max(1, int(argumen[0]))
                        rows_anim = math.ceil(len(current_text) / cols_anim)
                        padded_text = current_text + 'X' * (rows_anim * cols_anim - len(current_text))
                        matriks = [['' for _ in range(cols_anim)] for _ in range(rows_anim)]
                        
                        def render_matriks(m, hr=-1, hc=-1):
                            html = "<table style='margin: auto; text-align: center; font-family: monospace; font-size: 20px; border-collapse: collapse;'>"
                            for r in range(len(m)):
                                html += "<tr>"
                                for c in range(len(m[0])):
                                    val = m[r][c] if m[r][c] else "&nbsp;"
                                    bg = "#FF4B4B" if (r == hr and c == hc) else "transparent"
                                    html += f"<td style='border: 1px solid #666; padding: 10px; width: 40px; height: 40px; background-color: {bg}; color: white;'>{val}</td>"
                                html += "</tr>"
                            html += "</table><br>"
                            return html

                        idx = 0
                        if mode == "Enkripsi":
                            for r in range(rows_anim):
                                for c in range(cols_anim):
                                    if idx < len(padded_text): matriks[r][c] = padded_text[idx]; idx += 1
                            for c in range(cols_anim):
                                for r in range(rows_anim):
                                    hasil_sementara += matriks[r][c]
                                    ui_animasi1.markdown(render_matriks(matriks, r, c), unsafe_allow_html=True)
                                    ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                                    time.sleep(0.25) # Diperlambat agar kotak matriks terlihat berkedip
                        else:
                            for c in range(cols_anim):
                                for r in range(rows_anim):
                                    if idx < len(padded_text): matriks[r][c] = padded_text[idx]; idx += 1
                            for r in range(rows_anim):
                                for c in range(cols_anim):
                                    hasil_sementara += matriks[r][c]
                                    ui_animasi1.markdown(render_matriks(matriks, r, c), unsafe_allow_html=True)
                                    ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                                    time.sleep(0.25)

                    # ---------------------------------------------------------
                    # 3. ANIMASI RC4 CIPHER
                    # ---------------------------------------------------------
                    elif nama_tahap == "RC4 Cipher":
                        kunci_rc4 = clean_text(argumen[0]) or 'KEY'
                        mode_rc4 = argumen[1]
                        key_nums = [char_to_num(k) for k in kunci_rc4]
                        S = list(range(26)); j = 0
                        
                        ui_animasi1.info("Mengacak S-Box (KSA)...")
                        for i in range(26):
                            j = (j + S[i] + key_nums[i % len(key_nums)]) % 26
                            S[i], S[j] = S[j], S[i]
                            
                        i_prga = 0; j_prga = 0
                        op_symbol = "+" if mode_rc4 == 'Enkripsi' else "-"
                        for char in current_text:
                            i_prga = (i_prga + 1) % 26
                            j_prga = (j_prga + S[i_prga]) % 26
                            S[i_prga], S[j_prga] = S[j_prga], S[i_prga]
                            ks = S[(S[i_prga] + S[j_prga]) % 26]
                            
                            p = char_to_num(char)
                            c = (p + ks) % 26 if mode_rc4 == 'Enkripsi' else (p - ks) % 26
                            new_ch = num_to_char(c)
                            
                            html_prga = f"<div style='font-family: monospace; font-size: 16px; padding: 10px; background-color: #262730; color: white; border-radius: 8px;'>"
                            html_prga += f"P: <b>'{char}'</b> ({p}) | KS: <b>{ks}</b> | {p} {op_symbol} {ks} mod 26 = <b>{c}</b> ➡️ <span style='color: #FF4B4B;'><b>'{new_ch}'</b></span></div>"
                            ui_animasi2.markdown(html_prga, unsafe_allow_html=True)
                            
                            hasil_sementara += new_ch
                            ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                            time.sleep(0.4) # Diperlambat agar pembacaan proses XOR matematika lebih santai

                    # ---------------------------------------------------------
                    # 4. ANIMASI AES SIMPLIFIED
                    # ---------------------------------------------------------
                    elif nama_tahap == "AES Simplified":
                        kunci_aes = clean_text(argumen[0]) or 'KUNC'
                        kunci_aes = (kunci_aes * 4)[:4] if len(kunci_aes) < 4 else kunci_aes[:4]
                        key_nums = [char_to_num(k) for k in kunci_aes]
                        
                        blocks = [current_text[b:b+4].ljust(4, 'X') for b in range(0, len(current_text), 4)]
                        
                        for b_idx, block in enumerate(blocks):
                            nums = [char_to_num(c) for c in block]
                            
                            if argumen[1] == 'Enkripsi':
                                ark = [(nums[x] + key_nums[x]) % 26 for x in range(4)]
                                sb = [(x + 3) % 26 for x in ark]
                                final_nums = [sb[0], sb[1], sb[3], sb[2]]
                            else:
                                unshift = [nums[0], nums[1], nums[3], nums[2]]
                                isb = [(x - 3) % 26 for x in unshift]
                                final_nums = [(isb[x] - key_nums[x]) % 26 for x in range(4)]
                                
                            final_chars = ''.join(num_to_char(x) for x in final_nums)
                            
                            ui_animasi1.markdown(f"<div style='padding:15px; background:#262730; border-radius:8px;'>Memproses Blok: <b>{block}</b> ➡️ <span style='color:#FF4B4B;'><b>{final_chars}</b></span></div>", unsafe_allow_html=True)
                            
                            hasil_sementara += final_chars
                            ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                            time.sleep(1.2) # Diperlambat untuk memberikan jeda nyaman antar blok AES
                    
                    # ---------------------------------------------------------
                    # TRANSISI KE ALGORITMA BERIKUTNYA
                    # ---------------------------------------------------------
                    time.sleep(1.5) # Jeda antar algoritma diperpanjang agar tidak terburu-buru ganti layar
                    
                    if len(argumen) == 1:
                        current_text, _ = fungsi(current_text, argumen[0])
                    else:
                        current_text, _ = fungsi(current_text, argumen[0], argumen[1])
                    
                    ui_animasi1.empty()
                    ui_animasi2.empty()
                    ui_hasil.empty()
                
                ui_judul.empty()
            # --- AKHIR BLOK ANIMASI ---

            if mode == "Enkripsi":
                result, steps = super_encrypt(input_text, caesar_key, scytale_cols, rc4_key, aes_key)
                show_result("Hasil Akhir Ciphertext", result)
            else:
                result, steps = super_decrypt(input_text, caesar_key, scytale_cols, rc4_key, aes_key)
                show_result("Hasil Akhir Plaintext", result)
            
            show_steps_animated(steps, animate=gunakan_animasi)


# ------------------------------------------------------------------------
# FOOTER
# ------------------------------------------------------------------------
st.markdown("---")
st.caption("Dibuat untuk keperluan pembelajaran Kriptografi — implementasi disederhanakan pada basis 26 huruf alfabet (A-Z).")
