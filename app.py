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
from algos.rc4 import rc4_cipher
from algos.aes import aes_simple_cipher, sub_byte, _pad
from algos.super_crypto import super_encrypt, super_decrypt
from algos.utils import clean_text # Tambahan untuk mengambil fungsi pembersih teks
from algos.utils import clean_text, char_to_num, num_to_char
# from algos.rc4 import rc4_standard

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
    st.header("3️⃣ RC4 Cipher — Modern Stream Cipher (basis 256 byte)")
    st.write(
        "Implementasi RC4 standar menggunakan S-Box berukuran 256 byte dan operasi **XOR**. "
        "Hasil enkripsi berupa **Hexadesimal** karena output operasi byte sering kali berupa karakter yang tidak dapat dicetak (non-printable)."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        input_text = st.text_area(
            f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext Hexadesimal'})",
            height=120,
            key="rc4_text",
        )
    with col2:
        key = st.text_input("Kunci (String)", value="KUNCI")

    if st.button("🚀 Eksekusi RC4 Cipher", type="primary"):
        if not input_text.strip():
            st.warning("Silakan masukkan teks terlebih dahulu.")
        else:
            kunci_bersih = key if key else 'KEY'
            
            # --- BLOK ANIMASI RC4 (256 BYTE) ---
            if gunakan_animasi and input_text:
                ui_batas = st.empty()
                ui_judul_prga = st.empty()
                ruang_prga = st.empty()
                ui_judul_hasil = st.empty()
                ruang_hasil_sementara = st.empty()
                
                ui_batas.write("---")
                ui_judul_prga.write("### 🎬 Kalkulasi PRGA & XOR")
                ui_judul_hasil.write("### 📝 Hasil Sementara (Hex):")
                
                key_bytes = kunci_bersih.encode('utf-8')
                S = list(range(256))
                j = 0
                for i in range(256):
                    j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
                    S[i], S[j] = S[j], S[i]
                
                i_prga = 0
                j_prga = 0
                hasil_sementara = ""
                
                try:
                    text_bytes = input_text.encode('utf-8') if mode == 'Enkripsi' else bytes.fromhex(input_text.replace(" ", ""))
                    
                    for byte in text_bytes[:20]: # Animasi dibatasi 20 byte pertama agar optimal
                        i_prga = (i_prga + 1) % 256
                        j_prga = (j_prga + S[i_prga]) % 256
                        S[i_prga], S[j_prga] = S[j_prga], S[i_prga]
                        ks = S[(S[i_prga] + S[j_prga]) % 256]
                        
                        c = byte ^ ks
                        c_hex = f"{c:02X}"
                        
                        html_prga = f"""
                        <div style='font-family: monospace; font-size: 18px; padding: 15px; background-color: #262730; color: white; border-radius: 8px;'>
                            <span style='color: #87CEFA;'>Byte Input:</span> <b>{byte:02X}</b><br>
                            <span style='color: #FFD700;'>Keystream:</span> <b>{ks:02X}</b><br>
                            <hr style='border-top: 1px dashed #666; margin: 10px 0;'>
                            <span style='color: #FF4B4B;'>Kalkulasi XOR:</span> {byte:02X} ⊕ {ks:02X} = <b>{c_hex}</b>
                        </div>
                        """
                        ruang_prga.markdown(html_prga, unsafe_allow_html=True)
                        
                        hasil_sementara += c_hex + " "
                        tampilan_hasil = f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara[:-3]}<span style='color: #FF4B4B;'>{c_hex}</span></h2>"
                        ruang_hasil_sementara.markdown(tampilan_hasil, unsafe_allow_html=True)
                        time.sleep(0.15)
                        
                except ValueError:
                    st.error("Gagal melakukan dekripsi. Pastikan input berupa format Hexadesimal.")

                time.sleep(0.5)
                ui_batas.empty(); ui_judul_prga.empty(); ruang_prga.empty(); ui_judul_hasil.empty(); ruang_hasil_sementara.empty()
            # --- AKHIR BLOK ANIMASI ---

            result, steps = rc4_cipher(input_text, key, mode=mode)
            label = "Ciphertext (Hex)" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil Akhir {label}", result)
            show_steps_animated(steps, animate=gunakan_animasi)

# ==========================================================================
# MENU 4: AES SIMPLIFIED
# ==========================================================================
elif menu.startswith("4"):
    st.header("4️⃣ AES Simplified — Block Cipher (Byte-Level)")
    st.write(
        "Beroperasi pada blok 4-byte (32-bit). Menggunakan operasi XOR, "
        "S-Box 4-bit, dan ShiftRows pada matriks 2x2. "
        "Hasil enkripsi berupa **Hexadesimal**."
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        input_text = st.text_area(
            f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext Hexadesimal'})",
            height=120,
            key="aes_text",
        )
    with col2:
        key = st.text_input("Kunci (4 Karakter)", value="KUNC", max_chars=4)

    if st.button("🚀 Eksekusi AES Simplified", type="primary"):
        if not input_text.strip():
            st.warning("Silakan masukkan teks terlebih dahulu.")
        else:
            kunci_bersih = key if key else "KUNC"
            
            # --- BLOK ANIMASI AES (BYTE-LEVEL) ---
            if gunakan_animasi and input_text:
                ui_batas = st.empty()
                ui_judul_proses = st.empty()
                ruang_matriks = st.empty()
                ui_judul_hasil = st.empty()
                ruang_hasil_sementara = st.empty()
                
                ui_batas.write("---")
                ui_judul_proses.write("### 🎬 Visualisasi Blok AES (2x2 Byte):")
                ui_judul_hasil.write("### 📝 Hasil Sementara (Hex):")
                
                # Persiapan Kunci
                key_bytes = kunci_bersih.encode('utf-8')
                key_bytes = (key_bytes * 4)[:4] if len(key_bytes) < 4 else key_bytes[:4]
                
                try:
                    # Persiapan Teks (Padding untuk Enkripsi, Parse Hex untuk Dekripsi)
                    if mode == 'Enkripsi':
                        tb = input_text.encode('utf-8')
                        pad_len = 4 - (len(tb) % 4)
                        tb += bytes([pad_len] * pad_len) # padding PKCS7 manual
                    else:
                        tb = bytes.fromhex(input_text.replace(" ", ""))
                        
                    blocks = [list(tb[i:i+4]) for i in range(0, len(tb), 4)]
                    hasil_sementara = ""
                    
                    for b_idx, block in enumerate(blocks):
                        if mode == 'Enkripsi':
                            ark = [block[i] ^ key_bytes[i] for i in range(4)]
                            sb = [sub_byte(x, False) for x in ark]
                            final_block = [sb[0], sb[1], sb[3], sb[2]]
                        else:
                            isr = [block[0], block[1], block[3], block[2]]
                            isb = [sub_byte(x, True) for x in isr]
                            final_block = [isb[i] ^ key_bytes[i] for i in range(4)]
                            
                        final_hex = bytes(final_block).hex().upper()
                        
                        # Render Matriks HTML
                        html_matriks = f"""
                        <div style='font-family: monospace; font-size: 16px; padding: 15px; background-color: #262730; color: white; border-radius: 8px;'>
                            <b>Blok {b_idx + 1} / {len(blocks)}</b><br>
                            <span style='color: #87CEFA;'>Byte Input:</span> {[f"{x:02X}" for x in block]}<br>
                            <span style='color: #FFD700;'>Kunci Byte:</span> {[f"{x:02X}" for x in key_bytes]}<br>
                            <hr style='border-top: 1px dashed #666; margin: 10px 0;'>
                            <span style='color: #FF4B4B;'>Output Blok (Hex):</span> <b>{final_hex}</b>
                        </div>
                        """
                        ruang_matriks.markdown(html_matriks, unsafe_allow_html=True)
                        
                        hasil_sementara += final_hex + " "
                        tampilan_hasil = f"<h2 style='font-family: monospace; letter-spacing: 2px;'>{hasil_sementara[:-5]}<span style='color: #FF4B4B;'>{final_hex}</span></h2>"
                        ruang_hasil_sementara.markdown(tampilan_hasil, unsafe_allow_html=True)
                        
                        time.sleep(1.0) # Jeda per blok
                        
                except ValueError:
                    st.error("Gagal melakukan dekripsi. Pastikan input berupa format Hexadesimal (contoh: 4F 8A).")

                time.sleep(0.5)
                # Bersihkan layar animasi
                ui_batas.empty(); ui_judul_proses.empty(); ruang_matriks.empty(); ui_judul_hasil.empty(); ruang_hasil_sementara.empty()
            # --- AKHIR BLOK ANIMASI ---

            # Menjalankan Logika Asli
            result, steps = aes_simple_cipher(input_text, key, mode=mode)
            label = "Ciphertext (Hex)" if mode == "Enkripsi" else "Plaintext"
            show_result(f"Hasil Akhir {label}", result)
            show_steps_animated(steps, animate=gunakan_animasi)

# ==========================================================================
# MENU 5: SUPER ENKRIPSI
# ==========================================================================
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
        "⚠️ Catatan: Padding 'X' dari Scytale akan otomatis dibersihkan saat dekripsi "
        "sebelum masuk ke tahap Caesar."
    )

    input_text = st.text_area(
        f"Masukkan Teks ({'Plaintext' if mode == 'Enkripsi' else 'Ciphertext Hexadesimal'})",
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
            
            # [PERBAIKAN] Jangan jalankan clean_text jika mode Dekripsi agar format Hexadesimal (angka) tidak terhapus!
            if mode == "Enkripsi":
                teks_bersih = clean_text(input_text)
            else:
                teks_bersih = input_text.replace(" ", "")
            
            # --- BLOK ANIMASI SUPER ENKRIPSI ---
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
                        ("RC4 Cipher", rc4_cipher, (rc4_key, 'Enkripsi')),
                        ("AES Simplified", aes_simple_cipher, (aes_key, 'Enkripsi'))
                    ]
                else:
                    tahapan = [
                        ("AES Simplified", aes_simple_cipher, (aes_key, 'Dekripsi')),
                        ("RC4 Cipher", rc4_cipher, (rc4_key, 'Dekripsi')),
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
                            if char not in alfabet: continue
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
                            time.sleep(0.15)
                            
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
                                    time.sleep(0.15)
                        else:
                            for c in range(cols_anim):
                                for r in range(rows_anim):
                                    if idx < len(padded_text): matriks[r][c] = padded_text[idx]; idx += 1
                            for r in range(rows_anim):
                                for c in range(cols_anim):
                                    hasil_sementara += matriks[r][c]
                                    ui_animasi1.markdown(render_matriks(matriks, r, c), unsafe_allow_html=True)
                                    ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                                    time.sleep(0.15)

                    # ---------------------------------------------------------
                    # 3. ANIMASI RC4 CIPHER (BYTE-LEVEL)
                    # ---------------------------------------------------------
                    elif nama_tahap == "RC4 Cipher":
                        kunci_rc4_anim = argumen[0].encode('utf-8') if argumen[0] else b'KEY'
                        S_anim = list(range(256)); j_anim = 0
                        ui_animasi1.info("Mengacak S-Box 256-byte (KSA)...")
                        for i_idx in range(256):
                            j_anim = (j_anim + S_anim[i_idx] + kunci_rc4_anim[i_idx % len(kunci_rc4_anim)]) % 256
                            S_anim[i_idx], S_anim[j_anim] = S_anim[j_anim], S_anim[i_idx]
                            
                        try:
                            tb = current_text.encode('utf-8') if argumen[1] == 'Enkripsi' else bytes.fromhex(current_text)
                            i_prga = 0; j_prga = 0
                            
                            for byte in tb[:20]:
                                i_prga = (i_prga + 1) % 256
                                j_prga = (j_prga + S_anim[i_prga]) % 256
                                S_anim[i_prga], S_anim[j_prga] = S_anim[j_prga], S_anim[i_prga]
                                ks = S_anim[(S_anim[i_prga] + S_anim[j_prga]) % 256]
                                c = byte ^ ks
                                c_hex = f"{c:02X}"
                                
                                html_prga = f"<div style='font-family: monospace; font-size: 16px; padding: 10px; background-color: #262730; color: white; border-radius: 8px;'>"
                                html_prga += f"Teks Byte: <b>{byte:02X}</b> | Keystream: <b>{ks:02X}</b> | {byte:02X} ⊕ {ks:02X} = <span style='color: #FF4B4B;'><b>{c_hex}</b></span></div>"
                                ui_animasi2.markdown(html_prga, unsafe_allow_html=True)
                                
                                hasil_sementara += c_hex + " "
                                ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                                time.sleep(0.15)
                        except ValueError:
                            st.error("Animasi RC4: Format Hexadesimal tidak valid.")

                    # ---------------------------------------------------------
                    # 4. ANIMASI AES SIMPLIFIED (BYTE-LEVEL)
                    # ---------------------------------------------------------
                    elif nama_tahap == "AES Simplified":
                        kunci_aes_anim = argumen[0].encode('utf-8') if argumen[0] else b'KUNC'
                        kunci_aes_anim = (kunci_aes_anim * 4)[:4] if len(kunci_aes_anim) < 4 else kunci_aes_anim[:4]
                        
                        try:
                            if argumen[1] == 'Enkripsi':
                                tb = current_text.encode('utf-8')
                                pad = 4 - (len(tb) % 4)
                                tb += bytes([pad] * pad)
                            else:
                                tb = bytes.fromhex(current_text)
                                
                            blocks = [list(tb[b:b+4]) for b in range(0, len(tb), 4)]
                            
                            for b_idx, block in enumerate(blocks):
                                if argumen[1] == 'Enkripsi':
                                    ark = [block[x] ^ kunci_aes_anim[x] for x in range(4)]
                                    sb = [sub_byte(x, False) for x in ark]
                                    final_nums = [sb[0], sb[1], sb[3], sb[2]]
                                else:
                                    isr = [block[0], block[1], block[3], block[2]]
                                    isb = [sub_byte(x, True) for x in isr]
                                    final_nums = [isb[x] ^ kunci_aes_anim[x] for x in range(4)]
                                    
                                final_hex = bytes(final_nums).hex().upper()
                                
                                ui_animasi1.markdown(f"<div style='padding:15px; background:#262730; border-radius:8px;'>Memproses Blok Byte: <b>{[hex(x) for x in block]}</b> ➡️ <span style='color:#FF4B4B;'><b>{final_hex}</b></span></div>", unsafe_allow_html=True)
                                
                                hasil_sementara += final_hex + " "
                                ui_hasil.markdown(f"<h2 style='font-family: monospace; letter-spacing: 2px; color: #4CAF50;'>{hasil_sementara}</h2>", unsafe_allow_html=True)
                                time.sleep(1.0)
                        except ValueError:
                            st.error("Animasi AES: Format Hexadesimal tidak valid.")
                    
                    # ---------------------------------------------------------
                    # TRANSISI KE ALGORITMA BERIKUTNYA
                    # ---------------------------------------------------------
                    time.sleep(1.5) 
                    
                    if len(argumen) == 1:
                        current_text, _ = fungsi(current_text, argumen[0])
                    else:
                        current_text, _ = fungsi(current_text, argumen[0], argumen[1])
                        
                    # [PERBAIKAN] Hapus padding 'X' saat dekripsi Scytale sebelum diproses animasi Caesar
                    if nama_tahap == "Scytale Cipher" and mode == "Dekripsi":
                        current_text = current_text.rstrip('X')
                    
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
