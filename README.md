# Aplikasi Kriptografi A-Z (Streamlit)

Aplikasi web untuk Enkripsi & Dekripsi teks dengan visualisasi langkah-langkah
proses, dibuat untuk tugas kuliah Kriptografi. Semua algoritma beroperasi
murni pada 26 huruf alfabet (A-Z).

## Struktur Proyek

```
crypto_app/
├── app.py                  # UI utama Streamlit
├── requirements.txt
└── algos/
    ├── __init__.py
    ├── utils.py             # fungsi bersama (clean_text, konversi char<->num)
    ├── caesar.py            # Menu 1: Caesar Cipher
    ├── scytale.py           # Menu 2: Scytale Cipher
    ├── rc4.py                # Menu 3: RC4 Cipher (mod 26)
    ├── aes.py                 # Menu 4: AES Simplified (mod 26)
    └── super_crypto.py       # Menu 5: Super Enkripsi (gabungan 4 algoritma)
```

## Cara Menjalankan

1. Pastikan Python 3.8+ sudah terpasang.
2. Masuk ke folder proyek:
   ```bash
   cd crypto_app
   ```
3. (Opsional tapi disarankan) buat virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```
4. Install dependensi:
   ```bash
   pip install -r requirements.txt
   ```
5. Jalankan aplikasi:
   ```bash
   streamlit run app.py
   ```
6. Browser akan otomatis terbuka di `http://localhost:8501`.

## Catatan Implementasi

- **Pembersihan teks**: semua input diubah ke huruf besar, karakter selain A-Z
  (spasi, angka, tanda baca) dibuang otomatis.
- **Caesar Cipher**: substitusi geser, `C = (P + key) mod 26`.
- **Scytale Cipher**: transposisi matriks baris x kolom (isi baris, baca kolom).
- **RC4 mod 26**: KSA membangun S-Box 26 elemen dari kunci, PRGA membangkitkan
  keystream yang dijumlahkan/dikurangkan mod 26 dengan teks.
- **AES Simplified**: blok 4 karakter, tiap blok melalui AddRoundKey → SubBytes
  (+3 mod 26) → ShiftRows (rotasi baris matriks 2x2). Dekripsi membalik urutan.
- **Super Enkripsi**: Caesar → Scytale → RC4 → AES (enkripsi), dan urutan
  kebalikannya untuk dekripsi. Karena Scytale dan AES menambahkan padding
  'X', hasil dekripsi bisa memiliki 'X' tambahan di akhir teks — ini normal.

Setiap fungsi algoritma mengembalikan `(result_text, steps_log)` sehingga UI
bisa menampilkan hasil akhir sekaligus log detail proses di dalam
`st.expander` untuk keperluan presentasi/penjelasan.
