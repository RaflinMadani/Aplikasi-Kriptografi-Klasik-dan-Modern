# Classified E-Voting & Campaign Command System
Node.js + Express + MySQL. Frontend vanilla JS tanpa build step, disajikan langsung oleh `server.js`.

## Struktur Folder
```
e-voting-v2/
├── database/schema.sql        # tabel, trigger has_voted, brankas dokumen
├── server/
│   ├── server.js              # API + menyajikan folder public/ dan shared/
│   ├── ledger.js              # hash chaining + Merkle tree + tally
│   ├── package.json
│   └── .env.example
├── shared/layers.js           # Caesar -> Rail Fence -> AES-256-GCM (dipakai browser dan server)
└── public/
    ├── index.html             # sidebar + 6 menu
    ├── css/app.css
    └── js/
        ├── app.js             # orkestrator UI, memanggil API
        ├── dongle.js          # dongle .key (flashdisk) + auto-lock saat dicabut
        ├── face.js            # face-api.js, descriptor 128-d
        ├── file-crypto.js     # .secure = RC4 + HMAC-SHA256
        └── dct-stego.js       # steganografi DCT 8x8
```

## Cara Menjalankan
1. Nyalakan Apache dan MySQL di XAMPP. Di phpMyAdmin
2. `cd server`, `cp .env.example .env`, ganti semua nilai rahasia (`ADMIN_KEY` adalah kunci panitia). Jika MySQL XAMPP punya password, isi `DB_PASS`.
3. `npm install`, lalu `npm start` (Node.js 20+).
4. Buka `http://localhost:3000` di Chrome atau Edge (akses flashdisk memakai File System Access API). Perlu internet untuk memuat Chart.js dan model face-api dari CDN.

## Alur Pengujian
1. **Gatekeeper:** nyalakan kamera, isi NIK 16 digit dan PIN 4 digit, klik daftar, lalu pilih flashdisk agar `dongle-Vxxxxxx.key` ditulis ke sana (jika dibatalkan, berkas diunduh). Login: pilih flashdisk (dipantau, dicabut berarti terkunci otomatis) atau unggah `.key` (terkunci setelah 5 menit tanpa aktivitas), isi PIN, lalu pindai wajah.
2. **Surat Suara:** pilih kandidat, tabel 3 lapis muncul, suara dikirim dan sesi ditutup. Login kedua kali dengan akun yang sama ditolak (409).
3. **Super-Enkripsi Teks:** tabel per karakter memperlihatkan Plaintext, Caesar, lalu Rail Fence, diikuti AES-256-GCM.
4. **File Vault:** enkripsi berkas ke `.secure`, ubah satu byte lalu dekripsi: HMAC menolak. "Simpan ke server" menyimpan blob ke tabel `campaign_docs` (butuh kunci panitia di tab Dashboard).
5. **Steganografi DCT:** sisipkan token ke gambar, unduh PNG, ekstrak kembali. Uji juga simpan ulang sebagai JPEG kualitas 80.
6. **Dashboard:** isi kunci panitia, muat, lalu aktifkan auto-refresh. Grafik dihitung dari blok tersegel (`BLOCK_SIZE` suara per blok, atau klik Segel). "Tamper blok 1" mengubah isi blok di MySQL dan rantai berubah menjadi TAMPERED.

## Alur Sistem
Registrasi menyimpan hash NIK, hash PIN (PBKDF2), token dongle ter-hash, dan descriptor wajah terenkripsi AES-GCM. Login mengecek ketiganya di server. Suara dienkripsi 3 lapis di browser dengan kunci token sesi, didekripsi server, lalu hanya hash pilihan (HMAC) yang masuk ke antrean, disegel menjadi blok dengan Merkle root dan hash chaining. `has_voted` dikunci dalam transaksi dan oleh trigger.

## Keterbatasan
- Kunci panitia dikirim lewat header: gunakan HTTPS dan jangan tinggalkan nilai bawaan.
- Tidak ada deteksi liveness pada wajah.
- `ALLOW_FACE_SIM=true` hanya untuk demo.
- Dengan sedikit pemilih, blok kecil bisa mengungkap pilihan lewat kombinasi dengan data lain; naikkan `BLOCK_SIZE`.