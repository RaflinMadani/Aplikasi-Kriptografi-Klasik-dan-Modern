# Classified E-Voting & Campaign Command System

Sistem e-voting satu halaman (SPA) dengan dua peran: **Pemilih** dan **Panitia**. Dibangun dengan Node.js, Express, MySQL, dan Vanilla JS tanpa build step.

## Struktur Folder

```
e-voting-v2/
├── database/schema.sql        # tabel, trigger has_voted, tabel campaign_docs
├── server/
│   ├── server.js              # API, sesi, validasi, menyajikan public/ dan shared/
│   ├── ledger.js              # hash chaining, Merkle tree, tally
│   ├── package.json
│   └── .env.example
├── shared/layers.js           # Caesar -> Rail Fence -> AES-256-GCM (browser dan server)
└── public/
    ├── index.html             # sidebar berbasis peran
    ├── css/app.css
    ├── css/app-additions.css  # toast, topbar, kotak penjelasan
    └── js/
        ├── app.js             # orkestrator UI
        ├── dongle.js          # dongle .key (unduh otomatis)
        ├── face.js            # face-api.js, descriptor 128-d
        ├── file-crypto.js     # .secure = RC4 + HMAC-SHA256
        └── dct-stego.js       # steganografi DCT 8x8
```

## Persyaratan

- Node.js 20 atau lebih baru
- MySQL (XAMPP atau instalasi lain)
- Browser Chrome atau Edge (atau browser modern lain)
- Koneksi internet untuk memuat Chart.js dan model face-api dari CDN

## Instalasi

1. Nyalakan Apache dan MySQL di XAMPP, lalu impor `database/schema.sql` lewat phpMyAdmin.
2. Pastikan tabel `campaign_docs` ada (kolom: `id`, `name`, `size`, `data LONGBLOB`, `created_at`). Tabel ini tidak ada di skema lama.
3. Masuk ke folder server:
   ```bash
   cd server
   cp .env.example .env
   ```
   Ganti semua nilai rahasia di `.env`: `ADMIN_KEY`, `ELECTION_SECRET`, `NIK_SALT`, `FACE_KEY`. Jika MySQL punya password, isi `DB_PASS`.
4. Jalankan:
   ```bash
   npm install
   npm start
   ```
5. Buka `http://localhost:3000` di Chrome atau Edge.

Server menolak berjalan dengan `NODE_ENV=production` jika empat rahasia di atas belum diisi.

## Peran dan Menu

### Pemilih
Pemilih hanya melihat dua menu setelah login: **Surat Suara** dan **Status Pemilih**.

- **Gatekeeper**: daftar akun (NIK, PIN, rekam wajah). Dongle `.key` diunduh otomatis ke folder Downloads.
- **Login 3 faktor**: dongle `.key`, PIN, dan pemindaian wajah.
- **Surat Suara**: memilih satu kandidat. Suara dienkripsi tiga lapis di browser, lalu dikirim. Pemilih hanya bisa memilih sekali.
- **Status Pemilih**: menampilkan NIK tersamar, kode pemilih, status memilih, waktu pencatatan, dan nomor blok ledger. Pilihan tidak ditampilkan karena ledger tidak menyimpan identitas.

### Panitia (Admin)
Panitia masuk lewat kartu **Akses Panitia** di Gatekeeper dengan Kunci Panitia. Sesi panitia berlaku 30 menit. Panitia tidak bisa memilih.

- **Tactical Command Messaging**: kanal pesan perintah terenkripsi 3 lapis antar koordinator kampanye.
- **Campaign Logistical Vault**: brankas dokumen logistik. Berkas dienkripsi di browser (`.secure`), lalu disimpan ke server atau diunduh.
- **Anti-Counterfeit Credential**: menanam watermark DCT ke poster resmi, lalu memeriksa materi yang beredar. Hasilnya ASLI, MENCURIGAKAN (kode berbeda), atau TIRUAN (watermark tidak ditemukan).
- **Command Dashboard**: grafik suara tersegel, status rantai ledger, daftar blok, tombol segel, dan demo tamper.

## Alur Sistem

### Registrasi
1. Pemilih mengisi NIK 16 digit dan PIN 4 digit, lalu merekam wajah (5 sampel dirata-rata).
2. Server memeriksa apakah wajah sudah ada di database dengan jarak Euclidean ≤ 0.50. Jika cocok, registrasi ditolak dengan 400 (satu wajah tidak boleh dipakai untuk banyak NIK).
3. Server menyimpan hash NIK (SHA-256 dengan salt), hash PIN (PBKDF2), hash token dongle, dan descriptor wajah terenkripsi AES-256-GCM.
4. Dongle `dongle-Vxxxxxx.key` berisi kode pemilih, token, dan NIK tersamar, lalu diunduh otomatis.

### Login
Server memeriksa ketiga faktor: token dongle, PIN (PBKDF2, dibandingkan dengan `timingSafeEqual`), dan wajah. Lima kali gagal mengunci akun. Sesi pemilih berlaku 15 menit dan dihapus setelah vote.

### Voting
1. Browser membuat paket Caesar → Rail Fence → AES-256-GCM. Kunci AES diambil dari token sesi.
2. Server membuka paket, lalu mencatat hash HMAC pilihan ke antrean.
3. `has_voted` dikunci dalam transaksi dan oleh trigger database.
4. Antrean disegel menjadi blok (`BLOCK_SIZE` suara per blok) dengan urutan diacak, Merkle root, dan hash chaining.

## Penjelasan Algoritma

**Super-enkripsi 3 lapis (teks dan suara):**
- **Caesar**: setiap huruf digeser k posisi, C = (P + k) mod 26. Dekripsi menggeser balik.
- **Rail Fence**: huruf ditulis zig-zag pada N rel, lalu dibaca baris demi baris. Dekripsi membentuk ulang pola zig-zag.
- **AES-256-GCM**: kunci dari PBKDF2-SHA256 (100.000 iterasi, salt 16 B), IV 12 B, dan tag autentikasi 16 B. Paket Base64 berisi salt, IV, dan ciphertext+tag. Dekripsi memeriksa tag dulu.

Dekripsi membalik urutan: AES → Rail Fence → Caesar. Setiap tahap ditampilkan dalam tabel bertahap di halaman.

**File `.secure`:** PBKDF2 menghasilkan kunci RC4 (16 B) dan kunci HMAC (32 B). RC4 membuang 768 byte keystream pertama, lalu di-XOR dengan data. HMAC-SHA256 dihitung atas seluruh berkas (encrypt-then-MAC). Jika HMAC tidak cocok, dekripsi ditolak.

**Steganografi DCT:** luminans dibagi blok 8x8, lalu DCT. Satu bit disandikan lewat selisih C[3][4] dan C[4][3] (minimal 25), diulang 3 blok, dan dibaca dengan suara mayoritas. Header 16 bit menyimpan panjang pesan.

**Ledger:** hash pilihan memakai HMAC dengan `ELECTION_SECRET`. Blok memuat Merkle root dan hash blok sebelumnya (SHA-256). Mengubah satu blok membuat rantai berstatus TAMPERED.

## Variabel Lingkungan (.env)

| Variabel | Fungsi |
|---|---|
| `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME` | koneksi MySQL |
| `PORT` | port server (default 3000) |
| `ADMIN_KEY` | kunci panitia (wajib diganti) |
| `ELECTION_SECRET` | kunci HMAC hash pilihan (wajib diganti) |
| `NIK_SALT` | salt hash NIK (wajib diganti) |
| `FACE_KEY` | kunci enkripsi descriptor wajah (wajib diganti) |
| `ELECTION_SHIFT`, `ELECTION_RAILS` | parameter Caesar dan Rail Fence |
| `BLOCK_SIZE` | jumlah suara per blok (default 3) |
| `ALLOW_FACE_SIM` | `true` mengizinkan simulasi wajah (hanya demo) |
| `ALLOW_TAMPER_DEMO` | `false` mematikan tombol tamper demo |
| `NODE_ENV` | `production` mengaktifkan pemeriksaan rahasia wajib |

## Pengujian yang Disarankan

1. Daftar NIK pertama dengan wajah Anda, lalu unduh dongle.
2. Coba daftar NIK kedua dengan wajah yang sama. Server harus menolak dengan pesan wajah sudah terdaftar.
3. Login pemilih, pilih kandidat, lalu cek halaman Status.
4. Logout, lalu pilih kembali file `.key` dan pastikan login tetap berjalan.
5. Login panitia dan cek setiap menu, termasuk watermark DCT (tanam, lalu periksa dengan dan tanpa kode yang sama).
6. Tekan "Tamper blok 1" dan pastikan status rantai menjadi TAMPERED.

## Keterbatasan

- Kunci panitia dan token dikirim lewat HTTP. Gunakan HTTPS saat dipakai di luar lokal.
- Tidak ada deteksi liveness pada wajah, sehingga foto atau layar masih bisa dipakai. Cek Sybil hanya mitigasi.
- Simulasi wajah (`ALLOW_FACE_SIM=true`) hanya untuk demo.
- Dengan jumlah pemilih kecil, blok kecil dapat membuka pilihan lewat korelasi dengan data lain. Naikkan `BLOCK_SIZE`.
- Caesar dan Rail Fence adalah sandi klasik dan mudah dipecahkan. Keamanan utama ada pada AES-256-GCM.
- Dongle `.key` berada di folder Downloads, sehingga keamanannya bergantung pada pengguna yang menyimpannya.