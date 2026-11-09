# Classified E-Voting & Campaign Command System
Aplikasi e-voting tertutup, client-side murni (HTML5, CSS3, JS ES6), tugas akhir Kriptografi.

## Fitur (7 kriteria)
| # | Fitur | Algoritma | Berkas |
|---|---|---|---|
| 1 | Login 3FA (dongle .key, wajah, PIN) | HMAC/SHA-256, face-api.js (Euclidean <= 0.50) | face-scan.js |
| 2 | Login hash | PBKDF2-HMAC-SHA256 + salt | crypto.js |
| 3 | Super-enkripsi suara | Rail Fence (hanya A-Z) + AES-256-GCM | crypto.js |
| 4 | Enkripsi dokumen calon | RC4 (KSA, PRGA, XOR) + HMAC | file-crypto.js |
| 5 | Enkripsi basis data | AES-256-GCM per field, IndexedDB | db.js |
| 6 | Steganografi kartu pemilih | LSB RGB, delimiter 16 bit, PNG | stego.js |
| 7 | Blockchain log suara | SHA-256 hash chaining + Tamper Block | app.js |

## Menjalankan
Gunakan Chrome/Edge lewat server lokal (bukan file://):
- `npx http-server .` atau
- `python -m http.server 8000` atau
- VS Code Live Server

Buka `http://localhost:8000`.

## Pengujian
1. Daftarkan pemilih, buat dongle `.key`, login 3 faktor.
2. Kirim suara, cek ballot terenkripsi di ledger dan DB Inspector.
3. Tekan Tamper Block, validasi rantai harus berstatus TAMPERED.
4. Enkripsi dokumen, ubah 1 byte, dekripsi harus gagal.
5. Sisipkan token ke kartu PNG, ekstrak kembali.

## Keterbatasan
Berbasis browser dan IndexedDB, belum layak untuk pemilihan sungguhan. Hash ledger tanpa kunci rahasia, RC4 dipertahankan sebagai mode edukasi.
