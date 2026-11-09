// crypto.js - SHA-256, PBKDF2, Rail Fence (A-Z saja), AES-256-GCM
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const PBKDF2_ITERATIONS = 100000, SALT_BYTES = 16, IV_BYTES = 12;

async function sha256Hex(str) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(str)));
  return [...h].map(x => x.toString(16).padStart(2, '0')).join('');
}

async function _pbkdf2Base(pass) {
  return crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
}

// Login PIN: PBKDF2-HMAC-SHA256 + salt acak per akun
async function hashPin(pin, salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES))) {
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, await _pbkdf2Base(pin), 256);
  return { salt: b64(salt), hash: b64(new Uint8Array(bits)) };
}
async function verifyPin(pin, rec) {
  return (await hashPin(pin, unb64(rec.salt))).hash === rec.hash;
}

async function _aesKey(pass, salt) {
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    await _pbkdf2Base(pass), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// Paket Base64: salt(16) | iv(12) | ciphertext + tag(16)
async function aesEncrypt(plain, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await _aesKey(pass, salt), enc.encode(plain)));
  const out = new Uint8Array(SALT_BYTES + IV_BYTES + ct.length);
  out.set(salt, 0); out.set(iv, SALT_BYTES); out.set(ct, SALT_BYTES + IV_BYTES);
  return b64(out);
}
async function aesDecrypt(pkg, pass) {
  const u = unb64(pkg);
  const salt = u.slice(0, SALT_BYTES), iv = u.slice(SALT_BYTES, SALT_BYTES + IV_BYTES), ct = u.slice(SALT_BYTES + IV_BYTES);
  try { return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await _aesKey(pass, salt), ct)); }
  catch { throw new Error('Dekripsi gagal: kunci salah atau data diubah.'); }
}

// Rail Fence: hanya huruf A-Z/a-z yang ditransposisi; petik, koma, spasi, angka tetap di posisinya
function _railOrder(n, rails) {
  const rows = Array.from({ length: rails }, () => []);
  let r = 0, dir = 1;
  for (let i = 0; i < n; i++) {
    rows[r].push(i);
    if (rails > 1) { if (r === 0) dir = 1; else if (r === rails - 1) dir = -1; r += dir; }
  }
  return rows.flat();
}
function _railCore(text, rails, decrypt) {
  rails = Math.max(2, Math.floor(rails));
  const chars = [...text], pos = [];
  chars.forEach((c, i) => { if (/[A-Za-z]/.test(c)) pos.push(i); });
  const letters = pos.map(i => chars[i]), order = _railOrder(letters.length, rails), res = [];
  order.forEach((src, k) => { if (decrypt) res[src] = letters[k]; else res[k] = letters[src]; });
  pos.forEach((p, k) => { chars[p] = res[k]; });
  return chars.join('');
}
const railEncrypt = (t, rails) => _railCore(t, rails, false);
const railDecrypt = (t, rails) => _railCore(t, rails, true);

// Super-enkripsi suara: Rail Fence (klasik) -> AES-256-GCM (modern)
async function superEncrypt(text, rails, pass) {
  const mid = railEncrypt(text, rails);
  return { intermediate: mid, package: await aesEncrypt(mid, pass) };
}
async function superDecrypt(pkg, rails, pass) {
  return railDecrypt(await aesDecrypt(pkg, pass), rails);
}

// Enkripsi field basis data (JSON) dengan AES-256-GCM
const encryptField = (obj, pass) => aesEncrypt(JSON.stringify(obj), pass);
const decryptField = async (pkg, pass) => JSON.parse(await aesDecrypt(pkg, pass));
