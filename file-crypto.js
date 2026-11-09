// file-crypto.js - RC4 (KSA, PRGA, XOR) untuk dokumen calon. Format .enc:
// "RC4F" | namaLen(2) | RC4(namaLen... nama | data) | HMAC-SHA256(32)
const RC4_MAGIC = [0x52, 0x43, 0x34, 0x46], MAX_FILE = 50 * 1024 * 1024;

function rc4Core(key, data) {
  if (!key.length) throw new Error('Kunci RC4 kosong.');
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) { // KSA
    j = (j + S[i] + key[i % key.length]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
  }
  const out = new Uint8Array(data.length);
  let a = 0, b = 0;
  for (let n = 0; n < data.length; n++) { // PRGA + XOR
    a = (a + 1) & 255; b = (b + S[a]) & 255;
    [S[a], S[b]] = [S[b], S[a]];
    out[n] = data[n] ^ S[(S[a] + S[b]) & 255];
  }
  return out;
}

async function _mac(keyStr, bytes) {
  const k = await crypto.subtle.importKey('raw', enc.encode('mac|' + keyStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, bytes));
}

async function encryptFile(file, keyStr) {
  if (file.size > MAX_FILE) throw new Error('Maksimal 50 MB.');
  const name = enc.encode(file.name), data = new Uint8Array(await file.arrayBuffer());
  const plain = new Uint8Array(name.length + data.length);
  plain.set(name, 0); plain.set(data, name.length);
  const ct = rc4Core(enc.encode(keyStr), plain);
  const body = new Uint8Array(6 + ct.length);
  body.set(RC4_MAGIC, 0); body[4] = name.length >> 8; body[5] = name.length & 255; body.set(ct, 6);
  const tag = await _mac(keyStr, body), out = new Uint8Array(body.length + 32);
  out.set(body, 0); out.set(tag, body.length);
  return out;
}

async function decryptFile(buf, keyStr) {
  const u = new Uint8Array(buf), body = u.slice(0, -32), tag = u.slice(-32);
  if (!RC4_MAGIC.every((v, i) => body[i] === v)) throw new Error('Bukan berkas .enc valid.');
  const want = await _mac(keyStr, body);
  if (want.some((v, i) => v !== tag[i])) throw new Error('Kunci salah atau berkas diubah.');
  const nl = (body[4] << 8) | body[5], plain = rc4Core(enc.encode(keyStr), body.slice(6));
  return { name: dec.decode(plain.slice(0, nl)), data: plain.slice(nl) };
}
