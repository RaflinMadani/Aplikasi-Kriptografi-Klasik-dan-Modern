// stego.js - LSB pada kanal R,G,B (alpha dilewati), delimiter 0xFF 0xFE (16 bit)
function _canvas(img) {
  const c = document.createElement('canvas');
  c.width = img.naturalWidth; c.height = img.naturalHeight;
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  return { c, ctx, d: ctx.getImageData(0, 0, c.width, c.height) };
}
function embedLSB(img, message) {
  const { c, ctx, d } = _canvas(img), px = d.data;
  const bytes = [...enc.encode(message), 0xFF, 0xFE], total = bytes.length * 8;
  if (total > (px.length / 4) * 3) throw new Error('Kapasitas gambar tidak cukup.');
  for (let i = 0, k = 0; k < total; i++) {
    if (i % 4 === 3) continue;
    px[i] = (px[i] & 0xFE) | ((bytes[k >> 3] >> (7 - (k & 7))) & 1);
    k++;
  }
  ctx.putImageData(d, 0, 0);
  return c.toDataURL('image/png'); // lossless agar LSB tidak rusak
}
function extractLSB(img) {
  const px = _canvas(img).d.data, bytes = [];
  let cur = 0, n = 0;
  for (let i = 0; i < px.length; i++) {
    if (i % 4 === 3) continue;
    cur = (cur << 1) | (px[i] & 1);
    if (++n === 8) {
      if (cur === 0xFF) return dec.decode(new Uint8Array(bytes)); // 0xFF tak muncul di UTF-8
      bytes.push(cur); cur = 0; n = 0;
    }
  }
  throw new Error('Pesan tersembunyi tidak ditemukan.');
}
